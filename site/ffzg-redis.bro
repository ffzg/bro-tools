# FFZG specific

# Process packets despite bad checksums.
#redef ignore_checksums = T;
# use ethtool to turn off all offloading

# https://www.bro.org/sphinx-git/frameworks/netcontrol.html
@load protocols/ssh/detect-bruteforcing

redef SSH::password_guesses_limit=3;

event NetControl::init()
	{
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin, 0);
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == SSH::Password_Guessing )
		#NetControl::drop_address(n$src, 60min);
		add n$actions[Notice::ACTION_DROP];
	}



# redis

function only_some_notices(rec: Notice::Info) : bool
{
	return rec?$note && ( rec$note == HTTP::SQL_Injection_Attacker || rec$note == Scan::Address_Scan || rec$note == Scan::Port_Scan ) && ! ( rec$src in Site::local_nets );
	#return rec?$note && rec$note == HTTP::SQL_Injection_Attacker;
}

function only_non_local_nets(rec: Notice::Info) : bool
{
	return ! ( rec$src in Site::local_nets );
}

event bro_init() &priority=-5 {
	local redis_filter: Log::Filter =
	                     [$name = "http-extracted-redis",
	                      $writer = Log::WRITER_REDIS,
	                      $pred = only_non_local_nets,
	                      $config = table(["key"] = "dump_file",
	                                      ["db"] = "4",
	                                      ["server_host"] = "127.0.0.1",
	                                      ["server_port"] = "6379",
	                                      ["key_prefix"] = "",
	                                      ["key_expire"] = "600",
	                                      ["flush_period"] = "10")];
	
	Log::add_filter(NetControl::DROP, redis_filter);

	# detect sql injections
	local redis_filter2: Log::Filter =
	                     [$name = "notice-redis-sql",
	                      $pred = only_some_notices,
	                      $writer = Log::WRITER_REDIS,
	                      $config = table(["key"] = "dump_file",
	                                      ["db"] = "5",
	                                      ["server_host"] = "127.0.0.1",
	                                      ["server_port"] = "6379",
	                                      ["key_prefix"] = "",
	                                      ["key_expire"] = "600",
	                                      ["flush_period"] = "10")];
	
	Log::add_filter(Notice::LOG, redis_filter2);
}
