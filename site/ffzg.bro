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
		add n$actions[Notice::ACTION_DROP];
	}

event SSH::log_ssh(rec: SSH::Info)
{
    local s = fmt("bro.ssh.login.%s", rec$auth_success);
    statsd_increment(s, 1);
}

# DNS Events

event DNS::log_dns(rec: DNS::Info)
{
     statsd_increment("bro.log.dns", 1); #Track DNS log volume

     if(rec?$rcode && rec$rcode == 3) 
{statsd_increment("bro.dns.error.nxdomain", 1);}

     if(rec?$qtype_name && /query/ !in rec$qtype_name)
     {
         local s = fmt("bro.dns.query.type.%s", rec$qtype_name);
         statsd_increment(s, 1);
     }
}

# Notice Events

event Notice::log_notice(rec: Notice::Info)
{
     statsd_increment("bro.log.notice", 1); #Track Notice log volume

     if(rec?$note)
     {
         local s = fmt("bro.notice.type.%s", rec$note);
         local s2 = sub(s, /::/, "_"); #influxdb doesn't like :: so replace it with _
         statsd_increment(s2, 1);
     }
}

# Conn Events

event Conn::log_conn(rec: Conn::Info)
{
     statsd_increment("bro.log.conn", 1); #Track log volume

     if(rec?$vlan)
     {
         local s = fmt("bro.conn.vlan.%s", rec$vlan);
         statsd_increment(s, 1);
     }
}

# RADIUS Events

event RADIUS::log_radius(rec: RADIUS::Info)
{
     statsd_increment("bro.log.radius", 1);

     if(rec?$username)
     {
     	statsd_increment("bro.radius.username", 1);
#	local s = fmt("bro.radius.username.%s", rec$username);
#	statsd_increment(s, 1);
     }

     if(rec?$connect_info)
     {
     	statsd_increment("bro.radius.connect_info", 1);
     }

}

event Weird::log_weird(rec: Weird::Info)
{
     statsd_increment("bro.log.weird", 1);

     if(rec?$name)
     {
         local s = fmt("bro.weird.name.%s", rec$name);
         statsd_increment(s, 1);
     }
}

# known services
event Known::log_known_services(rec: Known::ServicesInfo)
{
     statsd_increment("bro.log.known-services", 1);

     if(rec?$service)
     {
	for ( svc in rec$service ) {
          local s = fmt("bro.known-services.service.%s", svc);
          local s2 = gsub(s, /::/, "_");
          statsd_increment(s2, 1);
        }
     }

     if(rec?$host)
     {
          statsd_set("bro.known-services.host",  fmt("%s", rec$host));
     }
}


# redis
#
#local redis_filter: Log::Filter =
#                     [$name = "http-extracted-redis",
#                      $writer = Log::WRITER_REDIS,
#                      $config = table(["key"] = "dump_file",
#                                      ["db"] = "4",
#                                      ["server_host"] = "127.0.0.1",
#                                      ["server_port"] = "6379",
#                                      ["key_prefix"] = "",
#                                      ["key_expire"] = "600",
#                                      ["flush_period"] = "10")];
#
#Log::add_filter(NetControl::DROP, redis_filter);
