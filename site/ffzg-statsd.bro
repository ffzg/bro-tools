# FFZG specific

event SSH::log_ssh(rec: SSH::Info)
{
    if (rec?$auth_success) {
        local s = fmt("bro.ssh.login.%s", rec$auth_success);
        statsd_increment(s, 1);
    }
}

# DNS Events

event DNS::log_dns(rec: DNS::Info)
{
     statsd_increment("bro.log.dns", 1); #Track DNS log volume

     if(rec?$rcode && rec$rcode == 3) {
	statsd_increment("bro.dns.error.nxdomain", 1);
     }

     if(rec?$qtype_name && /query/ !in rec$qtype_name)
     {
         local s = fmt("bro.dns.query-type.%s", rec$qtype_name);
         statsd_increment(s, 1);
     }
}

# Notice Events
event Notice::log_notice(rec: Notice::Info)
{
     statsd_increment("bro.log.notice", 1); #Track Notice log volume

#     if(rec?$note)
#     {
#         local s = fmt("bro.notice.note.%s", rec$note);
#         local s2 = sub(s, /::/, "_"); #influxdb doesn't like :: so replace it with _
#         statsd_increment(s2, 1);
#     }
}
#
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
	statsd_set("bro.radius.usernames", fmt("%s", rec$username));
     }

     if(rec?$connect_info)
     {
     	statsd_increment("bro.radius.connect_info", 1);
     }

}

# weird has too much tags to be useful
event Weird::log_weird(rec: Weird::Info)
{
     statsd_increment("bro.log.weird", 1);
#
#     if(rec?$name)
#     {
#         local s = fmt("bro.weird.name.%s", rec$name);
#         local s2 = gsub(s, /:/, "");
#         statsd_increment(s2, 1);
#     }
}

# known services
event Known::log_known_services(rec: Known::ServicesInfo)
{
     statsd_increment("bro.log.known_services", 1);

     if(rec?$service)
     {
	for ( svc in rec$service ) {
          local s = fmt("bro.known_services.service.%s", svc);
          local s2 = gsub(s, /::/, "_");
          statsd_increment(s2, 1);
        }
     }

     if(rec?$host)
     {
          statsd_set("bro.known_services.host",  fmt("%s", rec$host));
     }
}

# HTTP

event HTTP::log_http(rec: HTTP::Info)
{
     statsd_increment("bro.log.http", 1);

     statsd_set("bro.http.orig_h",  gsub(fmt("%s", rec$id$orig_h), /:/, "")); # handle IPv6 addr
     statsd_set("bro.http.resp_h",  gsub(fmt("%s", rec$id$resp_h), /:/, ""));

     if(rec?$status_code)
     {
	local s = fmt("bro.http.status_code.%s", rec$status_code);
	statsd_increment(s, 1);

     }

	if ( rec?$status_code && rec$id$resp_h in Site::local_nets ) {
		local s2 = fmt("bro.http.local.%s", rec$status_code);
		statsd_increment(s2, 1);

		if ( rec?$uri && rec$uri == "/wp-login.php" ) {
			s2 = fmt("bro.http.wp-login.%s", rec$status_code);
			statsd_increment(s2, 1);
		}
	}


}


event DHCP::log_dhcp(rec: DHCP::Info)
{
	statsd_increment("bro.log.dhcp", 1);
	statsd_set("bro.dhcp.trans", gsub( fmt("%s",rec$mac), /:/, "") );
	# statsd protocol uses : as delimiter, so we need to strip them all from mac
}

event Files::log_files(rec: Files::Info)
{
	statsd_increment("bro.log.files", 1);

	local s = fmt("bro.files.%s.%s.%s"
		, fmt("%s",rec$source)
		, fmt("%s",rec$local_orig)
		, fmt("%s",rec$is_orig)
	);
	statsd_increment(fmt("%s.count",s), 1);
	statsd_increment(fmt("%s.seen_bytes",s), rec$seen_bytes);
	statsd_increment(fmt("%s.missing_bytes",s), rec$missing_bytes);

}
