#!/usr/bin/perl
#
# sudo apt-get install libredis-perl libjson-perl libjson-xs-perl libdata-dump-perl libnet-subnet-perl
#
use warnings;
use strict;

# CIDR notation
my @whitelist = qw(
161.53.0.0/16
193.198.0.0/16
82.132.0.0/17
31.147.0.0/16 
188.252.128.0/17
188.252.196.0/22
93.139.0.0/16
93.140.0.0/16
93.141.0.0/16
93.142.0.0/16
93.143.0.0/16
94.253.128.0/17
95.168.96.0/19
213.149.32.0/19
31.147.204.112/32
109.227.0.0/18
);

use Redis;
use JSON;
use Data::Dump qw(dump);
use Net::Subnet;

open(my $fh, '<', '/etc/bro/networks.cfg');
while(<$fh>) {
	chomp;
	next if /^\s*#/ || /^$/;
	push @whitelist, $1 if /^(\S+)/;
}
warn "WHITELIST: ",dump( \@whitelist );
my $in_whitelist = subnet_matcher @whitelist;


my $r = Redis->new();
my $r2 = Redis->new();

my $channel = '__key*__:*';

$r2->config_set( 'notify-keyspace-events' => 'KEA' );

$r2->psubscribe( $channel,
	my $savecallback = sub {
		my ($message, $topic, $subscribed_topic) = @_;
			#warn "# $message | $topic\n";
			if ( $message eq 'set' && $topic =~ m/^__keyspace\@(\d+)__:(\S+)/ ) {
				my ($db, $key) = ( $1,$2 );
				$r->select( $db );
				if ( my $json_txt = $r->get($key) ) {
					my $json = from_json $json_txt;
					#warn "XXX $db $key ",dump($json);
					my ( $ip, $expire, $msg );
					if ( $db == 4 ) {
						$ip = $json->{orig_h};
						$expire = $json->{expire};
						$msg = $json->{location};
					} elsif ( $db == 5 ) {
						$ip = $json->{src};
						$expire = $json->{suppress_for};
						$msg = $json->{msg};
					} else {
						warn "IGNORED: db=$db\n";
					}

					if ( $in_whitelist->( $ip ) ) {
						warn "WHITELIST: $ip $expire | $msg\n";
						system 'logger', '--tag=bro', "--id=$db", "WHITELIST: $ip $expire $msg";
					} else {
						warn "ADD: $ip $expire | $msg\n";

						system 'ssh', '-i', '/home/dpavlin/.ssh/mtik/enesej', 'enesej@193.198.212.1', qq{/ip firewall address-list add list=public_blacklist address=$ip timeout=${expire}s comment="$msg"};

						system 'logger', '--tag=bro', "--id=$db", "$ip $expire $msg";
					}

					$r->del( $key );
				} else {
					warn "ERROR: can't get $key from $db";
				}
			}
		},
);

my $timeout = 5;
while (1) {
	$r2->wait_for_messages($timeout);
}
