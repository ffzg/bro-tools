#!/usr/bin/perl
#
# sudo apt-get install libredis-perl libjson-perl libjson-xs-perl libdata-dump-perl
#
use warnings;
use strict;

use Redis;
use JSON;
use Data::Dump qw)dump);

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

					warn "XXX $ip $expire | $msg\n";

					system 'ssh', '-i', '/home/dpavlin/.ssh/mtik/enesej', 'enesej@193.198.212.1', qq{/ip firewall address-list add list=public_blacklist address=$ip timeout=${expire}s comment="$msg"} if $ip;

					system 'logger', '--tag=json', "--id=$db", $json_txt;

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
