#!/usr/bin/perl
#
# sudo apt-get install libdata-dump-perl libnet-subnet-perl libregexp-common-perl libgeo-ip-perl
#
use warnings;
use strict;

# CIDR notation
open(my $wfh, '<', '/etc/whitelist.cdir');
my @whitelist = <$wfh>;
close($wfh);

use Data::Dump qw(dump);
use Net::Subnet;
use Geo::IP;
use Regexp::Common qw(net);

my $gi = Geo::IP->new(GEOIP_MEMORY_CACHE);

open(my $fh, '<', '/etc/bro/networks.cfg');
while(<$fh>) {
	chomp;
	next if /^\s*#/ || /^$/;
	push @whitelist, $1 if /^(\S+)/;
}
warn "WHITELIST: ",dump( \@whitelist );
my $in_whitelist = subnet_matcher @whitelist;

open(my $pipe, '-|', 'tail -F /opt/zeek/logs/current/notice.log');
while(<$pipe>) {
	chomp;
	if ( m/(Scan::Address_Scan|Scan::Port_Scan|SSH::Password_Guessing)\s+(.+?)\t/ ) {
		#print "# [$1] $2\n";
		my $msg = $2;
		my $ip = $1 if $msg =~ m/^($RE{net}{IPv4})/;
		my $expire = 60 * 60; # 1h

		if ( $in_whitelist->( $ip ) ) {
			warn "WHITELIST: $ip $expire | $msg\n";
			system 'logger', '--tag=zeek', "WHITELIST: $ip $expire $msg";
		} else {
			my $country = $gi->country_code_by_addr($ip);
			if ( $country eq 'HR' ) {
				warn "HR-IGNORE: $ip $country $expire | $msg\n";
			} else {
				warn "ADD: $ip $country $expire | $msg\n";

				system 'ssh', '-i', '/home/dpavlin/.ssh/mtik/enesej', 'enesej@193.198.212.1', qq{/ip firewall address-list add list=public_blacklist address=$ip timeout=${expire}s comment="$msg"};

				system 'logger', '--tag=zeek', "$ip $expire $msg";

			}
		}
	} else {
		print STDERR '.';
	}
}

