#!/usr/bin/perl
use warnings;
use strict;

use Socket qw( inet_aton );

use Getopt::Long;
my $col = 1;
my $del = '\s+';

GetOptions(
	# sort
	'field-separator|t=s' => \$del,
	'key|k=i' => \$col,
	# cut
	'delimiter|d=s' => \$del,
	'fields|f=i' => \$col,
);

my @lines;
my @sort;
while(<>) {
	chomp;
	push @lines, $_;
	my @f = split(/$del/, $_);
	my $ip = $f[ $col - 1 ];
	push @sort, inet_aton($ip) . $#lines;
}

my @sorted = map {
	substr($_,4)
} sort @sort;

foreach my $i ( @sorted ) {
	print $lines[$i], "\n";
}
