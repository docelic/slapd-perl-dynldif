#!/usr/bin/perl
# etc/default/slapd: preloading the libperl that back_perl is linked with
use strict;
use warnings;
use FindBin;
use Test::More;

my $file= "$FindBin::Bin/../etc/default/slapd";
my $modulepath= $ENV{SLAPD_MODULEPATH} || '/usr/lib/ldap';

# Source the file like the init script does (with -e, so that failing
# commands in it would abort), and print the resulting LD_PRELOAD
sub preload {
	my( $back_perl)= @_;
	local $ENV{BACK_PERL}= $back_perl;
	delete local $ENV{LD_PRELOAD};
	my $out= `sh -ec '. "\$0"; echo "[\${LD_PRELOAD-unset}]"' '$file'`;
	is( $?, 0, 'sourced without errors');
	$out=~ /\[(.*)\]/ ? $1 : undef
}

is( preload( '/nonexistent/back_perl.so'), 'unset',
	'nothing preloaded if back_perl is not found');

SKIP: {
	my $back_perl= "$modulepath/back_perl.so";
	skip "back_perl not found in $modulepath", 3 unless -e $back_perl;

	my( $linked)= `ldd '$back_perl'`=~ /^\s*libperl\.\S+ => (\S+)/m;
	my $lib= preload( $back_perl);
	like( $lib, qr{/libperl\.so\.[\d.]+$}, 'libperl preloaded');
	is( $lib, $linked, 'the one back_perl is linked with');
}

done_testing;
