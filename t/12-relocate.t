#!/usr/bin/perl
# addRelocate rules (Debconf entry relocation)
#
# check_relocation() is called directly here. (On ADD, it runs when
# enableRelocate is set; see 13-switches.t.)
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS/;

my $H= "cn=host1,ou=hosts,$SUFFIX";

my( $v, $dir)= new_dynldif([
	# The README examples (slapd.conf's \\ is a single \ here)
	[ 'addRelocate', 'Site', ',cn=\S+?,ou=', ',ou=defaults,ou=' ],
	[ 'addRelocate', 'Global', ',cn=\S+?,ou=hosts,.+', ',ou=hosts,ou=defaults' ],
	[ 'addRelocate', 'Here', ',cn=\S+?,ou=hosts,', ",ou=hosts," ],
]);
add_ok( $v, "dn: ou=defaults,ou=hosts,$SUFFIX\nobjectClass: organizationalUnit\nou: defaults\n");
add_ok( $v, "dn: $H\nobjectClass: device\ncn: host1\n");

sub dns {
	my( $filter)= @_;
	my( $ret, $dns)= search_dns( $v, $SUFFIX, filter => $filter);
	$dns
}

sub add_and_relocate {
	my( $cn, @variables)= @_;
	my $ldif= "dn: cn=$cn,$H\nobjectClass: device\ncn: $cn\n".
		join( '', map { "variables: $_\n"} @variables);
	add_ok( $v, $ldif);
	my( $ret, @e)= search_entries( $v, "cn=$cn,$H", scope => 0);
	is( $v->check_relocation( $e[0]), LDAP_SUCCESS, "relocate $cn");
}

subtest 'relocation to a label' => sub {
	add_and_relocate( 'k1', 'dynldif_location=Site', 'a=b');
	is_deeply( dns( '(cn=k1)'), [ "cn=k1,ou=defaults,ou=hosts,$SUFFIX" ],
		'moved to the Site location');
	ok( !-e data_file( $dir, "cn=k1,$H"), 'old file removed');
	my( $ret, @e)= search_entries( $v, "cn=k1,ou=defaults,ou=hosts,$SUFFIX", scope => 0);
	is_deeply( [ $e[0]->get_value( 'variables') ], [ 'a=b' ],
		'dynldif_location removed from variables');
	no_warnings();
};

subtest 'label without a rule' => sub {
	add_and_relocate( 'k2', 'dynldif_location=Host');
	is_deeply( dns( '(cn=k2)'), [ "cn=k2,$H" ], 'stays in place');
	my( $ret, @e)= search_entries( $v, "cn=k2,$H", scope => 0);
	ok( !$e[0]->exists( 'variables'), 'dynldif_location removed and re-saved');
	no_warnings();
};

subtest 'no dynldif_location' => sub {
	add_and_relocate( 'k3', 'a=b');
	is_deeply( dns( '(cn=k3)'), [ "cn=k3,$H" ], 'stays in place');
	no_warnings();
};

subtest 'failed relocation keeps the entry' => sub {
	# Outside of this backend's suffix
	add_and_relocate( 'k4', 'dynldif_location=Global');
	warnings_like( qr/Can't relocate 'cn=k4,/);
	is_deeply( dns( '(cn=k4)'), [ "cn=k4,$H" ], 'entry kept');

	# Target exists already
	add_ok( $v, "dn: cn=k5,ou=defaults,ou=hosts,$SUFFIX\nobjectClass: device\ncn: k5\nl: old\n");
	add_and_relocate( 'k5', 'dynldif_location=Site');
	warnings_like( qr/Can't relocate 'cn=k5,/);
	is_deeply( dns( '(cn=k5)'), [ sort "cn=k5,$H", "cn=k5,ou=defaults,ou=hosts,$SUFFIX" ],
		'both entries kept');
	my( $ret, @e)= search_entries( $v, "cn=k5,ou=defaults,ou=hosts,$SUFFIX", scope => 0);
	is( $e[0]->get_value( 'l'), 'old', 'existing target not overwritten');

	# Regex does not apply
	add_ok( $v, "dn: cn=k6,ou=users,$SUFFIX\nobjectClass: device\ncn: k6\nvariables: dynldif_location=Here\n");
	( $ret, @e)= search_entries( $v, "cn=k6,ou=users,$SUFFIX", scope => 0);
	is( $v->check_relocation( $e[0]), LDAP_SUCCESS);
	warnings_like( qr/does not apply/);
	is_deeply( dns( '(cn=k6)'), [ "cn=k6,ou=users,$SUFFIX" ], 'entry kept');
	no_warnings();
};

done_testing;
