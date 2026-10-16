#!/usr/bin/perl
# createTimestamp and modifyTimestamp ('timestamps')
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS/;

my $H= "ou=hosts,$SUFFIX";
my $X= "cn=x,$H";

my $now= '20260101000000Z';
{ no warnings 'redefine'; *DynLDIF::timestamp= sub { $now } }

sub stamps {
	my( $v, $dn)= @_;
	my( $ret, @e)= search_entries( $v, $dn, scope => 0);
	[ map { scalar $e[0]->get_value( $_)} qw/createTimestamp modifyTimestamp/ ]
}


subtest 'maintained by default' => sub {
	my( $v)= new_dynldif([[ 'searchFallback', '^cn=[^,]+,ou=hosts,', 'cn=default,ou=hosts,' ]]);
	add_ok( $v, "dn: $X\nobjectClass: device\ncn: x\n");
	is_deeply( stamps( $v, $X), [ $now, $now ], 'set on ADD');

	$now= '20260102000000Z';
	is( $v->modify( $X, 'REPLACE', 'l', 'a'), LDAP_SUCCESS);
	is_deeply( stamps( $v, $X), [ '20260101000000Z', $now ], 'modifyTimestamp updated');

	$now= '20260103000000Z';
	is( $v->modify( $X, 'REPLACE', 'l', 'a'), LDAP_SUCCESS);
	is_deeply( stamps( $v, $X), [ '20260101000000Z', '20260102000000Z' ],
		'not updated when nothing changes (modifySmarts)');

	is( $v->modrdn( $X, 'cn=y', 1), LDAP_SUCCESS);
	is_deeply( stamps( $v, "cn=y,$H"), [ '20260101000000Z', $now ], 'updated on MODRDN');

	$now= '20260104000000Z';
	add_ok( $v, "dn: cn=default,$H\nobjectClass: device\ncn: default\n".
		"createTimestamp: 20250101000000Z\nmodifyTimestamp: 20250101000000Z\n");
	is_deeply( stamps( $v, "cn=default,$H"), [ '20250101000000Z', '20250101000000Z' ],
		'values given on ADD are kept');
	is( $v->modify( "cn=new,$H", 'ADD', 'l', 'b'), LDAP_SUCCESS, 'copy on write');
	is_deeply( stamps( $v, "cn=new,$H"), [ $now, $now ], 'copy is a new entry');
	no_warnings();
};

subtest 'timestamps 0' => sub {
	my( $v)= new_dynldif([[ 'timestamps', 0 ]]);
	add_ok( $v, "dn: $X\nobjectClass: device\ncn: x\n");
	is( $v->modify( $X, 'REPLACE', 'l', 'a'), LDAP_SUCCESS);
	is_deeply( stamps( $v, $X), [ undef, undef ], 'not set');
	no_warnings();
};

done_testing;
