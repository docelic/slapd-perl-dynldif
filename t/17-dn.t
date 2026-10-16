#!/usr/bin/perl
# DNs: canonical form, special characters, spaces and Unicode
#
# (Strings are UTF-8 bytes, as passed by slapd.)
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_INVALID_DN_SYNTAX LDAP_NAMING_VIOLATION
	LDAP_ALREADY_EXISTS LDAP_UNWILLING_TO_PERFORM/;

my $H= "ou=hosts,$SUFFIX";

sub dns {
	my( $v, $base, %o)= @_;
	my( $ret, $dns)= search_dns( $v, $base, %o);
	$dns
}

subtest 'canonical form' => sub {
	my @cases= (
		[ 'uid=testuser,ou=users,dc=example,dc=com', 'uid=testuser,ou=users,dc=example,dc=com' ],
		[ 'CN=Smith\2C  John   Q ,OU=Users , DC=Example', 'cn=smith\2c john q,ou=users,dc=example', 'case, spaces, hex escape' ],
		[ 'cn=Smith\, John Q,dc=example', 'cn=smith\2c john q,dc=example', 'character escape' ],
		[ 'cn="Smith, John",dc=example', 'cn=smith\2c john,dc=example', 'quoted value' ],
		[ 'sn=Two+cn=One,dc=example', 'cn=one+sn=two,dc=example', 'multi-valued RDN sorted' ],
		[ "cn=\xc3\x9cn\xc3\xaf,dc=example", "cn=\xc3\xbcn\xc3\xaf,dc=example", 'Unicode lowercased' ],
		[ 'cn=\C3\9Cn,dc=example', "cn=\xc3\xbcn,dc=example", 'UTF-8 in hex escapes' ],
		[ 'cn=a/b 100%;o=x', 'cn=a/b 100%,o=x', '; as separator, / and %' ],
		[ 'cn=\#a\<b\>c\=d\+e\;f\"g\\\\h,o=x', 'cn=\23a\3cb\3ec\3dd\2be\3bf\22g\5ch,o=x', 'special characters' ],
		[ 'cn=\ a\ ,o=x', 'cn=a,o=x', 'escaped surrounding spaces are insignificant' ],
		[ '2.5.4.3=x,o=y', '2.5.4.3=x,o=y', 'OID' ],
	);
	for( @cases) {
		my( $in, $out, $name)= @$_;
		is( DynLDIF::canonical_dn( $in), $out, $name || $in);
	}
	for my $bad( 'cn', 'cn=x,,o=y', '=x', 'cn=a,=b', 'c n=x', 'cn="x', 'cn=a\4', ',cn=x') {
		is( DynLDIF::canonical_dn( $bad), undef, "invalid: $bad");
	}
	no_warnings();
};

subtest 'special characters' => sub {
	my( $v, $dir)= new_dynldif();

	add_ok( $v, "dn: cn=Smith\\2C John   Q,$H\nobjectClass: device\ncn: Smith, John Q\n",
		LDAP_SUCCESS, 'escaped comma, as passed by slapd');
	my $dn= "cn=smith\\2c john q,$H";
	ok( -e data_file( $dir, $dn), 'stored under canonical DN');
	is_deeply( dns( $v, "CN=Smith\\, John Q,$H", scope => 0), [ $dn ],
		'found by other forms of the DN');
	is_deeply( dns( $v, $H, scope => 1, filter => '(cn=Smith, John Q)'), [ $dn ],
		'found in one-level search');
	is( $v->modify( "cn=Smith\\2C John Q,$H", 'ADD', 'l', 'x'), LDAP_SUCCESS, 'modify');
	is( $v->compare( "cn=Smith\\2C John Q,$H", 'l=x'), 6, 'compare');

	add_ok( $v, "dn: cn=a/b 100%,$H\nobjectClass: device\ncn: a/b 100%\n");
	ok( -e "$dir/dc=com/dc=example/ou=hosts/cn=a%2fb 100%25.ldif", "'/' and '%' in file names");
	is_deeply( dns( $v, "cn=A/B 100%,$H", scope => 0), [ "cn=a/b 100%,$H" ]);

	add_ok( $v, "dn: cn=x\\2By\\3Dz,$H\nobjectClass: device\ncn: x+y=z\n",
		LDAP_SUCCESS, "escaped '+' and '='");
	is_deeply( dns( $v, $H, scope => 1, filter => '(cn=x+y=z)'), [ "cn=x\\2by\\3dz,$H" ]);
	no_warnings();
};

subtest 'spaces' => sub {
	my( $v, $dir)= new_dynldif();
	add_ok( $v, "dn: cn=John Smith,$H\nobjectClass: device\ncn: John Smith\n");
	add_ok( $v, "dn: cn=JohnSmith,$H\nobjectClass: device\ncn: JohnSmith\n",
		LDAP_SUCCESS, 'DN differing only in spaces is a different entry');
	add_ok( $v, "dn: cn=John  Smith,$H\nobjectClass: device\ncn: John Smith\n",
		LDAP_ALREADY_EXISTS, 'runs of spaces are insignificant');
	is_deeply( dns( $v, $H, scope => 1),
		[ "cn=john smith,$H", "cn=johnsmith,$H" ], 'both found');
	is( $v->delete( "cn=John Smith,$H"), LDAP_SUCCESS);
	is_deeply( dns( $v, $H, scope => 1), [ "cn=johnsmith,$H" ], 'deleted the right one');
	no_warnings();
};

subtest 'Unicode' => sub {
	my( $v, $dir)= new_dynldif();
	my $name= "\xc3\x9cn\xc3\xafc\xc3\xb8d\xc3\xa9"; # Ünïcødé
	add_ok( $v, "dn: cn=$name,$H\nobjectClass: device\ncn: $name\n");
	my $dn= "cn=\xc3\xbcn\xc3\xafc\xc3\xb8d\xc3\xa9,$H";
	is_deeply( dns( $v, "cn=\xc3\x9cN\xc3\x8fC\xc3\x98D\xc3\x89,$H", scope => 0), [ $dn ],
		'found case-insensitively');
	is( $v->compare( $dn, "cn=$name"), 6, 'RDN value in original case');
	my $upper= "\xc3\x9cN\xc3\x8fC\xc3\x98D\xc3\x89";
	is( $v->compare( $dn, "cn=$upper"), 6, 'compare is case-insensitive');
	is_deeply( dns( $v, $H, filter => "(cn=$upper)"), [ $dn ], 'filter is case-insensitive');
	is_deeply( dns( $v, $H, filter => "(cn=*\xc3\x98d\xc3\x89)"), [ $dn ], 'substring filter');
	no_warnings();
};

subtest 'multi-valued RDN' => sub {
	my( $v, $dir)= new_dynldif();
	add_ok( $v, "dn: cn=One+l=Two,$H\nobjectClass: device\ncn: One\n",
		LDAP_NAMING_VIOLATION, 'all RDN values required');
	add_ok( $v, "dn: cn=One+l=Two,$H\nobjectClass: device\ncn: One\nl: Two\n");
	is_deeply( dns( $v, "l=two+cn=one,$H", scope => 0), [ "cn=one+l=two,$H" ],
		'found with values in other order');
	is( $v->modify( "cn=one+l=two,$H", 'DELETE', 'l', 'Two'), 67,
		'RDN value can not be removed');

	is( $v->modrdn( "cn=one+l=two,$H", 'cn=Three+l=Four', 1), LDAP_SUCCESS, 'modrdn');
	my( $ret, @e)= search_entries( $v, "cn=three+l=four,$H", scope => 0);
	is_deeply( [ $e[0]->get_value( 'cn') ], [ 'Three' ], 'old values replaced');
	is_deeply( [ $e[0]->get_value( 'l') ], [ 'Four' ]);
	no_warnings();
};

subtest 'modrdn and copy on write keep values as given' => sub {
	my( $v, $dir)= new_dynldif([[ 'searchFallback', '^cn=[^,]+,ou=hosts,', 'cn=default,ou=hosts,' ]]);
	add_ok( $v, "dn: cn=default,$H\nobjectClass: device\ncn: default\n");
	add_ok( $v, "dn: cn=old,$H\nobjectClass: device\ncn: old\n");

	is( $v->modrdn( "cn=old,$H", 'cn=Doe\, Jane', 1), LDAP_SUCCESS, 'modrdn');
	my( $ret, @e)= search_entries( $v, "cn=doe\\2c jane,$H", scope => 0);
	is_deeply( [ $e[0]->get_value( 'cn') ], [ 'Doe, Jane' ], 'unescaped value');

	is( $v->modify( "cn=New  Host\\2C Two,$H", 'ADD', 'l', 'x'), LDAP_SUCCESS,
		'modify of fallback entry');
	( $ret, @e)= search_entries( $v, "cn=new host\\2c two,$H", scope => 0);
	is_deeply( [ $e[0]->get_value( 'cn') ], [ 'New  Host, Two' ], 'copy has value as given');
	no_warnings();
};

subtest 'invalid DNs' => sub {
	my( $v, $dir)= new_dynldif();
	add_ok( $v, "dn: cn=x,,$H\nobjectClass: device\ncn: x\n", LDAP_INVALID_DN_SYNTAX);
	warnings_like( qr/Invalid or non-normalized DN/);
	is( $v->modrdn( "cn=testuser,ou=groups,$SUFFIX", 'cn', 1), LDAP_INVALID_DN_SYNTAX,
		'modrdn to invalid RDN');
	no_warnings();
};

subtest 'RDNs too long for a file name' => sub {
	my( $v, $dir)= new_dynldif();
	my $ok= 'a' x 200;
	add_ok( $v, "dn: cn=$ok,$H\nobjectClass: device\ncn: $ok\n", LDAP_SUCCESS, '200 characters');
	for my $long( 'a' x 300, '%' x 100) {
		add_ok( $v, "dn: cn=$long,$H\nobjectClass: device\ncn: $long\n",
			LDAP_UNWILLING_TO_PERFORM, length( $long). " characters ($long)");
		warnings_like( qr/RDN too long for a file name/);
	}
	is( $v->modrdn( "cn=$ok,$H", 'cn='. 'b' x 300, 1), LDAP_UNWILLING_TO_PERFORM, 'modrdn');
	warnings_like( qr/RDN too long for a file name/);
	ok( -e data_file( $dir, "cn=$ok,$H"), 'entry kept');
	no_warnings();
};

done_testing;
