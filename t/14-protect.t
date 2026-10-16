#!/usr/bin/perl
# protectAttrs (attributes that can't be tested in filters and compare)
# and hiding of their values in debug output
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_COMPARE_TRUE LDAP_COMPARE_FALSE
	LDAP_INSUFFICIENT_ACCESS/;

my $U= "uid=testuser,ou=users,$SUFFIX";

sub dns {
	my( $v, $filter)= @_;
	my( $ret, $dns)= search_dns( $v, $SUFFIX, filter => $filter);
	is( $ret, LDAP_SUCCESS, "search $filter");
	$dns
}

sub read_log {
	my( $dir)= @_;
	open my $fh, '<', "$dir/dynldif.log" or return q{};
	local $/;
	<$fh>
}

subtest 'userPassword is protected by default' => sub {
	my( $v)= new_dynldif();
	is_deeply( dns( $v, '(userPassword=*)'), [], 'presence');
	is_deeply( dns( $v, '(userPassword=test)'), [], 'equality');
	is_deeply( dns( $v, '(userPassword=t*)'), [], 'substring');
	is_deeply( dns( $v, '(!(userPassword=*))'), [], 'negated presence');
	is_deeply( dns( $v, '(userpassword;x=test)'), [], 'case and options');
	is_deeply( dns( $v, '(|(uid=testuser)(userPassword=*))'), [ $U ],
		'OR with other components');
	is_deeply( dns( $v, '(&(uid=testuser)(!(userPassword=x)))'), [],
		'AND with negated protected component');

	is( $v->compare( $U, 'userPassword=test'), LDAP_INSUFFICIENT_ACCESS,
		'compare refused');
	is( $v->compare( $U, 'userPassword=wrong'), LDAP_INSUFFICIENT_ACCESS,
		'same result for a wrong value');
	is( $v->compare( "uid=nosuch,ou=users,$SUFFIX", 'userPassword=x'),
		LDAP_INSUFFICIENT_ACCESS, 'same result for a missing entry');
	is( $v->compare( $U, 'uid=testuser'), LDAP_COMPARE_TRUE,
		'other attributes can be compared');
	no_warnings();
};

subtest 'names from schema' => sub {
	my( $v)= new_dynldif([
		[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ],
		[ 'protectAttrs', 'userPassword', 'surname' ],
	]);
	is_deeply( dns( $v, '(2.5.4.35=*)'), [], 'OID');
	is( $v->compare( $U, '2.5.4.35=test'), LDAP_INSUFFICIENT_ACCESS, 'compare by OID');
	is_deeply( dns( $v, '(sn=User)'), [], 'name of an attribute listed by alias');
	is( $v->compare( $U, 'sn=User'), LDAP_INSUFFICIENT_ACCESS, 'compare by name');
	no_warnings();
};

subtest 'protectAttrs none' => sub {
	for my $none( [], [ 'none' ]) {
		my( $v)= new_dynldif([[ 'protectAttrs', @$none ]]);
		is_deeply( dns( $v, '(userPassword=test)'), [ $U ], 'filter');
		is( $v->compare( $U, 'userPassword=test'), LDAP_COMPARE_TRUE, 'compare');
		is( $v->compare( $U, 'userPassword=x'), LDAP_COMPARE_FALSE, 'compare');
	}
	no_warnings();
};

subtest 'other attributes' => sub {
	my( $v)= new_dynldif([[ 'protectAttrs', 'loginShell' ]]);
	is_deeply( dns( $v, '(loginShell=*)'), [], 'listed attribute protected');
	is_deeply( dns( $v, '(userPassword=test)'), [ $U ],
		'userPassword not protected when not listed');
	no_warnings();
};

subtest 'internal searches are not restricted' => sub {
	# Searches from overlays come from the configuration, not from clients
	my( $v)= new_dynldif([[ 'findVal', '.', '^$' ]]);
	add_ok( $v, "dn: cn=t,ou=hosts,$SUFFIX\nobjectClass: device\ncn: t\n".
		"l: \$ find \$ $SUFFIX 2 0 0 0 (userPassword=test) 0 uid\n");
	my( $ret, @e)= search_entries( $v, "cn=t,ou=hosts,$SUFFIX", scope => 0);
	is( $e[0]->get_value( 'l'), 'testuser', 'find overlay filter');
	no_warnings();
};

subtest 'values hidden in debug output' => sub {
	my( $v, $dir)= new_dynldif([[ 'debug', 'all' ], [ 'protectAttrs', 'userPassword', 'title' ]]);
	add_ok( $v, "dn: uid=u2,ou=users,$SUFFIX\nobjectClass: inetOrgPerson\nuid: u2\n".
		"cn: u2\nsn: u2\ntitle: secrettitle\nuserPassword: secretpw1\n");
	is( $v->add( "dn: uid=u3,ou=users,$SUFFIX\nobjectClass: inetOrgPerson\nuid: u3\n".
		"cn: u3\nsn: u3\nuserPassword: secret\n pw2folded\nuserPassword:: c2VjcmV0cHcz\n"),
		LDAP_SUCCESS, 'add with folded and base64 values');
	is( $v->modify( $U, 'REPLACE', 'userPassword', 'secretpw4', 'ADD', 'description', 'visible'),
		LDAP_SUCCESS);
	dns( $v, '(|(userPassword=secretpw5)(userPassword;x>=secretpw6)(cn=visible2))');
	is( $v->compare( $U, 'userPassword=secretpw7'), LDAP_INSUFFICIENT_ACCESS);
	$v->config( 'debug', 'none');

	my $log= read_log( $dir);
	like( $log, qr/^### ADD/m, 'debug output present');
	unlike( $log, qr/secret/, 'no protected values in the log');
	like( $log, qr/^userPassword: \*\*\*\*\*$/m, 'ADD');
	like( $log, qr/^title: \*\*\*\*\*$/m, 'ADD, other protected attribute');
	like( $log, qr/^userPassword:: \*\*\*\*\*$/m, 'ADD, base64 value');
	like( $log, qr/MODIFY .*REPLACE userPassword: \*\*\*\*\*; ADD description: visible/,
		'MODIFY');
	like( $log, qr/\(\|\(userPassword=\*\*\*\*\*\)\(userPassword;x>=\*\*\*\*\*\)\(cn=visible2\)\)/,
		'SEARCH filter');

	# userPassword is hidden even if not protected
	( $v, $dir)= new_dynldif([[ 'debug', 1 ], [ 'protectAttrs', 'none' ]]);
	is( $v->modify( $U, 'REPLACE', 'userPassword', 'secretpw8'), LDAP_SUCCESS);
	unlike( read_log( $dir), qr/secret/, 'userPassword always hidden');
	$v->config( 'debug', 'none');
	no_warnings();
};

done_testing;
