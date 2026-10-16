#!/usr/bin/perl
# COMPARE, MODRDN and BIND operations
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_NO_SUCH_OBJECT LDAP_ALREADY_EXISTS
	LDAP_NOT_ALLOWED_ON_NONLEAF LDAP_COMPARE_TRUE LDAP_COMPARE_FALSE
	LDAP_NO_SUCH_ATTRIBUTE LDAP_INVALID_CREDENTIALS LDAP_UNWILLING_TO_PERFORM/;

my $U= "uid=testuser,ou=users,$SUFFIX";
my $G= "cn=testuser,ou=groups,$SUFFIX";

sub get {
	my( $v, $dn)= @_;
	my( $ret, @e)= search_entries( $v, $dn, scope => 0);
	$e[0]
}

subtest 'compare' => sub {
	my( $v, $dir)= new_dynldif([
		[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ],
		[ 'entryAppend', 'objectClass', '^posixAccount$', '->',
			'append', '.+', "cn=defaults,ou=hosts,$SUFFIX" ],
	]);
	add_ok( $v, "dn: cn=defaults,ou=hosts,$SUFFIX\nobjectClass: device\ncn: defaults\nl: Zagreb\n");

	is( $v->compare( $U, 'uid=testuser'), LDAP_COMPARE_TRUE, 'match');
	is( $v->compare( $U, 'uid=other'), LDAP_COMPARE_FALSE, 'no match');
	is( $v->compare( $U, 'cn=test user'), LDAP_COMPARE_TRUE,
		'case-insensitive match');
	is( $v->compare( $U, 'objectClass=posixAccount'), LDAP_COMPARE_TRUE,
		'one of multiple values');
	is( $v->compare( $U, 'l=Zagreb'), LDAP_COMPARE_TRUE,
		'value from entryAppend');
	is( $v->compare( $U, 'title=x'), LDAP_NO_SUCH_ATTRIBUTE,
		'attribute not present');
	is( $v->compare( $U, 'cn=*'), LDAP_COMPARE_FALSE,
		'value is not interpreted as a filter');
	is( $v->compare( "uid=nosuch,ou=users,$SUFFIX", 'uid=x'),
		LDAP_NO_SUCH_OBJECT, 'nonexistent entry');
	no_warnings();
};

subtest 'modrdn' => sub {
	my( $v, $dir)= new_dynldif();

	is( $v->modrdn( $G, 'cn=Renamed Group', 1), LDAP_SUCCESS,
		'rename with deleteoldrdn');
	my $new= "cn=renamed group,ou=groups,$SUFFIX";
	ok( !-e data_file( $dir, $G), 'old file removed');
	ok( -e data_file( $dir, $new), 'new file created');
	my $e= get( $v, $new);
	is( $e->dn, $new, 'entry has new DN');
	is_deeply( [ $e->get_value( 'cn') ], [ 'Renamed Group' ],
		'old RDN value removed, new one added with original case');
	is( $e->get_value( 'gidNumber'), 12000, 'other attributes kept');
	is( get( $v, $G), undef, 'old DN gone');

	is( $v->modrdn( $new, 'cn=third', 0), LDAP_SUCCESS,
		'rename keeping old RDN');
	is_deeply( [ sort { $a cmp $b } get( $v, "cn=third,ou=groups,$SUFFIX")->get_value( 'cn') ],
		[ 'Renamed Group', 'third' ], 'old RDN value kept');

	is( $v->modrdn( "cn=third,ou=groups,$SUFFIX", 'cn=moved', 1, "ou=hosts,$SUFFIX"),
		LDAP_SUCCESS, 'move to new superior');
	ok( get( $v, "cn=moved,ou=hosts,$SUFFIX"), 'entry found under new parent');
	ok( !-e data_file( $dir, "cn=third,ou=groups,$SUFFIX"), 'old file removed');
	is( $v->delete( "ou=groups,$SUFFIX"), LDAP_SUCCESS,
		'old parent is a leaf again');

	is( $v->modrdn( "ou=users,$SUFFIX", 'ou=people', 1),
		LDAP_NOT_ALLOWED_ON_NONLEAF, 'non-leaf refused');
	is( $v->modrdn( "cn=moved,ou=hosts,$SUFFIX", 'uid=testuser', 1, "ou=users,$SUFFIX"),
		LDAP_ALREADY_EXISTS, 'existing target refused');
	ok( get( $v, "cn=moved,ou=hosts,$SUFFIX"), 'source kept after refusal');
	is( $v->modrdn( "cn=nosuch,ou=hosts,$SUFFIX", 'cn=x', 1),
		LDAP_NO_SUCH_OBJECT, 'nonexistent entry');
	is( $v->modrdn( "cn=moved,ou=hosts,$SUFFIX", 'cn=x', 1, "ou=nosuch,$SUFFIX"),
		LDAP_NO_SUCH_OBJECT, 'nonexistent new superior');
	ok( get( $v, "cn=moved,ou=hosts,$SUFFIX"), 'source kept after failure');
	is( $v->modrdn( "cn=moved,ou=hosts,$SUFFIX", 'cn=moved', 1),
		LDAP_SUCCESS, 'rename to same DN is a no-op');
	no_warnings();
};

subtest 'bind' => sub {
	my( $v)= new_dynldif();
	is( $v->bind( $U, 'test'), LDAP_UNWILLING_TO_PERFORM,
		'disabled by default');

	( $v)= new_dynldif([[ 'enableBind', 1 ]]);
	is( $v->bind( $U, 'test'), LDAP_SUCCESS, 'correct password');
	is( $v->bind( $U, 'wrong'), LDAP_INVALID_CREDENTIALS, 'wrong password');
	is( $v->bind( "uid=nosuch,ou=users,$SUFFIX", 'test'),
		LDAP_INVALID_CREDENTIALS, 'nonexistent entry');
	no_warnings();
};

subtest 'hashed passwords' => sub {
	my( $v)= new_dynldif([[ 'enableBind', 1 ]]);

	# Generated with slappasswd(8), password 'secret'
	my @hashes= qw(
		{SSHA}eHy8TGKEINjS8nSCVwjZ87stV4zV3An6
		{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=
		{SMD5}LR5EfFFTThhNzyNAD1k0y4e6viU=
		{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ==
		{CLEARTEXT}secret
		{CRYPT}$6$PXueELpw3jU8vUvq$LMy62c59WMXWIHcyrkEqtQfEBKT0.yZDEnjTmuNhCpqRmE/m6P2Rqalo3L6VgwaGW8r9TopJmavNdwseuhOsb1
		{CRYPT}$1$EtM5R0NU$oSflxZpVezSoMkOlRkSL81
		{SHA256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=
		{SSHA256}/Bh3LkjYKt+ySHMWR3F5ooBJJkh8TzPmJKN++5eDXCergKIZ3aBzqg==
		{SHA512}vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==
		{SSHA512}BQk6vCORNGQxSMSa+K8qGlmxxOBPWk/3SiwmWBoLnJaoZNR2KWZbNKY7v96zcMgkJCfZQJ1U2Bdk2LYfax/LgPPe8g+TCzhS
	);
	for my $hash( @hashes) {
		my( $scheme)= $hash=~ /^(\{\w+\})/;
		is( $v->modify( $U, 'REPLACE', 'userPassword', $hash), LDAP_SUCCESS);
		is( $v->bind( $U, 'secret'), LDAP_SUCCESS, "$scheme correct password");
		is( $v->bind( $U, 'Secret'), LDAP_INVALID_CREDENTIALS, "$scheme wrong password");
		is( $v->bind( $U, $hash), LDAP_INVALID_CREDENTIALS,
			"$scheme hash is not accepted as password");
	}

	is( $v->modify( $U, 'REPLACE', 'userPassword', '{SSHA}', '{FOO}secret'),
		LDAP_SUCCESS);
	is( $v->bind( $U, 'secret'), LDAP_INVALID_CREDENTIALS,
		'unknown scheme or bad hash never matches');
	is( $v->bind( $U, '{FOO}secret'), LDAP_INVALID_CREDENTIALS,
		'value with unknown scheme is not compared literally');

	is( $v->modify( $U, 'REPLACE', 'userPassword', 'plain', $hashes[0]), LDAP_SUCCESS);
	is( $v->bind( $U, 'plain'), LDAP_SUCCESS, 'any of multiple values');
	is( $v->bind( $U, 'secret'), LDAP_SUCCESS, 'any of multiple values');
	no_warnings();
};

done_testing;
