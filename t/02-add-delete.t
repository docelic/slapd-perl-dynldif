#!/usr/bin/perl
# ADD and DELETE operations
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use MIME::Base64 qw/encode_base64/;
use Encode qw//;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_ALREADY_EXISTS LDAP_NO_SUCH_OBJECT
	LDAP_INVALID_DN_SYNTAX LDAP_NOT_ALLOWED_ON_NONLEAF LDAP_OBJECT_CLASS_VIOLATION LDAP_TYPE_OR_VALUE_EXISTS
	LDAP_NAMING_VIOLATION LDAP_PROTOCOL_ERROR LDAP_OPERATIONS_ERROR/;

my $host= "dn: cn=h1,ou=hosts,$SUFFIX\nobjectClass: device\ncn: h1\n";

subtest 'add' => sub {
	my( $v, $dir)= new_dynldif();

	add_ok( $v, $host, LDAP_SUCCESS, 'new entry added');
	my $file= data_file( $dir, "cn=h1,ou=hosts,$SUFFIX");
	ok( -e $file, 'stored in expected file');
	ok( -d "$dir/dc=com/dc=example/ou=hosts", 'parent directory created');

	my( $ret, @e)= search_entries( $v, "cn=h1,ou=hosts,$SUFFIX", scope => 0);
	is( $e[0]->get_value( 'cn'), 'h1', 'entry readable');

	add_ok( $v, $host, LDAP_ALREADY_EXISTS, 'duplicate rejected');
	add_ok( $v, "dn: cn=x,ou=nosuch,$SUFFIX\nobjectClass: device\ncn: x\n",
		LDAP_NO_SUCH_OBJECT, 'missing parent rejected');
	add_ok( $v, "dn: cn=a,=b,ou=hosts,$SUFFIX\nobjectClass: device\ncn: a\n",
		LDAP_INVALID_DN_SYNTAX, 'invalid DN rejected');
	warnings_like( qr/Invalid or non-normalized DN/);

	add_ok( $v, "dn: CN=Upper Case , OU=hosts,$SUFFIX\nobjectClass: device\ncn: Upper Case\n",
		LDAP_SUCCESS, 'DN is normalized');
	ok( -e data_file( $dir, "cn=upper case,ou=hosts,$SUFFIX"),
		'stored under normalized DN');
	no_warnings();
};

subtest 'entry validation' => sub {
	my( $v, $dir)= new_dynldif();
	add_ok( $v, "dn: cn=x,ou=hosts,$SUFFIX\ncn: x\n",
		LDAP_OBJECT_CLASS_VIOLATION, 'objectClass required');
	add_ok( $v, "dn: cn=x,ou=hosts,$SUFFIX\nobjectClass: device\ncn: other\n",
		LDAP_NAMING_VIOLATION, 'RDN value required');
	add_ok( $v, "dn: cn=X Y,ou=hosts,$SUFFIX\nobjectClass: device\ncn: x y\n",
		LDAP_SUCCESS, 'RDN value compared like DNs (case, spaces)');
	add_ok( $v, "dn: cn=a,=b,ou=hosts,$SUFFIX\ncn: other\n",
		LDAP_INVALID_DN_SYNTAX, 'DN syntax checked first');
	warnings_like( qr/Invalid or non-normalized DN/);
	add_ok( $v, "dn: cn=d,ou=hosts,$SUFFIX\nobjectClass: device\ncn: d\nl: a\nl: A\n",
		LDAP_TYPE_OR_VALUE_EXISTS, 'duplicate values');
	is( $v->add( ''), LDAP_PROTOCOL_ERROR, 'no entry');
	is( $v->add( "objectClass: device\ncn: x\n"), LDAP_OPERATIONS_ERROR, 'no DN');
	warnings_like( qr/^LDIF Load Error: First line of LDIF entry does not begin with "dn:"$/);
	ok( !-e data_file( $dir, "cn=x,ou=hosts,$SUFFIX"), 'nothing stored');
	no_warnings();
};

subtest 'binary and UTF-8 values' => sub {
	my( $v, $dir)= new_dynldif();
	my $bin= join '', map { chr} 0 .. 255;
	add_ok( $v, "dn: cn=bin,ou=hosts,$SUFFIX\nobjectClass: device\ncn: bin\n".
		'jpegPhoto:: '. encode_base64( $bin, ''). "\n");
	my( $ret, @e)= search_entries( $v, "cn=bin,ou=hosts,$SUFFIX", scope => 0);
	ok( $e[0]->get_value( 'jpegPhoto') eq $bin, 'binary value intact');

	my $utf= "\x{106}evap\x{10d}i\x{107}i";
	my $bytes= Encode::encode( 'UTF-8', $utf);
	add_ok( $v, "dn: cn=utf,ou=hosts,$SUFFIX\nobjectClass: device\ncn: utf\n".
		'description:: '. encode_base64( $bytes, ''). "\n");
	( $ret, @e)= search_entries( $v, "cn=utf,ou=hosts,$SUFFIX", scope => 0);
	is( $e[0]->get_value( 'description'), $bytes, 'UTF-8 value intact');
	no_warnings();
};

subtest 'DNs with slashes' => sub {
	my( $v, $dir)= new_dynldif();
	my $hosts= "$dir/dc=com/dc=example/ou=hosts";

	add_ok( $v, "dn: cn=a/b,ou=hosts,$SUFFIX\nobjectClass: device\ncn: a/b\n");
	ok( -e "$hosts/cn=a%2fb.ldif", 'slash stored as %2f');
	add_ok( $v, "dn: cn=a.b,ou=hosts,$SUFFIX\nobjectClass: device\ncn: a.b\n",
		LDAP_SUCCESS, 'DN differing only in "/" vs "." can be added');

	my( $ret, @e)= search_entries( $v, "cn=a/b,ou=hosts,$SUFFIX", scope => 0);
	is( $e[0]->get_value( 'cn'), 'a/b', 'entry with slash');
	( $ret, @e)= search_entries( $v, "cn=a.b,ou=hosts,$SUFFIX", scope => 0);
	is( $e[0]->get_value( 'cn'), 'a.b', 'entry with dot');

	add_ok( $v, "dn: cn=c,cn=a/b,ou=hosts,$SUFFIX\nobjectClass: device\ncn: c\n");
	ok( -e "$hosts/cn=a%2fb/cn=c.ldif", 'child stored under encoded name');
	my $dns;
	( $ret, $dns)= search_dns( $v, "cn=a/b,ou=hosts,$SUFFIX", scope => 1);
	is_deeply( $dns, [ "cn=c,cn=a/b,ou=hosts,$SUFFIX" ], 'children found');

	is( $v->modrdn( "cn=c,cn=a/b,ou=hosts,$SUFFIX", 'cn=d/e', 1), LDAP_SUCCESS,
		'rename to DN with slash');
	ok( -e "$hosts/cn=a%2fb/cn=d%2fe.ldif", 'renamed file');
	no_warnings();
};

subtest 'extension' => sub {
	my( $v, $dir)= new_dynldif([[ 'extension', '.entry' ]]);
	ok( -e "$dir/dc=com/dc=example/ou=users.entry", 'custom extension used');
	ok( !glob( "$dir/dc=com/dc=example/*.ldif"), 'default extension not used');
	my( $ret, $dns)= search_dns( $v, $SUFFIX);
	is( scalar @$dns, 6, 'entries found');
	no_warnings();
};

subtest 'addIgnoreDups' => sub {
	my( $v, $dir)= new_dynldif([[ 'addIgnoreDups', 1 ]]);
	add_ok( $v, $host);
	add_ok( $v, "dn: cn=h1,ou=hosts,$SUFFIX\nobjectClass: device\ncn: h1\nl: new\n",
		LDAP_SUCCESS, 'duplicate silently ignored');
	my( $ret, @e)= search_entries( $v, "cn=h1,ou=hosts,$SUFFIX", scope => 0);
	ok( !$e[0]->exists( 'l'), 'existing entry unchanged');
	no_warnings();
};

subtest 'addOverwrites' => sub {
	my( $v, $dir)= new_dynldif([[ 'addOverwrites', 1 ]]);
	add_ok( $v, $host);
	add_ok( $v, "dn: cn=h1,ou=hosts,$SUFFIX\nobjectClass: device\ncn: h1\nl: new\n",
		LDAP_SUCCESS, 'duplicate overwrites');
	my( $ret, @e)= search_entries( $v, "cn=h1,ou=hosts,$SUFFIX", scope => 0);
	is( $e[0]->get_value( 'l'), 'new', 'existing entry replaced');
	no_warnings();
};

subtest 'delete' => sub {
	my( $v, $dir)= new_dynldif();
	add_ok( $v, $host);

	is( $v->delete( "cn=h1,ou=hosts,$SUFFIX"), LDAP_SUCCESS, 'leaf deleted');
	ok( !-e data_file( $dir, "cn=h1,ou=hosts,$SUFFIX"), 'file removed');
	is( $v->delete( "cn=h1,ou=hosts,$SUFFIX"), LDAP_NO_SUCH_OBJECT,
		'deleting again fails');

	is( $v->delete( "ou=users,$SUFFIX"), LDAP_NOT_ALLOWED_ON_NONLEAF,
		'non-leaf not deleted by default');
	ok( -e data_file( $dir, "uid=testuser,ou=users,$SUFFIX"), 'children kept');

	is( $v->delete( "ou=hosts,$SUFFIX"), LDAP_SUCCESS,
		'entry whose children were all deleted is a leaf');
	no_warnings();
};

subtest 'deleteTrees' => sub {
	my( $v, $dir)= new_dynldif([[ 'deleteTrees', 1 ]]);
	is( $v->delete( "ou=users,$SUFFIX"), LDAP_SUCCESS, 'non-leaf deleted');
	ok( !-e "$dir/dc=com/dc=example/ou=users", 'subtree removed');
	ok( !-e "$dir/dc=com/dc=example/ou=users.ldif", 'entry removed');

	# Part of the tree can't be removed (i.e. files of another user)
	{
		no warnings 'redefine';
		local *DynLDIF::rmtree= sub {
			${ $_[1]{error}}= [{ "$_[0]/x.ldif"=> 'Permission denied' }];
			0
		};
		is( $v->delete( "ou=groups,$SUFFIX"), LDAP_OPERATIONS_ERROR, 'failure');
	}
	ok( -e "$dir/dc=com/dc=example/ou=groups.ldif", 'entry kept');
	warnings_like( qr{^DELETE: can't remove '.*/ou=groups/x.ldif' \(Permission denied\)$});
	no_warnings();
};

done_testing;
