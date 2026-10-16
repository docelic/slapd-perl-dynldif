#!/usr/bin/perl
# MODIFY operation
#
# DynLDIF receives modifications from back-perl as a flat list:
#   DN, ACTION, ATTR, VALUE..., ACTION, ATTR, VALUE..., ...
# where ACTION is ADD, DELETE or REPLACE, and a DELETE of the whole
# attribute has a single undef value.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use File::Find qw//;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_NO_SUCH_OBJECT LDAP_OPERATIONS_ERROR
	LDAP_TYPE_OR_VALUE_EXISTS LDAP_NO_SUCH_ATTRIBUTE LDAP_NOT_ALLOWED_ON_RDN
	LDAP_OBJECT_CLASS_VIOLATION/;

my $U= "uid=testuser,ou=users,$SUFFIX";

sub get {
	my( $v, $dn)= @_;
	my( $ret, @e)= search_entries( $v, $dn, scope => 0);
	$e[0]
}

subtest 'add, replace, delete' => sub {
	my( $v, $dir)= new_dynldif();

	is( $v->modify( $U, 'ADD', 'description', 'one', 'two'), LDAP_SUCCESS,
		'add values');
	is_deeply( [ get( $v, $U)->get_value( 'description') ], [ qw/one two/ ]);

	is( $v->modify( $U, 'DELETE', 'description', 'one'), LDAP_SUCCESS,
		'delete value');
	is_deeply( [ get( $v, $U)->get_value( 'description') ], [ 'two' ]);

	is( $v->modify( $U, 'REPLACE', 'sn', 'Other', 'ADD', 'title', 'Boss'),
		LDAP_SUCCESS, 'several modifications at once');
	is( get( $v, $U)->get_value( 'sn'), 'Other');
	is( get( $v, $U)->get_value( 'title'), 'Boss');

	is( $v->modify( $U, 'DELETE', 'title', undef), LDAP_SUCCESS,
		'delete attribute');
	ok( !get( $v, $U)->exists( 'title'));

	is( $v->modify( $U, 'REPLACE', 'description'), LDAP_SUCCESS,
		'replace with no values deletes attribute');
	ok( !get( $v, $U)->exists( 'description'));

	is( $v->modify( "uid=nosuch,ou=users,$SUFFIX", 'REPLACE', 'sn', 'x'),
		LDAP_NO_SUCH_OBJECT, 'nonexistent entry');
	no_warnings();
};

subtest 'result codes' => sub {
	my( $v, $dir)= new_dynldif();

	is( $v->modify( $U, 'ADD', 'sn', 'User'), LDAP_TYPE_OR_VALUE_EXISTS,
		'add existing value');
	is( $v->modify( $U, 'ADD', 'sn', 'USER'), LDAP_TYPE_OR_VALUE_EXISTS,
		'add existing value in other case');
	is( $v->modify( $U, 'ADD', 'sn', 'Other', 'ADD', 'cn', 'Test User'),
		LDAP_TYPE_OR_VALUE_EXISTS, 'later modification fails');
	is_deeply( [ get( $v, $U)->get_value( 'sn') ], [ 'User' ],
		'no duplicates, and nothing applied');

	is( $v->modify( $U, 'DELETE', 'sn', 'nope'), LDAP_NO_SUCH_ATTRIBUTE,
		'delete missing value');
	is( $v->modify( $U, 'DELETE', 'title', undef), LDAP_NO_SUCH_ATTRIBUTE,
		'delete missing attribute');
	is( $v->modify( $U, 'DELETE', 'title', 'x'), LDAP_NO_SUCH_ATTRIBUTE,
		'delete value of missing attribute');
	is( $v->modify( $U, 'DELETE', 'givenName', 'TEST'), LDAP_SUCCESS,
		'delete value in other case');
	ok( !get( $v, $U)->exists( 'givenName'), 'value deleted');

	is( $v->modify( $U, 'REPLACE', 'title', undef), LDAP_SUCCESS,
		'replace missing attribute with nothing');

	is( $v->modify( $U, 'DELETE', 'uid', 'testuser'), LDAP_NOT_ALLOWED_ON_RDN,
		'delete RDN value');
	is( $v->modify( $U, 'DELETE', 'uid', undef), LDAP_NOT_ALLOWED_ON_RDN,
		'delete RDN attribute');
	is( $v->modify( $U, 'REPLACE', 'uid', 'other'), LDAP_NOT_ALLOWED_ON_RDN,
		'replace RDN value');
	is( $v->modify( $U, 'ADD', 'uid', 'second'), LDAP_SUCCESS,
		'add value to RDN attribute');
	is( $v->modify( $U, 'REPLACE', 'uid', 'TestUser', 'third'), LDAP_SUCCESS,
		'replace keeping RDN value');
	is_deeply( [ get( $v, $U)->get_value( 'uid') ], [ 'TestUser', 'third' ]);

	is( $v->modify( $U, 'DELETE', 'objectClass', undef), LDAP_OBJECT_CLASS_VIOLATION,
		'objectClass can not be removed');
	is( $v->modify( $U, 'DELETE', 'objectClass', qw/person inetOrgPerson organizationalPerson posixAccount/),
		LDAP_OBJECT_CLASS_VIOLATION, 'nor all of its values');
	is( $v->modify( $U, 'REPLACE', 'description', 'a', 'b', 'A'), LDAP_TYPE_OR_VALUE_EXISTS,
		'duplicate values in REPLACE');
	is( $v->modify( $U, 'ADD', 'description', 'a', 'A'), LDAP_TYPE_OR_VALUE_EXISTS,
		'duplicate values in ADD');
	ok( !get( $v, $U)->exists( 'description'), 'nothing applied');
	is( $v->modify( $U, 'ADD', 'description', map { "value $_" } 1.. 2000), LDAP_SUCCESS,
		'many distinct values');
	no_warnings();
};

subtest 'entries without RDN value' => sub {
	# I.e. created outside of DynLDIF; modifying them is still possible
	my( $v, $dir)= new_dynldif();
	my $dn= "cn=old,ou=hosts,$SUFFIX";
	mkdir "$dir/dc=com/dc=example/ou=hosts";
	open my $fh, '>', data_file( $dir, $dn) or die;
	print $fh "dn: $dn\nobjectClass: device\ncn: other\n";
	close $fh;
	is( $v->modify( $dn, 'ADD', 'l', 'x'), LDAP_SUCCESS);
	no_warnings();
};

subtest 'equality rules from schema' => sub {
	# homeDirectory is case-exact (caseExactIA5Match)
	my( $v)= new_dynldif();
	is( $v->modify( $U, 'DELETE', 'homeDirectory', '/HOME/TESTUSER'), LDAP_SUCCESS,
		'without schema, case-insensitive');

	( $v)= new_dynldif([[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ]]);
	is( $v->modify( $U, 'DELETE', 'homeDirectory', '/HOME/TESTUSER'),
		LDAP_NO_SUCH_ATTRIBUTE, 'with schema, case-exact');
	is( $v->modify( $U, 'ADD', 'homeDirectory', '/HOME/TESTUSER'), LDAP_SUCCESS,
		'value differing in case is a different value');
	is( $v->modify( $U, 'ADD', 'cn', 'TEST USER'), LDAP_TYPE_OR_VALUE_EXISTS,
		'case-insensitive attribute');
	is( $v->modify( $U, 'REPLACE', 'homeDirectory', '/a', '/A'), LDAP_SUCCESS,
		'values differing in case are distinct for case-exact attributes');
	no_warnings();
};

subtest 'value named like an attribute' => sub {
	my( $v, $dir)= new_dynldif();
	is( $v->modify( $U, 'ADD', 'description', 'cn', 'uid'), LDAP_SUCCESS);
	is_deeply( [ get( $v, $U)->get_value( 'description') ], [ qw/cn uid/ ],
		'values stored as given');
	is( get( $v, $U)->get_value( 'cn'), 'Test User', 'other attrs untouched');
	no_warnings();
};

subtest 'values that look like modify actions' => sub {
	my( $v, $dir)= new_dynldif();
	# (Parsing is tested in detail in 09-modlist.t)
	is( $v->modify( $U, 'ADD', 'description', 'ADD', 'x'), LDAP_SUCCESS);
	is_deeply( [ get( $v, $U)->get_value( 'description') ], [ qw/ADD x/ ],
		'value "ADD" stored');
	no_warnings();
};

subtest 'modifySmarts and write errors' => sub {
	my( $v, $dir)= new_dynldif();
	my $file= data_file( $dir, $U);

	# Make the directory unwritable (entries are written to a temporary
	# file there, then renamed): a no-op modify must not try to write,
	# while a real change must report the write failure.
	( my $parent= $file)=~ s{/[^/]+$}{};
	chmod 0555, $parent;
	SKIP: {
		skip 'running as root, permissions are not enforced', 3
			if open( my $fh, '>', "$parent/probe");

		is( $v->modify( $U, 'REPLACE', 'sn', 'User'), LDAP_SUCCESS,
			'no-op modify does not write');
		is( $v->modify( $U, 'REPLACE', 'sn', 'Changed'), LDAP_OPERATIONS_ERROR,
			'failed write is reported');
		warnings_like( qr/Can't wropen/);
	}
	chmod 0755, $parent;
	is( get( $v, $U)->get_value( 'sn'), 'User', 'entry unchanged');
	is_deeply( [ glob "$parent/*.tmp*" ], [], 'no temporary file left');

	# Successful writes replace the file, leaving no temporary files
	my $inode= ( stat $file)[1];
	is( $v->modify( $U, 'REPLACE', 'sn', 'Changed'), LDAP_SUCCESS);
	isnt( ( stat $file)[1], $inode, 'file replaced');
	is( get( $v, $U)->get_value( 'sn'), 'Changed', 'entry changed');
	my @tmp;
	File::Find::find( sub { push @tmp, $_ if /\.tmp/}, $dir);
	is_deeply( \@tmp, [], 'no temporary files in the tree');
	no_warnings();
};

subtest 'deleting and adding back in one request' => sub {
	my( $v, $dir)= new_dynldif();
	my $file= data_file( $dir, $U);
	is( $v->modify( $U, 'ADD', 'description', 'a', 'b'), LDAP_SUCCESS);
	my $inode= ( stat $file)[1];

	is( $v->modify( $U, 'DELETE', 'description', 'a', 'ADD', 'description', 'a'),
		LDAP_SUCCESS, 'value');
	is( $v->modify( $U, 'DELETE', 'description', undef, 'ADD', 'description', 'a', 'b'),
		LDAP_SUCCESS, 'attribute');
	is_deeply( [ get( $v, $U)->get_value( 'description') ], [ 'a', 'b' ]);
	is( ( stat $file)[1], $inode, 'no change, nothing written (modifySmarts)');

	is( $v->modify( $U, 'DELETE', 'description', undef, 'ADD', 'description', 'c'),
		LDAP_SUCCESS, 'other value');
	is_deeply( [ get( $v, $U)->get_value( 'description') ], [ 'c' ], 'old values not brought back');
	no_warnings();
};

subtest 'copy on write from fallback' => sub {
	my $fallback= [ 'searchFallback', '^cn=[^,]+,ou=hosts,', 'cn=default,ou=hosts,' ];
	my $default= "dn: cn=default,ou=hosts,$SUFFIX\nobjectClass: device\ncn: default\nl: Zagreb\n";
	my $new= "cn=new,ou=hosts,$SUFFIX";

	my( $v, $dir)= new_dynldif([ $fallback ]);
	add_ok( $v, $default);
	is( $v->modify( $new, 'REPLACE', 'description', 'mine'), LDAP_SUCCESS,
		'modify of fallback entry');
	ok( -e data_file( $dir, $new), 'entry copied to its own location');
	my $e= get( $v, $new);
	is( $e->dn, $new, 'copy has its own DN');
	is( $e->get_value( 'description'), 'mine', 'modification applied');
	is( $e->get_value( 'l'), 'Zagreb', 'fallback values copied');
	is_deeply( [ $e->get_value( 'cn') ], [ 'new' ],
		'copy has its own RDN value instead of the fallback one');
	ok( !get( $v, "cn=default,ou=hosts,$SUFFIX")->exists( 'description'),
		'fallback entry unchanged');

	( $v, $dir)= new_dynldif([ $fallback, [ 'modifyCopyOnWrite', 0 ]]);
	add_ok( $v, $default);
	is( $v->modify( $new, 'REPLACE', 'description', 'mine'),
		LDAP_NO_SUCH_OBJECT, 'refused with modifyCopyOnWrite 0');
	ok( !-e data_file( $dir, $new), 'nothing created');
	no_warnings();
};

subtest 'attributes coming from entryAppend' => sub {
	my( $v, $dir)= new_dynldif([
		[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ],
		[ 'entryAppend', 'objectClass', '^posixAccount$', '->',
			'append', '.+', "cn=defaults,ou=hosts,$SUFFIX" ],
	]);
	add_ok( $v, "dn: cn=defaults,ou=hosts,$SUFFIX\nobjectClass: device\ncn: defaults\nl: Zagreb\n");
	is( get( $v, $U)->get_value( 'l'), 'Zagreb', 'appended value visible');

	is( $v->modify( $U, 'ADD', 'l', 'Split'), LDAP_SUCCESS,
		'add value to appended attribute');
	is_deeply( [ sort { $a cmp $b } get( $v, $U)->get_value( 'l') ], [ qw/Split Zagreb/ ],
		'appended value kept alongside the new one');

	is( $v->modify( $U, 'REPLACE', 'description', 'l'), LDAP_SUCCESS,
		'value named like the appended attribute');
	is( get( $v, $U)->get_value( 'description'), 'l');
	no_warnings();
};

done_testing;
