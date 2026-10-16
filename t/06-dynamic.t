#!/usr/bin/perl
# Dynamic values: entryAppend and the file/exp/find overlays
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS/;

my $U= "uid=testuser,ou=users,$SUFFIX";

sub get {
	my( $v, $dn)= @_;
	my( $ret, @e)= search_entries( $v, $dn, scope => 0);
	is( $ret, LDAP_SUCCESS, "loaded $dn");
	$e[0]
}

subtest 'entryAppend with append' => sub {
	my( $v, $dir)= new_dynldif([
		[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ],
		[ 'entryAppend', 'objectClass', '^posixAccount$', '->',
			'append', '.+', "cn=defaults,ou=hosts,$SUFFIX" ],
	]);
	add_ok( $v, "dn: cn=defaults,ou=hosts,$SUFFIX\nobjectClass: device\n".
		"cn: defaults\nl: Zagreb\ndescription: default\n");
	add_ok( $v, "dn: cn=h1,ou=hosts,$SUFFIX\nobjectClass: device\ncn: h1\n");

	my $e= get( $v, $U);
	is( $e->get_value( 'l'), 'Zagreb', 'missing attribute appended');
	is( $e->get_value( 'description'), 'default', 'another one appended');
	is( $e->get_value( 'cn'), 'Test User', 'existing attribute not overridden');
	ok( !$e->exists( 'serialNumber'), 'only attributes allowed by schema');

	ok( !get( $v, "cn=h1,ou=hosts,$SUFFIX")->exists( 'l'),
		'not appended when conditions do not match');

	open my $fh, '<', data_file( $dir, $U) or die;
	ok( !grep( /^l:/, <$fh>), 'appended values not stored on disk');
	no_warnings();
};

subtest 'entryAppend conditions' => sub {
	my $defaults= "dn: cn=defaults,ou=hosts,$SUFFIX\nobjectClass: device\n".
		"cn: defaults\nl: Zagreb\n";
	my $rule= sub { [ 'entryAppend', @_, '->', 'append', '.+', "cn=defaults,ou=hosts,$SUFFIX" ] };
	my $schema= [ 'schemaLDIF', "$DATA_DIR/schema.ldif" ];

	my( $v)= new_dynldif([ $schema, $rule->( 'dn', '^uid=', 'objectClass', '^posixAccount$') ]);
	add_ok( $v, $defaults);
	is( get( $v, $U)->get_value( 'l'), 'Zagreb', 'all conditions match');

	( $v)= new_dynldif([ $schema, $rule->( 'dn', '^cn=', 'objectClass', '^posixAccount$') ]);
	add_ok( $v, $defaults);
	ok( !get( $v, $U)->exists( 'l'), 'one condition does not match');
	no_warnings();
};

subtest 'entryAppend with missing source entry' => sub {
	my( $v)= new_dynldif([
		[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ],
		[ 'entryAppend', 'objectClass', '^posixAccount$', '->',
			'append', '.+', "cn=nosuch,ou=hosts,$SUFFIX" ],
		[ 'entryAppend', 'objectClass', '^posixAccount$', '->',
			'append', '.+', "cn=defaults,ou=hosts,$SUFFIX" ],
	]);
	add_ok( $v, "dn: cn=defaults,ou=hosts,$SUFFIX\nobjectClass: device\ncn: defaults\nl: Zagreb\n");
	is( get( $v, $U)->get_value( 'l'), 'Zagreb', 'following rules still applied');
	warnings_like( qr/EntryAppend: can't load 'cn=nosuch/, 'warning issued');
	no_warnings();
};

subtest 'entryAppend with attr' => sub {
	my( $v, $dir)= new_dynldif([
		[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ],
		[ 'entryAppend', 'objectClass', '^device$', '->', 'attr', 'seeAlso' ],
	]);
	add_ok( $v, "dn: cn=defaults,ou=hosts,$SUFFIX\nobjectClass: device\n".
		"cn: defaults\nl: Zagreb\n");
	add_ok( $v, "dn: cn=h1,ou=hosts,$SUFFIX\nobjectClass: device\ncn: h1\n".
		"seeAlso: cn=defaults,ou=hosts,$SUFFIX\n");
	is( get( $v, "cn=h1,ou=hosts,$SUFFIX")->get_value( 'l'), 'Zagreb',
		'appended from entry named in seeAlso');
	no_warnings();
};

subtest 'overlays' => sub {
	my( $v, $dir)= new_dynldif([
		[ 'fileVal', '.', '^$' ],
		[ 'expandVal', '.', '^$' ],
		[ 'findVal', '.', '^$' ],
	]);

	open my $fh, '>', "$dir/motd.txt" or die;
	print $fh "line one\nline two\n";
	close $fh;

	add_ok( $v, <<"EOF");
dn: cn=dyn,ou=hosts,$SUFFIX
objectClass: device
cn: dyn
description: name=\$ exp \$ $U cn
description: shell \$ exp \$ $U loginShell \$ ok
l: \$ file \$ motd.txt 1
l: \$ file \$ motd.txt ^line\\s(o\\w+)
l: \$ file \$ motd.txt line
l: x\$ file \$ motd.txt nomatch
l: \$ file \$ motd.txt
title: \$ file \$ nosuchfile
ou: \$ find \$ ou=users,$SUFFIX 2 0 0 0 (objectClass=posixAccount) 0 uid
seeAlso: plain value
EOF

	my $e= get( $v, "cn=dyn,ou=hosts,$SUFFIX");
	is_deeply( [ $e->get_value( 'description') ],
		[ 'name=Test User', 'shell /bin/bash ok' ], 'exp');
	is_deeply( [ $e->get_value( 'l') ], [
		'line two',            # line number
		'one',                 # regex with capture
		'line one',            # regex, first match wins
		'x',                   # no match is empty
		"line one\nline two",  # whole file
	], 'file');
	is( $e->get_value( 'title'), '', 'missing file is empty');
	is( $e->get_value( 'ou'), 'testuser', 'find');
	is( $e->get_value( 'seeAlso'), 'plain value', 'plain values untouched');
	is( $e->get_value( 'cn'), 'dyn');

	open $fh, '<', data_file( $dir, "cn=dyn,ou=hosts,$SUFFIX") or die;
	ok( grep( /\$ exp \$/, <$fh>), 'specifications kept on disk');

	is( $v->compare( "cn=dyn,ou=hosts,$SUFFIX", 'ou=testuser'),
		Net::LDAP::Constant::LDAP_COMPARE_TRUE(), 'compare sees expanded value');
	warnings_like( qr/Can't rdopen .*nosuchfile/);
	no_warnings();
};

subtest 'find overlay outside of search' => sub {
	my( $v, $dir)= new_dynldif([[ 'findVal', '.', '^$' ], [ 'enableBind', 1 ]]);
	my $find= "\$ find \$ ou=groups,$SUFFIX 2 0 0 0 (cn=testuser) 0 gidNumber";
	is( $v->modify( $U, 'ADD', 'description', $find), LDAP_SUCCESS);

	# Each of these loads the entry and expands it, outside of a SEARCH
	is( $v->bind( $U, 'test'), LDAP_SUCCESS, 'bind');
	is( $v->compare( $U, 'description=12000'),
		Net::LDAP::Constant::LDAP_COMPARE_TRUE(), 'compare');
	is( $v->modify( $U, 'REPLACE', 'sn', 'Other'), LDAP_SUCCESS, 'modify');
	is( get( $v, $U)->get_value( 'description'), '12000', 'search');
	no_warnings();
};

subtest 'overlays only run on configured attributes' => sub {
	my( $v, $dir)= new_dynldif([[ 'expandVal', '^description$', '^$' ]]);
	add_ok( $v, "dn: cn=dyn,ou=hosts,$SUFFIX\nobjectClass: device\ncn: dyn\n".
		"description: \$ exp \$ $U uid\nl: \$ exp \$ $U uid\n");
	my $e= get( $v, "cn=dyn,ou=hosts,$SUFFIX");
	is( $e->get_value( 'description'), 'testuser', 'matching attribute expanded');
	like( $e->get_value( 'l'), qr/\$ exp \$/, 'other attribute left as is');
	no_warnings();
};

done_testing;
