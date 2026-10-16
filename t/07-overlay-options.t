#!/usr/bin/perl
# Overlay specification details: relative DNs, value selection and joiners,
# options (cache, prefix, if), and handling of failing references
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS/;

my $U= "uid=testuser,ou=users,$SUFFIX";
my $T= "cn=t,ou=hosts,$SUFFIX";

my( $v, $dir)= new_dynldif([
	[ 'expandVal', '.', '^$' ],
	[ 'fileVal', '.', '^$' ],
	[ 'findVal', '.', '^$' ],
]);
is( $v->modify( $U, 'ADD', 'description', 'a', 'b'), LDAP_SUCCESS);

# Store an entry with given 'l' values and return the expanded values
sub expand {
	my( @specs)= @_;
	$v->delete( $T);
	my $ret= $v->add( "dn: $T\nobjectClass: device\ncn: t\n".
		join( '', map { "l: $_\n"} @specs));
	die "add failed ($ret)" unless $ret== LDAP_SUCCESS;
	my( $r, @e)= search_entries( $v, $T, scope => 0);
	die "search failed ($r)" unless $r== LDAP_SUCCESS;
	[ $e[0]->get_value( 'l') ]
}

subtest 'exp' => sub {
	is_deeply( expand( '$ exp $ cn'), [ 't' ], 'attribute of the entry itself');
	is_deeply( expand( "\$ exp \$ $U description"), [ 'a' ],
		'first value by default');
	is_deeply( expand( "\$ exp \$ $U description 1"), [ 'b' ], 'value index');
	is_deeply( expand( "\$ exp \$ $U description ,"), [ 'a,b' ], 'joiner');
	is_deeply( expand( "\$ exp \$ $U description \\x2c\\x20"), [ 'a, b' ],
		'hex joiner');
	no_warnings();
};

subtest 'relative DNs' => sub {
	is_deeply( expand( '$ exp $ uid=testuser,ou=users,.. uid'), [ 'testuser' ],
		'trailing dots after a comma');
	is_deeply( expand( '$ exp $ uid=testuser,ou=users.. uid'), [ 'testuser' ],
		'trailing dots without a comma');
	is_deeply( expand( '$ exp $ ... ou'), [ 'hosts' ],
		'dots only');
	is_deeply( expand( '$ exp $ uid=testuser,ou=users,...... uid'), [],
		'more dots than DN components');
	warnings_like( qr/can't load 'uid=testuser,ou=users,cn=t,ou=hosts,dc=example,dc=com'/,
		'whole DN used');
	no_warnings();
};

subtest 'circular references' => sub {
	is_deeply( expand( '$ exp $ .... cn', 'other'), [ 'other' ],
		'reference to the entry itself');
	warnings_like( qr/circular reference to '\Q$T\E'/);

	my $T2= "cn=t2,ou=hosts,$SUFFIX";
	add_ok( $v, "dn: $T2\nobjectClass: device\ncn: t2\nl: \$ exp \$ $T l\n");
	is_deeply( expand( "\$ exp \$ $T2 l", 'other'), [ 'other' ],
		'reference through another entry');
	warnings_like( qr/circular reference/);
	warnings_like( qr/ExpandVal of l for \Q$T2\E is empty/,
		'the other entry gets an empty value');
	is( $v->delete( $T2), LDAP_SUCCESS);
	no_warnings();
};

subtest 'find' => sub {
	my $find= '$ find $ .. 2 0 0 0 (gidNumber=12000) 0 cn';
	is_deeply( expand( "$find 0 0"), [ 'Test User' ], 'first result');
	is_deeply( expand( "$find 0 1"), [ 'testuser' ], 'result index');
	# (Order of search results is not defined)
	like( expand( "$find 0 \\x2c")->[0],
		qr/^(Test User,testuser|testuser,Test User)$/, 'hex joiner between results');
	is_deeply( [ sort { $a cmp $b} @{ expand( "$find \\x00 \\x00")} ],
		[ 'Test User', 'testuser' ], '\x00 expands to multiple values');
	is_deeply( [ sort { $a cmp $b} @{ expand( "pre $find 0 \\x00")} ],
		[ 'pre Test User', 'pre testuser' ],
		'multiple values keep surrounding text');
	is_deeply( expand( '$ find $ ou=users,.. 2 0 0 0 (uid=testuser) 0 uid'),
		[ 'testuser' ], 'relative base');
	no_warnings();
};

subtest 'find if' => sub {
	my $find= '$ .. 2 0 0 0 (uid=testuser) 0 uid';
	is_deeply( expand( "\$ find if cn ^t $find"), [ 'testuser' ],
		'condition met');
	is_deeply( expand( "\$ find if cn nomatch $find", 'other'), [ 'other' ],
		'condition not met drops the value');
	is_deeply( expand( "\$ find if !cn nomatch $find"), [ 'testuser' ],
		'negated condition');
	is_deeply( expand( "\$ find if cn nomatch cache 1 $find"), [],
		'condition not met, with cache');
	no_warnings();
};

subtest 'failing references' => sub {
	is_deeply( expand( '$ exp $ cn=nosuch,.. cn', '$ exp $ cn'), [ 't' ],
		'exp: failed value dropped, others still expanded');
	warnings_like( qr/ExpandVal: can't load 'cn=nosuch,dc=example,dc=com'/,
		'warning names the DN');

	is_deeply( expand( '$ exp $ a b c d', '$ exp $ cn'), [ 't' ],
		'exp: invalid specification');
	warnings_like( qr/Invalid specification/);

	is_deeply( expand( '$ find $ ou=nosuch,.. 2 0 0 0 (cn=*) 0 cn', '$ exp $ cn'),
		[ 't' ], 'find: failed search');
	warnings_like( qr/FindVal: search .* failed \(32\)/);

	is_deeply( expand( '$ find $ .. 2 0', '$ exp $ cn'), [ 't' ],
		'find: wrong number of arguments');
	warnings_like( qr/Must specify 10 options/);

	is_deeply( expand( "\$ file \$ nosuchfile", '$ exp $ cn'), [ '', 't' ],
		'file: missing file expands to empty value');
	warnings_like( qr/Can't rdopen/);

	# Invalid regexes come from data, so they must not be fatal
	open my $fh, '>', "$dir/r.txt" or die;
	print $fh "line\n";
	close $fh;
	is_deeply( expand( '$ file $ r.txt (', '$ exp $ cn'), [ '', 't' ],
		'file: invalid regex expands to empty value');
	warnings_like( qr/Invalid regex '\('/);
	is_deeply( expand( '$ find if cn ( $ .. 2 0 0 0 (uid=testuser) 0 uid', '$ exp $ cn'),
		[ 't' ], 'find: invalid regex in if drops the value');
	warnings_like( qr/FindVal: invalid regex '\('/);
	no_warnings();
};

subtest 'file prefix' => sub {
	mkdir "$dir/sub" or die;
	open my $fh, '>', "$dir/sub/p.txt" or die;
	print $fh "prefixed\n";
	close $fh;
	is_deeply( expand( '$ file prefix sub/ $ p.txt'), [ 'prefixed' ]);
	is_deeply( expand( '$ file prefix ../sub/ $ p.txt'), [ 'prefixed' ],
		'prefix cannot escape the data directory');
	no_warnings();
};

subtest 'overlay cache' => sub {
	my $f= "$dir/c.txt";
	my $write= sub { open my $fh, '>', $f or die; print $fh "$_[0]\n"; close $fh };

	$write->( 'v1');
	is_deeply( expand( '$ file cache 2 $ c.txt'), [ 'v1' ], 'read');
	$write->( 'v2');

	# Cache queue for '2' is valid for 2 direct operations
	my $get= sub {
		my( $r, @e)= search_entries( $v, $T, scope => 0);
		$e[0]->get_value( 'l')
	};
	my @seen= map { $get->()} 1 .. 3;
	is( $seen[0], 'v1', 'cached value used');
	is( $seen[-1], 'v2', 'refreshed after expiry');
	no_warnings();
};

subtest 'overlayConfig defaults' => sub {
	my( $v2, $dir2)= new_dynldif([
		[ 'fileVal', '.', '^$' ],
		[ 'overlayConfig', 'file', 'prefix', 'sub/' ],
	]);
	mkdir "$dir2/sub" or die;
	open my $fh, '>', "$dir2/sub/p.txt" or die;
	print $fh "from default\n";
	close $fh;
	add_ok( $v2, "dn: $T\nobjectClass: device\ncn: t\nl: \$ file \$ p.txt\n");
	my( $r, @e)= search_entries( $v2, $T, scope => 0);
	is( $e[0]->get_value( 'l'), 'from default', 'default prefix applied');
	no_warnings();
};

done_testing;
