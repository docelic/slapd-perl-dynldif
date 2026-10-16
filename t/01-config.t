#!/usr/bin/perl
# Config directive processing
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_PARAM_ERROR LDAP_OPERATIONS_ERROR/;

my( $v, $dir)= new_dynldif( undef, empty => 1);

subtest 'directive names' => sub {
	is( $v->config( 'addOverwrites', 1), LDAP_SUCCESS, 'case-insensitive');
	is( $v->{addoverwrites}, 1, 'value set');

	is( $v->config( 'expandVal', '.', '^$'), LDAP_SUCCESS,
		'long name accepted');
	is_deeply( $v->{'exp'}, [[ '.', '^$' ]], 'resolved to short name');

	is( $v->config( 'nosuchdirective', 1), LDAP_PARAM_ERROR, 'unknown rejected');
	warnings_like( qr/Unknown config directive/);

	# Both 'save' and 'savedump' are prefixes of this
	is( $v->config( 'savedumpx', 1), LDAP_PARAM_ERROR, 'ambiguous rejected');
	warnings_like( qr/Ambiguous config directive/);
	no_warnings();
};

subtest 'variables and directive expansion' => sub {
	is( $v->config( 'var', 'name', 'dynldif', 'status', 'OK'), LDAP_SUCCESS);
	is( $v->config( 'message', '${name}', '%{treesuffix}', '${status}'),
		LDAP_SUCCESS);
	warnings_like( qr/^Message: dynldif \Q$SUFFIX\E OK$/, 'message expanded');

	$v->config( 'parse', 0);
	$v->config( 'message', '${name}');
	warnings_like( qr/^Message: \$\{name\}$/, 'not expanded with parse 0');
	$v->config( 'parse', 1);
	no_warnings();
};

subtest 'rule syntax is validated' => sub {
	for my $rule(
		[ qw/objectClass posixAccount append .+ cn=x/ ], # no arrow
		[ qw/objectClass -> append .+ cn=x/ ],           # odd conditions
		[ qw/-> append .+ cn=x/ ],                       # no conditions
		[ qw/objectClass posixAccount ->/ ],             # no actions
	) {
		is( $v->config( 'entryAppend', @$rule), LDAP_PARAM_ERROR,
			"entryAppend '@$rule' rejected");
		warnings_like( qr/Invalid 'entryappend' rule/);
	}

	is( $v->config( 'searchSubst', qw/base x base .+ y/), LDAP_PARAM_ERROR,
		'searchSubst without arrow rejected');
	warnings_like( qr/Invalid 'searchsubst' rule/);

	is( $v->config( 'entryAppend', qw/objectClass x dn y -> append .+ cn=x/),
		LDAP_SUCCESS, 'valid entryAppend accepted');
	is( $v->config( 'searchSubst', qw/base x -> base .+ y/),
		LDAP_SUCCESS, 'valid searchSubst accepted');
	no_warnings();
};

subtest 'save and load config stack' => sub {
	my( $v2)= new_dynldif( undef, empty => 1);
	$v2->config( 'reset');
	$v2->config( 'deleteTrees', 1);
	$v2->config( 'searchFallback', 'cn=a', 'cn=b');
	is( $v2->config( 'save', 'stack1'), LDAP_SUCCESS, 'stack saved');

	my( $v3)= new_dynldif( undef, empty => 1);
	# Stack files live in the data dir; point v3 at the same one
	$v3->config( 'directory', $v2->{directory});
	is( $v3->config( 'load', 'stack1', 'cn=b', 'cn=c'), LDAP_SUCCESS,
		'stack loaded');
	is( $v3->{deletetrees}, 1, 'scalar directive restored');
	is_deeply( $v3->{searchfallback}, [[ 'cn=a', 'cn=c' ]],
		'substitution applied on load');
	no_warnings();
};

subtest 'saveDump and loadDump' => sub {
	my( $v2, $dir2)= new_dynldif([
		[ 'searchFallback', '^cn=[^,]+,ou=hosts,', 'cn=default,ou=hosts,' ],
	]);
	add_ok( $v2, "dn: cn=default,ou=hosts,$SUFFIX\nobjectClass: device\ncn: default\n");
	is( $v2->config( 'saveDump', 'test.dump'), LDAP_SUCCESS, 'dump saved');
	ok( -e "$dir2/tmp/test.dump", 'dump file created');

	# This is how scripts/dynldif.pl runs DynLDIF standalone
	my $v3= DynLDIF->new;
	is( $v3->config( 'directory', $v2->{directory}), LDAP_SUCCESS);
	is( $v3->config( 'loadDump', 'test.dump'), LDAP_SUCCESS, 'dump loaded');
	is( $v3->init, LDAP_SUCCESS, 'init');
	my( $ret, @e)= search_entries( $v3, "cn=x,ou=hosts,$SUFFIX", scope => 0);
	is( $ret, LDAP_SUCCESS, 'config restored (fallback works)');
	is( $e[0]->dn, "cn=default,ou=hosts,$SUFFIX");
	no_warnings();
};

subtest 'clean' => sub {
	my( $v2, $dir2)= new_dynldif( undef, empty => 1);
	$v2->config( 'save', 'stack1');
	$v2->config( 'saveDump', 'test.dump');
	ok( -e "$dir2/tmp/stack1", 'stack file exists');
	is( $v2->config( 'clean'), LDAP_SUCCESS);
	is_deeply( [ glob "$dir2/tmp/*" ], [], 'tmp files removed');
	no_warnings();
};

subtest 'invalid values' => sub {
	my $v2= DynLDIF->new;
	is( $v2->config( 'message', '[${nosuch}] [%{nosuch}] [%{var}]'), LDAP_SUCCESS);
	warnings_like( qr/^Undefined variable '\$\{nosuch\}'/);
	warnings_like( qr/^Unknown directive '%\{nosuch\}'/);
	warnings_like( qr/^Unknown directive '%\{var\}'/, 'non-scalar directive');
	warnings_like( qr/^Message: \[\] \[\] \[\]/, 'expanded to empty values');

	for my $line( [ 'save', 'x' ], [ 'load', 'x' ], [ 'saveDump', 'x' ], [ 'loadDump', 'x' ]) {
		is( $v2->config( @$line), LDAP_OPERATIONS_ERROR, "$line->[0] before directory");
		warnings_like( qr/before 'directory' has been set/);
	}

	is( $v->config( 'loadDump', 'nosuch'), LDAP_OPERATIONS_ERROR, 'missing dump');
	warnings_like( qr/^Can't load dump/);

	is( $v2->config( 'cacheRead', 'abc'), LDAP_PARAM_ERROR, 'invalid cacheRead');
	is( $v2->config( 'cacheRead', '1o'), LDAP_PARAM_ERROR, 'invalid cacheRead');
	warnings_like( qr/^Invalid cache value 'abc'/);
	warnings_like( qr/^Invalid cache value '1o'/);
	is( $v2->config( 'cacheRead', 0), LDAP_SUCCESS, 'cacheRead 0');
	is( $v2->config( 'cacheRead', 5), LDAP_SUCCESS, 'cacheRead 5');

	for my $line(
		[ 'searchFallback', '(', 'x' ],
		[ 'searchSubst', 'base', '[', '->', 'base', '.+', 'y' ],
		[ 'searchSubst', 'base', 'x', '->', 'base', '(', 'y' ],
		[ 'entryAppend', 'objectClass', '*x', '->', 'append', '.+', 'y' ],
		[ 'entryAppend', 'objectClass', 'x', '->', 'append', '+', 'y' ],
		[ 'addRelocate', 'Site', '(', 'y' ],
		[ 'addPrompt', '(', 'x', 'y' ],
		[ 'expandVal', '(', '^$' ],
		[ 'findVal', '.', ')' ],
	) {
		is( $v2->config( @$line), LDAP_PARAM_ERROR, "invalid regex in @$line");
		warnings_like( qr/^Invalid regex/);
	}
	is( $v2->config( 'searchSubst', 'base', '^(x)$', '->', 'base', '$[0][0]', 'y'),
		LDAP_SUCCESS, 'references to captures are accepted');
	no_warnings();
};

subtest 'unusable directory' => sub {
	# A file where the directory should be: mkdir fails even as root
	open my $fh, '>', "$dir/afile" or die;
	close $fh;
	my $v2= DynLDIF->new;
	is( $v2->config( 'directory', "$dir/afile/data"), LDAP_OPERATIONS_ERROR,
		'error returned');
	warnings_like( qr{^Can't mkdir '\Q$dir\E/afile/data/tmp' \(.+\)$});
	no_warnings();
};

done_testing;
