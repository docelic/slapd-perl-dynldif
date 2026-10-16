#!/usr/bin/perl
# SEARCH operation: scopes, filters, limits, rewriting and fallbacks
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_NO_SUCH_OBJECT LDAP_FILTER_ERROR
	LDAP_SIZELIMIT_EXCEEDED LDAP_TIMELIMIT_EXCEEDED/;

use Cwd qw/getcwd/;

my $CWD= getcwd;
my $U= "uid=testuser,ou=users,$SUFFIX";
my $G= "cn=testuser,ou=groups,$SUFFIX";

my( $v, $dir)= new_dynldif([
	[ 'searchFallback', '^cn=[^,]+,ou=hosts,', 'cn=default,ou=hosts,' ],
	[ 'searchSubst', 'base', "^ou=people,$SUFFIX\$", '->', 'base', '.+', "ou=users,$SUFFIX" ],
	[ 'searchSubst', 'base', "^ou=groups,$SUFFIX\$", 'scope', '^1$', '->',
		'filter', '.+', '(gidNumber=12000)', 'scope', '.+', '2' ],
]);
add_ok( $v, "dn: cn=default,ou=hosts,$SUFFIX\nobjectClass: device\ncn: default\nl: fallback\n");

my $all= [ sort $SUFFIX, "ou=users,$SUFFIX", "ou=groups,$SUFFIX",
	"ou=hosts,$SUFFIX", "cn=default,ou=hosts,$SUFFIX", $U, $G ];

subtest 'scopes' => sub {
	my( $ret, $dns);

	( $ret, $dns)= search_dns( $v, $SUFFIX, scope => 0);
	is( $ret, LDAP_SUCCESS);
	is_deeply( $dns, [ $SUFFIX ], 'base');

	( $ret, $dns)= search_dns( $v, $SUFFIX, scope => 1);
	is( $ret, LDAP_SUCCESS);
	is_deeply( $dns, [ sort map { "$_,$SUFFIX"} qw/ou=users ou=groups ou=hosts/ ],
		'one');

	( $ret, $dns)= search_dns( $v, $SUFFIX, scope => 2);
	is( $ret, LDAP_SUCCESS);
	is_deeply( $dns, $all, 'sub');

	( $ret, $dns)= search_dns( $v, $SUFFIX, scope => 3);
	is( $ret, LDAP_SUCCESS);
	is_deeply( $dns, [ grep { $_ ne $SUFFIX} @$all ], 'children');

	( $ret, $dns)= search_dns( $v, $U, scope => 1);
	is( $ret, LDAP_SUCCESS);
	is_deeply( $dns, [], 'one on a leaf');
	no_warnings();
};

subtest 'nonexistent base' => sub {
	for my $scope( 0 .. 3) {
		my( $ret, $dns)= search_dns( $v, "ou=nosuch,$SUFFIX", scope => $scope);
		is( $ret, LDAP_NO_SUCH_OBJECT, "scope $scope");
		is_deeply( $dns, [], 'no entries');
	}
	no_warnings();
};

subtest 'filters' => sub {
	my( $ret, $dns);

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(uid=testuser)');
	is_deeply( $dns, [ $U ], 'equality');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(uid=TESTUSER)');
	is_deeply( $dns, [ $U ], 'equality is case-insensitive');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(gidNumber=12000)');
	is_deeply( $dns, [ sort $G, $U ], 'matching several entries');

	( $ret, $dns)= search_dns( $v, $SUFFIX,
		filter => '(&(objectClass=posixAccount)(cn=Test*))');
	is_deeply( $dns, [ $U ], 'and + substring');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(!(objectClass=*))');
	is_deeply( $dns, [], 'nothing matches');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(uid=testuser');
	is( $ret, LDAP_FILTER_ERROR, 'invalid filter');
	warnings_like( qr/Invalid filter/);
	no_warnings();
};

subtest 'filters from slapd' => sub {
	my( $ret, $dns);

	# slapd marks undefined filter components (i.e. invalid value for the
	# attribute's syntax) as (?...)
	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(?gidNumber=012000)');
	is( $ret, LDAP_SUCCESS, 'undefined component is not an error');
	is_deeply( $dns, [], 'undefined component does not match');

	( $ret, $dns)= search_dns( $v, $SUFFIX,
		filter => '(|(?gidNumber=012000)(uid=testuser))');
	is_deeply( $dns, [ $U ], 'undefined component in OR');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(&(?=true)(uid=testuser))');
	is_deeply( $dns, [ $U ], '(?=true)');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(?=false)');
	is_deeply( $dns, [], '(?=false)');

	# Undefined is neither TRUE nor FALSE (RFC 4511, 4.5.1.7)
	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(!(?gidNumber=012000))');
	is_deeply( $dns, [], 'NOT of undefined is undefined');

	( $ret, $dns)= search_dns( $v, $SUFFIX,
		filter => '(!(&(?gidNumber=012000)(uid=nomatch)))');
	is_deeply( $dns, $all, 'AND with a FALSE component is FALSE');

	( $ret, $dns)= search_dns( $v, $SUFFIX,
		filter => '(!(|(?gidNumber=012000)(uid=testuser)))');
	is_deeply( $dns, [], 'OR without a TRUE component stays undefined');

	( $ret, $dns)= search_dns( $v, $SUFFIX,
		filter => '(!(!(|(?gidNumber=012000)(uid=testuser))))');
	is_deeply( $dns, [ $U ], 'OR with a TRUE component is TRUE');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(!(?=false))');
	is_deeply( $dns, $all, '(!(?=false))');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(!(!(?=undefined)))');
	is_deeply( $dns, [], 'double NOT of undefined');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(cn~=test user)');
	is_deeply( $dns, [ $U ], 'approximate match');

	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(cn:caseExactMatch:=Test User)');
	is_deeply( $dns, [ $U ], 'extensible match');
	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(ou:dn:=groups)');
	is_deeply( $dns, [ sort "ou=groups,$SUFFIX", $G ], 'extensible match on DN attributes');
	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(&(cn=test*)(cn=*user)(cn=*st u*))');
	is_deeply( $dns, [ $U ], 'substrings');
	( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(&(uidNumber>=12000)(uidNumber<=12000))');
	is_deeply( $dns, [ $U ], 'ordering');
	no_warnings();
};

subtest 'matching rules from schema' => sub {
	my( $v2)= new_dynldif([[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ]]);
	my( $ret, $dns);

	# homeDirectory is case-exact (caseExactIA5Match)
	( $ret, $dns)= search_dns( $v,  $SUFFIX, filter => '(homeDirectory=/HOME/TESTUSER)');
	is_deeply( $dns, [ $U ], 'without schema, case-insensitive');
	( $ret, $dns)= search_dns( $v2, $SUFFIX, filter => '(homeDirectory=/HOME/TESTUSER)');
	is_deeply( $dns, [], 'with schema, case-exact');
	( $ret, $dns)= search_dns( $v2, $SUFFIX, filter => '(homeDirectory=/home/testuser)');
	is_deeply( $dns, [ $U ], 'with schema, exact value matches');

	( $ret, $dns)= search_dns( $v2, $SUFFIX, filter => '(cn=TEST USER)');
	is_deeply( $dns, [ $U ], 'with schema, case-insensitive attribute');
	( $ret, $dns)= search_dns( $v2, $SUFFIX, filter => '(uidNumber>=11000)');
	is_deeply( $dns, [ $U ], 'with schema, integer ordering');

	( $ret, $dns)= search_dns( $v2, $SUFFIX,
		filter => '(&(objectClass=*)(homeDirectory=/HOME/TESTUSER))');
	is_deeply( $dns, [], 'with schema, matching rules apply inside AND');
	( $ret, $dns)= search_dns( $v2, $SUFFIX,
		filter => '(|(uid=nomatch)(!(homeDirectory=/HOME/TESTUSER)))');
	is_deeply( $dns, [ grep { !/^cn=default,/} @$all ],
		'with schema, matching rules apply inside OR and NOT');
	no_warnings();
};

subtest 'attribute options' => sub {
	for my $schema( 0, 1) {
		my( $v2)= new_dynldif( $schema ? [[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ]] : []);
		my $X= "cn=x,ou=hosts,$SUFFIX";
		add_ok( $v2, "dn: $X\nobjectClass: device\ncn: x\ncn;lang-en: Y\ndescription;lang-de: d\n");
		my $with= $schema ? 'with schema' : 'without schema';
		for( [ '(cn;lang-en=y)', [ $X ], 'attribute with option' ],
			[ '(cn=y)', [ $X ], 'subtype values match the attribute' ],
			[ '(cn;lang-de=y)', [], 'other option' ],
			[ '(cn;lang-en=x)', [], 'value without the option' ],
			[ '(description=*)', [ $X ], 'presence of a subtype' ],
			[ '(description;lang-de=*)', [ $X ], 'presence with option' ],
			[ '(cn;lang-en=*Y*)', [ $X ], 'substring' ],
		) {
			my( $f, $expect, $name)= @$_;
			my( $ret, $dns)= search_dns( $v2, $SUFFIX, filter => $f);
			is_deeply( $dns, $expect, "$name $f, $with");
		}
		is( $v2->compare( $X, 'cn;lang-en=y'), 6, "compare, $with");
		is( $v2->compare( $X, 'cn=y'), 6, "compare subtype, $with");
		is( $v2->modify( $X, 'ADD', 'cn;lang-en', 'a', 'A'), 20, "duplicates, $with");
		is( $v2->modify( $X, 'DELETE', 'cn;lang-en', 'y'), 0, "delete value, $with");
		no_warnings();
	}
};

subtest 'extensible match' => sub {
	my( $v2)= new_dynldif([[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ]]);
	for( [ '(cn:caseExactMatch:=Test User)', [ $U ] ],
		[ '(cn:caseExactMatch:=test user)', [] ],
		[ '(cn:2.5.13.5:=Test User)', [ $U ], 'rule by OID' ],
		[ '(cn:=test user)', [ $U ], 'equality rule' ],
		[ '(ou:dn:=users)', [ "ou=users,$SUFFIX", $U ], 'DN attributes' ],
		[ '(:dn:caseIgnoreMatch:=users)', [ "ou=users,$SUFFIX", $U ], 'rule without attribute' ],
		[ '(:dn:2.5.13.2:=users)', [ "ou=users,$SUFFIX", $U ], 'rule by OID without attribute' ],
	) {
		my( $f, $expect, $name)= @$_;
		# (Net::LDAP::Schema's order of definitions varies, so repeated)
		for( 1.. 2) {
			my( $v3)= $_== 1 ? $v2 : new_dynldif([[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ]]);
			my( $ret, $dns)= search_dns( $v3, $SUFFIX, filter => $f);
			is_deeply( $dns, $expect, $name || $f);
		}
	}
	no_warnings();
};

subtest 'corrupt entry files are skipped' => sub {
	my( $v2, $dir2)= new_dynldif();
	my $file= data_file( $dir2, "cn=bad,ou=hosts,$SUFFIX");
	mkdir $file=~ s{/[^/]+$}{}r;
	for( [ "objectClass: device\ncn: x\n", qr/Invalid LDIF .* \(First line of LDIF entry does not begin with "dn:"\)/ ],
		[ "dn: cn=bad,ou=hosts,$SUFFIX\nfoo\n", qr/Invalid LDIF .* \(illegal LDIF line 'foo'\)/ ],
		[ '', undef ], # (Empty files are placeholders, see t/00-init.t)
	) {
		my( $data, $warning)= @$_;
		open my $fh, '>', $file or die;
		print $fh $data;
		close $fh;
		my( $ret, $dns)= search_dns( $v2, $SUFFIX);
		is( $ret, LDAP_SUCCESS, 'search succeeds');
		is( scalar @$dns, 6, 'other entries found');
		warnings_like( $warning) if $warning;
	}
	no_warnings();
};

subtest 'size limit' => sub {
	my( $ret, $dns);
	( $ret, $dns)= search_dns( $v, $SUFFIX, size => 2);
	is( $ret, LDAP_SIZELIMIT_EXCEEDED, 'exceeded');
	is( scalar @$dns, 2, 'returns exactly the limit');

	( $ret, $dns)= search_dns( $v, $SUFFIX, size => scalar @$all);
	is( $ret, LDAP_SUCCESS, 'not exceeded when all entries fit exactly');
	is( scalar @$dns, scalar @$all, 'all entries returned');

	# slapd passes -1 for unlimited (for example to rootdn)
	( $ret, $dns)= search_dns( $v, $SUFFIX, size => -1, time => -1);
	is( $ret, LDAP_SUCCESS, 'unlimited');
	is( scalar @$dns, scalar @$all, 'all entries returned when unlimited');
	no_warnings();
};

subtest 'exceeded limits leave the working directory unchanged' => sub {
	my( $ret)= search_entries( $v, $SUFFIX, size => 1);
	is( $ret, LDAP_SIZELIMIT_EXCEEDED);
	is( getcwd, $CWD, 'size limit');

	# Time passes while the search runs
	{
		no warnings 'redefine';
		my $load= \&DynLDIF::load;
		local *DynLDIF::load= sub { $_-= 100 for @{ $v->{start}}; $load->( @_) };
		( $ret)= search_entries( $v, $SUFFIX, time => 10);
	}
	is( $ret, LDAP_TIMELIMIT_EXCEEDED);
	is( getcwd, $CWD, 'time limit');

	my( $r, $dns)= search_dns( $v, $SUFFIX);
	is_deeply( $dns, $all, 'later searches find everything');
	no_warnings();
};

subtest 'no limit means no limit' => sub {
	my( $v)= new_dynldif( undef, empty => 1);
	$v->add( "dn: $SUFFIX\nobjectClass: domain\ndc: example\n");
	for my $i( 1.. 7000) {
		my $ret= $v->add( "dn: cn=h$i,$SUFFIX\nobjectClass: device\ncn: h$i\n");
		die "add failed ($ret)" if $ret;
	}
	for my $limit( -1, 0) {
		my( $ret, @e)= $v->search( $SUFFIX, 1, 0, $limit, $limit, '(objectClass=*)', 0);
		is( $ret, LDAP_SUCCESS, "limit $limit");
		is( scalar @e, 7000, 'all entries returned');
	}
	no_warnings();
};

subtest 'searchSubst' => sub {
	my( $ret, $dns)= search_dns( $v, "ou=people,$SUFFIX", scope => 0);
	is( $ret, LDAP_SUCCESS);
	is_deeply( $dns, [ "ou=users,$SUFFIX" ], 'base rewritten');

	( $ret, $dns)= search_dns( $v, "ou=groups,$SUFFIX", scope => 1);
	is_deeply( $dns, [ $G ], 'filter and scope rewritten');

	( $ret, $dns)= search_dns( $v, "ou=groups,$SUFFIX", scope => 2,
		filter => '(cn=nomatch)');
	is_deeply( $dns, [], 'rule not applied when a condition does not match');
	no_warnings();
};

subtest 'searchFallback' => sub {
	my( $ret, @e)= search_entries( $v, "cn=nosuch,ou=hosts,$SUFFIX", scope => 0);
	is( $ret, LDAP_SUCCESS, 'found via fallback');
	is( $e[0]->get_value( 'l'), 'fallback', 'fallback entry returned');

	my $dns;
	( $ret, $dns)= search_dns( $v, "cn=nosuch,ou=hosts,$SUFFIX", scope => 1);
	is( $ret, LDAP_SUCCESS, 'one-level search on fallback base');

	( $ret, $dns)= search_dns( $v, "cn=nosuch,ou=users,$SUFFIX", scope => 0);
	is( $ret, LDAP_NO_SUCH_OBJECT, 'no fallback rule applies');
	no_warnings();
};

subtest 'searchSubst backreferences' => sub {
	# $[N][M] refers to capture group M+1 of condition N
	my( $v2)= new_dynldif([[ 'searchSubst',
		'base', "^ou=(\\w+),ou=alias,$SUFFIX\$", 'filter', '^\(uid=(\w+)\)$', '->',
		'base', '.+', "ou=\$[0][0],$SUFFIX",
		'filter', '.+', '(cn=$[1][0])' ]]);
	my( $ret, $dns)= search_dns( $v2, "ou=groups,ou=alias,$SUFFIX",
		filter => '(uid=testuser)');
	is( $ret, LDAP_SUCCESS);
	is_deeply( $dns, [ $G ], 'base and filter rewritten using captures');
	no_warnings();
};

subtest 'searchSubst captures are inserted literally' => sub {
	# Captures come from the request, so regex characters in them must not
	# be interpreted (an invalid regex would be fatal)
	my( $v2)= new_dynldif([[ 'searchSubst',
		'base', "^ou=([^,]+),ou=alias,$SUFFIX\$", '->',
		'base', '^ou=$[0][0],ou=alias', 'ou=groups' ]]);
	my( $ret, $dns)= search_dns( $v2, "ou=a(b,ou=alias,$SUFFIX", scope => 0);
	is( $ret, LDAP_SUCCESS);
	is_deeply( $dns, [ "ou=groups,$SUFFIX" ], 'regex characters matched literally');
	( $ret, $dns)= search_dns( $v2, "ou=a.b,ou=alias,$SUFFIX", scope => 0);
	is( $ret, LDAP_SUCCESS);
	is_deeply( $dns, [ "ou=groups,$SUFFIX" ]);
	no_warnings();
};

subtest 'searchFallback chain' => sub {
	my( $v2)= new_dynldif([
		[ 'searchFallback', '^cn=[^,]+,ou=hosts,', 'cn=site,ou=hosts,' ],
		[ 'searchFallback', '^cn=[^,]+,ou=hosts,', 'cn=global,ou=hosts,' ],
	]);
	add_ok( $v2, "dn: cn=global,ou=hosts,$SUFFIX\nobjectClass: device\ncn: global\n");
	my( $ret, $dns)= search_dns( $v2, "cn=x,ou=hosts,$SUFFIX", scope => 0);
	is_deeply( $dns, [ "cn=global,ou=hosts,$SUFFIX" ], 'falls through to second');

	add_ok( $v2, "dn: cn=site,ou=hosts,$SUFFIX\nobjectClass: device\ncn: site\n");
	( $ret, $dns)= search_dns( $v2, "cn=x,ou=hosts,$SUFFIX", scope => 0);
	is_deeply( $dns, [ "cn=site,ou=hosts,$SUFFIX" ], 'first found wins');
	no_warnings();
};

subtest 'nested search restores depth' => sub {
	my $level= $v->{level};
	# Trailing hashref marks an internal (nested) search
	my( $ret)= $v->search( "ou=nosuch,$SUFFIX", 0, 0, 10, 10,
		'(objectClass=*)', 0, {});
	is( $ret, LDAP_NO_SUCH_OBJECT, 'nested search fails');
	is( $v->{level}, $level, 'level restored after error');

	( $ret)= $v->search( $SUFFIX, 0, 0, 10, 10, '(objectClass=*)', 0, {});
	is( $ret, LDAP_SUCCESS, 'nested search succeeds');
	is( $v->{level}, $level, 'level restored after success');
	no_warnings();
};

done_testing;
