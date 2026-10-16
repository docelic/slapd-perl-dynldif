#!/usr/bin/perl
# Backend initialization and creation of the path leading up to the suffix
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_PARAM_ERROR/;

subtest 'two-component suffix' => sub {
	my( $v, $dir)= new_dynldif( undef, empty => 1);
	ok( -e "$dir/dc=com.ldif", 'parent component created');
	ok( -d "$dir/tmp", 'tmp dir created');

	add_ok( $v, "dn: $SUFFIX\nobjectClass: domain\ndc: example\n");
	ok( -e "$dir/dc=com/dc=example.ldif", 'suffix entry stored on disk');
	no_warnings();
};

subtest 'three-component suffix' => sub {
	my $suffix= 'dc=example,dc=co,dc=uk';
	my( $v, $dir)= new_dynldif( undef, suffix => $suffix, empty => 1);

	ok( -e "$dir/dc=uk.ldif", 'top component created');
	ok( -e "$dir/dc=uk/dc=co.ldif", 'second component created under first');
	ok( !-e "$dir/dc=co.ldif", 'second component not created at top level');

	add_ok( $v, "dn: $suffix\nobjectClass: domain\ndc: example\n");
	ok( -e "$dir/dc=uk/dc=co/dc=example.ldif", 'suffix entry stored on disk');

	my( $ret, $dns)= search_dns( $v, $suffix);
	is( $ret, LDAP_SUCCESS, 'search succeeds');
	is_deeply( $dns, [ $suffix ], 'suffix entry found');
	no_warnings();
};

subtest 'four-component suffix' => sub {
	my $suffix= 'ou=a,dc=b,dc=c,dc=d';
	my( $v, $dir)= new_dynldif( undef, suffix => $suffix, empty => 1);
	ok( -e "$dir/dc=d/dc=c/dc=b.ldif", 'all components created');
	no_warnings();
};

subtest 'single-component suffix' => sub {
	my( $v, $dir)= new_dynldif( undef, suffix => 'ou=defaults', empty => 1);
	add_ok( $v, "dn: ou=defaults\nobjectClass: organizationalUnit\nou: defaults\n");
	ok( -e "$dir/ou=defaults.ldif", 'entry stored on disk');
	no_warnings();
};

subtest 'empty extension is rejected' => sub {
	my $ret;
	new_dynldif( [[ 'extension', '' ]], empty => 1, init_ret => \$ret);
	is( $ret, LDAP_PARAM_ERROR, 'init fails');
	warnings_like( qr/extension.*cannot be empty/);
	no_warnings();
};

subtest 'databases in the same directory' => sub {
	# Components above the suffix are created as empty placeholders, which
	# don't prevent another database from storing them
	my( $v, $dir)= new_dynldif( undef, empty => 1);
	ok( -e "$dir/dc=com.ldif" && -z _, 'placeholder');
	my $v2= DynLDIF->new;
	$v2->config( 'directory', "$dir/");
	$v2->config( 'treeSuffix', 'dc=com');
	is( $v2->init, LDAP_SUCCESS);
	my( $ret, $dns)= search_dns( $v2, 'dc=com', scope => 0);
	is( $ret, 32, 'placeholder is not an entry');
	add_ok( $v2, "dn: dc=com\nobjectClass: domain\ndc: com\n", LDAP_SUCCESS, 'suffix entry added');
	( $ret, $dns)= search_dns( $v2, 'dc=com', scope => 0);
	is_deeply( $dns, [ 'dc=com' ], 'and found');
	add_ok( $v, "dn: $SUFFIX\nobjectClass: domain\ndc: example\n");
	( $ret, $dns)= search_dns( $v2, 'dc=com');
	is_deeply( $dns, [ 'dc=com', $SUFFIX ], 'other database entries below');
	no_warnings();
};

subtest 'directory and treeSuffix are required' => sub {
	my( $v, $dir)= new_dynldif( undef, empty => 1);

	my $v2= DynLDIF->new;
	$v2->config( 'treeSuffix', $SUFFIX);
	is( $v2->init, LDAP_PARAM_ERROR, 'no directory');
	warnings_like( qr/^Directive 'directory' is not set/);

	$v2= DynLDIF->new;
	$v2->config( 'directory', $dir);
	is( $v2->init, LDAP_PARAM_ERROR, 'no treeSuffix');
	warnings_like( qr/^Directive 'treeSuffix' is not set/);

	$v2->config( 'treeSuffix', 'dc=a,,dc=b');
	is( $v2->init, LDAP_PARAM_ERROR, 'invalid treeSuffix');
	warnings_like( qr/^Invalid 'treeSuffix' 'dc=a,,dc=b'/);
	no_warnings();
};

done_testing;
