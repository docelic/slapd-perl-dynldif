#!/usr/bin/perl
# cacheRead: caching of entries read from disk
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_NO_SUCH_OBJECT/;

my $U= "uid=testuser,ou=users,$SUFFIX";
my $G= "cn=testuser,ou=groups,$SUFFIX";

sub get {
	my( $v, $dn)= @_;
	my( $ret, @e)= search_entries( $v, $dn, scope => 0);
	$e[0]
}

subtest 'cache is used' => sub {
	my( $v, $dir)= new_dynldif([[ 'cacheRead', 1000 ]]);
	get( $v, $G) for 1 .. 20;
	my @keys= grep { /^\Q$G\E\|/} keys %{ $v->{cache}{read}{1000}};
	is( scalar @keys, 1, 'repeated reads share one cache entry');

	# Change the file behind DynLDIF's back; cached copy is served
	my $file= data_file( $dir, $G);
	open my $fh, '>>', $file or die;
	print $fh "description: changed on disk\n";
	close $fh;
	ok( !get( $v, $G)->exists( 'description'), 'cached entry served');
	no_warnings();
};

subtest 'cache expires' => sub {
	my( $v, $dir)= new_dynldif([[ 'cacheRead', 1 ]]);
	get( $v, $G);
	open my $fh, '>>', data_file( $dir, $G) or die;
	print $fh "description: changed on disk\n";
	close $fh;
	is( get( $v, $G)->get_value( 'description'), 'changed on disk',
		'cacheRead 1 re-reads on the next operation');
	no_warnings();
};

subtest 'writes invalidate the cache' => sub {
	my( $v, $dir)= new_dynldif([[ 'cacheRead', 1000 ]]);

	get( $v, $U);
	is( $v->modify( $U, 'REPLACE', 'sn', 'New'), LDAP_SUCCESS);
	is( get( $v, $U)->get_value( 'sn'), 'New', 'modify');

	get( $v, $G);
	is( $v->delete( $G), LDAP_SUCCESS);
	is( get( $v, $G), undef, 'delete');
	my( $ret)= search_entries( $v, $G, scope => 0);
	is( $ret, LDAP_NO_SUCH_OBJECT, 'deleted entry not found');

	add_ok( $v, "dn: $G\nobjectClass: posixGroup\ncn: testuser\ngidNumber: 1\n");
	is( get( $v, $G)->get_value( 'gidNumber'), 1, 'add');

	is( $v->modrdn( $G, 'cn=renamed', 1), LDAP_SUCCESS);
	is( get( $v, $G), undef, 'modrdn: old DN');
	ok( get( $v, "cn=renamed,ou=groups,$SUFFIX"), 'modrdn: new DN');
	no_warnings();
};

done_testing;
