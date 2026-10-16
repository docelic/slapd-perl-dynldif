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

subtest 'cacheEntries' => sub {
	my( $v, $dir)= new_dynldif();
	my $file= data_file( $dir, $G);
	is( get( $v, $G)->get_value( 'gidNumber'), 12000, 'read');
	ok( ( grep { m{/ou=groups/cn=testuser\.ldif$}} keys %{ $v->{entry_cache}}), 'kept');

	# Changes through the backend replace the file
	is( $v->modify( $G, 'REPLACE', 'gidNumber', 5), LDAP_SUCCESS);
	is( get( $v, $G)->get_value( 'gidNumber'), 5, 'modify');

	# Changes by other programs, in place and with the same size
	for my $n( 6, 7) {
		open my $fh, '+<', $file or die;
		my $data= do { local $/; <$fh> };
		$data=~ s/^gidNumber: \d+$/gidNumber: $n/m or die;
		seek $fh, 0, 0;
		print $fh $data;
		close $fh;
		is( get( $v, $G)->get_value( 'gidNumber'), $n, "edited in place ($n)");
	}

	# Values changed by overlays etc. don't change the kept entries
	my $e= get( $v, $G);
	$e->replace( gidNumber=> 99);
	is( get( $v, $G)->get_value( 'gidNumber'), 7, 'returned entries are copies');

	# Limit
	my( $v2)= new_dynldif([[ 'cacheEntries', 2 ]]);
	search_entries( $v2, $SUFFIX);
	ok( keys %{ $v2->{entry_cache}}<= 2, 'at most cacheEntries entries kept');
	my( $v3)= new_dynldif([[ 'cacheEntries', 0 ]]);
	search_entries( $v3, $SUFFIX);
	is( scalar keys %{ $v3->{entry_cache}}, 0, 'cacheEntries 0');

	is( DynLDIF->new->config( 'cacheEntries', 'x'), 89, 'invalid value');
	warnings_like( qr/Invalid 'cacheEntries' value 'x'/);
	no_warnings();
};

done_testing;
