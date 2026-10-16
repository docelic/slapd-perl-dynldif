#!/usr/bin/perl
# Internal errors: slapd terminates if the backend dies, so they must be
# returned as LDAP errors
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_OTHER/;

my $U= "uid=testuser,ou=users,$SUFFIX";
my( $v, $dir)= new_dynldif([[ 'enableBind', 1 ]]);

{
	no warnings 'redefine';
	local *DynLDIF::dn2leaf= sub { die "boom\n" };

	my( $ret, @e)= $v->search( $SUFFIX, 2, 0, 10, 10, '(objectClass=*)', 0);
	is( $ret, LDAP_OTHER, 'search');
	is( scalar @e, 0, 'no entries');
	is( $v->add( "dn: cn=x,ou=hosts,$SUFFIX\nobjectClass: device\ncn: x\n"), LDAP_OTHER, 'add');
	is( $v->modify( $U, 'REPLACE', 'sn', 'x'), LDAP_OTHER, 'modify');
	is( $v->delete( $U), LDAP_OTHER, 'delete');
	is( $v->modrdn( $U, 'uid=x', 1), LDAP_OTHER, 'modrdn');
	is( $v->compare( $U, 'sn=User'), LDAP_OTHER, 'compare');
	is( $v->bind( $U, 'test'), LDAP_OTHER, 'bind');
	is( $v->config( 'directory', $dir), LDAP_SUCCESS, 'config (not affected)');
	warnings_like( qr/^Internal error in $_: boom$/, "warning for $_")
		for qw/search add modify delete modrdn compare bind/;

	# Internal (nested) calls are not wrapped, so that the error reaches
	# the operation that made them
	ok( !eval { $v->search( $SUFFIX, 2, 0, 10, 10, '(objectClass=*)', 0, {}); 1 },
		'nested call dies');
}

my( $ret, @e)= $v->search( $SUFFIX, 2, 0, 10, 10, '(objectClass=*)', 0);
is( $ret, LDAP_SUCCESS, 'operations work after errors');
is( scalar @e, 6, 'all entries found');
no_warnings();

done_testing;
