#!/usr/bin/perl
# scripts/read-ldif.pl (scripts/schema.pl is tested in 10-slapd.t)
use strict;
use warnings;
use FindBin;
use File::Temp qw/tempdir/;
use Test::More;

my $script= "$FindBin::Bin/../scripts/read-ldif.pl";
my $example= "$FindBin::Bin/../ldifs/example.ldif";

sub run {
	my $cmd= join ' ', map { "'$_'"} $^X, $script, @_;
	my $out= `$cmd 2>&1`;
	( $? >> 8, $out)
}

my( $code, $out)= run( $example);
is( $code, 0, 'valid LDIF');
is( $out, join( '', map { "$_\n"} 'dc=example,dc=com', 'ou=users,dc=example,dc=com',
	'ou=groups,dc=example,dc=com', 'ou=hosts,dc=example,dc=com',
	'cn=testuser,ou=groups,dc=example,dc=com', 'uid=testuser,ou=users,dc=example,dc=com'),
	'DNs listed');

( $code, $out)= run( '-v', $example);
is( $code, 0, '-v');
like( $out, qr/^dc=example,dc=com\n\$VAR1 = bless/, 'entries dumped');

my $dir= tempdir( CLEANUP => 1);
open my $fh, '>', "$dir/bad.ldif" or die;
print $fh "dn: cn=x\nfoo\n\ndn: cn=y\ncn: y\n";
close $fh;
( $code, $out)= run( "$dir/bad.ldif");
is( $code, 1, 'invalid LDIF');
like( $out, qr/^Error msg: illegal LDIF line 'foo'$/m, 'error reported');
like( $out, qr/^cn=y$/m, 'following entries still read');

( $code, $out)= run();
isnt( $code, 0, 'no arguments');
like( $out, qr/^Usage:/);
( $code, $out)= run( "$dir/nosuch.ldif");
isnt( $code, 0, 'missing file');
like( $out, qr/Can't open/);

done_testing;
