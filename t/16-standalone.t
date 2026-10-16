#!/usr/bin/perl
# scripts/dynldif.pl: standalone searches using a saved config dump
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_NO_SUCH_OBJECT/;

my $script= "$FindBin::Bin/../scripts/dynldif.pl";
my $U= "uid=testuser,ou=users,$SUFFIX";

# As at the end of database config in slapd.conf
my( $v, $dir)= new_dynldif([
	[ 'searchSubst', 'base', "^ou=people,$SUFFIX\$", '->', 'base', '.+', "ou=users,$SUFFIX" ],
	[ 'saveDump', 'test.dump' ],
]);
ok( -e "$dir/tmp/test.dump", 'dump saved');

# Run the script, return ( exit code, [ DNs in output order ], output )
sub run {
	my $cmd= join ' ', map { "'$_'"} $^X, $script, @_;
	my $out= `$cmd 2>&1`;
	( $? >> 8, [ $out=~ /^dn: (.+)$/mg ], $out )
}

my( $code, $dns, $out)= run( '-d', $dir, '-f', 'test.dump');
is( $code, 0, 'search') or diag( $out);
is( $dns->[0], $SUFFIX, 'defaults to the database suffix, base entry first');
ok( ( grep { $_ eq $U} @$dns), 'whole tree');

( $code, $dns, $out)= run( '-d', $dir, '-f', 'test.dump', '-b', "ou=people,$SUFFIX",
	'-s', 'one', '(uid=testuser)', 'uid');
is( $code, 0) or diag( $out);
is_deeply( $dns, [ $U ], 'base, scope and filter (with searchSubst from dump)');
unlike( $out, qr/^cn:/m, 'attribute list');

( $code, $dns, $out)= run( '-d', $dir, '-f', 'test.dump', '-z', 1);
is( $code, 4, 'size limit exceeded exits with result code 4');
is( scalar @$dns, 1, 'one entry returned');

( $code, $dns, $out)= run( '-d', $dir, '-f', 'test.dump', '-b', "ou=nosuch,$SUFFIX");
is( $code, LDAP_NO_SUCH_OBJECT, 'nonexistent base') or diag( $out);

( $code, $dns, $out)= run( '-d', $dir, '-f', 'test.dump', '-D', 'general', '(uid=x)');
like( $out, qr/^### SEARCH: /m, 'debug output');

( $code, $dns, $out)= run( '-d', $dir);
is( $code, 2, 'missing --dump');
like( $out, qr/Missing --dump/);

( $code, $dns, $out)= run( '-d', $dir, '-f', 'test.dump', '-s', 'deep');
is( $code, 2, 'invalid scope');

( $code, $dns, $out)= run( '-d', $dir, '-f', 'nosuch.dump');
isnt( $code, 0, 'missing dump file');

done_testing;
