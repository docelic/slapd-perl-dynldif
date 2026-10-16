#!/usr/bin/perl
# The example configuration (etc/ldap/slapd.conf) is valid: its backend
# directives are accepted, and the backend initializes with them
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use File::Temp        qw/tempdir/;
use Text::ParseWords  qw/parse_line/;
use Net::LDAP::Constant qw/LDAP_SUCCESS/;

# Directives handled by slapd itself
my %SLAPD= map { $_=> 1} qw/suffix rootdn rootpw access perlmodulepath perlmodule/;

my $file= "$FindBin::Bin/../etc/ldap/slapd.conf";
open my $fh, '<', $file or die "Can't open $file: $!";
my $text= do { local $/; <$fh> };
$text=~ s/\n[ \t]+/ /g; # Continuation lines
my( $database)= $text=~ /^database\s+perl\s*\n(.*)/ms or die 'No perl database';

# Backend directives, and commented-out ones (examples of further settings)
my( @lines, @commented);
for( split /\n/, $database) {
	next if /^\s*$/;
	my $comment= s/^#//;
	next if $comment and !/^[a-zA-Z]+\s/; # (Text)
	my( $key, @val)= parse_line( '\s+', 0, $_);
	next if $SLAPD{ lc $key};
	push @{ $comment ? \@commented : \@lines}, [ $key, @val ];
}
ok( scalar @lines, 'backend directives found');
ok( scalar @commented, 'commented-out directives found');

for my $set( [ 'directives', @lines ], [ 'with commented-out directives', @lines, @commented ]) {
	my( $name, @set)= @$set;
	subtest $name => sub {
		my $dir= tempdir( CLEANUP => 1);
		open STDERR, '>>', "$dir/dynldif.log" or die;
		my $v= DynLDIF->new;
		for( @set) {
			my @line= @$_;
			next if lc $line[0] eq 'save'; # (Uses a variable that is not defined)
			$line[1]= "$dir/" if lc $line[0] eq 'directory';
			$line[1]= "$DATA_DIR/schema.ldif" if lc $line[0] eq 'schemaldif';
			is( $v->config( @line), LDAP_SUCCESS, "@line");
		}
		is( $v->init, LDAP_SUCCESS, 'init');
		warnings_like( qr/^Message: slapd-perl-dynldif, configuring dc=example,dc=com -- OK\.$/,
			'message with variables expanded');
		no_warnings();
	};
}

done_testing;
