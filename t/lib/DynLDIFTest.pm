package DynLDIFTest;
# Helpers for testing DynLDIF directly, without slapd.
#
# DynLDIF is instantiated and configured the same way slapd's back-perl
# does it: new(), a series of config() calls, then init().
#
# DynLDIF's debug output goes to STDERR; it is redirected to dynldif.log in
# each test's data directory. Perl warnings and warn() calls are collected
# so that tests can assert none were issued.

use strict;
use warnings;
use Exporter     qw/import/;
use File::Temp   qw/tempdir/;
use File::Spec   qw//;
use FindBin      qw//;
use Test::More;
use Net::LDAP::LDIF qw//;
use Net::LDAP::Constant qw/LDAP_SUCCESS/;

use lib "$FindBin::Bin/..";
use DynLDIF;

our @EXPORT= qw/new_dynldif add_ok search_entries search_dns entry_of
	warnings_like no_warnings data_file $SUFFIX $DATA_DIR/;

our $SUFFIX= 'dc=example,dc=com';
our $DATA_DIR= "$FindBin::Bin/data";

our @WARNINGS;
$SIG{__WARN__}= sub { push @WARNINGS, $_[0] };

# STDERR goes to dynldif.log, so report fatal errors via Test::More
$SIG{__DIE__}= sub {
	return if $^S; # Inside eval
	print { Test::More->builder->failure_output} "# Died: $_[0]";
};

# Example tree loaded by new_dynldif() unless 'empty' is requested
our $EXAMPLE= <<"EOF";
dn: $SUFFIX
objectClass: domain
objectClass: dcObject
dc: example

dn: ou=users,$SUFFIX
objectClass: organizationalUnit
ou: users

dn: ou=groups,$SUFFIX
objectClass: organizationalUnit
ou: groups

dn: ou=hosts,$SUFFIX
objectClass: organizationalUnit
ou: hosts

dn: cn=testuser,ou=groups,$SUFFIX
objectClass: posixGroup
cn: testuser
gidNumber: 12000

dn: uid=testuser,ou=users,$SUFFIX
objectClass: person
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: posixAccount
uid: testuser
homeDirectory: /home/testuser
uidNumber: 12000
gidNumber: 12000
loginShell: /bin/bash
cn: Test User
sn: User
givenName: Test
userPassword: test
EOF

# new_dynldif( [ key => value... ] list of config lines, %opts )
#
# Config lines are arrayrefs, i.e. [ 'addoverwrites', 1 ].
# Options: suffix => SUFFIX, empty => 1 (don't load example tree),
# init_ret => \$ret (don't fail on init error, return code instead).
sub new_dynldif {
	my( $config, %opts)= @_;
	my $suffix= $opts{suffix} || $SUFFIX;

	my $dir= tempdir( CLEANUP => 1);

	open STDERR, '>>', "$dir/dynldif.log" or die "Can't redirect STDERR: $!";

	my $v= DynLDIF->new;
	for my $line(
		[ 'directory', "$dir/" ],
		[ 'treesuffix', $suffix ],
		@{ $config || []},
	) {
		my $ret= $v->config( @$line);
		die "config(@$line) returned $ret" unless $ret== LDAP_SUCCESS;
	}

	my $ret= $v->init;
	if( $opts{init_ret}) {
		${ $opts{init_ret}}= $ret;
		return ( $v, $dir)
	}
	die "init() returned $ret" unless $ret== LDAP_SUCCESS;

	unless( $opts{empty}) {
		for my $ldif( split /\n\n/, $EXAMPLE) {
			$ret= $v->add( "$ldif\n");
			die "Adding example entry failed ($ret):\n$ldif" unless
				$ret== LDAP_SUCCESS;
		}
	}

	( $v, $dir)
}

# Add LDIF and check the return code
sub add_ok {
	my( $v, $ldif, $expect, $name)= @_;
	local $Test::Builder::Level= $Test::Builder::Level+ 1;
	$expect= LDAP_SUCCESS unless defined $expect;
	$ldif=~ s/^\s+//mg;
	is( $v->add( $ldif), $expect, $name || "add returns $expect");
}

# Run a direct (slapd-like) search, return ( $ret, @entries ).
# DynLDIF returns LDIF strings to slapd; they're parsed back into entries.
sub search_entries {
	my( $v, $base, %o)= @_;
	my( $ret, @ldifs)= $v->search(
		$base,
		defined $o{scope} ? $o{scope} : 2,
		0,
		$o{size} || 500,
		$o{time} || 3600,
		$o{filter} || '(objectClass=*)',
		0,
	);

	my @entries= map { entry_of( $_) } @ldifs;
	( $ret, @entries)
}

# Like search_entries(), but returns ( $ret, [ sorted DNs ] )
sub search_dns {
	my( $ret, @entries)= search_entries( @_);
	( $ret, [ sort map { $_->dn} @entries ])
}

# Parse LDIF string into an entry
sub entry_of {
	my( $ldif)= @_;
	open my $fh, '<', \$ldif or die;
	my $entry= Net::LDAP::LDIF->new( $fh)->read_entry;
	die "Can't parse LDIF:\n$ldif" unless $entry;
	$entry
}

# Path of the file backing a DN in the data dir (assumes normalized DN)
sub data_file {
	my( $dir, $dn)= @_;
	join( '/', $dir, map { s/%/%25/gr =~ s{/}{%2f}gr } reverse split /,/, $dn). '.ldif'
}

sub warnings_like {
	my( $re, $name)= @_;
	local $Test::Builder::Level= $Test::Builder::Level+ 1;
	my @w= grep { /$re/} @WARNINGS;
	@WARNINGS= grep { !/$re/} @WARNINGS;
	ok( scalar @w, $name || "warning matching $re issued");
}

sub no_warnings {
	my( $name)= @_;
	local $Test::Builder::Level= $Test::Builder::Level+ 1;
	is_deeply( \@WARNINGS, [], $name || 'no warnings issued')
		or diag( join '', @WARNINGS);
	@WARNINGS= ();
}

1
