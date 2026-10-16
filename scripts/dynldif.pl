#!/usr/bin/perl
use warnings;
use strict;

# Runs DynLDIF as a standalone program, separate from slapd, and performs
# a search. Usage in this way is suitable if you want to read directory
# data while circumventing slapd but still getting the exact same
# results and code paths.
#
# Most notable use is running your search query of choice under Perl
# profiler, such as one of:
#
#  perl -d:DProf     scripts/dynldif.pl ...; dprofpp
#
#  perl -d:SmallProf scripts/dynldif.pl ...; ./scripts/sprofpp
#
# To produce the exact same behavior as when running from slapd, DynLDIF
# has to be initialized with the same config. To do so, run slapd once,
# with directive 'saveDump FILE' at the end of database config. That will
# produce a Storable dump of the database's config (in DIRECTORY/tmp/),
# which this script loads.
#
# Usage:
#   scripts/dynldif.pl [options] [FILTER [ATTR...]]
#
# Options:
#   -d, --directory DIR  Database directory (default: /var/lib/ldap/dynldif)
#   -f, --dump FILE      Config dump to load from DIR/tmp/ (required)
#   -b, --base DN        Search base (default: the database's treeSuffix)
#   -s, --scope SCOPE    base, one, sub or children (default: sub)
#   -z, --size N         Size limit (default: unlimited)
#   -l, --time N         Time limit in seconds (default: unlimited)
#   -D, --debug WORDS    Debug output, as the 'debug' directive (i.e. "all")
#
# Davor Ocelic <docelic@crystallabs.io>
# Crystal Labs, https://crystallabs.io/
# Released under GPL v3.

use FindBin;
use lib "$FindBin::Bin/..";
use Getopt::Long qw/GetOptions :config no_ignore_case/;
use Net::LDAP::Constant qw/LDAP_SUCCESS/;
use Net::LDAP::LDIF;
use DynLDIF;

my %SCOPES= ( base => 0, one => 1, sub => 2, children => 3);

my %o= (
	directory => '/var/lib/ldap/dynldif',
	scope     => 'sub',
	size      => -1,
	time      => -1,
);
GetOptions( \%o, 'directory|d=s', 'dump|f=s', 'base|b=s', 'scope|s=s',
	'size|z=i', 'time|l=i', 'debug|D=s', 'help|h')
	or usage( 2);
usage( 0) if $o{help};
usage( 2, 'Missing --dump') unless $o{dump};
usage( 2, "Invalid scope '$o{scope}'") unless exists $SCOPES{ $o{scope}};

my( $filter, @attrs)= @ARGV;
$filter= '(objectClass=*)' unless defined $filter;

my $obj= DynLDIF->new;

for my $line(
	# Set base directory so that loaddump can operate
	[ 'directory', $o{directory} ],
	# Load Storable dump of complete config
	[ 'loaddump', $o{dump} ],
	( defined $o{debug} ? [ 'debug', split ' ', $o{debug} ] : ()),
) {
	my $ret= $obj->config( @$line);
	die "Config directive '@$line' failed ($ret)\n" unless $ret== LDAP_SUCCESS;
}

# Must invoke to re-initialize object pointers within config
# (they don't survive Storable dump/restore, of course).
my $ret= $obj->init;
die "Init failed ($ret)\n" unless $ret== LDAP_SUCCESS;

my $base= defined $o{base} ? $o{base} : $obj->{treesuffix};
my( $code, @res)= $obj->search( $base, $SCOPES{ $o{scope}}, 0, $o{size},
	$o{time}, $filter, 0, @attrs);

# Selecting attributes to return is done by slapd, not the backend
if( @attrs and !grep { $_ eq '*'} @attrs) {
	my %want= map { lc $_=> 1} @attrs;
	@res= map { only_attrs( $_, \%want)} @res;
}

# Entries come in reverse order (slapd reads them that way)
s/^\s+|\s+$//g for @res;
print map { "$_\n\n"} reverse @res;

# Like ldapsearch, exit with the LDAP result code
if( $code!= LDAP_SUCCESS) {
	warn "Search returned $code\n";
	exit $code
}

sub only_attrs {
	my( $ldif, $want)= @_;
	open my $in, '<', \$ldif or die;
	my $entry= Net::LDAP::LDIF->new( $in)->read_entry or return $ldif;
	for( $entry->attributes) {
		( my $name= lc)=~ s/;.*//;
		$entry->delete( $_) unless $want->{$name};
	}
	open my $out, '>', \my $str or die;
	Net::LDAP::LDIF->new( $out, 'w', change => 0)->write_entry( $entry);
	close $out;
	$str
}

sub usage {
	my( $exit, $msg)= @_;
	print STDERR "$msg\n" if $msg;
	print STDERR "Usage: $0 [-d DIR] -f DUMP [-b BASE] [-s SCOPE] ".
		"[-z SIZE] [-l TIME] [-D DEBUG] [FILTER [ATTR...]]\n";
	exit $exit
}
