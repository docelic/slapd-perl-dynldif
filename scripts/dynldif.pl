#!/usr/bin/perl
use warnings;
use strict;

# Script showing how to run DynLDIF as a standalone program, separate
# from slapd. Usage in this way is suitable if you want to read directory
# data while circumventing slapd but still getting the exact same
# results and code paths.
#
# Most notable use is running your search query of choice under Perl
# profiler, such as one of:
#
#  perl -d:DProf     scripts/dynldif.pl; dprofpp
#
#  perl -d:SmallProf scripts/dynldif.pl; ./scripts/sprofpp
#
# The script contains some hardcoded values, reflecting the specific
# issue that was being profiled the last time the script was used.
#
# There are no command line switches or options.
# To make the script suit your purposes you will most probably want to
# edit the source.
#
# To produce the exact same behavior as when running from slapd, DynLDIF
# has to be initialized with the same config.
# One way to do so is to initialize both with the same options.
# Another option is to run a configured LDAP/DynLDIF once, while having
# directive 'savedump FILE' at the end of database config. That will
# produce a Storable dump of the database's config. Then, instead of
# sending a series of ->config() directives seen below, you can just
# replace it with ->loaddump(FILE).
#
# Davor Ocelic <docelic@crystallabs.io>
# Crystal Labs, https://crystallabs.io/
# Released under GPL v3.

use DynLDIF;
package DynLDIF;

my $obj= DynLDIF->new;
p $obj;

# Set base directory so that loaddump can operate
$obj->config( 'directory', '/var/lib/ldap/dynldif');

# Load Storable dump of complete config
$obj->config( 'loaddump',  'example.com.dump');
p $obj;

# Must invoke to re-initialize object pointers within config
# (they don't survive Storable dump/restore, of course).
$obj->init;

# Perform a search
my @res= $obj->search( 'dc=example,dc=com', 2, 0, 500, 3600, "(objectClass=*)", 0);

# Show results
p @res;
