#!/usr/bin/env perl
use warnings;
use strict;

# Tool to retrieve schema from server in LDIF format.
#
# This is just a basic script that assumes unauthenticated or
# pre-authenticated schema retrieval will work.
#
# Apart from its standalone use, this is also useful/needed with
# the DynLDIF backend because slapd does not provide slapd-perl with
# access to the schema.
#
# So, after starting the LDAP server, this script is run to download
# schema into a file, and then DynLDIF's option "schemaLDIF" can find
# and load it, and thus become aware of schema.
#
# ./schema.pl [hostname]
#
# Example:
#
# sudo sh -c './scripts/schema.pl > /etc/ldap/slapd-perl-dynldif/schema.ldif'
#
# Davor Ocelic <docelic@crystallabs.io>
# Crystal Labs, https://crystallabs.io/
# Released under GPL v3.

use Net::LDAP qw//;
use Net::LDAP::Schema qw//;

my $server= $ARGV[0]|| '0';

my $ldap = Net::LDAP->new ($server) or die "$@\n";
$ldap->bind or die "Can't bind\n";

my $schema = $ldap->schema or die "Can't get schema\n";
$schema->dump
