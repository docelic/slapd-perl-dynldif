#!/usr/bin/perl
# Integration test: runs slapd with the DynLDIF backend and talks to it over
# LDAP. This verifies that arguments are passed between slapd's back-perl
# and DynLDIF as expected.
#
# Skipped if slapd, its back_perl module or the standard schema files are
# not installed. Locations can be overridden with SLAPD, SLAPD_MODULEPATH
# and SLAPD_SCHEMADIR environment variables.
use strict;
use warnings;
use FindBin;
use Test::More;
use File::Temp   qw/tempdir/;
use IO::Socket::INET;
use POSIX        qw/WNOHANG/;
use Time::HiRes  qw/sleep/;
use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Schema;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_NO_SUCH_OBJECT LDAP_ALREADY_EXISTS
	LDAP_TYPE_OR_VALUE_EXISTS LDAP_NO_SUCH_ATTRIBUTE LDAP_NOT_ALLOWED_ON_RDN
	LDAP_OBJECT_CLASS_VIOLATION LDAP_NAMING_VIOLATION
	LDAP_COMPARE_TRUE LDAP_COMPARE_FALSE LDAP_INVALID_CREDENTIALS
	LDAP_NOT_ALLOWED_ON_NONLEAF LDAP_SIZELIMIT_EXCEEDED
	LDAP_INSUFFICIENT_ACCESS/;

my $slapd     = $ENV{SLAPD}            || '/usr/sbin/slapd';
my $modulepath= $ENV{SLAPD_MODULEPATH} || '/usr/lib/ldap';
my $schemadir = $ENV{SLAPD_SCHEMADIR}  || '/etc/ldap/schema';
my @schemas   = qw/core cosine nis inetorgperson/;

plan skip_all => "slapd not found at $slapd" unless -x $slapd;
plan skip_all => "back_perl not found in $modulepath"
	unless glob "$modulepath/back_perl*";
plan skip_all => "schema files not found in $schemadir"
	if grep { !-r "$schemadir/$_.schema"} @schemas;

my $SUFFIX= 'dc=example,dc=com';
my $ADMIN = "cn=admin,$SUFFIX";
my $PW    = 'secret';
my $U     = "uid=testuser,ou=users,$SUFFIX";
my $G     = "cn=testuser,ou=groups,$SUFFIX";

my $dir= tempdir( CLEANUP => !$ENV{KEEP_TMP});
diag( "Temp dir: $dir") if $ENV{KEEP_TMP};
mkdir "$dir/data" or die;

# Find a free port
my $sock= IO::Socket::INET->new( Listen => 1, LocalAddr => '127.0.0.1',
	LocalPort => 0, ReuseAddr => 1) or die "Can't get a port: $!";
my $port= $sock->sockport;
close $sock;

open my $cfg, '>', "$dir/slapd.conf" or die;
print $cfg join( '', map { "include $schemadir/$_.schema\n"} @schemas), <<"EOF";
pidfile    $dir/slapd.pid
argsfile   $dir/slapd.args
modulepath $modulepath
moduleload back_perl
sizelimit  500

database           perl
suffix             "$SUFFIX"
rootdn             $ADMIN
rootpw             $PW
perlModulePath     "$FindBin::Bin/.."
perlModule         "DynLDIF"
directory          "$dir/data/"
treeSuffix         "$SUFFIX"
cacheRead          1
enableBind         1
expandVal          .   ^\$
fileVal            .   ^\$
findVal            .   ^\$
debug              1

access to attrs=userPassword
	by self write
	by anonymous auth
	by * none
access to *
	by * read
EOF
close $cfg;

my $pid= fork;
die "Can't fork: $!" unless defined $pid;
if( !$pid) {
	open STDOUT, '>', "$dir/slapd.log";
	open STDERR, '>&', \*STDOUT;
	exec $slapd, '-d', 256, '-f', "$dir/slapd.conf",
		'-h', "ldap://127.0.0.1:$port/";
	die "Can't exec $slapd: $!";
}

END {
	if( $pid) {
		kill 'TERM', $pid;
		waitpid $pid, 0;
	}
}

my $ldap;
for( 1 .. 100) {
	last if waitpid( $pid, WNOHANG);
	last if $ldap= Net::LDAP->new( "127.0.0.1:$port", timeout => 2);
	sleep 0.1;
}
unless( $ldap) {
	my $log= do { local( @ARGV, $/)= "$dir/slapd.log"; <> };
	BAIL_OUT( "slapd did not start:\n$log");
}

sub code { $_[0]->code }

# slapd's working directory (to check that DynLDIF doesn't change it)
my $cwd= readlink "/proc/$pid/cwd";

is( code( $ldap->bind( $ADMIN, password => $PW)), LDAP_SUCCESS, 'admin bind');

subtest 'add example data' => sub {
	my $ldif= Net::LDAP::LDIF->new( "$FindBin::Bin/../ldifs/example.ldif", 'r')
		or die;
	while( my $e= $ldif->read_entry) {
		is( code( $ldap->add( $e)), LDAP_SUCCESS, 'add '. $e->dn);
	}
	is( code( $ldap->add( $G, attrs => [ objectClass => 'posixGroup',
		cn => 'testuser', gidNumber => 1 ])), LDAP_ALREADY_EXISTS, 'duplicate');
};

subtest 'search' => sub {
	my $r= $ldap->search( base => $SUFFIX, filter => '(objectClass=*)');
	is( code( $r), LDAP_SUCCESS);
	is( $r->count, 6, 'subtree');

	$r= $ldap->search( base => $SUFFIX, scope => 'one', filter => '(objectClass=*)');
	is( $r->count, 3, 'one level');

	$r= $ldap->search( base => $SUFFIX, filter => '(uid=testuser)', attrs => [ 'cn' ]);
	is( $r->count, 1, 'filter');
	is_deeply( [ $r->entry( 0)->attributes ], [ 'cn' ], 'requested attributes only');

	$r= $ldap->search( base => $SUFFIX, sizelimit => 2, filter => '(objectClass=*)');
	is( code( $r), LDAP_SIZELIMIT_EXCEEDED, 'size limit');
	is( $r->count, 2, 'entries up to the limit');

	$r= $ldap->search( base => "ou=nosuch,$SUFFIX", scope => 'one',
		filter => '(objectClass=*)');
	is( code( $r), LDAP_NO_SUCH_OBJECT, 'nonexistent base');
};

subtest 'limits' => sub {
	SKIP: {
		skip 'no /proc', 1 unless defined $cwd;
		is( readlink "/proc/$pid/cwd", $cwd, "working directory unchanged after size limit");
	}

	# More entries than any default limit (written directly, which is faster)
	my $hosts= "$dir/data/dc=com/dc=example/ou=hosts";
	mkdir $hosts unless -d $hosts;
	for my $i( 1.. 7000) {
		open my $fh, '>', "$hosts/cn=h$i.ldif" or die;
		print $fh "dn: cn=h$i,ou=hosts,$SUFFIX\nobjectClass: device\ncn: h$i\n";
	}
	my $r= $ldap->search( base => "ou=hosts,$SUFFIX", scope => 'one',
		filter => '(objectClass=*)');
	is( code( $r), LDAP_SUCCESS, 'rootdn: no limit');
	is( $r->count, 7000, 'all entries');

	my $anon= Net::LDAP->new( "127.0.0.1:$port") or die;
	$r= $anon->search( base => "ou=hosts,$SUFFIX", scope => 'one',
		filter => '(objectClass=*)');
	is( code( $r), LDAP_SIZELIMIT_EXCEEDED, "others: slapd's sizelimit");
	is( $r->count, 500);
	unlink glob "'$hosts/cn=h*.ldif'";
	ok( !-e "$hosts/cn=h1.ldif", 'removed');

	# A search with a 'find' subsearch, and a later one with a time limit
	my $T= "cn=t,ou=hosts,$SUFFIX";
	is( code( $ldap->add( $T, attrs => [ objectClass => 'device', cn => 't',
		l => '$ find $ .. 2 0 0 0 (uid=testuser) 0 uid' ])), LDAP_SUCCESS);
	$r= $ldap->search( base => $T, scope => 'base', filter => '(objectClass=*)');
	is( $r->entry( 0)->get_value( 'l'), 'testuser', 'find');
	sleep 2;
	$r= $ldap->search( base => $SUFFIX, timelimit => 1, filter => '(objectClass=*)');
	is( code( $r), LDAP_SUCCESS, 'time limit counts from the start of the search');
	is( code( $ldap->delete( $T)), LDAP_SUCCESS);

	# Same value from several entries (gidNumber of the user and the group)
	is( code( $ldap->add( $T, attrs => [ objectClass => 'device', cn => 't',
		l => '$ find $ .. 2 0 0 0 (gidNumber=12000) 0 gidNumber \x00 \x00' ])), LDAP_SUCCESS);
	$r= $ldap->search( base => $T, scope => 'base', filter => '(objectClass=*)');
	is( $r->count, 1, 'entry with values found more than once');
	is_deeply( [ $r->count ? $r->entry( 0)->get_value( 'l') : () ], [ 12000 ], 'returned once');
	is( code( $ldap->delete( $T)), LDAP_SUCCESS);
};

subtest 'modify' => sub {
	is( code( $ldap->modify( $U,
		add     => { description => [ 'one', 'two' ] },
		replace => { sn => 'Other' },
	)), LDAP_SUCCESS, 'add and replace');
	is( code( $ldap->modify( $U, delete => { description => 'one' })),
		LDAP_SUCCESS, 'delete value');
	is( code( $ldap->modify( $U, delete => [ 'loginShell' ])),
		LDAP_SUCCESS, 'delete attribute');

	my $e= $ldap->search( base => $U, scope => 'base', filter => '(objectClass=*)')
		->entry( 0);
	is_deeply( [ $e->get_value( 'description') ], [ 'two' ]);
	is( $e->get_value( 'sn'), 'Other');
	ok( !$e->exists( 'loginShell'));

	is( code( $ldap->modify( $U, replace => {
		description => "\$ exp \$ $G gidNumber" })), LDAP_SUCCESS, 'dynamic value');
	$e= $ldap->search( base => $U, scope => 'base', filter => '(objectClass=*)')
		->entry( 0);
	is( $e->get_value( 'description'), 12000, 'expanded');

	# Values equal to modify action names
	is( code( $ldap->modify( $U, changes => [
		replace => [ title => [ 'DELETE', 'sn' ] ],
		add     => [ ou => 'ADD' ],
	])), LDAP_SUCCESS, 'values that look like actions');
	$e= $ldap->search( base => $U, scope => 'base', filter => '(objectClass=*)')
		->entry( 0);
	is_deeply( [ $e->get_value( 'title') ], [ 'DELETE', 'sn' ], 'first attribute');
	is_deeply( [ $e->get_value( 'ou') ], [ 'ADD' ], 'second attribute');
	is( $e->get_value( 'sn'), 'Other', 'sn untouched');

	# Failed reference must not produce an empty (invalid) value
	is( code( $ldap->modify( $U, replace => {
		l => [ "\$ exp \$ cn=nosuch,.. cn", 'static' ] })), LDAP_SUCCESS);
	$e= $ldap->search( base => $U, scope => 'base', filter => '(objectClass=*)')
		->entry( 0);
	is_deeply( [ $e->get_value( 'l') ], [ 'static' ],
		'failed reference dropped');
};

subtest 'compare' => sub {
	is( code( $ldap->compare( $U, attr => 'uid', value => 'testuser')),
		LDAP_COMPARE_TRUE, 'true');
	is( code( $ldap->compare( $U, attr => 'uid', value => 'other')),
		LDAP_COMPARE_FALSE, 'false');
	is( code( $ldap->compare( $U, attr => 'description', value => '12000')),
		LDAP_COMPARE_TRUE, 'dynamic value');
};

subtest 'bind as entry' => sub {
	my $l= Net::LDAP->new( "127.0.0.1:$port") or die;
	is( code( $l->bind( $U, password => 'test')), LDAP_SUCCESS, 'correct password');
	$l= Net::LDAP->new( "127.0.0.1:$port") or die;
	is( code( $l->bind( $U, password => 'wrong')), LDAP_INVALID_CREDENTIALS,
		'wrong password');
};

subtest 'modrdn' => sub {
	is( code( $ldap->moddn( $G, newrdn => 'cn=grp', deleteoldrdn => 1)),
		LDAP_SUCCESS, 'rename');
	my $e= $ldap->search( base => "cn=grp,ou=groups,$SUFFIX", scope => 'base',
		filter => '(objectClass=*)')->entry( 0);
	ok( $e, 'renamed entry found');
	is_deeply( [ $e->get_value( 'cn') ], [ 'grp' ], 'RDN value updated');

	is( code( $ldap->moddn( "cn=grp,ou=groups,$SUFFIX", newrdn => 'cn=grp',
		newsuperior => "ou=hosts,$SUFFIX")), LDAP_SUCCESS, 'move');
	is( $ldap->search( base => "ou=hosts,$SUFFIX", scope => 'one',
		filter => '(objectClass=*)')->count, 1, 'found under new parent');

	is( code( $ldap->moddn( "ou=users,$SUFFIX", newrdn => 'ou=people')),
		LDAP_NOT_ALLOWED_ON_NONLEAF, 'non-leaf');
};

subtest 'LDAP result codes' => sub {
	my %tests= (
		'add existing value'      => [ LDAP_TYPE_OR_VALUE_EXISTS, add => [ sn => 'Other' ]],
		'delete missing value'    => [ LDAP_NO_SUCH_ATTRIBUTE, delete => [ sn => 'nope' ]],
		'delete missing attribute'=> [ LDAP_NO_SUCH_ATTRIBUTE, delete => [ roomNumber => [] ]],
		'delete RDN value'        => [ LDAP_NOT_ALLOWED_ON_RDN, delete => [ uid => 'testuser' ]],
		'delete in other case'    => [ LDAP_SUCCESS, delete => [ sn => 'OTHER' ]],
	);
	for my $name( sort keys %tests) {
		my( $code, @changes)= @{ $tests{$name}};
		is( code( $ldap->modify( $U, changes => [ @changes ])), $code, $name);
	}

	is( code( $ldap->add( "cn=x,ou=hosts,$SUFFIX", attrs => [ cn => 'x' ])),
		LDAP_OBJECT_CLASS_VIOLATION, 'add without objectClass');
	is( code( $ldap->add( "cn=x,ou=hosts,$SUFFIX",
		attrs => [ objectClass => 'device', cn => 'y' ])),
		LDAP_NAMING_VIOLATION, 'add without RDN value');

	my $r= $ldap->search( base => $SUFFIX, filter => '(gidNumber=012000)');
	is( code( $r), LDAP_SUCCESS, 'filter with invalid integer is not an error');
	is( $r->count, 0, 'and matches nothing');

	$r= $ldap->search( base => $SUFFIX, filter => '(cn~=test user)');
	is( $r->count, 1, 'approximate match');
};

subtest 'passwords' => sub {
	my $anon= Net::LDAP->new( "127.0.0.1:$port") or die;
	my $e= $anon->search( base => $U, scope => 'base', filter => '(objectClass=*)')
		->entry( 0);
	ok( $e && !$e->exists( 'userPassword'), 'anonymous can not read userPassword');

	# slappasswd -s secret -h {SSHA}
	is( code( $ldap->modify( $U, replace => {
		userPassword => '{SSHA}eHy8TGKEINjS8nSCVwjZ87stV4zV3An6' })), LDAP_SUCCESS);
	my $l= Net::LDAP->new( "127.0.0.1:$port") or die;
	is( code( $l->bind( $U, password => 'secret')), LDAP_SUCCESS, 'bind with hashed password');
	$l= Net::LDAP->new( "127.0.0.1:$port") or die;
	is( code( $l->bind( $U, password => '{SSHA}eHy8TGKEINjS8nSCVwjZ87stV4zV3An6')),
		LDAP_INVALID_CREDENTIALS, 'hash is not accepted as password');

	# Filters and compare can not be used to find out about passwords
	my $count= sub {
		my( $conn, $filter)= @_;
		my $r= $conn->search( base => $SUFFIX, filter => $filter);
		is( code( $r), LDAP_SUCCESS, "search $filter");
		scalar $r->entries
	};
	$anon= Net::LDAP->new( "127.0.0.1:$port") or die;
	is( $count->( $anon, '(userPassword=*)'), 0, 'presence filter matches nothing');
	is( $count->( $anon, '(!(userPassword=*))'), 0, 'negated presence filter matches nothing');
	is( $count->( $anon, '(userPassword={SSHA}eHy8TGKEINjS8nSCVwjZ87stV4zV3An6)'), 0,
		'equality filter on hash matches nothing');
	is( $count->( $anon, '(|(uid=testuser)(userPassword=*))'), 1,
		'other filter components still work');
	is( code( $anon->compare( $U, attr => 'userPassword',
		value => '{SSHA}eHy8TGKEINjS8nSCVwjZ87stV4zV3An6')), LDAP_INSUFFICIENT_ACCESS,
		'compare refused');
};

subtest 'DNs with special characters' => sub {
	my $name= "\xc3\x9cn\xc3\xafc\xc3\xb8d\xc3\xa9"; # Unicode, as UTF-8
	for(
		[ "cn=Smith\\, John   Q,ou=users,$SUFFIX", 'Smith, John Q',
			"cn=smith\\2c john q,ou=users,$SUFFIX" ],
		[ "cn=John Smith,ou=users,$SUFFIX", 'John Smith', "cn=john smith,ou=users,$SUFFIX" ],
		[ "cn=JohnSmith,ou=users,$SUFFIX", 'JohnSmith', "cn=johnsmith,ou=users,$SUFFIX" ],
		[ "cn=$name,ou=users,$SUFFIX", $name, "cn=\xc3\xbcn\xc3\xafc\xc3\xb8d\xc3\xa9,ou=users,$SUFFIX" ],
	) {
		my( $dn, $cn, $canonical)= @$_;
		is( code( $ldap->add( $dn, attrs => [ objectClass => 'person', cn => $cn, sn => 'x' ])),
			LDAP_SUCCESS, "add $cn");
		my $r= $ldap->search( base => $dn, scope => 'base', filter => '(objectClass=*)');
		is( code( $r), LDAP_SUCCESS, "search $cn");
		# (slapd formats the DN, with hex escapes in upper case)
		is( lc( ( $r->entries)[0] && ( $r->entries)[0]->dn), $canonical, 'canonical DN returned');
		is( code( $ldap->compare( $dn, attr => 'cn', value => $cn)), LDAP_COMPARE_TRUE,
			"compare $cn");
	}
	is( code( $ldap->moddn( "cn=John Smith,ou=users,$SUFFIX", newrdn => 'cn=Doe\\, Jane',
		deleteoldrdn => 1)), LDAP_SUCCESS, 'modrdn');
	my $e= $ldap->search( base => "cn=Doe\\, Jane,ou=users,$SUFFIX", scope => 'base',
		filter => '(objectClass=*)')->entry( 0);
	is_deeply( $e && [ $e->get_value( 'cn') ], [ 'Doe, Jane' ], 'renamed');
	for( "cn=Smith\\, John Q", 'cn=JohnSmith', "cn=$name", 'cn=Doe\\, Jane') {
		is( code( $ldap->delete( "$_,ou=users,$SUFFIX")), LDAP_SUCCESS, "delete $_");
	}
};

subtest 'bad values are not fatal' => sub {
	open my $fh, '>', "$dir/data/f.txt" or die;
	print $fh "x\n";
	close $fh;
	is( code( $ldap->add( "cn=bad,ou=hosts,$SUFFIX", attrs => [ objectClass => 'device',
		cn => 'bad', description => '$ file $ f.txt (' ])), LDAP_SUCCESS, 'add');
	my $r= $ldap->search( base => "cn=bad,ou=hosts,$SUFFIX", scope => 'base',
		filter => '(objectClass=*)');
	is( code( $r), LDAP_SUCCESS, 'entry with invalid regex in a value can be read');
	is( code( $ldap->delete( "cn=bad,ou=hosts,$SUFFIX")), LDAP_SUCCESS, 'server still running');
};

subtest 'schema.pl' => sub {
	my $out= `$^X '$FindBin::Bin/../scripts/schema.pl' 127.0.0.1:$port 2>&1`;
	is( $?, 0, 'schema retrieved') or diag( $out);
	open my $fh, '>', "$dir/schema.ldif" or die;
	print $fh $out;
	close $fh;
	my $schema= Net::LDAP::Schema->new( "$dir/schema.ldif");
	ok( $schema && $schema->attribute( 'uidNumber'), 'and can be loaded');
};

subtest 'delete' => sub {
	is( code( $ldap->delete( "ou=users,$SUFFIX")), LDAP_NOT_ALLOWED_ON_NONLEAF,
		'non-leaf');
	is( code( $ldap->delete( $U)), LDAP_SUCCESS, 'leaf');
	is( code( $ldap->delete( $U)), LDAP_NO_SUCH_OBJECT, 'already deleted');
	is( code( $ldap->delete( "ou=users,$SUFFIX")), LDAP_SUCCESS,
		'empty parent');
};

$ldap->unbind;

my $log= do { local( @ARGV, $/)= "$dir/slapd.log"; <> };
my @warnings= grep { !/^[0-9a-f]{8}\./ and /warn|uninitialized| line \d+/i }
	split /\n/, $log;
is_deeply( \@warnings, [], 'no warnings in slapd log') or diag( join "\n", @warnings);

# Debug output is on, but passwords are not logged (slapd's own log lines,
# which include filters sent by clients, are not ours)
my $ours= join "\n", grep { !/^[0-9a-f]{8}\./} split /\n/, $log;
like( $ours, qr/^### MODIFY .*userPassword: \*\*\*\*\*/m, 'debug output present');
unlike( $ours, qr/eHy8TGKEINjS8nSCVwjZ87stV4zV3An6/, 'password hash not logged');
unlike( $ours, qr/^userPassword: test/mi, 'password from ADD not logged');

done_testing;
