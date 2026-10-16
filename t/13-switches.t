#!/usr/bin/perl
# Feature switches (enable* directives) and the 'debug' directive
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_PARAM_ERROR/;

my $U= "uid=testuser,ou=users,$SUFFIX";
my $T= "cn=t,ou=hosts,$SUFFIX";
my @OVERLAYS= (
	[ 'expandVal', '.', '^$' ],
	[ 'fileVal', '.', '^$' ],
	[ 'findVal', '.', '^$' ],
	[ 'perl', '.', '^$' ],
);

sub read_log {
	my( $dir)= @_;
	open my $fh, '<', "$dir/dynldif.log" or return q{};
	local $/;
	<$fh>
}

# Store an entry with given 'l' values and return the expanded values
sub expand {
	my( $v, @specs)= @_;
	$v->delete( $T);
	my $ret= $v->add( "dn: $T\nobjectClass: device\ncn: t\n".
		join( '', map { "l: $_\n"} @specs));
	die "add failed ($ret)" unless $ret== LDAP_SUCCESS;
	my( $r, @e)= search_entries( $v, $T, scope => 0);
	die "search failed ($r)" unless $r== LDAP_SUCCESS;
	[ $e[0]->get_value( 'l') ]
}

subtest 'debug' => sub {
	my( $v, $dir)= new_dynldif();
	search_entries( $v, $SUFFIX);
	unlike( read_log( $dir), qr/^###/m, 'off by default');

	is( $v->config( 'debug', 1), LDAP_SUCCESS);
	is_deeply( \%DynLDIF::DEBUG,
		{ general => 1, overlay => 1, detail => 0, cache => 0 }, 'debug 1');
	search_entries( $v, $SUFFIX);
	like( read_log( $dir), qr/^### SEARCH: ldapsearch/m, 'output when enabled');

	is( $v->config( 'debug', 'cache', 'Detail'), LDAP_SUCCESS);
	is_deeply( \%DynLDIF::DEBUG,
		{ general => 0, overlay => 0, detail => 1, cache => 1 },
		'list of categories replaces previous setting');

	is( $v->config( 'debug', 'all'), LDAP_SUCCESS);
	ok( !grep( { !$_} values %DynLDIF::DEBUG), 'all');

	is( $v->config( 'debug', 'none'), LDAP_SUCCESS);
	ok( !grep( { $_} values %DynLDIF::DEBUG), 'none');
	is( $v->config( 'debug', 'all'), LDAP_SUCCESS);
	is( $v->config( 'debug', 0), LDAP_SUCCESS);
	ok( !grep( { $_} values %DynLDIF::DEBUG), '0');

	is( $v->config( 'debug', 'general', 'bogus'), LDAP_PARAM_ERROR,
		'invalid category');
	warnings_like( qr/Invalid 'debug' value 'bogus'/);
	ok( !grep( { $_} values %DynLDIF::DEBUG), 'unchanged after error');
	no_warnings();
};

subtest 'overlays' => sub {
	my( $v, $dir)= new_dynldif([ @OVERLAYS ]);
	open my $fh, '>', "$dir/f.txt" or die;
	print $fh "from file\n";
	close $fh;
	my @specs= ( '$ exp $ cn', '$ file $ f.txt',
		"\$ find \$ $U 0 0 0 0 (objectClass=*) 0 uid", '$ perl $ 6*7');

	is_deeply( expand( $v, @specs), [ 't', 'from file', 'testuser', $specs[3] ],
		'perl disabled by default, others enabled');

	( $v, $dir)= new_dynldif([ @OVERLAYS, [ 'enablePerl', 1 ]]);
	is_deeply( expand( $v, '$ perl $ 6*7'), [ 42 ], 'enablePerl 1');
	is_deeply( expand( $v, q{$ perl $ die "boom\n"}, '$ perl $ 1 +', '$ perl $ @comps= (); 1',
		'$ perl $ 2'), [ 2 ], 'errors drop the value, internals are not visible');
	warnings_like( qr/^PerlEval: error in 'die "boom\\n"' \(boom\)$/, 'error reported');
	warnings_like( qr/^PerlEval: error in '1 \+' \(syntax error/);
	warnings_like( qr/^PerlEval: error in '\@comps= \(\); 1' \(Global symbol "\@comps"/,
		'(under strict)');

	for my $ovl( [ enableExp => 0 ], [ enableFile => 1 ], [ enableFind => 2 ]) {
		my( $switch, $i)= @$ovl;
		( $v, $dir)= new_dynldif([ @OVERLAYS, [ $switch, 0 ]]);
		is_deeply( expand( $v, $specs[$i]), [ $specs[$i] ], "$switch 0");
	}
	no_warnings();
};

subtest 'enableAppend' => sub {
	my @config= (
		[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ],
		[ 'entryAppend', 'objectClass', '^posixAccount$', '->',
			'append', '.+', "cn=defaults,ou=hosts,$SUFFIX" ],
	);
	my $defaults= "dn: cn=defaults,ou=hosts,$SUFFIX\nobjectClass: device\ncn: defaults\nl: Zagreb\n";
	for( [ 1, 'Zagreb' ], [ 0, undef ]) {
		my( $on, $expect)= @$_;
		my( $v)= new_dynldif([ @config, [ 'enableAppend', $on ]]);
		add_ok( $v, $defaults);
		my( $ret, @e)= search_entries( $v, $U, scope => 0);
		is( $e[0]->get_value( 'l'), $expect, "enableAppend $on");
	}
	no_warnings();
};

subtest 'enableCache' => sub {
	for( [ 1, 'v1' ], [ 0, 'v2' ]) {
		my( $on, $expect)= @$_;
		my( $v, $dir)= new_dynldif([ @OVERLAYS, [ 'enableCache', $on ]]);
		my $write= sub { open my $fh, '>', "$dir/c.txt" or die; print $fh "$_[0]\n"; close $fh };
		$write->( 'v1');
		expand( $v, '$ file cache 1000 $ c.txt');
		$write->( 'v2');
		my( $ret, @e)= search_entries( $v, $T, scope => 0);
		is( $e[0]->get_value( 'l'), $expect,
			"enableCache $on: ". ( $on ? 'cached value' : 'value re-read'));
	}
	no_warnings();
};

subtest 'enableRelocate' => sub {
	my @config= (
		[ 'addRelocate', 'Site', ',cn=\S+?,ou=', ',ou=defaults,ou=' ],
	);
	for( [ 0, "cn=k,cn=host1,ou=hosts,$SUFFIX" ],
			[ 1, "cn=k,ou=defaults,ou=hosts,$SUFFIX" ]) {
		my( $on, $expect)= @$_;
		my( $v)= new_dynldif([ @config, [ 'enableRelocate', $on ]]);
		add_ok( $v, "dn: ou=defaults,ou=hosts,$SUFFIX\nobjectClass: organizationalUnit\nou: defaults\n");
		add_ok( $v, "dn: cn=host1,ou=hosts,$SUFFIX\nobjectClass: device\ncn: host1\n");
		add_ok( $v, "dn: cn=k,cn=host1,ou=hosts,$SUFFIX\nobjectClass: device\ncn: k\n".
			"variables: dynldif_location=Site\n");
		my( $ret, $dns)= search_dns( $v, $SUFFIX, filter => '(cn=k)');
		is_deeply( $dns, [ $expect ], "enableRelocate $on");
	}
	no_warnings();
};

subtest 'enableStack and enableDump' => sub {
	my( $v, $dir)= new_dynldif();
	is( $v->config( 'save', 'stack1'), LDAP_SUCCESS);
	is( $v->config( 'saveDump', 'dump1'), LDAP_SUCCESS);
	ok( -e "$dir/tmp/stack1", 'save enabled by default');
	ok( -e "$dir/tmp/dump1", 'saveDump enabled by default');

	( $v, $dir)= new_dynldif([[ 'enableStack', 0 ], [ 'enableDump', 0 ]]);
	is( $v->config( 'save', 'stack1'), LDAP_SUCCESS);
	is( $v->config( 'saveDump', 'dump1'), LDAP_SUCCESS);
	ok( !-e "$dir/tmp/stack1", 'enableStack 0');
	ok( !-e "$dir/tmp/dump1", 'enableDump 0');
	no_warnings();
};

done_testing;
