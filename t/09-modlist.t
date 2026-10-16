#!/usr/bin/perl
# Parsing of the flat modification list that back-perl passes to modify()
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use DynLDIFTest;

my( $v)= new_dynldif( undef, empty => 1);
my( $vs)= new_dynldif([[ 'schemaLDIF', "$DATA_DIR/schema.ldif" ]], empty => 1);

sub parses {
	my( $dl, $list, $expect, $name)= @_;
	local $Test::Builder::Level= $Test::Builder::Level+ 1;
	is_deeply( $dl->parse_modlist( $list), $expect, $name);
}

subtest 'regular lists' => sub {
	parses( $v, [ qw/ADD description v/ ], [[ qw/ADD description v/ ]], 'one value');
	parses( $v, [ qw/ADD description v1 v2 REPLACE sn x DELETE l y/ ],
		[[ qw/ADD description v1 v2/ ], [ qw/REPLACE sn x/ ], [ qw/DELETE l y/ ]],
		'several modifications');
	parses( $v, [ 'DELETE', 'l', undef, 'REPLACE', 'sn', undef, 'ADD', 'title', 't' ],
		[[ qw/DELETE l/ ], [ qw/REPLACE sn/ ], [ qw/ADD title t/ ]],
		'undef marks no values');
	parses( $v, [ qw/ADD description;lang-en v/ ], [[ qw/ADD description;lang-en v/ ]],
		'attribute options');
	parses( $v, [ qw/ADD 2.5.4.13 v/ ], [[ qw/ADD 2.5.4.13 v/ ]], 'OID');
	parses( $v, [ qw/REPLACE sn/ ], [[ qw/REPLACE sn/ ]],
		'no values without undef (older back-perl)');
	parses( $v, [], [], 'empty list');
	no_warnings();
};

subtest 'values equal to action names' => sub {
	parses( $v, [ qw/ADD description ADD x/ ], [[ qw/ADD description ADD x/ ]],
		'first value is always a value');
	parses( $v, [ qw/ADD description x ADD/ ], [[ qw/ADD description x ADD/ ]],
		'last value');
	parses( $v, [ qw/ADD description x REPLACE/, 'two words' ],
		[[ 'ADD', 'description', 'x', 'REPLACE', 'two words' ]],
		'not followed by an attribute name');
	parses( $v, [ qw/ADD description x ADD y/ ],
		[[ qw/ADD description x ADD y/ ]],
		'would leave ADD without values');
	parses( $v, [ qw/ADD description x REPLACE DELETE/ ],
		[[ qw/ADD description x REPLACE DELETE/ ]],
		'action names are not attribute names');

	# This is what slapd passed for: replace l: DELETE, sn; add title: t
	parses( $v, [ qw/REPLACE l DELETE sn ADD title t/ ],
		[[ qw/REPLACE l DELETE sn/ ], [ qw/ADD title t/ ]],
		'value list followed by another modification');
	no_warnings();
};

subtest 'schema resolves remaining ambiguity' => sub {
	my $list= [ qw/ADD description x ADD nosuchattr y/ ];
	parses( $v, $list, [[ qw/ADD description x/ ], [ qw/ADD nosuchattr y/ ]],
		'without schema, a new modification is assumed');
	parses( $vs, $list, [[ qw/ADD description x ADD nosuchattr y/ ]],
		'with schema, unknown attribute means it is a value');
	parses( $vs, [ qw/ADD description x ADD sn y/ ],
		[[ qw/ADD description x/ ], [ qw/ADD sn y/ ]],
		'known attribute starts a new modification');
	no_warnings();
};

subtest 'invalid lists' => sub {
	is( $v->parse_modlist( [ qw/FOO description v/ ]), undef, 'unknown action');
	is( $v->parse_modlist( [ qw/ADD/ ]), undef, 'no attribute');
	is( $v->parse_modlist( [ qw/ADD description/ ]), undef, 'ADD without values');
	is( $v->parse_modlist( [ 'ADD', 'bad attr', 'v' ]), undef, 'bad attribute name');
	no_warnings();
};

subtest 'modify with such values' => sub {
	my( $v2)= new_dynldif();
	my $U= "uid=testuser,ou=users,$SUFFIX";
	is( $v2->modify( $U, 'REPLACE', 'description', 'ADD', 'REPLACE', 'DELETE'), 0);
	my( $ret, @e)= search_entries( $v2, $U, scope => 0);
	is_deeply( [ $e[0]->get_value( 'description') ], [ qw/ADD REPLACE DELETE/ ]);
	no_warnings();
};

done_testing;
