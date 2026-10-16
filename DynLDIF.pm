package DynLDIF;
# vim: se ts=2 sts=2 sw=2 ai
#
# DynLDIF -- Custom Perl backend for use with the OpenLDAP server.
#
# Davor Ocelic <docelic@crystallabs.io>
# Crystal Labs, https://crystallabs.io/
# Released under GPL v3.
#
# The DynLDIF backend implements regular LDAP functionality and can be used in
# general-purpose LDAP scenarios where you want quick results on a platform
# that comes with extra features (default entries, query rewriting, dynamic
# values, etc.), and also lends itself to further customization.
#
# Smallest working configuration can be seen in etc/ldap/slapd.conf.
#

use strict;
use warnings;
use IO::File            qw//;
use Data::Dumper        qw/Dumper/;
use File::Find::Rule    qw/find/;
use Net::LDAP::Constant qw/LDAP_SUCCESS LDAP_PARAM_ERROR LDAP_OPERATIONS_ERROR/;
use Net::LDAP::Constant qw/LDAP_ALREADY_EXISTS LDAP_NO_SUCH_OBJECT LDAP_OTHER/;
use Net::LDAP::Constant qw/LDAP_INVALID_SYNTAX LDAP_INVALID_DN_SYNTAX/;
use Net::LDAP::Constant qw/LDAP_NOT_ALLOWED_ON_NONLEAF LDAP_FILTER_ERROR/;
use Net::LDAP::Constant qw/LDAP_INVALID_CREDENTIALS LDAP_UNWILLING_TO_PERFORM/;
use Net::LDAP::Constant qw/LDAP_TIMELIMIT_EXCEEDED LDAP_SIZELIMIT_EXCEEDED/;
use Net::LDAP::Constant qw/LDAP_COMPARE_TRUE LDAP_COMPARE_FALSE/;
use Net::LDAP::Constant qw/LDAP_NO_SUCH_ATTRIBUTE LDAP_TYPE_OR_VALUE_EXISTS/;
use Net::LDAP::Constant qw/LDAP_NOT_ALLOWED_ON_RDN LDAP_NAMING_VIOLATION/;
use Net::LDAP::Constant qw/LDAP_OBJECT_CLASS_VIOLATION LDAP_PROTOCOL_ERROR/;
use Net::LDAP::Constant qw/LDAP_INSUFFICIENT_ACCESS/;
use Net::LDAP::LDIF     qw//;
use Net::LDAP::Schema   qw//;
use Net::LDAP::Filter   qw//;
# (Not 'qw//': import() selects the installed approximate matching modules)
use Net::LDAP::FilterMatch;
use Net::LDAP::Entry    qw//;
use Net::LDAP::Util     qw/escape_filter_value/;
use Storable            qw/freeze nstore retrieve/;
use Digest::SHA         qw/sha1 sha256 sha384 sha512/;
use Digest::MD5         qw/md5/;
use MIME::Base64        qw/decode_base64/;
use File::Path          qw/rmtree mkpath/;
use Fcntl               qw/:flock/;
use Net::LDAP           qw//;
use Text::CSV_XS        qw//;
use List::MoreUtils     qw/any all firstidx uniq/;
use Scalar::Util        qw/reftype/;

use subs                qw/p pd pc pcd po pod/;

# Evaluates code of the 'perl' overlay. (Defined here, before any lexical
# variables, so that the code can't see or change variables of DynLDIF.)
sub perl_eval { eval $_[0] }

# Debug output goes to STDERR (slapd's log; run slapd in foreground to see
# it, i.e. sudo -u openldap /usr/sbin/slapd -d 0). It is enabled with the
# 'debug' config directive. Being process-wide, it applies to all databases
# using this backend.
our %DEBUG= (
	general => 0, # General debug
	detail  => 0, # Detailed debug
	overlay => 0, # Overlays debug
	cache   => 0, # Cache debug
);
sub DEBUG()     { $DEBUG{general} }
sub DEBUG_DTL() { $DEBUG{detail} }
sub DEBUG_OVL() { $DEBUG{overlay} }
sub DEBUG_CCH() { $DEBUG{cache} }

# Search scope defines
use constant BASE     => 0;
use constant ONE      => 1;
use constant SUB      => 2;
use constant CHILDREN => 3;
our %SCOPE2NAME = (
	0 => "base",
	1 => "one",
	2 => "sub",
	3 => "children",
);

# Referral chasing
use constant NEVER    => 0;
use constant ALWAYS   => 1;
use constant SEARCH   => 2;
use constant FIND     => 3;
our %DEREF2NAME = (
	0 => "never",
	1 => "always",
	2 => "search",
	3 => "find",
);

# Raw/binary value regex
our $RAW              = qr/(?i:^jpegPhoto|;binary)/;

# LDAP scope to fs tree depth level
our %S2L= (
	1 => 1,     # ONE      (1 level)
	2 => undef, # SUB      (unlimited)
	3 => undef, # CHILDREN (unlimited)
);

# Overlays, in order of execution. Each runs on an entry if enabled
# ('enableFile', 'enableExp', 'enableFind', 'enablePerl'). Name here should
# match the name of overlay's config array (see sub new()'s $this object)
# and in turn it is also name by which overlay will be recognized by
# run_overlays() within attribute's values.
our @OVERLAYS= qw/file exp find perl/;

# Placeholder for filter components that are undefined (see filter_match())
our $UNDEFINED_ATTR= 'x-dynldif-undefined';

# Attributes whose values are always hidden in debug output
our @REDACT_ATTRS= qw/userPassword/;

# Necessary variables for Debconf interaction and server-side prompting.
#  cin/cout, tin/tout: config DB in/out pipe, templates DB in/out pipe, used
#   for initializing prompter's debconf state.
#  dc/dt/df/dm: references to debconf's config/templates/frontend/confmodule.
our ( $cin, $cout, $tin, $tout);
our ( $dc, $dt, $df, $dm);


# Keys of the instance (see new()) that hold internal state, and are not
# config directives
our %INTERNAL= map { $_=> 1} qw/schema tmpdir stack standard_parse level
	cache op_cache_valid start match_schema rule_cache expanding/;

# Backend instance
sub new {
	my( $class)= @_;

	p "NEW @_ ----------------------------------------";

	# Assign instance defaults. List all allowed options here,
	# even if their value is '' or 0. (Do not use undef if you expect to
	# set it from the config file, because it will implicitly make the
	# option invalid).
	# Scalars get values assigned, arrays pushed, hashes arrayref'd.
	my $this= {
		treesuffix     => q{},     # Suffix (too bad we're not called with it),
		                           # and 'suffix' directive can only be specified
		                           # before DynLDIF.pm module so we can't get that
		                           # one from slapd. We basically have to invent
		                           # a new directive and set it to the same value.
		directory      => q{},     # Base directory / datadir for tree. Can be
		                           # different for each suffix, but suffixes when
		                           # in the same directory can use each other's
		                           # fallback/default values etc.
		extension      => '.ldif', # Extension for leaf nodes (files). Can be set
		                           # to anything, but .ldif is usually most
		                           # reasonable. Note that you cannot go without
		                           # extension as that makes files and directories
		                           # indistinguishable, and breaks the server.

		addoverwrites  => 0,       # Allow ADD to overwrite existing entries?
		addignoredups  => 0,       # If overw=0, ignore ADD on existing entries?
		addrelocate    => {},      # name=>[$a,$b] for $name==loc && $dn=~ s/$a/$b/
		addprompt      => {},      # Run prompter under name, cfg->tpl=~ s/$a/$b/


		modifysmarts   => 1,       # Allow MODIFY to detect no-change
		modifycopyonwrite=> 1,     # Modify & copy dfl entry to new DN if !exist?

		deletetrees    => 0,       # DELETE allows deleting of non-leafs?

		searchsubst    => [],      # List of [...->...] search subst rules
		searchfallback => [],      # List of [$a,$b] for $dn or $dn=~ s/$a/$b/
		entryappend    => [],      # List of [$a,$t,$b,$p,$n] to append with attrs

		# All directives below are in form [ [$m, $nm], ... ], where $m and
		# $nm are regexes that attribute name must match and NOT match (respe-
		# ctively) for the overlay to execute on its values.
		perl           => [],      # Match/No-Match regex list for perleval
		'exp'          => [],      # Match/No-Match regex list for expandval
		file           => [],      # Match/No-Match regex list for fileval
		'find'         => [],      # Match/No-Match regex list for findval

		overlayconfig  => {},      # default overlay opts ('OVLNAME|default SPEC')

		schemaldif     => [],      # Schema in LDIF format (to be aware of schema).
		                           # To produce schema file, start server, then use
		                           # schema.pl to retrieve schema from server in
		                           # LDIF format and dump it to a file.
		schemafatal    => 0,       # Missing schema is fatal problem? (Allowed to be
		                           #  missing by default so that you can run server,
		                           #  get schema, save it and have it on next start)
		enablebind     => 0,       # Allow bind? Our implementation is minimal.

		# Features
		enableappend   => 1,       # Append entries with other entries' attrs
		enablefile     => 1,       # Value expansion by reading files
		enableexp      => 1,       # Value expansion by loading DN attrs
		enablefind     => 1,       # Re-searching and returning certain attrs
		enableperl     => 0,       # Perl evaluation of values (dangerous)
		enablecache    => 1,       # Honor cache options for overlay values
		enablerelocate => 0,       # Relocation of Debconf keys from client
		enableprompt   => 0,       # Server-side Debconf prompter
		enablestack    => 1,       # save/reset/load/clean config directives
		enabledump     => 1,       # savedump/loaddump config directives

		protectattrs   => 'userPassword', # Attrs not usable in filters/compare
		debug          => q{},     # Debug output (sets global %DEBUG)

		# Keys that control parsing behavior in slapd.conf and basically take
		# effect directly when encountered.

		message        => q{},     # Print message to console

		var            => {},      # Define a variable, var NAME "V A L"
		parse          => 1,       # Parse vars in following cfg lines (yes/no)

		clean          => q{},     # Clean temp/stack files in $directory/tmp/
		save           => q{},     # Save current cfg stack to named file
		'reset'        => q{},     # Clean cfg stack currently in memory
		load           => q{},     # Load cfg stack from a named file
		'savedump'     => q{},     # Storable dump to named file (for standalone)
		'loaddump'     => q{},     # Storable load from named file (for standalone)

		# Keys that will contain data generated on startup or during run

		schema         => undef,   # Will contain schema (load with 'schemaLDIF')
		tmpdir         => undef,   # $directory/tmp, hardcoded
		stack          => [],      # Current config stack, can 'save' or 'reset' it

		standard_parse => undef,   # Text::CSV_XS obj. for parsing various input
		level          => 0,       # Loop/depth count. Usually 1
		cache          => {},      # Cache for dn2leaf file reads & ldif parsing
		op_cache_valid => {},      # Num-ops cache validity (per-overlay)
		cacheread      => '',      # Num-ops cache validity (dn2leaf disk reads)

		'start'        => [],      # Time of search start (array ID= search level)
	};

	# Must be done here as schema parser already has to be present
	# during config parsing step.
	$this->{schema}= Net::LDAP::Schema->new;

	bless $this, $class
}


# Called after all configuration processing is over
sub init {
	my( $this)= @_;

	p "INIT @_ $this->{treesuffix}";

	# Let's do some checking.

	# Make sure 'extension' is non-empty. (As to why, read note on
	# 'extension' above).
	if( not $this->{extension}) {
		warn 'File extension for leaf nodes cannot be empty; ' .
			"set a value (such as '.ldif') and restart slapd.\n";
		return LDAP_PARAM_ERROR
	}

	# Now ensure that the root of the configured tree exists. To do that,
	# all we need to do is create the components on the way to final
	# component.

	my $dn= $this->{treesuffix};
	$this->normalize( \$dn);

	# Reduce DN to part of the path that needs to be there. Suffixes with
	# a single component (such as ou=defaults) have nothing leading up
	# to them.
	if( $dn=~ s/^.+?,//) {
		my( $ret, %ret);

		# Note: this return doesn't bail out on File not found because dn2leaf
		# is called with namesonly param, so no actual checking is done.
		$ret= $this->dn2leaf( "$dn", \%ret, qw/namesonly 1 leaf 0 writeop 1 create 1/);
		return $ret unless $ret== LDAP_SUCCESS;

		# Note: $dn=~ check is here to avoid the error message on
		# suffixes with two components (such as dc=example,dc=com)
		if( $dn=~ qr/,/o and not -e $ret{file}) {
			warn 'Components leading up to the tree suffix '.
			"for $this->{treesuffix} are missing; ".
				"create them and restart slapd.\n";
			return LDAP_OPERATIONS_ERROR
		}
	}

	## Now make symlinks for all virtual paths, unless present already.

	#my( $ret, %ret);

	## Figure out our basedir where symlinks are to be created
	## (dc=tmp is added here brutally like this so that $ret{directory} shows
	## the directory we want, not one level too low).
	#$ret= $this->dn2leaf( "dc=tmp,$this->{treesuffix}", \%ret, qw/namesonly 1/);
	#return $ret unless $ret== LDAP_SUCCESS;

	## XXX Error ckin
	#mkpath $ret{directory};

	#for my $virtual_line( @{ $this->{virtual}}) {
	#	for my $virtual( @$virtual_line) {
	#		$ret= $this->dn2leaf( "dc=tmp,$virtual", \%ret, qw/namesonly 1/);
	#		return $ret unless $ret== LDAP_SUCCESS;

	#		warn " VIRTUAL $virtual, PATH $ret{directory} / $ret{file}\n";
	#	}
	#}

	# Initialize schema obj. We do that in new(), but add ||= check here
	# for situations where DynLDIF is ran standalone using config dump from
	# file, where references to objects are of course lost.
	$this->{schema}||= new Net::LDAP::Schema;

	# Schema to use for matching values (filters, comparisons), if loaded.
	# Without it, values are compared case-insensitively.
	$this->{match_schema}= ( () = $this->{schema}->all_attributes) ?
		$this->{schema} : undef;
	$this->{rule_cache}= {}; # Matching rules of attributes (see leaf_match())

	# Debconf-related init code
	if( $this->{enableprompt}) {
		my $ret= $this->debconf_initialize;
		return $ret unless $ret== LDAP_SUCCESS;
	}

	# Initialize Text::CSV_XS parser suitable for generic use
	$this->{standard_parse}= Text::CSV_XS->new({
		# We better use default escape_char and not \ because it's VERY
		# confusing. (It's already too confusing that you DO have to write
		# \\ instead of just \ in slapd.conf, but you DO NOT do that when
		# a value is in LDIF source). So let's not add another layer of
		# confusion -- the default escape char (" - literal double quote)
		# probably works fine.
		#escape_char      => q{\\},
		sep_char         => q{ },
		binary           => 1,
		# Unfortunately, this option does not result in us being able to use
		# multiple spaces (probably due to sep_char also being whitespace).
		#allow_whitespace => 1,
	});

	LDAP_SUCCESS
}


# Called to verify bind credentials.
#
# Note that if rootdn and rootpw are set in slapd.conf, and you try to
# authenticate as rootdn, slapd will perform the password check itself,
# and will not call this function.
#
# Also, if you authenticate as a user belonging to some other part of DIT,
# that backend's bind() will be called, not this one.
#
# Also, if you authenticate via e.g. GSSAPI, this won't be called.
#
# Finally, due to limited implementation of this function, we default to
# simply not allowing it, unless allow_bind is enabled.
sub bind {
	my( $this, $dn, $pw)= @_;

	return LDAP_UNWILLING_TO_PERFORM unless $this->{enablebind};

	$this->setup_state( \@_);

	$this->normalize( \$dn);

	p "BIND $dn"; # Print bind DN only, don't show $pw in log.

	return LDAP_INVALID_DN_SYNTAX unless $this->valid_dn( $dn);

	# Only the entry itself counts, not fallbacks (which would allow binding
	# as any DN with a default entry's password) nor appended attributes.
	my( $ret, %ret);
	$ret= $this->dn2leaf( $dn, \%ret, qw/entry 1/);
	return LDAP_INVALID_CREDENTIALS unless $ret== LDAP_SUCCESS;
	my $entry= $ret{entry};

	my @pws= $entry->get_value( 'userPassword');

	# See if any userPassword (can be multi-value) matches
	# the provided password
	if( any{ $this->check_password( $pw, $_)} @pws) {
		return LDAP_SUCCESS
	}

	LDAP_INVALID_CREDENTIALS
}


# Check password against a userPassword value. The value is either plain
# text, or hashed with one of the schemes supported by slapd (see
# slappasswd(8)): {SSHA}, {SHA}, {SMD5}, {MD5}, {CRYPT}, {CLEARTEXT}, and
# {SHA256}/{SSHA256} etc. from the pw-sha2 module. Values with an unknown
# scheme never match.
my %DIGESTS= ( SHA=> \&sha1, SHA256=> \&sha256, SHA384=> \&sha384,
	SHA512=> \&sha512, MD5=> \&md5);

sub check_password {
	my( $this, $pw, $stored)= @_;

	# (An empty password is an unauthenticated bind, RFC 4513 5.1.2, which
	# slapd normally handles itself. It never matches here.)
	return 0 unless defined $pw and length $pw and defined $stored and length $stored;

	my( $scheme, $hash)= $stored=~ /^\{([^}]+)\}(.*)$/s
		or return _equal( $pw, $stored);
	$scheme= uc $scheme;

	return _equal( $pw, $hash) if $scheme eq 'CLEARTEXT';

	if( $scheme eq 'CRYPT') {
		my $crypted= crypt( $pw, $hash);
		return defined $crypted && _equal( $crypted, $hash)
	}

	my( $salted, $name)= $scheme=~ /^(S?)(SHA(?:256|384|512)?|MD5)$/ or return 0;
	my $digest= $DIGESTS{$name};
	my $len= length $digest->( '');
	my $raw= decode_base64( $hash);

	return 0 if length $raw< $len or ( !$salted and length $raw!= $len);
	my( $d, $salt)= ( substr( $raw, 0, $len), substr( $raw, $len));

	_equal( $digest->( $pw. $salt), $d)
}

# Constant-time string comparison
sub _equal {
	my( $a, $b)= @_;
	return 0 unless length $a== length $b;
	my $r= 0;
	$r|= ord( substr $a, $_, 1) ^ ord( substr $b, $_, 1) for 0.. length( $a)- 1;
	$r== 0
}


# Handle our config lines. Called by slapd for each directive.
sub config {
		my( $this, $key, @val)= @_;

		$key= lc $key;

		p "CONFIG $key @val";

		# Support config file to specify longer names of config options for
		# clarity. Internally, we use short names. I.e. a config line of 
		# "expandval opt1 opt2" is translated to "exp" internally.
		# (But you can also specify 'exp' directly (or anything in between)).
		if( !defined $this->{$key} or $INTERNAL{$key}) {
			my @keys;
			for my $cfgkey( grep { !$INTERNAL{$_}} keys %$this) {
				push @keys, $cfgkey if $key=~ /^\Q$cfgkey/
			}
			if( @keys== 1) { # Great, uniquely found the right key
				p "Resolved config key '$key' to '$keys[0]'";
				$key= $keys[0];

			} elsif( @keys> 1) {
				warn "Ambiguous config directive '$key' (@keys)\n";
				return LDAP_PARAM_ERROR

			} else { #elsif( @keys== 0) {
				warn "Unknown config directive '$key'\n";
				return LDAP_PARAM_ERROR
			}
		}

		# Push config line, barely processed, to the config stack
		# (Note: but not if it's one of the save/load/reset/etc commands).
		push @{ $this->{stack}}, [ $key, @val] if
			$key ne 'save' and $key ne 'reset' and $key ne 'load' and
				$key!~ qr/dump$/o;

		# Apply generic changes/replacements we do for every line and
		# field. (Basically just a series of convenience helpers).
		for( @val) {

			# Parse/expand variables if parsing currently enabled.
			# ${var} expands to variables, %{directive} to values of
			# scalar config directives.
			if( $this->{parse}) {
				s/\$\{(\S+?)\}/$this->expand_var( $1)/ge;
				s/\%\{(\S+?)\}/$this->expand_directive( $1)/ge;
			}
		}

		# Very simple: if we know about this key, allow it. If not, throw a fit.
		unless( defined $this->{$key}) {
			return LDAP_PARAM_ERROR
		}

		# Directives that work with files in $directory/tmp/
		if( !$this->{tmpdir} and (
				( $key=~ /^(?:save|load)$/ and $this->{enablestack}) or
				( $key=~ /^(?:savedump|loaddump)$/ and $this->{enabledump}))) {
			warn "Called '$key' before 'directory' has been set\n";
			return LDAP_OPERATIONS_ERROR
		}

		# Regexes are compiled here, so that invalid ones are reported now,
		# and not when they are used
		for my $re( $this->config_regexes( $key, @val)) {
			next if eval { qr/$re/; 1 };
			( my $err= $@)=~ s/ at \S+ line \d+.*//s;
			warn "Invalid regex '$re' in '$key' ($err)\n";
			return LDAP_PARAM_ERROR
		}

		# Now handle config directives that call for immediate work as soon
		# as they're encountered:

		if( $key eq 'message') {                    # MESSAGE
			warn 'Message: ', join( ' ', @val), "\n"

		} elsif( $key eq 'debug') {                 # DEBUG OUTPUT
			# debug [general] [detail] [overlay] [cache] | all | 1 | none | 0
			my %set= map { $_=> 0} keys %DEBUG;
			for my $word( map { lc} @val) {
				if( $word eq 'all') {
					$set{$_}= 1 for keys %set
				} elsif( $word eq '1') {
					@set{qw/general overlay/}= ( 1, 1)
				} elsif( exists $set{$word}) {
					$set{$word}= 1
				} elsif( $word ne 'none' and $word ne '0') {
					warn "Invalid 'debug' value '$word'; expected one or more of ".
						join( ', ', sort( keys %set), qw/all 1 none 0/). "\n";
					return LDAP_PARAM_ERROR
				}
			}
			%DEBUG= %set;

		} elsif( $key eq 'entryappend' or $key eq 'searchsubst') { # RULES
			# Rules are in form "ATTR PATTERN ... -> ...". Without a valid
			# '->' marker, rule processing would loop forever.
			my $arrow= firstidx { $_ eq '->'} @val;
			if( $arrow< 2 or $arrow % 2 or $arrow== $#val) {
				warn "Invalid '$key' rule '@val'; expected ".
					"'ATTR PATTERN [ATTR PATTERN ...] -> ...'\n";
				return LDAP_PARAM_ERROR
			}

		} elsif( $key eq 'schemaldif') {            # SCHEMA LDIF
			my $schema= $this->{schema};

			for( @val) {
				p "Parsing schema file '$_'";

				unless( $schema->parse( $_)) {
					my $error= $schema->error;
					warn "Error parsing schema '$_' ($error)\n";

					return LDAP_OPERATIONS_ERROR if $this->{schemafatal}
				}
			}

		} elsif( $key eq 'var') {                   # SET VARIABLE
			for( my $i= 0; $i< @val; $i+= 2) {
				$this->{var}{$val[$i]}= [ $val[$i+1]];
			}

		} elsif( $key eq 'cacheread') {             # DISKREAD CACHE
			return LDAP_PARAM_ERROR if $val[0] and
				!defined $this->parse_cache_opt( 'read', $val[0]);

		} elsif( $key eq 'reset' and $this->{enablestack}) {   # RESET STACK
			$this->{stack}= undef

		} elsif( $key eq 'save' and $this->{enablestack}) {    # SAVE STACK
			for( @val) {
				s/[^\w\.]//g; # allow only [\w\.]+ in filename
				s/^\.//; # delete all '.' prefix on the filename

				# XXX idea: generic write routine that knows how to write
				# plain file, entry, and ldif
				my $ret= $this->write_file(
					$this->{tmpdir}, $_, Dumper $this->{stack});
				return $ret unless $ret== LDAP_SUCCESS;
			}

		} elsif( $key eq 'load' and $this->{enablestack}) {    # LOAD STACK

			# In load specification, the first argument is the filename. The rest,
			# if present, is a list of PATTERN REPLACEMENT to perform
			# on each stored line before sending it to the config processor.
			local $_= shift @val;
			my $orig_fn= $_;

			s/[^\w\.]//g; # allow only [\w\.]+ in filename
			s/^\.//; # delete all '.' prefix on the filename

			if( $orig_fn ne $_) {
				p "Stack load filename sanitized to '$_'";
			}

			# Evaluate Dumper data that we read in
			my $edata;
			{
				use vars qw/$VAR1/;
				my( $ret, @data)= $this->read_file( $this->{tmpdir}, $_);
				return $ret unless $ret== LDAP_SUCCESS;

				my $data= join q{}, @data;
				$edata= eval $data;

				if( $@) {
					warn "Error loading stack file '$_' ($@)\n";
					return LDAP_OPERATIONS_ERROR
				}
			}

			if( defined $edata) {
					if( ref $edata ne 'ARRAY') {
					warn "Loaded stack file '$_', but it's not an arrayref!\n";
					return LDAP_OPERATIONS_ERROR
				}

				# List of substitutions to perform on each line and each
				# argument before sending everything to the config processor.
				my %substs= @val;

				# Now send line by line to the config routine
				for my $line( @$edata) {

					# Perform any substs specified as 'load FILE PAT REPL...':
					for my $arg( @$line) {
						while( my( $p, $r)= each %substs) {
							$arg=~ s/$p/$r/g;
						}
					}

					my $ret= $this->config( @$line);
					unless( $ret== LDAP_SUCCESS) {
						warn "Error in line '@$line' of stack file '$_'\n";
						return $ret
					}
				}
			} else {
				warn "Empty stack file '$_'. Configuration mistake?\n"
			}

		} elsif( $key eq 'clean' and $this->{enablestack}) {   # DELETE OLD STACK FILES

			unless( $this->{tmpdir}) {
				warn "Called 'clean' before 'directory' has been set\n";
				return LDAP_OPERATIONS_ERROR
			}
			
			my $glob= join '/', $this->{tmpdir}, '*';
			for my $file( glob $glob) {
				p "Unlinking tmp stack file '$file'";
				unless( unlink $file) {
					warn "Can't unlink tmp stack file '$file' ($!)\n";
					return LDAP_OPERATIONS_ERROR
				}
			}

		} elsif( $key eq 'savedump' and $this->{enabledump}) { # SAVE DUMP
			my $file= "$this->{tmpdir}/$val[0]";
			unless( eval { nstore $this, $file }) {
				( my $err= $@)=~ s/ at \S+ line \d+.*//s;
				warn "Can't save dump '$file' ($err)\n";
				return LDAP_OPERATIONS_ERROR
			}

		} elsif( $key eq 'loaddump' and $this->{enabledump}) { # LOAD DUMP
			my $file= "$this->{tmpdir}/$val[0]";
			my $dump= eval { retrieve $file };
			unless( ref $dump eq ref $this) {
				( my $err= $@ || 'not a dump')=~ s/ at \S+ line \d+.*//s;
				warn "Can't load dump '$file' ($err)\n";
				return LDAP_OPERATIONS_ERROR
			}

			# Load all keys into $this and effectively restore state
			%$this= %$dump;
		}

		# Now generic, regular handling of the config keys:

		# NOTE: this will happen for "dynamic" options as well (i.e.
		# reset/load/save/message etc.), which don't have any benefit from
		# that processing. But we don't particularly care about that; we still
		# do it, and we just have a side-effect that we remember the name of
		# last saved/loaded stack, message printed etc. This might even show
		# handy once in the future.

		# If key is defined as arrayref, push [a, b, ...] onto it;
		# If key is defined as hashref, do name= [a, b, ...];
		# Otherwise, perform regular scalar assignment.
		if( ref $this->{$key} eq 'ARRAY') {
			push @{ $this->{$key}}, [ @val]

		} elsif( ref $this->{$key} eq 'HASH') {
			my $locname= shift @val;
			$this->{$key}{$locname}= [ @val];

		} else {
			$this->{$key}= join ' ', @val
		}

		# Now post-handling of options:

		# When directory is defined, create tmp/ inside of it to use
		# as a temporary directory store for save/load commands.
		if( $key eq 'directory') {
			$this->{tmpdir}= join '/', $this->{directory}, 'tmp';

			if( ! -e $this->{tmpdir} or ! -d $this->{tmpdir}) {
				# (mkpath dies on errors)
				unless( eval { mkpath $this->{tmpdir}; 1 } and -d $this->{tmpdir}) {
					( my $err= $@ || $!)=~ s/ at \S+ line \d+.*//s;
					warn "Can't mkdir '$this->{tmpdir}' ($err)\n";
					return LDAP_OPERATIONS_ERROR
				}
			}
		}

		LDAP_SUCCESS
}

# Value of ${NAME} in config lines (see 'var')
sub expand_var {
	my( $this, $name)= @_;
	my $value= $this->{var}{$name};
	return $value->[0] if $value and defined $value->[0];
	warn "Undefined variable '\${$name}'\n";
	q{}
}

# Value of %{NAME} in config lines (a scalar config directive)
sub expand_directive {
	my( $this, $name)= @_;
	my $value= $this->{ lc $name};
	return $value if defined $value and !ref $value;
	warn "Unknown directive '%{$name}' (or not a single value)\n";
	q{}
}

# Regexes in a config line
sub config_regexes {
	my( $this, $key, @val)= @_;

	return $val[0] if $key eq 'searchfallback';
	return $val[1] if $key eq 'addrelocate';
	return @val[ grep { $_ % 2} 1.. $#val] if $key eq 'load'; # FILE PATTERN REPLACEMENT...
	return @val[ grep { $_ % 2} 1.. $#val] if $key eq 'load'; # PATTERN REPLACEMENT ...
	return @val[0, 1] if $key eq 'addprompt';
	return grep { defined} @val[0, 1] if $key=~ /^(?:exp|file|find|perl)$/;

	if( $key eq 'entryappend' or $key eq 'searchsubst') {
		my $arrow= firstidx { $_ eq '->'} @val;
		return () if $arrow< 0; # (Invalid rules are reported in config())
		my @re= @val[ grep { $_ % 2} 0.. $arrow- 1]; # Conditions
		my @action= @val[ $arrow+ 1.. $#val];
		if( $key eq 'searchsubst') {
			# KEY PATTERN REPLACEMENT ..., with $[N][M] references to captures
			push @re, map { s/(?<!\\)\$\[\d+\]\[\d+\]/x/gr }
				@action[ grep { $_ % 3== 1} 0.. $#action];
		} elsif( @action and $action[0] eq 'append') {
			push @re, $action[1];
		}
		return grep { defined} @re
	}

	()
}


# Adding entries
sub add {
	my( $this, $ldif)= @_;

	my( $ret, $entry)= $this->ldif2e( \$ldif);
	return $ret unless $ret== LDAP_SUCCESS;
	return LDAP_PROTOCOL_ERROR unless $entry;

	#
	# LDIF now as ENTRY, do any changes
	#

	# Normalize DN
	$this->normalize( $entry);

	#
	# Save ENTRY
	#

	my $dn= $entry->dn;

	DEBUG and p "ADD '$dn':\n". $this->redact_ldif( $ldif);

	# Entry must have an objectClass and contain its RDN value
	unless( $this->valid_dn( $dn)) {
		warn "ADD Invalid or non-normalized DN '$dn'\n";
		return LDAP_INVALID_DN_SYNTAX
	}
	return LDAP_OBJECT_CLASS_VIOLATION unless $entry->exists( 'objectClass');
	return LDAP_NAMING_VIOLATION unless $this->has_rdn_value( $entry, $dn);
	return LDAP_TYPE_OR_VALUE_EXISTS
		if any { $this->has_duplicates( $_, $entry->get_value( $_))} $entry->attributes;

	$ret= $this->save( $dn, $entry);
	return $ret unless $ret== LDAP_SUCCESS;

	#
	# See if there's work for relocator.
	#

	if( $this->{enablerelocate}) {
		$ret= $this->check_relocation( $entry);
		return $ret unless $ret== LDAP_SUCCESS;
	}

	#
	# See if there's work for server-side prompter.
	#

	if( $this->{enableprompt}) {
		$ret= $this->check_prompter( $entry);
		return $ret unless $ret== LDAP_SUCCESS;
	}

	LDAP_SUCCESS
}


# Searching for entries
sub search {
	my $this= shift;

	$this->setup_state( \@_);

	my( %req, @attrs); 
	( @req{qw/base scope deref size time filter attrOnly/}, @attrs)=@_;

	# Explanation of input parameters:
	#
	# BASE search base
	# SCOPE (0-3) base, one, sub, children
	#   base: just the one
	#   one: 1-level sub, no base
	#   sub: base + sub
	#   children: sub, no base
	# DEREF (0-3) never, always, search, find
	#   search: only on search
	#   find: only the base object
	# TIMELIMIT: secs, 0 - unlimited, max - max
	# SIZELIMIT: nr. entries limit. 0 -unlimited, max - max
	# FILTER: dfl (objectClass=*)
	# ATTRONLY - attributes only, no values
	# @ATTRS list of attrs to return, special: */null= all, += operational

	# slapd passes -1 for no limit (i.e. for rootdn), clients may send 0.
	# (Then the limit is 'none' for display, and infinite for comparisons.)
	my %limit;
	for my $limit( qw/size time/) {
		no warnings 'numeric';
		if( !$req{$limit} or $req{$limit} eq 'max' or $req{$limit}< 0) {
			$req{$limit}= 9**9**9;
			$limit{$limit}= 'none';
		} else {
			$limit{$limit}= $req{$limit};
		}
	}

	p '-' x 78;
	my $search = qq|ldapsearch -x -b '$req{base}' -s $SCOPE2NAME{$req{scope}} -a $DEREF2NAME{$req{deref}} -z $limit{size} -l $limit{time} '$req{filter}' @attrs|;
	DEBUG and p "SEARCH: ". $this->redact_filter( $search);

	# Normalize base DN
	$this->normalize( \$req{base});

	#
	# Let's see if we have to do any substitution on input params. SearchSubst
	# allows one to match arbitrary parameters of the search request, and if
	# all of them satisfy, then perform arbitrary substitutions on the params.
	#

	my( $id, $i, $ok, $k, $v, $r, @stack)= ( 0);
	for my $rule( @{ $this->{searchsubst}}) {
		$id++;

		( $i, $ok, $k, $v, $r)= ( 0, 1, undef, undef, undef); # Clear vars
		$#stack= -1; # Clear stack

		# Phase 1: see if all subst conditions match
		do {
			# (Rule syntax is validated in config())
			( $k, $v)= ( $$rule[$i], $$rule[$i+1]);

			# If rule matches, save eventual matches to @stack
			if( $req{$k}=~ /$v/) {
				push @stack, [ $1, $2, $3, $4, $5, $6, $7, $8, $9];

			} else {
				DEBUG_DTL and pd "SEARCH SUBST #$id skipped ($k!~ /$v/)";
				$ok= 0;
			}

		} while( $ok and $i+= 2 and $$rule[$i] ne '->');

		next if !$ok; # if this rule doesn't match, search further

		# Phase 2: now we know all conditions matched, so perform actual substs
		pd "SEARCH SUBST #$id matched '@$rule'";
		$i++; # Skip the '->' marker

		do {
			( $k, $v, $r)= ( $$rule[$i], $$rule[$i+1], $$rule[$i+2]);
			# (Captured values come from the request, so they are inserted into
			# the pattern literally)
			$v=~ s{(?<!\\)\$\[(\d+)\]\[(\d+)\]}{quotemeta( $stack[$1][$2] // q{})}ge;
			$r=~ s{(?<!\\)\$\[(\d+)\]\[(\d+)\]}{$stack[$1][$2] // q{}}ge;

			$req{$k}=~ s/$v/$r/; # <- substs performed here (XXX /g needed?)

			DEBUG_DTL and pd "SEARCH SUBST #$id action $k=~ s/$v/$r/ RESULT ".
				$this->redact_filter( $req{$k});

		} while(
			$i+= 3
			and defined $$rule[$i]
			and defined $$rule[$i+1]
			and defined $$rule[$i+2]
		);
	}

	# Now, continue search as normal as if nothing ever happened

	DEBUG && do {
		my $rewrtn = qq|ldapsearch -x -b '$req{base}' -s $SCOPE2NAME{$req{scope}} -a $DEREF2NAME{$req{deref}} -z $limit{size} -l $limit{time} '$req{filter}' @attrs|;
		p "REWRTN: ". $this->redact_filter( $rewrtn) if $search ne $rewrtn;
	};

	# Save original requested base. (Need to have it, unmodified, for proper
	# expansion of "." (dots) in DN specifications). Note that this is the
	# base AFTER rewriting.
	$req{origbase}= $req{base};

	# We were letting OpenLDAP handle filtering with filterSearchResults
	# directive, but that wasn't optimal because we weren't able to modify
	# search filter. Now we do filtering ourselves and we can do
	# anything we want anywhere we want (with filter and all other search
	# params), producing only final results for passing back onto slapd.
	# slapd passes filter components that are undefined (i.e. invalid
	# assertion value for the attribute's syntax) or computed as (?...).
	# Undefined ones are evaluated as Undefined by filter_match().
	( my $filterstr= $req{filter})=~ s/\(\?=true\)/(objectClass=*)/g;
	$filterstr=~ s/\(\?=false\)/(!(objectClass=*))/g;
	$filterstr=~ s/\(\?[^()]*\)/($UNDEFINED_ATTR=*)/g;

	my $filter;
	unless( $filter= Net::LDAP::Filter->new( $filterstr)) {
		warn "Invalid filter '$req{filter}'\n";
		$this->{level}-= 1;
		return LDAP_FILTER_ERROR
	}
	$filter= decode_utf8_deep( $filter); # (Once, see filter_match())

	my @matches= ();

	my( $ret, $newbase, %ret);
	my( $ldif, $entry);

	# slapd expects results in LDIF, but our internal subinvocations basically
	# always want entry results, not LDIF. So, in a direct call from slapd,
	# $as_ldif will be true, otherwise false (implying we want entry objects).
	my $as_ldif= $this->{level}== 0? 1: 0;

	# First entry is always the base, if -s base or -s sub was specified
	# for search scope.
	if( $req{scope}== BASE or $req{scope}== SUB) {

		# origdn is the original DN, which will be used for "." (dots" expansion
		# in DN specs (i.e. cn=abc...)
		( $ret, $newbase, $ldif, $entry)=
			$this->load( $req{base}, qw/entry 1 ldif 1/, 'origdn', $req{origbase});
		if( $ret!= LDAP_SUCCESS) { $this->{level}-= 1; return $ret }

		# If original search base was found, this is a no-op. Otherwise
		# $newbase is some fallback base found and we "switch" to it.
		$req{base}= $newbase;

		# We unshift because on return from Perl to ldap, data is read
		# in reverse order.
		if( $this->filter_match( $filter, $entry, $as_ldif)) {
			DEBUG and p "SEARCH ($this->{level}) MATCH:", $entry->dn;
			unshift @matches, $as_ldif? $ldif: $entry;
		}

		my $time= time;
		goto TIME_LIMIT if any{ $time- $_> $req{time}} @{ $this->{start}}
	}

	# Further entries may follow unless only base was specifically
	# requested with -s base
	if( $req{scope}!= BASE){
		my $level= 0;

		# For scopes which do not include the base entry itself, make sure
		# that the base exists (directly or via fallback) before listing
		# its children.
		if( $req{scope}!= SUB) {
			( $ret, $req{base})= $this->resolve( $req{base}, \%ret, qw/entry 1/);
			if( $ret!= LDAP_SUCCESS) { $this->{level}-= 1; return $ret }
		}

		( $ret, $req{base})= $this->resolve( $req{base}, \%ret, qw/leaf 0/);
		if( $ret!= LDAP_SUCCESS) { $this->{level}-= 1; return $ret }

		my $dir= $ret{directory};
		my $md= $S2L{$req{scope}};

		# Use File::Find::Rule to traverse the directory tree selectively
		# and scoop out what we want. When a limit is exceeded, the traversal
		# is ended with die(). (Without no_chdir, that would leave the process
		# in some directory of the tree.)
		my $limit; # Limit exceeded (result code)
		eval {
			File::Find::Rule->file()
				->name( qr/\Q$this->{extension}\E\z/) # (Full paths, see no_chdir)
				->extras({ follow => 1, no_chdir => 1})
				->readable
				->exec( sub{
						# Note that here we don't pass origdn onto load(). If a specific
						# search base is known and requested, we take that as origdn
						# (such as shown above). But if we go into tree subsearch,
						# then each time we use DN of the entry found (treating it
						# as a specific search base).
						( $ret, undef, $ldif, $entry)= $this->load(
							$_[2], qw/dnasfile 1/);

						return 0 unless $ret== LDAP_SUCCESS;
						if( $this->filter_match( $filter, $entry, $as_ldif)) {
							# Size limit is exceeded only when there's a match beyond it
							if( @matches>= $req{size}) {
								$limit= LDAP_SIZELIMIT_EXCEEDED;
								die "limit\n"
							}

							DEBUG and p "SEARCH ($this->{level}) MATCH:", $entry->dn;
							unshift @matches, $as_ldif? $ldif: $entry;
						}

						my $time= time;
						if( any{ $time- $_> $req{time}} @{ $this->{start}}) {
							$limit= LDAP_TIMELIMIT_EXCEEDED;
							die "limit\n"
						}
						0 # (Files are not collected)
				} )
				->maxdepth( $md)
				->in( $dir);
			1
		} or do {
			die $@ unless $limit and $@ eq "limit\n";
			goto TIME_LIMIT if $limit== LDAP_TIMELIMIT_EXCEEDED;
			goto SIZE_LIMIT
		};
	}

	$ret= LDAP_SUCCESS;
	goto SEARCH_DONE;

	TIME_LIMIT:
	$ret= LDAP_TIMELIMIT_EXCEEDED;
	goto SEARCH_DONE;

	SIZE_LIMIT:
	$ret= LDAP_SIZELIMIT_EXCEEDED;

	SEARCH_DONE:

	my ( $level, $start)= ( $this->{level}, $this->{start}[ $this->{level}]);

	p "SEARCH ($this->{level}) TOTAL:", scalar @matches, 'matches ('.
		"time=". ( time- $start). "/$limit{time}, ".
		"size=". ( scalar @matches). "/$limit{size})";

	$this->{level}-= 1;

	# $ret will be 0 (LDAP_SUCCESS) if no limits were hit.
	( $ret, @matches)
}


# Modifying existing entries
sub modify {
	my( $this, $dn, @list)= @_;
	my $ldif;

	$this->setup_state( \@_);

	# Normalize DN
	my $odn= $dn;
	$this->normalize( \$dn);

	my( $ret, $newdn, %ret, $fh, $entry, $orig);

	# Load existing entry. In the beginning, this was done with load() so
	# that all dynamic work is honored. However, that approach has a problem:
	# entry is appended with attributes from the default entry (if any), then
	# modified and saved back to disk. So if you had an entry with 5
	# regular and 10 appended attributes, and you modify one of those 5, you
	# end up with that one modified, and the other 10 copied and added without
	# your control (instead of having them kept away in the default entry).
	# So what we do now is:
	# - load with resolve() which does not expand or run overlays
	# - modify entries
	# - save back to disk.
	# If it happens that a person modifies one of the attributes that came
	# in via append, we open another copy of the entry (entry2), this time with
	# load(), import the missing value from it (for absolute transparency),
	# and then let modify continue. In that case, the modified attribute
	# would end up in the original entry, copied over and then modified.

	( $ret, $newdn)= $this->resolve( $dn, \%ret, 'entry', 1);
	return $ret unless $ret== LDAP_SUCCESS;

	( $entry, $fh)= @ret{qw/entry fh/};

	# Entry from a fallback (to be copied to $dn if modified) gets its own
	# RDN value in place of the fallback's
	if( $newdn ne $dn) {
		for( $this->rdn_avas( $newdn)) {
			my( $fattr, $fval)= @$_;
			my @keep= $this->values_except( $entry, $fattr, $fval);
			if( @keep) { $entry->replace( $fattr=> [ @keep]) }
			else       { $entry->delete( $fattr) }
		}

		# (Values as given, in original case)
		for( $this->rdn_avas( $odn)) {
			my( $attr, $val)= @$_;
			$entry->add( $attr=> $val) unless
				$this->has_rdn_value( $entry, "$attr=". escape_dn_value( $val));
		}
	}

	$orig= $entry->clone; # For comparison when modifysmarts==1

	# Indicator whether we opened another copy of the entry with load()
	# and placed it in $entry2.
	my $loaded= 0;
	my $entry2;

	my $mods= $this->parse_modlist( \@list);
	unless( $mods) {
		warn "MODIFY: invalid modification list for '$dn'\n";
		return LDAP_OTHER
	}
	DEBUG and p "MODIFY '$dn': ". $this->redact_mods( $mods);

	# Perform changes on the in-memory entry
	for my $mod( @$mods) {
		# A key with no values (only undef) gets deleted due to the
		# if( scalar @values) check below.
		my( $action, $key, @values)= @$mod;

		$action= lc $action;
		next unless $key;

		# Make sure that the attr we will operate on exists in the
		# entry. Actually, if it's not there, we just try to load it
		# from $entry2 and continue (it's still possible that it won't
		# exist even after that). No error checking is done here, as
		# that'll be handled by the actual modification routine below.
		if( scalar @values and !$entry->exists( $key)) {
			# If we didn't load() yet, do it now. We don't want to open
			# every entry twice unless there's a real need to operate
			# on entry2.
			if( !$loaded) {
				( $ret, undef, undef, $entry2)= $this->load( $dn, qw/entry 1/);
				return $ret unless $ret== LDAP_SUCCESS;
				$loaded= 1;
			}

			# Now, if the attribute does exist in $entry2, it means it's
			# one of the appended attributes, so we add it to $entry, and
			# the actual modification routine below can operate on it
			# flawlessly.
			# We also don't need to worry that get_value() will return an
			# empty list because we have the exists() check.
			if( $entry2->exists( $key)) {
				$entry->add( $key=> [ $entry2->get_value( $key)]);
			}
		}

		# Values in the request must be distinct
		if( $action ne 'delete' and $this->has_duplicates( $key, @values)) {
			p "MODIFY: duplicate values of '$key' for '$dn'";
			return LDAP_TYPE_OR_VALUE_EXISTS
		}

		if( $action eq 'add') {
			# Values must not exist already
			for my $value( @values) {
				if( $this->matching_values( $key, $value, $entry->get_value( $key))) {
					p "MODIFY: value of '$key' exists in '$dn'";
					return LDAP_TYPE_OR_VALUE_EXISTS
				}
			}
			$entry->add( $key=> [ @values]);

		} elsif( $action eq 'delete') {
			# Attribute, and values if given, must exist
			return LDAP_NO_SUCH_ATTRIBUTE unless $entry->exists( $key);

			my @current;
			if( @values) {
				@current= $entry->get_value( $key);
				for my $value( @values) {
					my %idx= map { $_=> 1} $this->matching_values( $key, $value, @current);
					return LDAP_NO_SUCH_ATTRIBUTE unless %idx;
					@current= @current[ grep { !$idx{$_}} 0.. $#current];
				}
			}
			if( @current) { $entry->replace( $key=> [ @current]) }
			else          { $entry->delete( $key) }

		} else { # replace (no values deletes the attribute)
			if( @values) { $entry->replace( $key=> [ @values]) }
			else         { $entry->delete( $key) }
		}
	}

	# objectClass can't be removed
	return LDAP_OBJECT_CLASS_VIOLATION unless $entry->exists( 'objectClass');

	# RDN value can't be removed
	if( $this->has_rdn_value( $orig, $dn) and !$this->has_rdn_value( $entry, $dn)) {
		p "MODIFY: can't remove RDN value of '$dn'";
		return LDAP_NOT_ALLOWED_ON_RDN
	}

	# Changes to the in-memory entry have been performed correctly.
	# We can now remove the old entry and create a new one.
	# NOTE: we do NO-OP if modifysmarts==1 and entry is the same after
	# change. (Debconf submits MODIFY lines for every requested key even
	# if no values actually changed in it, so detecting this is great).
	my $changed= 1;

	# For comparison, set DN of old and new entry to be equal as that is not
	# the point of difference we care about.
	# (Entry stays with $dn, since that is also where it'll be saved, even
	# if it was loaded from a fallback.)
	$entry->dn( $dn);
	$orig->dn( $dn);
	$changed= 0 if $this->{modifysmarts} and $this->dequal( $entry, $orig);

	# If changed (true if we have (1) any request, or (2) modifySmarts== 1
	# and real change has been detected.)
	if( $changed) {

		# If entry existed already, no probs.
		# But if it is changed and does not exist (i.e. it comes from a fallback)
		# then we look up config option modifyCopyOnWrite. When 1, modification
		# is performed and entry is saved to where it belongs (we create&modify it)
		# However, if modifyCopyOnWrite is 0, we return LDAP_NO_SUCH_OBJECT.
		if( $newdn ne $dn) {
			if( $this->{modifycopyonwrite}) {
				p "MODIFY AND COPY '$newdn' to '$dn'"
			} else {
				p "MODIFY WON'T WORK ON FALLBACK NOR CREATE '$dn' ".
					'(modifyCopyOnWrite == OFF)';
				return LDAP_NO_SUCH_OBJECT
			}
		}

		$ret= $this->save( $dn, $entry, qw/overwrite 1 modify 1/);
		return $ret unless $ret== LDAP_SUCCESS;
	}

	$this->{level}-= 1;

	LDAP_SUCCESS
}


# Indices of @values that are equal to $assertion, according to the
# equality matching rule of $attr (case-insensitive without schema)
sub matching_values {
	my( $this, $attr, $assertion, @values)= @_;

	# (Matching rules are those of the attribute type, without options)
	( my $type= $attr)=~ s/;.*//;
	my $filter= Net::LDAP::Filter->new(
		"($type=". escape_filter_value( $assertion). ')') or return;

	grep {
		my $e= Net::LDAP::Entry->new( 'cn=x', $type=> $values[$_]);
		$filter->match( $e, $this->{match_schema})
	} 0.. $#values
}

# Whether some of @values are equal, according to the equality matching
# rule of $attr
sub has_duplicates {
	my( $this, $attr, @values)= @_;

	# Values are first grouped by a key that is the same for values equal
	# by any of the matching rules (case, spaces and hyphens, and leading
	# zeros don't matter), and only values within a group are compared.
	my %groups;
	for( @values) {
		( my $k= lc)=~ s/[\s-]+//g;
		$k=~ s/(?<!\d)0+(?=\d)//g;
		push @{ $groups{$k}}, $_;
	}
	for my $group( grep { @$_> 1} values %groups) {
		for my $i( 0.. $#$group- 1) {
			return 1 if $this->matching_values( $attr, $group->[$i], @$group[ $i+ 1.. $#$group]);
		}
	}
	0
}

# Does entry contain the RDN value of (normalized) $dn?
sub has_rdn_value {
	my( $this, $entry, $dn)= @_;

	my @avas= $this->rdn_avas( $dn) or return 0;

	# (All values of a multi-valued RDN)
	all {
		my( $attr, $value)= @$_;
		my $n= normalize_value( $value);
		any { normalize_value( $_) eq $n} $entry->get_value( $attr)
	} @avas
}

# Parse the flat list of modifications that back-perl passes to modify():
#   ACTION, ATTR, VALUE..., ACTION, ATTR, VALUE..., ...
# where ACTION is ADD, DELETE or REPLACE, and a modification without values
# has a single undef instead. Returns arrayref of [ ACTION, ATTR, VALUES... ]
# or undef if the list can't be parsed.
#
# Since there are no value counts, a value equal to an action name is
# ambiguous. What slapd guarantees resolves most cases: every action is
# followed by an attribute name and then by at least one value (or undef).
# Attribute names are also checked against the schema, if loaded. Where
# both readings are still possible, a new modification is assumed.
sub parse_modlist {
	my( $this, $list)= @_;

	my $attr_re= qr/^(?:[a-z][a-z0-9-]*|\d+(?:\.\d+)+)(?:;[a-z0-9-]+)*$/i;
	my $schema= $this->{schema};
	my $check_schema= $schema ? scalar( () = $schema->all_attributes) : 0;

	# Can a modification start at position $i?
	my $is_start= sub {
		my( $i)= @_;
		my( $action, $attr)= @$list[ $i, $i+ 1];
		return 0 unless defined $action and $action=~ /^(?:ADD|DELETE|REPLACE)$/;
		return 0 unless defined $attr and $attr=~ $attr_re and
			$attr!~ /^(?:ADD|DELETE|REPLACE)$/;
		return 1 unless $check_schema;
		( my $type= $attr)=~ s/;.*//;
		$schema->attribute( $type) ? 1 : 0
	};

	my( %memo, $parse, $allow_empty);
	$parse= sub {
		my( $i)= @_;
		return [] if $i== @$list;
		return $memo{$i} if exists $memo{$i};
		return $memo{$i}= undef unless $is_start->( $i);

		my( $action, $attr)= @$list[ $i, $i+ 1];
		my $j= $i+ 2; # First value

		if( $j< @$list and !defined $list->[$j]) {
			my $rest= $parse->( $j+ 1);
			return $memo{$i}= $rest && [[ $action, $attr], @$rest];
		}

		# Values are $j .. $k-1, and next modification starts at $k.
		# Try the earliest possible $k first.
		for my $k( $j+ 1 .. scalar @$list) {
			next if $k< @$list and !$is_start->( $k);
			my $rest= $parse->( $k) or next;
			return $memo{$i}= [[ $action, $attr, @$list[ $j.. $k- 1]], @$rest];
		}

		# DELETE/REPLACE without values and without undef (as older back-perl
		# versions may pass it) is only considered if nothing else parses
		if( $allow_empty and $action ne 'ADD') {
			my $rest= $parse->( $j);
			return $memo{$i}= [[ $action, $attr], @$rest] if $rest;
		}
		$memo{$i}= undef
	};

	my $mods= $parse->( 0);
	if( !$mods) {
		%memo= ();
		$allow_empty= 1;
		$mods= $parse->( 0);
	}
	undef $parse; # Break reference cycle
	$mods
}


# Deleting entries
sub delete {
	# XXX Make perl backend actually pass various delete options onto us.
	# (-r not possible currently because we don't receive any parms, so
	# whether non-leaf delete is allowed is controled with 'deletetrees' option)
	my( $this, $dn)= @_;

	# Normalize DN
	$this->normalize( \$dn);

	DEBUG and p "DELETE '$dn'";

	my( $ret, %ret);

	# For now, this function is deleting actual entries, not taking into
	# account various fallbacks etc. So it means it's possible to get
	# NO_SUCH_OBJECT error on delete even if you get the value when you
	# search for it. Let's see how that works in practice for a while and if
	# it needs a change or not.
	# And this is also consistent with ADD where the entries are also
	# added to specific locations.
	# In any case, to switch to a fallback-aware version (which then deletes
	# the fallback), replace dn2leaf() with resolve() and the same args.
	$ret= $this->dn2leaf( $dn, \%ret, qw/leaf 0 namesonly 1 verify 1/);
	return $ret unless $ret== LDAP_SUCCESS;

	# If entry ain't there in the first place...
	return LDAP_NO_SUCH_OBJECT if !$ret{file} and !$ret{directory};

	if( defined $ret{directory}) {
		if( $this->{deletetrees}) {
			# (The entry is kept if any part of the tree can't be removed)
			rmtree( $ret{directory}, { error => \my $errors });
			if( @$errors) {
				for( @$errors) {
					my( $file, $msg)= %$_;
					warn "DELETE: can't remove '$file' ($msg)\n";
				}
				return LDAP_OPERATIONS_ERROR
			}
		} elsif( !rmdir $ret{directory}) {
			return LDAP_NOT_ALLOWED_ON_NONLEAF if $!{ENOTEMPTY} or $!{EEXIST};
			return LDAP_OPERATIONS_ERROR if $!{EACCES};
			return LDAP_OTHER
		}
	}

	# $ret{file} should always be defined if we reach here, but if directory
	# exists and file does not, in dn2leaf we don't halt but issue a serious
	# warning and resume processing, so in that case it may be undefined.
	if( defined $ret{file}) {
		unlink $ret{file} or return LDAP_OPERATIONS_ERROR
	}

	$this->clear_read_cache;

	LDAP_SUCCESS
}

#
# Ok, at this point we're done with direct-entry functions from slapd.
# The next thing we'll cover are overlays.
#

# DynLDIF supports overlays that are similar to slapd overlays in effect,
# but have nothing to do with slapd -- they're implemented in DynLDIF
# entirely, and use a different set of configuration directives to enable.

# All overlays have been put together in a single function for efficiency;
# here are their individual descriptions, in order of execution,
# soonest-first:
#
#  1. File expansion overlay.
#  2. Values expansion overlay.
#  3. Find (subsearch) overlay.
#  4. Perl evaluation overlay (*DANGEROUS*, so disabled by default).

# So here's the all-in-one overlay sub. It's a bit nested, so hang on
# in there. Most of the work in it is generic, overlay specific code is
# usually a few lines in the innermost block.
sub run_overlays {
	my( $this, $e, $odn)= @_;

	# Original DN requested. Used in replacing dots (".") at the end of
	# attribute value's DN spec with components from the original entry.
	$odn||= $e->dn;

	# Entries being expanded, to detect circular references (an entry
	# expanding to its own values, directly or via other entries).
	local $this->{expanding}{ lc $e->dn}= 1;

	# Find attributes that are not RAW and have at least one value that's
	# a candidate for overlays run.
	my @candidates=
	 grep{ $_!~ qr/$RAW/o and any{ index( $_, '$')> -1}
	  $e->get_value( $_)} $e->attributes;

	for my $a( @candidates) {

		for my $ovl( grep { $this->{"enable$_"}} @OVERLAYS) {
			pod "Running OVERLAY $ovl on '$a'";

			my @v= $e->get_value( $a);

			for my $cond( @{ $this->{$ovl}}) {
				if( $a=~ /$$cond[0]/ and $a!~ /$$cond[1]/ ){
					# Ok, we know overlay is configured with at least one line in
					# slapd.conf and that line matches our attribute name.

					pod "OVERLAY $ovl on '$a' due to rule @$cond";

					my @v2;

					# Implemented via while( defined( shift @v) and not using
					# for( @v) so that one value can result in instantiating
					# multiple values. For that we need to be able to
					# modify @v while iterating through it.
					while( defined( my $v= shift @v)) {

						my @vstack;

						# Use if() and not 'next unless...' here, because we might
						# once want to do s/if/while/ to get some extra features.
						# (Nothing that I have in mind right now, though).
						if( index( $v, '$') != -1) {
							# Ok, there are at least two components in this 
							# attribute's value, so it makes sense for us to run.

							my @comps;
							my @splits= ( []); # (So that indices match)

							# Fill @comps with components split on \s*\$\s*, but 
							# also remember the exact splitter that was used. (For
							# later re-construction of components that we did not
							# modify and for inserting appropriate space before/after
							# the processed components).
							while ( $v=~ qr/(\s*)\$(\s*)/o) {
								my( $pre, $post)= (
									(defined $1 ? $1 : q{}),
									(defined $2 ? $2 : q{}),
								);
								my $c;
								( $c, $v)= split /$pre\$$post/, $v, 2;
								push @comps, $c;
								push @splits, [ $pre, $post]
							}
							push @comps, $v;

							# Now run; loop over all components and see if any has
							# the name of our overlay, and if yes, do whatever the
							# overlay's function is on the next component.
							# (i.e.  "perl $ 3 + 4" ===> "7" )
							my $run= 0;
							my %opts; # Eventual options passed to overlay
							for my $comp( @comps) {
								if( $run) {
									$run= 0;

									# OVERLAY FILEVAL
									if( $ovl eq 'file') { # fileval
										# We want to include file contents
										my( $file, $spec)= split /\s+/, $comp, 2;

										if( my $prefix= $opts{prefix}) {
											$file= $prefix. $file;
										}

										my $key= join( '|', $file, $spec||'');

										# See if cached value exists. To determine that, as usual
										# with Memoize principle, we'll create a hash key
										# consisting of all our options. It would be phenomenal
										# if we could do it directly at the beginning of overlay
										# but we can't because DN can be specified as say, '...',
										# which expands to different values for different clients.
										# NOTE: We do it only when another DN should be looked up.
										#  For cases where lookup is in the entry itself, we just
										#  do it, we don't take that from cache.
										my $cacheref= $opts{cacheref};
										if( $cacheref and exists $cacheref->{$key}) {
											pc "Using cache value for FILE '$key'";
											$comp= $cacheref->{$key};
											goto FILE_DONE
										}

										po 'FILE: will read dir='.  $this->{directory}.
											', file='. $file.
											', spec='. ( $spec|| '');

										# Load file contents, end if reading wasn't successful
										my( $ret, @comp)= $this->read_file(
											$this->{directory}, $file, $spec);

										# Comment this if you want even unsuccessful attempts
										# to be cached (empty value).
										if( $ret!= LDAP_SUCCESS) {
											$comp= q{};
											goto FILE_DONE
										}

										$comp= join q{}, @comp;
										chomp $comp if defined $comp;

										# If cacheref exists and $key is there, time for
										# us to save key to cache.
										if( $cacheref) {
											pc "Rebuilding cache value for FILE '$key'";
											$cacheref->{$key}= $comp
										}

										FILE_DONE:

									# OVERLAY EXPANDVAL
									} elsif( $ovl eq 'exp') { # expandval
										# Ok, we want to expand to some DN's attribute
										my @f= split /\s+/, $comp; # @f== (dn, attr, valx)
										my ( $dn, $attr, $valx, $ret, $ent);
										# If less than 3 args given, we want attr/valx in the
										# current entry and no foreign lookup will be needed.
										if( @f== 1) {
											$ent= $e;
											($attr, $valx)= (@f, 0)

										} elsif( @f== 2) {
											($dn, $attr, $valx)= (@f, 0)

										} elsif( @f== 3) {
											($dn, $attr, $valx)= @f;

										} else {
											warn "EXPANDVAL: Invalid specification '$comp'\n";
											$comp= undef; # Drops the value
											goto EXP_END
										}

										my $val_joiner;
										# Support for valx to be joiner on which values
										# should be joined. If it's a number, it's specific
										# valx, if it contains non-number, it's a joiner
										# element that'll join all values.
										if( $valx=~ qr/\D/o) {
											$val_joiner= $valx;

											# Done this way because, with specifying \x20, I wasn't
											# able to get \x20 back to ' ' (no amount of "$joiner" or
											# sprintf %s, $joiner seemed to convert it back.
											$val_joiner=~ s/\\x([0-9a-fA-F]{2})/chr hex $1/ge;

											$valx= undef;
										}

										$dn||= q{};
										$this->normalize( \$dn);

										my $key;

										# Allow constructing the new DN from relative part
										# and ending of the current entry's DN.
										if( $dn) {
											$this->expand_dots( \$dn, $odn);
											
											$key= join( '|', $dn, $attr, $valx|| '');

											if( $opts{cacheref} and exists $opts{cacheref}{$key}) {
												pc "Using cache value for EXP '$key'";
												$comp= $opts{cacheref}{$key};
												goto EXP_DONE
											}
										}

										# If DN is set, we need to load it. If not, it means
										# only one arg was given (attr name), defaulting to
										# current entry.
										if( $dn and $this->{expanding}{$dn}) {
											warn "ExpandVal: circular reference to '$dn'\n";
											$comp= undef; # Drops the value
											goto EXP_END
										}
										if( $dn) {
											( $ret,undef,undef,$ent)= $this->load( $dn, qw/entry 1/);
											# Failed lookup drops the value (and does not prevent
											# other values from being expanded).
											if( $ret!= LDAP_SUCCESS) {
												warn "ExpandVal: can't load '$dn' ($ret)\n";
												$comp= undef; # Drops the value
												goto EXP_END
											}
										}

										my @vals= $ent->get_value( $attr);
										if( defined $valx){
											$comp= $vals[$valx];
										} else {
											$comp= join $val_joiner, @vals;
										}

										# If cacheref exists, time to save in cache
										if( $opts{cacheref} and $key) {
											pc "Rebuilding cache value for EXP '$key'";
											$opts{cacheref}{$key}= $comp
										}

										EXP_DONE:

										# XXX add this check to other ovls too?
										if( !defined $comp or !length $comp) {
											warn "ExpandVal of $attr for ".
												($dn|| 'local entry'). " is empty. ".
												"Wrong server schemas and/or schema.ldif file?\n";
										}

										EXP_END:

									# OVERLAY FIND / SUBSEARCH
									} elsif( $ovl eq 'find') { # findval
									
										# Do not operate on the attribute if this is not the
										# first level search (direct entry).
										next if $this->{level}> 0;

										if( $opts{if}) {
											my( $k, $v)= @{ $opts{if}};
											# Set up initial condition. If key begins with !,
											# it means negation, so passed== 1 instead of the
											# usual 0. Within the loop, $passed= !$passed is
											# used to always do the right thing regardless of !.
											my $passed= $k=~ s/^!//;
											my @vals= $e->get_value( $k);
											my $re= eval { qr/$v/ };
											unless( $re) {
												warn "FindVal: invalid regex '$v' in 'if'\n";
												$comp= undef; # Drops the value
												goto FIND_DONE
											}
											if( any{ $_=~ $re} @vals) {
												$passed= !$passed;
											}
											if( not $passed) {
												$comp= undef;
												goto FIND_DONE
											}
										}

										my( @f, $parser);
										$parser= $this->{standard_parse};

										if( not $parser->parse( $comp)) {
											warn q{Cannot parse '}. $parser->error_input.
												q{. Reason: }. $parser->error_diag. "\n";
											$comp= undef; # Drops the value
											goto FIND_DONE
										}

										# @f= base scope deref size time filter attrOnly attr
										@f= $parser->fields;

										$this->expand_dots( \$f[0], $odn);

										my $key= join( '|', @f);

										if( $opts{cacheref} and exists $opts{cacheref}{$key}) {
											pc "Using cache value for FIND '$key'";
											$comp= $opts{cacheref}{$key};
											goto FIND_DONE
										}

										# Strip valx and gvalx which are last two fields.
										# Make sure what's left are exactly 8 args for search().
										my( $gvalx, $valx)= ( 0, 0);
										if( @f== 10) { $gvalx= pop @f}
										if( @f== 9)  { $valx=  pop @f}
										if( @f!= 8)  {
											warn "Must specify 10 options for findVal overlay ".
												"(have @f).\n";
											$comp= undef; # Drops the value
											goto FIND_DONE
										}

										# val_joiner is per-result
										my $val_joiner;
										# Support for valx to be joiner on which values
										# should be joined. If it's a number, it's specific
										# valx, if it contains non-number, it's a joiner
										# element that'll join all values.
										if( $valx=~ qr/\D/o) {
											$val_joiner= $valx;
											# Done this way because, with specifying \x20, I wasn't
											# able to get \x20 back to ' ' (no amount of "$joiner" or
											# sprintf %s, $joiner seemed to convert it back.
											$val_joiner=~ s/\\x([0-9a-fA-F]{2})/chr hex $1/ge;

											$valx= undef;
										}

										# gval_joiner is for final value
										my $gval_joiner;
										if( $gvalx=~ qr/\D/o) {
											$gval_joiner= $gvalx;
											$gval_joiner=~ s/\\x([0-9a-fA-F]{2})/chr hex $1/ge;
											$gvalx= undef;
										}

										# NOTE: MUST use {} as last arg to indicate subsearch.
										my( $sret, @entries)= $this->search( @f, {});
										if( $sret!= LDAP_SUCCESS) {
											warn "FindVal: search '@f' failed ($sret)\n";
											$comp= undef; # Drops the value
											goto FIND_DONE
										}

										# Super good. So what we have now is:
										#
										# 1) We know there have been no errors
										# 2) We have entries found in @entries
										# 3) We have valx and gvalx defined
										# 4) All that's left to do is join on valx/gvalx and
										#    produce final value

										my @comp;
										$comp= q{};
										for my $ent( @entries) {
											# $f[7] is the last arg to search() -- attr to return
											my @vals= $ent->get_value( $f[7]);
											if( defined $valx){
												push @comp, $vals[$valx];
											} elsif( $val_joiner eq "\0") {
												push @comp, @vals;
											} else {
												push @comp, join $val_joiner, @vals;
											}
										}

										if( defined $gvalx){
											$comp= $comp[$gvalx];
										} elsif( $gval_joiner eq "\0") {
											$comp= \@comp;
										} else {
											$comp= join $gval_joiner, @comp;
										}

										if( $opts{cacheref}) {
											pc "Rebuilding cache value for FIND '$key'";
											$opts{cacheref}{$key}= $comp
										}

										FIND_DONE:

									# OVERLAY PERLEVAL
									} elsif( $ovl eq 'perl') {

										my $key= $comp;

										if( $opts{cacheref} and exists $opts{cacheref}{$key}) {
											pc "Using cache value for PERL '$key'";
											$comp= $opts{cacheref}{$key};
											goto PERL_DONE
										}

										# (Not a sandbox, which is why the overlay is disabled
										# by default)
										$comp= perl_eval( $comp);
										if( $@) {
											( my $err= $@)=~ s/\s+$//;
											warn "PerlEval: error in '$key' ($err)\n";
											$comp= undef; # Drops the value
											goto PERL_DONE
										}

										# If cacheref exists and $key is there, time for
										# us to save key to cache.
										if( $opts{cacheref}) {
											pc "Rebuilding cache value for PERL '$key'";
											$opts{cacheref}{$key}= $comp
										}

										PERL_DONE:
									}

								} elsif( $comp=~ /^$ovl\b/) {
									$run= 1; # Operate on the next component

									# Now extract any overlay options (i.e. exp cache 1 $ ...)
									# Make sure that we remove overlay options and leave only
									# overlay name in $comp (need to do it for the code that
									# joins the whole thing back to a value to work properly).
									# Do not skip processing if there are no options because
									# they may be defined in config file as default options.
									#next if( ( my $i= index $comp, q{ }) < 0);
									$comp=~ s/^(\w+)\s*(.*)$/$1/;
									%opts= $this->ovl_options( $ovl, $2);
								}
							}

							#
							# Here comes the part with some complicated elements. This is
							# the part of code that combines components (that were split
							# on \$) back to the processed value.
							#
							# The code is written in such a way that it remembers
							# the whitespace that was surrounding the $ ovl $ parms $ block,
							# so that the traces of the overlay can be removed, and the
							# remaining components put together, honoring the surrounding
							# whitespace exactly.
							#
							# For example, spec of "before  $ exp $ ..... $after" would be
							# processed (on 'exp' overlay's turn) into this exact value:
							# "before  VALUEafter".
							#
							# This is achieved by the innermost for() block -- 
							#   for( my $i=0; $i < @comps; $i++) { ..... }
							#
							# However, this approach did not allow the overlay to create
							# new attribute values -- expansion can happen only in-place,
							# within the string. This means that you were not able to get
							# say, the list of NTP servers via 'find' overlay as an array.
							# You were only able to get it as a string, with values 
							# joined on a joiner string of choice (such as "IP1 IP2 IP3").
							#
							# It became obvious that this wasn't gonna fly without support
							# for "instantiating" new values in a 1:N manner. For example,
							# we want the following specification and result:
							#
							# value: find $ ... 2 0 500 3600 \
							#   (&(objectClass=puppetClient)(puppetClass=ntp::server)) \
							#   0 ipHostNumber \0 \0
							#
							# To produce:
							#
							# value: IP1
							# value: IP2
							# value: IP3
							#
							# Note that in a direct LDAP query, this would return multiple
							# value:s as shown. In a client that replaces
							# the param name ('value') with the key name, it'd look
							# perfectly meaningful (assuming that the Debconf key is named
							# myapp/ntp_server):
							#
							# myapp_ntp_server: IP1
							# myapp_ntp_server: IP2
							# myapp_ntp_server: IP3
							#
							# But ok, anyway, to make the expansion to multiple attributes,
							# overlay should first return an arrayref instead of a scalar.
							# Then, this code right below detects are arrayrefs in the list,
							# and expands them into multiple attribute values.
							#
							# This support for expanding into multiple attribute values
							# took me good half a day of battling to barrel through.
							#

							# Each component that is an arrayref is expanded into its values,
							# producing one list of components (pushed onto @compstack) for
							# each combination of values. (Without arrayrefs, @compstack
							# will have just the one list, of course.)
							my @compstack= ( [ @comps]);
							for my $idx( grep { ref $comps[$_]} 0.. $#comps) {
								@compstack= map {
									my $list= $_;
									map { my @c= @$list; $c[$idx]= $_; \@c } @{ $comps[$idx]}
								} @compstack;
							}

							# Now, for every line on compstack, load it and go into
							# processing as if that was the single line and string-only
							# expansion (it's the old code that didn't know about expanding
							# to multiple values -- we can perfectly re-use that).
							for my $tmpref( @compstack) {
								@comps= @$tmpref;

								my $skip= 0;
								# Empty current value to prepare it for putting back together
								$v= q{};

								# Put the thing back together into an attribute value, BUT
								# honoring original elements used for splitting components.
								# (NOTE: This is not a routine running at the end of all overlay
								# processing, it's a routine running at the end of each individual
								# overlay.)
								for( my $i=0; $i < @comps; $i++) {
									my $comp= $comps[$i];

									# Indicates we want to ignore the whole value, even if some
									# of its components were not undef.
									if( !defined $comp) {
										$v= undef;
										last
									}

									if( $comp eq $ovl) {
										# XXX Can be undef if value begins with some sort of
										# expansion right away. See why its happening since we
										# already do have a provision above for $1|| ''
										$v.= defined( local $_= $splits[$i][0]) ? $_ : '';
										$skip= 2
									} elsif( $skip== 2) {
										$v.= $comp;
										$skip--
									} elsif( $skip== 1) {
										$v.= $splits[$i][1] . $comp;
										$skip--
									} else {
										if( $i> 0) {
											$v.= $splits[$i][0] . '$' . $splits[$i][1];
										}
										$v.= $comp
									}

								} # FOR $comp

								# @vstack== 1 for simple string replacement, but will contain
								# multiple values if we're expanding to multiple values.
								push @vstack, $v if defined $v;

							} # FOR my $tmpref

						} else { # IF index( $v, '$') != -1

							# IF '$' not present in entry it means there are no components
							# nor overlay processing, so directly assign $v to @vstack.
							@vstack= ( $v);
						}

						# Load all expanded values onto @v2
						push @v2, @vstack;

					} # FOR my $v

					# Finally, peddle @v2 to the attribute as its values. (Values
					# must be distinct, but i.e. a search can return the same value
					# from many entries.)
					$e->replace( $a, [ uniq @v2 ]);
					last # As soon as regex matched and overlay ran, we're done with it.

				} # IF $cond matched

			} # FOR my $cond (condition)

		} # FOR my $ovl (overlay)

	} # FOR my $a (attribute)

}


#
# Helper functions below
#

# A function with a lot of built-in value. Given DN OR FILE,
# reads it in, performs all dynamic operations and returns final
# entry as either entry object or ldif.
# Error handling and everything is proper, feel free to propagate
# non-success return value back to OpenLDAP.
sub load {
	my( $this, $dn, %opts)= @_;
	%opts= (
		dnasfile => 0,
		ldif     => 0,
		entry    => 0,
		%opts,
	);
	$opts{ldif}= 1 unless $opts{entry};

	DEBUG and pd "LOAD $dn, opts: ", join( ' ', %opts);

	my( $ret, %ret);

	# Find our base entry, with possible fallbacks etc. (Note that the entry
	# is right away opened here as entry object or filehandle through %opts).
	( $ret, $dn)= $this->resolve( $dn, \%ret,
		'entry', 1, 'dnasfile', $opts{dnasfile});
	return $ret unless $ret== LDAP_SUCCESS;

	my( $entry, $fh)= @ret{qw/entry fh/};

	my $ldif= q{};

	# If open as entry, and dynamic functions are enabled, do the whole thing.
	$this->run_appender( $entry) if $this->{enableappend};
	$this->run_overlays( $entry, $opts{origdn}); # origdn can be empty

	# If we opened as entry but need to return as ldif, convert.
	if( $opts{ldif}) {
		# Entry -> LDIF
		open my $out, '>', \$ldif;
		my $writer= new Net::LDAP::LDIF (
			$out, 'w',
			change => 0,
			raw => $RAW
		);
		if( not $writer->write_entry( $entry)) {
			warn "Can't write_entry('$dn') to scalar\n";
			return LDAP_OPERATIONS_ERROR
		}
		$writer->done;
	}

	$ldif and $ldif=~ s/^\s*//s; # !@#$%^& LDIF write_entry outputs \n at the top!
	( LDAP_SUCCESS, $dn, $ldif, $entry)
}

# Resolve DN->file.ldif. Takes into account fallbacks and everything else.
# No dynamic operations happen (no appending or overlays).
sub resolve {
	my( $this, $obase, $oret, %opts)= @_;

	DEBUG and pd "RESOLVE '$obase', opts:", join( ' ', %opts);

	# Open entry
	my $ret= $this->dn2leaf( $obase, $oret, %opts);
	# If not there, loop over defaults
	if( $ret!= LDAP_SUCCESS) {

		# Weird to see error happen if DN was specific file...
		# some permission error on file? In that case we do report
		# an error, we don't ignore it and go for fallbacks.
		return LDAP_OTHER if $opts{dnasfile};

		for( @{ $this->{searchfallback}}) {
			my $base= $obase;
			# If substitution from config file is successful
			if( $base=~ s/$$_[0]/$$_[1]/) {
				p "RESOLVE: TRY FALLBACK TO '$base'";

				$ret= $this->dn2leaf( $base, $oret, %opts);
				if( $ret== LDAP_SUCCESS) {
					$obase= $base;
					last
				}
			}
		}
	}

	# Return what we have, either the entry was there, or it came
	# from some fallback (in which case DN of the fallback is returned),
	# or if none of that worked, empty values.
	( $ret, $obase)
}

# Main function converting DNs to filesystem hierarchy. Optionally, it 
# can create missing paths, read/write/overwrite entries, return open
# file handle, etc.
# Additionally, this function was extended to accept filename in place
# of DN when option dnasfile=1. Most often, this is done when
# subtree is requested in search results, so Find routine goes reading
# in file by file, and does not need various DN resolving, but can still
# benefit from various file open functionalities built-in to dn2leaf.
sub dn2leaf {
	my( $this, $dn, $ret, %opts)= @_;
	%opts= (
		# List defaults here
		dnasfile => 0, # DN passed is a file we want to open?
		leaf     => 1, # Last element in path is entry? (if leaf=0, it's a dir)
		writeop  => 0, # Some write operation or pure read?
		overwrite=> 0, # Overwrite if exists? (Allows ADD on existing entries)
		openfh   => 0, # Open the file and return filehandle?
		entry    => 0, # Return Net::LDAP::Entry?
		verify   => 0, # Verify that fs path components exists. Ret '' if not.
		namesonly=> 0, # Return leaf name and parent dir name of an entry.
		create   => 0, # Create all missing paths (use rarely!)
		# Add caller options to our default set
		%opts
	);

	DEBUG and pd "DN2LEAF '$dn', opts: ", join(' ', %opts);

	my( $file, $fh, $directory, $entry);

	# (Options must be sorted, hash order is not stable)
	my $key= join( '|', $dn, map { "$_=$opts{$_}"} sort keys %opts);

	# Check if we're in cache. Excellent how we can cut right in here.
	if( exists $this->{cache}{'read'}{$this->{cacheread}}{$key}) {
		pc "Using cache value for DN2LEAF '$key'";

		$file= $this->{cache}{'read'}{$this->{cacheread}}{$key}[0];
		$directory= $this->{cache}{'read'}{$this->{cacheread}}{$key}[1];
		$entry= $this->{cache}{'read'}{$this->{cacheread}}{$key}[2]->clone;

		goto DN2LEAF_DONE
	}

	# Preserve original value of openfh. openfh gets modified during run, but
	# we need the original setting for determining whether we can cache the
	# result (we can when openfh= 0).
	$opts{orig_openfh}= $opts{openfh};

	# Quick provision for re-using this function's code even in cases
	# where DN is a literal file we want to open and read in.
	# (Most notably in returning results from subtree traversals).
	if( $opts{dnasfile}) {
		$file= $dn;
		( $directory= $file)=~ s{/.[^/]*$}{};
		goto DN_AS_FILE
	}

	# Must be normalized by the time we reach here
	unless( $this->valid_dn( $dn)) {
		warn "DN2LEAF Invalid or non-normalized DN '$dn'";
		return LDAP_INVALID_DN_SYNTAX
	}

	# First, split DN into filesystem path
	my @rdns= reverse( split ',', $dn);
	my @paths= $this->rdns2paths( @rdns);

	# File names (with extension and suffix of temporary files) must fit
	# the usual limit of 255 bytes
	if( $opts{writeop}) {
		my $max= 255- length( $this->{extension})- length( ".tmp$$");
		if( my( $long)= grep { length> $max} @paths) {
			warn "Can't store '$dn': RDN too long for a file name ('$long')\n";
			return LDAP_UNWILLING_TO_PERFORM
		}
	}

	my $leaf;

	$leaf= pop @paths if $opts{leaf};

	# Important that this rewinds $currdir to the right place and does
	# the right things if we're going for any filesystem work besides reading.
	#
	# Here, we only create missing directories if the LDIF leafs otherwise
	# already exist.
	#
	# As one exception to this rule, we also create the LDIF leafs along the
	# whole path if 'create' is true. Typically, this should only be true when
	# calling this method from init() and creating the basic path up to the
	# configured suffix on which we don't have global superior knowledge.
	if( $opts{writeop}) {
		my $currdir= $this->{directory};
		my @i= @paths;
		my @r= @rdns;
		my @done; # Components processed so far (to construct their DN)
		while ( my $comp= shift @i) {

			$currdir .= '/'.$comp;
			my $currfile= $currdir . $this->{extension};
			unshift @done, shift @r;

			if( ! -r $currfile) {
				if( $opts{create}) {
					# Must save under the full DN of the component, not just the
					# component itself, or it ends up at the top of the tree.
					my $ret= $this->save( join( ',', @done), '');
					return $ret unless $ret== LDAP_SUCCESS;
				} else {
					p "DN2LEAF: -r '$currfile': $!\n";
					return LDAP_NO_SUCH_OBJECT
				}

			# We could create dir along with .ldif file on every ADD, but that would
			# leave us with empty dirs for all leaf entries. So to avoid that, we
			# create the directory only when subentries are to be placed in it.
			# The cost of this is a bit more complex elsif as follows:
			} elsif( ! -d $currdir) {
				if( @i or ( !@i and $leaf)) {
					unless( mkdir $currdir) {
						warn "dn2leaf: mkdir '$currdir': $!\n";
						return LDAP_OPERATIONS_ERROR
					}
				} elsif( @i) {
					return LDAP_NO_SUCH_OBJECT
				}
			}
		}
	}

	$directory= join( '/', $this->{directory}, @paths);

	push @paths, $leaf if $leaf;

	$file= join( '/', $this->{directory}, @paths). $this->{extension};

	if( $opts{namesonly}) {
		# If names only requested, return file and directory (subtree) name
		# of the corresponding entry.

		# If verify==0, return whatever the fs path appears to be. Otherwise,
		# return undef if file or directory is not actually there.
		if( ! -e $directory) { $directory= $opts{verify} ? undef : $directory}

		if( ! -e $file) {
			# Small consistency check -- this should never happen:
			if( defined $directory and $directory ne $this->{directory}) {
				warn "WARNING: data tree inconsistency: directory about to be used, " .
					"but file '$file' missing.\n";
			}
			$file= $opts{verify} ? undef : $file
		}

		@$ret{qw/file directory/}= ( $file, $directory);
		return LDAP_SUCCESS
	}

	DN_AS_FILE:

	$opts{openfh}= 1 if $opts{entry} or $opts{ldif};

	if( -e $file) {
		if( $opts{writeop} and !$opts{overwrite}) {
			p "DN2LEAF: WON'T OVERWRITE: '$dn'\n";
			return LDAP_ALREADY_EXISTS
		} else {
			pd "DN2LEAF: FOUND '$dn'"; # in file '$file'";
		}
	} else {
		if( $opts{openfh}) {
			p "DN2LEAF: NOT FOUND '$dn'"; # in file '$file'";
			return LDAP_NO_SUCH_OBJECT
		}
	}

	my $open_type; # Used for printing in error message

	if( $opts{writeop}) {
		# Data is written to a temporary file, which save() renames to $file
		# when done, so that readers never see a partially written entry.
		$open_type= 'wr';
		$ret->{tmpfile}= "$file.tmp$$";
		$fh= IO::File->new( $ret->{tmpfile}, '>');
		unless( defined $fh) {
			warn "Can't wropen '$ret->{tmpfile}' ($!)\n";
			return LDAP_OPERATIONS_ERROR
		}
	}
	elsif( $opts{openfh}) {
		$open_type= 'rd';
		$fh= IO::File->new( $file, '<');
		unless( defined $fh) {
			warn "Can't rdopen '$file' ($!)\n";
			return LDAP_OPERATIONS_ERROR
		}
		unless( flock $fh, LOCK_SH) {
			warn "Can't flock_SH rdopened '$file' ($!)\n";
			return LDAP_OPERATIONS_ERROR
		}
	}

	if( $fh and $opts{entry}) {
		my $ldif= new Net::LDAP::LDIF $fh;

		if( $ldif->error) {
			warn 'LDIF Load Error: '.$ldif->error.': '.$ldif->error_lines;

			unless( flock $fh, LOCK_UN) {
				warn "Can't flock_UN '$file' ($!)\n";
			}
			return LDAP_OPERATIONS_ERROR
		}

		$entry= $ldif->read_entry;

		unless( $entry) {
			warn "No error but also no LDIF data in '$file'; correct manually.\n";
			return LDAP_OPERATIONS_ERROR
		}

		unless( flock $fh, LOCK_UN) {
			warn "Can't flock_UN '$file' ($!)\n";
			return LDAP_OPERATIONS_ERROR
		}
		unless( $fh->close) {
			warn "Can't ${open_type}close '$file' ($!)\n";
			return LDAP_OPERATIONS_ERROR
		}
	}

	# If here, cache result. Caching enabled with cacheRead directive
	if( $this->{cacheread} and $entry and
	 !$opts{orig_openfh} and !$opts{writeop}) {

		pc "Rebuilding cache value for DN2LEAF '$key'";

		$this->{cache}{'read'}{$this->{cacheread}}{$key}=
		 [ $file, $directory, $entry->clone];
	}

	DN2LEAF_DONE:

	@$ret{qw/file fh directory entry/}= ( $file, $fh, $directory, $entry);

	LDAP_SUCCESS
}

# Map DN components (in canonical form) to their file system names
sub rdns2paths {
	my( $this, @rdns)= @_;
	map { rdn2name( $_)} @rdns
}

# File system name of an RDN (in canonical form). As '/' can't be used in
# file names, it is stored as '%2f' (and '%' as '%25').
sub rdn2name {
	my( $rdn)= @_;
	$rdn=~ s/%/%25/g;
	$rdn=~ s{/}{%2f}g;
	$rdn
}

# Attributes listed in 'protectAttrs', as hashref of lowercase names
our %PROTECTED;
sub protected_attrs {
	my( $this)= @_;
	my $list= $this->{protectattrs} // q{};
	$PROTECTED{$list}||= {
		map { lc $_=> 1} grep { lc $_ ne 'none'} split ' ', $list
	}
}

# Attributes whose values are hidden in debug output
sub redacted_attrs {
	my( $this)= @_;
	+{ %{ $this->protected_attrs}, map { lc $_=> 1} @REDACT_ATTRS }
}

# Whether attribute description (name, alias or OID, possibly with
# options) refers to one of the attributes in $names (as returned by
# protected_attrs()).
sub attr_in {
	my( $this, $attr, $names)= @_;
	return 0 if !defined $attr or !%$names;

	( my $name= lc $attr)=~ s/;.*//;
	return 1 if $names->{$name};

	my $schema= $this->{match_schema} or return 0;
	my $at= $schema->attribute( $name) or return 0;
	( any { $names->{ lc $_}} $at->{name}, $at->{oid}, @{ $at->{aliases} || []})
		? 1 : 0
}

# LDIF, with values of redacted attributes hidden (for debug output)
sub redact_ldif {
	my( $this, $ldif)= @_;
	my $names= $this->redacted_attrs;

	my( $hide, @out)= ( 0);
	for my $line( split /\n/, $ldif, -1) {
		# Continuation of a folded line
		if( $line=~ /^ /) {
			push @out, $line unless $hide;
			next
		}
		$hide= $line=~ /^([^:\s]+)(:[:<]?)/ && $this->attr_in( $1, $names);
		push @out, $hide ? "$1$2 *****" : $line;
	}
	join "\n", @out
}

# Modification list (as returned by parse_modlist()), with values of
# redacted attributes hidden (for debug output)
sub redact_mods {
	my( $this, $mods)= @_;
	my $names= $this->redacted_attrs;

	join '; ', map {
		my( $action, $attr, @values)= @$_;
		my $hide= $this->attr_in( $attr, $names);
		"$action $attr". ( @values ? ': '. join( ', ', map {
			!defined $_ ? '(none)' : $hide ? '*****' : $_ } @values) : q{})
	} @$mods
}

# Filter string, with assertion values on redacted attributes hidden
# (for debug output)
sub redact_filter {
	my( $this, $filter)= @_;
	my $names= $this->redacted_attrs;

	$filter=~ s{\((\??)([\w.;-]+)((?::[\w.-]*)*)(~=|>=|<=|:=|=)([^()]*)\)}{
		$this->attr_in( $2, $names) ? "($1$2$3$4*****)" : "($1$2$3$4$5)"
	}ge;
	$filter
}

# Evaluates filter on an entry with three-valued logic (RFC 4511, 4.5.1.7),
# returning 1 (TRUE), 0 (FALSE) or undef (Undefined). Entries match when
# the result is TRUE.
# Strings in $filter must be decoded from UTF-8 (see decode_utf8_deep()),
# entry values are decoded as they are matched.
# Components which slapd found undefined (passed as $UNDEFINED_ATTR, see
# search()) are Undefined, and if $protect is true, so are components on
# attributes listed in 'protectAttrs' (like slapd does for attributes the
# client has no access to).
sub filter_match {
	my( $this, $filter, $entry, $protect)= @_;
	my( $op, $args)= %$filter;

	if( $op eq 'and' or $op eq 'or') {
		# Result that decides the outcome on its own
		my $decisive= $op eq 'and' ? 0 : 1;
		my $undefined= 0;
		for my $sub( @$args) {
			my $r= $this->filter_match( $sub, $entry, $protect);
			if( !defined $r) { $undefined= 1 }
			elsif( $r== $decisive) { return $decisive }
		}
		return $undefined ? undef : 1- $decisive
	}

	if( $op eq 'not') {
		my $r= $this->filter_match( $args, $entry, $protect);
		return defined $r ? 1- $r : undef
	}

	my $attr= $op eq 'present' ? $args :
		( $op eq 'substrings' or $op eq 'extensibleMatch') ? $args->{type} :
		$args->{attributeDesc};

	return undef if defined $attr and lc $attr eq $UNDEFINED_ATTR;
	return undef if $protect and $this->attr_in( $attr, $this->protected_attrs);

	# Leaf components are matched using the matching rules of
	# Net::LDAP::FilterMatch (undef if no matching rule is available).
	# Values are UTF-8, and are matched as characters (so that i.e.
	# case-insensitive matching works for non-ASCII characters too).
	my $r= $this->leaf_match( $op, $args, DynLDIF::CharEntry->new( $entry));
	defined $r ? ( $r ? 1 : 0) : undef
}

# Matching rule types of filter operators
our %OP2RULE= (
	equalityMatch  => 'equality',
	greaterOrEqual => 'ordering',
	lessOrEqual    => 'ordering',
	substrings     => 'substr',
);

# Matches a leaf filter component, like Net::LDAP::FilterMatch does, but
# calling matching rules directly (it does a string eval for each, which is
# slow when matching many entries), with matching rules from schema cached.
sub leaf_match {
	my( $this, $op, $args, $entry)= @_;

	return $entry->exists( $args) ? 1 : 0 if $op eq 'present';

	# Others (extensibleMatch) are rare
	unless( $op eq 'approxMatch' or $OP2RULE{$op}) {
		my $schema= $this->{match_schema};
		# Matching rule is passed by name. (Net::LDAP::Schema finds matching
		# rule use only by name, and a rule's OID can refer to its use instead.)
		if( $schema and defined( my $id= $args->{matchingRule})) {
			my $name= $this->{rule_cache}{"mr:$id"}//= do {
				my( $mr)= grep { $_->{oid} eq $id or lc $_->{name} eq lc $id}
					$schema->all_matchingrules;
				$mr ? $mr->{name} : $id
			};
			$args= { %$args, matchingRule=> $name};
		}
		return Net::LDAP::Filter::match( { $op=> $args}, $entry, $schema)
	}

	my( $attr, $assertion);
	if( $op eq 'substrings') {
		$attr= $args->{type};
		my @parts= @{ $args->{substrings}};
		$assertion= join '.*', map { "\Q$_\E"} map { values %$_} @parts;
		$assertion= "^$assertion" if exists $parts[0]{initial};
		$assertion.= '$' if exists $parts[-1]{final};
	} else {
		( $attr, $assertion)= @$args{qw/attributeDesc assertionValue/};
	}

	my $schema= $this->{match_schema};
	my $rule= 'cis_'. $op;
	if( $schema and $op ne 'approxMatch') {
		# (Matching rules are those of the attribute type, without options)
		( my $type= lc $attr)=~ s/;.*//;
		my $cache= $this->{rule_cache}{$type}||= {};
		$cache->{$op}= $schema->matchingrule_for_attribute( $type, $OP2RULE{$op})
			unless exists $cache->{$op};
		$rule= $cache->{$op};
		return undef unless defined $rule;
	}

	# (Net::LDAP::FilterMatch defines them in package Net::LDAP::Filter)
	my $match= Net::LDAP::Filter->can( "_$rule") or return undef;
	my $r= eval { $match->( $assertion, $op, $entry->get_value( $attr)) };
	$r
}

# Copy of a data structure, with strings that are valid UTF-8 decoded
# into characters
sub decode_utf8_deep {
	my( $data)= @_;
	my $type= reftype( $data) // q{};
	if( $type eq 'HASH') {
		return { map { $_=> decode_utf8_deep( $data->{$_})} keys %$data }
	} elsif( $type eq 'ARRAY') {
		return [ map { decode_utf8_deep( $_)} @$data ]
	} elsif( defined $data and !ref $data) {
		my $chars= $data;
		return utf8::decode( $chars) ? $chars : $data
	}
	$data
}

# Quick debug print. p(...)
sub p{  if( DEBUG) { print {*STDERR} '### ', join( ' ', @_), "\n"}}
sub pd{ if( DEBUG_DTL) { print {*STDERR} '### ', join(' ', @_), "\n"}}

sub po{ if( DEBUG_OVL) { print {*STDERR} 'OOO ', join(' ', @_), "\n"}}
sub pod{if( DEBUG_DTL and DEBUG_OVL){ print {*STDERR} 'OOO ', join(' ', @_), "\n"}}

sub pc{ if( DEBUG_CCH) { print {*STDERR} '+++ ', join(' ', @_), "\n"}}
sub pcd{if( DEBUG_DTL and DEBUG_CCH){print {*STDERR} '+++ ',join(' ',@_),"\n"}}

# Subroutine that appends the entry with attributes from other entries
# according to 'entryappend' config directive. This has become a quite
# sophisticated gun.
sub run_appender {
	my( $this, $e)= @_;

	# Appender syntax can get hard to keep in mind all the time, so here's the
	# list of available ways to set it up, and the corresponding explanations:
	#
	# <attr> <value_regex> ... -> attr   <attrName>   [attrAttr]   [attrs]
	# <attr> <value_regex> ... -> append <regex_what> <regex_with> [attrs]
	#
	# Explanations:
	#
	# 0) <attr> <value_regex> is a list of attr/value pairs. All pairs must
	#    match on an entry to make it a candidate for appending.
	#
	# 1) 'attr' method: look up <attrName> attribute in each entry
	#    found. Its values are DNs which we should look up to append the
	#    original entry.
	#    Then: if there are no <attrAttr> values nor [attrs] list is given,
	#    append entry with all attributes from lookup DN.
	#    Otherwise, append only with attributes listed in [attrs] and
	#    <attrAttr> attribute.
	#
	# 2) 'append' method: similar to 1), but DN to look up is not read from 
	#    <attrName> in the entry, but is derived in-place by doing
	#    $lookup_DN= ( $entry_DN=~ s/regex_what/regex_with/).
	#    Also, similarly, either all attributes are appended, or only those
	#    listed in [attrs].

	my( $ret, %ret);

	pd "SEARCH APPENDING ". $e->dn;

	my( $id, $i, $ok, $k, $v, $r, @stack)= ( 0); # $id= 0
	for my $rule( @{ $this->{entryappend}}) {
		$id++;

		( $i, $ok, $k, $v, $r)= ( 0, 1, undef, undef, undef); # Clear vars
		$#stack= -1; # Clear stack

		# Phase 1: see if all append conditions match
		do {
			# (Rule syntax is validated in config())
			( $k, $v)= ( $$rule[$i], $$rule[$i+1]);

			my @cond;

			if( $k eq 'dn') { @cond= $e->dn }
			else { @cond= $e->get_value( $k) }

			my $local_ok= 0;
			for my $cond( @cond) {
				if( $cond=~ /$v/) {
					$local_ok= 1;
					last
				}
			} # FOR my $cond

			if( !$local_ok) {
				pd "SEARCH APPEND #$id skipped ($k!~ /$v/)";
				$ok= 0;
			}

		} while( $i+= 2 and $$rule[$i] ne '->');

		next if !$ok; # if this rule doesn't match, search further

		# Phase 2: now we know all conditions matched, so go on
		pd "SEARCH APPEND #$id matched '@$rule'";
		$i++; # Skip the '->' marker

		# Attributes to append with: the ones listed in the rule (and for
		# 'attr', in the entry's ATTRATTR attribute), or if none are listed,
		# all attributes of the other entry. Only attributes that the entry
		# doesn't have and that its object classes allow are appended.
		my @lookup_attrs;
		@lookup_attrs= @$rule[$i+3..$#$rule] if $$rule[$i+3];

		my @dns;
		if( $$rule[$i] eq 'attr') {
			# List of DNs to lookup (usually contained in seeAlso attr.)
			@dns= $e->get_value( $$rule[$i+1]);
			push @lookup_attrs, $e->get_value( $$rule[$i+2]) if defined $$rule[$i+2];

		} elsif( $$rule[$i] eq 'append') {
			( my $dn= $e->dn)=~ s/$$rule[$i+1]/$$rule[$i+2]/;
			@dns= ( $dn);
		}

		for my $dn( @dns) {
			# Allow constructing the new DN from relative part
			# and ending of the current entry's DN.
			$this->expand_dots( \$dn, $e->dn) if $$rule[$i] eq 'attr';

			$this->normalize( \$dn);
			$ret= $this->dn2leaf( $dn, \%ret, qw/entry 1/);
			if( $ret!= LDAP_SUCCESS) {
				warn "EntryAppend: can't load '$dn' for '". $e->dn. "' ($ret)\n";
				next
			}
			$this->append_attrs( $e, $ret{entry}, @lookup_attrs);
		}

	} # FOR my $rule
}

# Append entry $e with attributes of entry $ae: the ones in @attrs, or all if
# none are given. Only attributes that $e does not have, and that its object
# classes allow (according to the schema), are appended.
sub append_attrs {
	my( $this, $e, $ae, @attrs)= @_;
	@attrs= $ae->attributes unless @attrs;

	my $can= $this->allowed_attrs( $e);
	my %seen;
	for my $a( @attrs) {
		next if $seen{ lc $a}++ or $e->exists( $a);
		unless( $this->attr_in( $a, $can)) {
			pd "Entry does not allow append with $a";
			next
		}
		my @v= $ae->get_value( $a) or next;
		$e->add( $a, [ @v])
	}
}

# Attributes allowed in entry by the schema (MUST and MAY attributes of its
# object classes), as hashref of lowercase names, aliases and OIDs
sub allowed_attrs {
	my( $this, $e)= @_;
	my $schema= $this->{schema};
	my %can;
	for my $oc( $e->get_value( 'objectClass')) {
		for my $at( $schema->may( $oc), $schema->must( $oc)) {
			$can{ lc $_}= 1 for grep { defined}
				$at->{name}, $at->{oid}, @{ $at->{aliases} || []};
		}
	}
	\%can
}

# Expand trailing dots in a DN specification to that many last components
# of another DN. I.e. "cn=x,.." relative to "cn=y,dc=example,dc=com" gives
# "cn=x,dc=example,dc=com" (comma before the dots is optional).
sub expand_dots {
	my( $this, $dnref, $base)= @_;

	if( my $count= $$dnref=~ s/\.(?=\.*$)//g) {
		$$dnref=~ s/,\s*$//;
		my @comps= split ',', $base;
		$count= @comps if $count> @comps;
		$$dnref.= ( length $$dnref ? ',' : ''). join ',', @comps[ -$count.. -1]
			if $count;
	}
}

# Deep comparison of arbitrary structures
sub dequal {
  my( $this, $a_ref, $b_ref)= @_;
  local $Storable::canonical= 1;
  return freeze( $a_ref) eq freeze( $b_ref)
}

# Function able to read a file and return it all, or according to $spec
# which is a specific linenumber or line matching a regex
sub read_file {
	my( $this, $directory, $file, $spec)= @_;

	unless( $directory and length $directory) {
		warn "read_file( '$file') attempted before 'directory' has been set\n";
		return LDAP_OPERATIONS_ERROR
	}

	$file=~ s{^[\./]+}{};
	$file=~ s{\.\.+}{\.}g;
	$file= join( '/', $directory, $file);

	DEBUG and p "READ FILE '$file'";

	my( $fh, @data);

	$fh= new IO::File "< $file";
	unless( defined $fh) {
		warn "Can't rdopen '$file' ($!)\n";
		return LDAP_OPERATIONS_ERROR
	}
	unless( flock $fh, LOCK_SH) {
		warn "Can't flock_SH rdopened '$file' ($!)\n";
		return LDAP_OPERATIONS_ERROR
	}

	@data= <$fh>;

	unless( flock $fh, LOCK_UN) {
		warn "Can't flock_UN rdopened '$file' ($!)\n";
		return LDAP_OPERATIONS_ERROR
	}
	unless( $fh->close) {
		warn "Can't rdclose '$file' ($!)\n";
		return LDAP_OPERATIONS_ERROR
	}

	# Spec may be a number (line number), or a regex. If it
	# is specified, the specific line number or $1 from the first
	# line matching the regex is returned. If not found, empty string
	# is returned.
	if( defined $spec and $spec=~ qr/^\d+$/o) {

		@data= defined $data[$spec] ? ( $data[$spec]) : ();
	} elsif( $spec) {
		my $re= eval { qr/$spec/ };
		unless( $re) {
			warn "Invalid regex '$spec' for reading '$file'\n";
			return LDAP_PARAM_ERROR
		}
		my @found;
		for( @data) {
			if( $_=~ $re) {
				@found= ( defined $1 ? $1 : $_);
				last
			}
		}
		@data= @found;
	}

	( LDAP_SUCCESS, @data)
}

# Function to write file on disk, taking into account proper
# steps, locking and error messages. (This is for writing regular
# files; for writing LDIF data see save() below)
sub write_file {
	my( $this, $directory, $file, $data)= @_;

	$file=~ s/^[\/\.]+//;
	$file=~ s/\.\./\./g;
	$file= join( '/', $directory, $file);

	DEBUG and p "WRITE FILE '$file'";

	my $fh= new IO::File "> $file";
	unless( defined $fh) {
		warn "Can't wropen '$file' ($!)\n";
		return LDAP_OPERATIONS_ERROR
	}
	unless( flock $fh, LOCK_EX) {
		warn "Can't flock_EX wropened '$file' ($!)\n";
		return LDAP_OPERATIONS_ERROR
	}

	unless( print {$fh} $data) {
		warn "Can't write '$file' ($!)\n";
		unless( flock $fh, LOCK_UN) {
			warn "Can't flock_UN wropened '$file' ($!)\n";
		}
		return LDAP_OPERATIONS_ERROR
	}

	unless( flock $fh, LOCK_UN) {
		warn "Can't flock_UN wropened '$file' ($!)\n";
		return LDAP_OPERATIONS_ERROR
	}
	unless( $fh->close) {
		warn "Can't wrclose '$file' ($!)\n";
		return LDAP_OPERATIONS_ERROR
	}

	LDAP_SUCCESS
}

# Save LDIF string to given DN.
# $ldif can directly be an entry and it's then first converted to
# LDIF.
# File we save to is determined from $dn, not from dn: specified in ldif.
# XXX if data is already in ldif, does it have proper dn: when it's saved?
#   (when $dn!= ldif{dn})
sub save {
	my( $this, $dn, $ldif, %opts)= @_;

	my( $ret, %ret);

	# If we were called with an entry, turn it to LDIF.
	if( ref $ldif) {
		my $entry= $ldif;
		$ldif= $this->e2ldif( $dn, $entry);
		return $ldif if $ldif=~ /^\d+$/; # (Error)
	}

	# Locate/resolve the file to which we'll save data and open filehandle
	# to it. Two things can also be specified in the config file which
	# affect behavior:
	#  addoverwrites= 1/0  -- overwrite existing entry with new ADD?
	#  addignoredups= 0/1  -- if overwrite=0, do we complain or ignore the ADD?
	$ret= $this->dn2leaf( $dn, \%ret,
		qw/writeop 1/, 'overwrite', $this->{addoverwrites}, %opts);

	if( $ret!= LDAP_SUCCESS) {
		return LDAP_SUCCESS if $ret== LDAP_ALREADY_EXISTS and
			$this->{addignoredups} and !$opts{modify};
		return $ret
	}

	# Save ldif data into a temporary file, and rename it to the entry's file
	my( $fh, $tmp)= @ret{qw/fh tmpfile/};
	unless( print( {$fh} $ldif) and $fh->close) {
		warn "Can't write '$tmp' ($!)\n";
		unlink $tmp;
		return LDAP_OPERATIONS_ERROR
	}
	unless( rename $tmp, $ret{file}) {
		warn "Can't rename '$tmp' to '$ret{file}' ($!)\n";
		unlink $tmp;
		return LDAP_OPERATIONS_ERROR
	}

	$this->clear_read_cache;

	LDAP_SUCCESS
}

# Data on disk has changed, so cached reads (cacheRead) are no longer valid
sub clear_read_cache {
	my( $this)= @_;
	$_= {} for values %{ $this->{cache}{'read'} || {} };
}

# Entry 2 LDIF
sub e2ldif {
	my( $this, $dn, $entry)= @_;

	my $ldif= q{};
	open my $out, '>', \$ldif;
	my $writer= new Net::LDAP::LDIF (
		$out, 'w',
		change => 0,
		raw => $RAW
	);
	if( not $writer->write_entry( $entry)) {
		warn "Can't write_entry('$dn') to scalar\n";
		return LDAP_OPERATIONS_ERROR
	}
	$writer->done;

	$ldif=~ s/^\s*//s; # !@#$%^& LDIF write_entry outputs \n at the top!

	$ldif
}

# LDIF 2 entry
sub ldif2e {
	my( $this, $ldifref)= @_;

	# Turn $ldif into an entry object right away.
	open my $fh, '<', $ldifref;
	my $input= new Net::LDAP::LDIF $fh;
	my $entry= $input->read_entry;

	if( $input->error) {
		warn 'LDIF Load Error: '.$input->error.': '.$input->error_lines;
		return LDAP_OPERATIONS_ERROR
	}

	unless( $fh->close) {
		warn "Can't rdclose filehandle on scalar ($!)\n";
		return LDAP_OPERATIONS_ERROR
	}

	( LDAP_SUCCESS, $entry)
}

# Normalize. Can give scalar ref (just a DN), or a whole entry so possibly
# more than DN normalization will be done.
# Normalizes DN (scalar ref) or entry's DN (entry) to canonical form (see
# canonical_dn()). Invalid DNs are left unchanged, to be rejected by
# valid_dn().
sub normalize {
	my( $this, $ptr)= @_;

	# Just in case we only get DN as a scalar to normalize.
	if( ref $ptr eq 'SCALAR') {
		my $dn= canonical_dn( $$ptr);
		$$ptr= $dn if defined $dn;
	} else {
		my $dn= canonical_dn( $ptr->dn);
		$ptr->dn( $dn) if defined $dn;
	}

	LDAP_SUCCESS
}

# Whether DN is valid and in canonical form
sub valid_dn {
	my( $this, $dn)= @_;
	my $canonical= canonical_dn( $dn);
	defined $canonical and length $canonical and $canonical eq $dn
}

# DNs are kept in a canonical form, which is also what the directory tree
# on disk is named by: attribute names and values are lowercased (values
# are compared case-insensitively), whitespace around values is removed and
# runs of whitespace within values collapsed to a single space, special
# characters in values are escaped as \xx, and values of multi-valued RDNs
# are sorted. Since ',' and '+' in values are always escaped, DNs in
# canonical form can be split into RDNs on ',', and RDNs into attribute and
# value on the first '='.
#
# Returns undef for invalid DNs.
our %CANONICAL;
sub canonical_dn {
	my( $dn)= @_;
	return $CANONICAL{$dn} if exists $CANONICAL{$dn};
	%CANONICAL= () if keys %CANONICAL> 10000;

	my $rdns= parse_dn( $dn);
	$CANONICAL{$dn}= $rdns ? join ',', map {
		join '+', sort map {
			lc( $$_[0]). '='. escape_dn_value( normalize_value( $$_[1]))
		} @$_
	} @$rdns : undef
}

# Parses DN (in string representation of RFC 4514) into a list of RDNs, each
# an arrayref of [ attribute, value ] pairs, with values unescaped. Returns
# undef for invalid DNs.
sub parse_dn {
	my( $dn)= @_;
	return undef unless defined $dn;

	my( @rdns, @avas);
	for( $dn) {
		return [] unless /\S/;

		while( 1) {
			/\G\s*([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+)\s*=\s*/gc or return undef;
			my( $attr, $value)= ( $1);

			if( /\G"((?:[^"\\]|\\.)*)"\s*/gc) {
				( $value= $1)=~ s/\\(.)/$1/gs;

			} elsif( /\G((?:[^,;+"\\]|\\(?:[0-9A-Fa-f]{2}|[^0-9A-Fa-f]))*)/gc) {
				$value= $1;
				$value=~ s/(?<!\\)\s+$//; # Unescaped trailing space is insignificant
				$value=~ s/\\([0-9A-Fa-f]{2}|.)/length $1== 2 ? chr hex $1 : $1/gse;
			}

			push @avas, [ $attr, $value ];
			next if /\G\+/gc;

			push @rdns, [ @avas ];
			@avas= ();
			last if /\G\z/gc;
			/\G[,;]/gc or return undef;
		}
	}

	\@rdns
}

# Normalized form of a value (as in RDNs): lowercased, with surrounding
# whitespace removed and runs of whitespace collapsed to a single space.
# Values are UTF-8.
sub normalize_value {
	my( $value)= @_;
	return $value unless defined $value;

	my $chars= $value;
	my $utf8= utf8::decode( $chars);
	$chars= lc $chars;
	$chars=~ s/^\s+|\s+$//g;
	$chars=~ s/\s+/ /g;
	utf8::encode( $chars) if $utf8;
	$chars
}

# Escapes special characters in a DN value (canonical form, see
# canonical_dn())
sub escape_dn_value {
	my( $value)= @_;
	$value=~ s/([\\",+;<>=\x00-\x1f])/sprintf '\\%02x', ord $1/ge;
	$value=~ s/^([ #])/sprintf '\\%02x', ord $1/e;
	$value=~ s/ $/\\20/;
	$value
}

# The [ attribute, value ] pairs of DN's first RDN, with values unescaped
sub rdn_avas {
	my( $this, $dn)= @_;
	my $rdns= parse_dn( $dn) or return;
	@{ $rdns->[0] || []}
}

# Values of entry's attribute, without the ones equal to value (compared
# as in RDNs)
sub values_except {
	my( $this, $entry, $attr, $value)= @_;
	my $n= normalize_value( $value);
	grep { normalize_value( $_) ne $n} $entry->get_value( $attr)
}

# Relocator code is Debconf/LDAP specific. It looks for 'variables' attribute
# in the Debconf entry ('variables' and debconfDBEntry is defined in
# debconf.schema so it makes sense to enable this only under the debconf tree).
# If 'variables' attrs exist, parse them to grep out dynldif_location=NAME (there
# should always be none or one found).
# If name matches a known relocation recipe, perform DN regex replacement
# that corresponds to this named relocation, and actually relocate it.
# The 'variables' attribute gets filled by a slightly modified Debconf
# frontend on the client side which inserts those values.
sub check_relocation {
	my ($this, $entry, $where)= @_;

	my ($ret, @variables);

	# No work if there's no 'variables' attribute
	return LDAP_SUCCESS unless @variables= $entry->get_value( 'variables');

	my $dn= $entry->dn;

	my $location_name= q{}; # Wanted relocation place

	# XXX Safety check, remove when confident it's not happening
	# We don't want two var=value definitions in the single attribute value.
	# (This does prevent multiple variables, each in its own attribute value,
	# this only checks that we do not encounter multiple = in one value).
	for( @variables) {
		if( /=.+=/) {
			warn "***** Multiple '=' found in $dn variables attribute, skipping relocation *****\n";
			return LDAP_SUCCESS
		}
	}

	# Extract location we want to relocate to and remove it from the 
	# variables list. (Implementation without removal would be more
	# elegant, but it's better to remove them).
	my @variables2;
	for( @variables) {
		if( /dynldif_location=(.+)/) {
			$location_name= $1
		} else {
			push @variables2, $_
		}
	}

	# No work if no dynldif_location= specified among variables
	return LDAP_SUCCESS unless $location_name;

	# If the location specification was found, replace variables with
	# whatever is left after taking dynldif_location= out of the list, and
	# relocate the entry.
	if( @variables!= @variables2) {
		if( @variables2) {
			$entry->replace( 'variables', [ @variables2]);
		} else {
			$entry->delete( 'variables');
		}

		$ret= $this->relocate( $entry, $location_name);
		return $ret unless $ret== LDAP_SUCCESS;
	}

	LDAP_SUCCESS
}

# Server-side prompter! This is a beautiful piece of code that was removed
# a while ago, and then I brought it back. Here's how it operates: when a
# Debconf entry is added to LDAP, we first make sure that both question and
# template are present, and then, THEN, we do a bit of magic on its own
# merits. We manage to open a complete, perfect Gnome Debconf frontend on
# administrator's X display of choice, where the admin can see full Debconf
# question, value input field AND another field to specify where to save
# the question (typical choices are global level, site level, host level).
# There is just one drawback to that approach-- as Debconf adds questions
# at the end of its run, it means the admin is asked the questions after
# debconf basically already does its thing and decides on answers, so the
# conditional relation between questions is lost (i.e. you don't have the
# ability to answer "NO" and then let Debconf continue as it really would
# with a "NO" answer). And there are two solutions to this problem: one,
# admin could be familiar with the package they're installing, or at least
# with the logical dependency between questions, and answer them correctly.
# Two (and better approach), use slight debconf modification on client side
# that saves the question to LDAP as soon as it is asked (this triggers 
# server prompting, and when it is done, the client re-reads the question
# to pick possibly changed value by the admin), and then debconf is aware
# of the admin's response in "real time" and can continue accordingly.
# Note that the X window is opened from the LDAP server to the admin's
# display, which is most suitable on local LANs where firewall rules or
# NAT won't make the display unreachable from the server side.
sub check_prompter {
	my( $this, $entry, $where)= @_;

	my $dn= $entry->dn;

	# Extract priority that would be used to ask the question. To have the
	# question asked, priority must be set.
	my $priority= exists $entry->{attrs}->{priority} ?
		${$entry->{attrs}->{priority}}[0] : 0;
	
	return LDAP_SUCCESS unless $priority;
	$priority||= 'low';

	my $key; # Will contain Debconf key name, if it can be found in DN

	# For each configured prompt-under location,
	while( my( $ps, $pr)= each %{$this->{addprompt}}) {

		# skip if it doesn't match the entry being ADDed
		next if $dn!~ /$ps/;

		# Figure out Debconf key name from entry DN.
		# A bit suboptimal, since it runs in a loop while it could be
		# done outside. But, doing it here ensures it runs only if the key
		# is being added under the matching place in the tree, so it doesn't
		# trigger warning on unrelated keys.
		$dn=~ /^cn=(\S+?),/;
		if( not $key= $1) {
			warn "Unable to determine Debconf key (regex '^cn=(\\S+?),') " .
				"from DN '$dn'\n";
			return LDAP_OPERATIONS_ERROR
		}

		# Great. We in game like snail in his house.

		# To be able to ask a question, we need to load the config entry
		# corresponding to the template. All 'c'-prefixed variables are 
		# config parts of the template.
		my $cdn= $dn;
		my( $ret, %ret, $centry);

		# Try and see if mapping from template to config DN succeeds.
		if( $cdn=~ s/$$pr[0]/$$pr[1]/) {
			$ret= $this->dn2leaf( $cdn, \%ret, qw/entry 1/);
		}

		if( !defined $ret) {
			warn 'Return value undefined; missing successful addPrompt '.
				'definitions in config file?\n';
			return LDAP_OPERATIONS_ERROR
		}

		# If no config entry found, even after looping over all configured 
		# template -> config regex replacements, bail out. Regularly, this
		# should not happen as Debconf saves first config then template, so
		# config should already be there. If this happens, maybe the 
		# addPromptMap did not make a correct substitution to derive the
		# config key name.
		if( $ret!= LDAP_SUCCESS) {
			p "Can't load template's corresponding config '$cdn' ($ret)";
			return $ret
		}

		# We've got the config entry.
		$centry= $ret{entry}; 

		# Do not show prompts for questions of irrelevant type (where no user
		# input is expected). But, do relocate such questions automatically to
		# site-level.
		if( $entry->{attrs}->{type}=~ /^(note|title|error)$/) {
			$this->relocate( $entry, 'Site');
			$this->relocate( $centry, 'Site');
			return LDAP_SUCCESS
		}

		# A by-the-way commentary: we manage to get Debconf running on server
		# side and not interfering with the host's regular Debconf by initializing
		# it with a custom config and Pipe driver, and feeding data about questions
		# that have to be asked via the pipe.
		# Also, this Debconf instance keeps running all the time along with
		# slapd server, it is not re-started on every question, first because
		# it would be many times slower, and second because it's not even possible
		# to do (re-initializing debconf multiple times within the same process is
		# a terrible problem).

		# Pointers from DN to template/config entry attributes, ready for loading
		# the data into Debconf Pipe cache, by reusing function for the same thing
		# in LDAP.pm
		my $et= { $dn  => $entry->{attrs}};
		my $ec= { $cdn => $centry->{attrs}};

		# Load config template and entry into Pipe's cache.
		Debconf::DbDriver::LDAP::parse_records( $dt, $et);
		Debconf::DbDriver::LDAP::parse_records( $dc, $ec);

		# Names of keys we'll check for determining if and where to relocate
		# the just-added config and template.
		# NOTE: Do not use separate fields for question/template location,
		# we used to do that but it's more annoying than really useful. To
		# enable it back, look for commented lines with comment "NO SPLIT".
		#my $tkey= 'debconf-ldap/template-location'; # NO SPLIT
		my $ckey= my $tkey= 'debconf-ldap/config-location';

		# Load previous values for later change detection.
		my $oldval=  $dm->command_get( $key);
		#my $oldtkey= $dm->command_get( $tkey); # NO SPLIT
		my $oldckey= my $oldtkey= $dm->command_get( $ckey);

		# Make sure the questions (the real question and relocation
		# questions) are always asked.
		$dm->command_fset( $key,  'seen', 'false');
		#$dm->command_fset( $tkey, 'seen', 'false'); # NO SPLIT
		$dm->command_fset( $ckey, 'seen', 'false');

		# Ask the actual question, plus subquestions where to relocate the
		# template and config entry. (On sophisticated frontends, i.e.
		# Gnome, all questions are asked in the same window due to 
		# common begin/end block, making this wonderful).
		$dm->command_beginblock;
		$dm->command_input( 'high', $key);
		$dm->command_input( 'high', $ckey);
		#$dm->command_input( 'high', $tkey); # NO SPLIT
		$dm->command_endblock;

		# Go.
		$dm->command_go;

		# New values, after answering.
		my $newval=  $dm->command_get( $key);
		my $newtkey= 'Host'; #$dm->command_get( $tkey); # NO SPLIT, XXX Site?
		my $newckey= $dm->command_get( $ckey);

		# A little beautiful hack to hide the Gnome window that stays open
		# (but unusable!) until the next question is to be asked.
		$df->win->hide;
		Gtk2->main_iteration while Gtk2->events_pending;

		# Save updated entry to the location where it was originally added.
		# (Most probably, the host level.)
		if( "$oldval" ne "$newval") { # Quotes force string comparison
			$centry->replace( value => $newval);
			$this->save( $cdn, $centry);
		}

		# Relocate if relocation requested.
		$this->relocate( $entry, $newtkey) if $newtkey ne 'Host';
		$this->relocate( $centry, $newckey) if $newckey ne 'Host';

		last # One prompter run per entry is enough, of course.

	} # WHILE my( $ps, $pr)

	# Now that the Debconf question has been asked and completely dealt
	# with, remove it from the memory cache.
	if( $key and $dt->{exists}->{$key}) {
		undef $dt->{cache}->{$key};
		$dt->{exists}->{$key}= 0;
		undef $dc->{cache}->{$key};
		$dc->{exists}->{$key}= 0;
		# XXX config option to select whether saveloc is always reinitialized
		# or set to last-state.
	}

	LDAP_SUCCESS
}

# Move entry from place to place on the filesystem.
# $loc should be one of pre-configured relocation regexes.
sub relocate {
	my( $this, $entry, $loc)= @_;

	my $dn= $entry->dn;
	my $newdn= $dn;

	$loc||= 'Site';

	# NOTE: Delete is disabled in default configurations. (To enable, add
	# "Delete" under Choices: for the template/config-location templates).
	if( $loc eq 'Delete') {
		$this->delete( $dn);
		return LDAP_SUCCESS
	}

	# If the relocation rule is defined, go through the whole cycle.
	# If not, we'll re-save the entry to its existing place.
	# (Relocation rule is not defined for location=Host (since that's
	# effectively no relocation), but we still want to re-save the
	# entry with appropriate 'variables' removed.)
	if( exists( $this->{addrelocate}->{$loc})) {
		my( $a, $b)= @{$this->{addrelocate}->{$loc}};

		unless( $newdn=~ s/$a/$b/) {
			warn sprintf("Regex for '%s' does not apply (%s=~ s/%s/%s/), skipping relocation\n", $loc, $dn, $a, $b);
			return LDAP_SUCCESS
		}
	}

	# Finally, save, and delete old entry if it was relocated. (If saving
	# fails, the old entry is kept.)
	$entry->dn( $newdn);
	my $ret= $this->save( $newdn, $entry,
		$newdn eq $dn ? ( overwrite => 1) : ());
	if( $ret!= LDAP_SUCCESS) {
		warn "Can't relocate '$dn' to '$newdn' ($ret), keeping it in place\n";
		$entry->dn( $dn);
		return LDAP_SUCCESS
	}
	$this->delete( $dn) if $newdn ne $dn;

	LDAP_SUCCESS
}

# In the beginning, there were no overlay options supported, i.e. you
# could only specify $ exp $ .... , but to support caching etc., the need
# arose to be able to specify something like $ exp cache 10min $ ....
# Therefore, this routine should be called after overlay name is stripped,
# and it'll parse the options and do eventual adjustments on the values.
sub ovl_options {
	my( $this, $ovl, $opts)= @_;

	my @opts= split /\s+/, $opts;
	# XXX break if @opts!= even num

	unshift @opts, @{ $this->{overlayconfig}{$ovl}}
		if exists $this->{overlayconfig}{$ovl};

	unshift @opts, @{ $this->{overlayconfig}{default}}
		if exists $this->{overlayconfig}{default};
	
	my @newopts;

	# Implemented as while() and not for(i;i<@opts;i++) so that
	# we could support variable-number arguments.
	while( my $opt= shift @opts) {

		# If it's a cache time specfication, it accepts either number of
		# seconds or number of uses. Make sure time spec is converted to
		# seconds, and that the queue to place the key in is properly
		# named, and that it exists (create if not).
		if( $opt eq 'cache' and $this->{enablecache}) {
			my $spec= shift @opts;
			
			$this->parse_cache_opt( $ovl, $spec);

			# Onto @newopts, add cacheref which is a direct pointer to the queue
			# in question that the caller can query to see if the cached value
			# is in there.
			# We unshift here so that any manual specs in the entry always
			# would override our values dereived here. The override will elegantly
			# happen when @newopts is turned to a hash on the receiver end,
			# i.e. %opts= $this->ovl_options( $optspec).
			unshift @newopts, 'cacheref', $this->{cache}{$ovl}{$spec};

			# Push could be done outside of per-option block, but the way we do it
			# here, we can achieve the option to be ignored if the top if() doesn't
			# match (if say, caching is disabled with enableCache 0).
			# XXX Note that we push original $spec here, not the processed one,
			# even if we did process it to extract expiry time etc. It's left
			# to see what is more useful.
			push @newopts, $opt, $spec;

		# If it's prefix= (file prefix), remove any [./]+ at the beginning
		# of file spec.
		} elsif( $opt eq 'prefix') {
			my $val= shift @opts;
			$val=~ s{^[\./]+}{};
			$val=~ s{\.\.+}{\.}g;
			push @newopts, $opt, $val;

		# Conditional
		} elsif( $opt eq 'if') {
			push @newopts, $opt, [ (shift @opts), (shift @opts)];

		} else {
			# Default action -- just pass option on
			push @newopts, $opt, (shift @opts)
		}
	}

	# We return an array, but it is required that the caller 
	# takes it as a hash.
	@newopts
}

sub parse_cache_opt {
	my( $this, $ovl, $n)= @_;

	return if not $n;

	unless( $n=~ /^\d+$/) {
		warn "Invalid cache value '$n' for '$ovl' (expected a number of operations)\n";
		return
	}

	pcd "Parsed cache validity '$n' for ovl $ovl";

	# Create queue if it doesn't exist yet.
	if( not defined $this->{cache}{$ovl}{$n}) {
		$this->{cache}{$ovl}{$n}= {};
		$this->{'op_cache_valid'}{$ovl}{$n}= $n;
		pc "Created cache queue $ovl-$n ($n operations)";
	}

	$n
}

# This function became necessary when it became possible for direct-entry
# functions (sub search, sub modify etc.) to result in calling each other
# recursively (we needed to control looping depth), and later, it was also
# necessary for the functions to know if they're direct entry or not, so that
# they can clean or keep per-operation cache.
sub setup_state {
	my( $this, $arg)= @_;

	# hashref as last arg identifies we're re-invoking search from backend,
	# that is, it's not a direct call from slapd.
	# We keep track of how many loops we've done via $this->{level}.
	if( ref $$arg[@$arg-1]) {
		pop @$arg;
		$this->{level}++;

	# If here, means we are entering a new search from slapd
	} else {
		$this->{level}= 0;
		$this->{start}= []; # (Start times of earlier nested searches are stale)

		# Trim cache when needed
		# XXX this being a hash means you cant guarantee order of
		# cache expiry if a line uses two caches. Btw, is it possible
		# that a line uses two caches in the first place, and does the
		# order matter?
		while( my( $ovl, $ovlref)=
			each %{ $this->{op_cache_valid}}) {

			for my $n( keys %{ $ovlref}) {
				if( --$ovlref->{$n}< 1) {
					pc "Clearing $ovl op cache ($n ops)";
					$this->{cache}{$ovl}{$n}= {};
					$ovlref->{$n}= $n;
				}
			}
		}
	}

	$this->{start}[ $this->{level}]= time;
}

#
# Debconf stuff for server-side prompting
#

# Debconf initializer function. Initially, the idea was to (re)initialize
# debconf on every run, but as things progressed and the overall design
# improved, it became possible to initialize debconf just once and keep it
# running. (Which is great, because re-initializing debconf without exiting
# the program does not work for the most part anyway ;-)
sub debconf_initialize {
	my( $this)= @_;

	# Loaded only when the prompter is enabled, so that the server can run on
	# machines without Debconf.
	$ENV{DEBCONF_SYSTEMRC}= '/etc/debconf.conf.pipe';
	unless( -r $ENV{DEBCONF_SYSTEMRC}) {
		warn "enablePrompt: can't read '$ENV{DEBCONF_SYSTEMRC}'\n";
		return LDAP_OTHER
	}
	unless( eval {
		require Debconf::Db;
		require Debconf::Config;
		require Debconf::AutoSelect;
		require Debconf::Format::822;
		require Debconf::DbDriver::LDAP;
		1
	}) {
		warn "enablePrompt: can't load Debconf modules ($@)";
		return LDAP_OTHER
	}

	# Set up minimal valid debconf state (in the end, it'll contain
	# the fixed contents below + the template/config of the question
	# it gets to ask).
	$cin= qq{
Name: debconf/frontend
Template: debconf/frontend
Value: Gnome
Owners: debconf
Flags: seen

Name: debconf-ldap/template-location
Template: debconf-ldap/template-location
Value: Site
Owners: debconf-ldap
Flags: seen

Name: debconf-ldap/config-location
Template: debconf-ldap/config-location
Value: Site
Owners: debconf-ldap
Flags: seen
};

	$tin= qq{
Name: debconf/frontend
Choices: Dialog, Readline, Gnome, Kde, Editor, Noninteractive
Default: Dialog
Description: Interface to use:
Extended_description: Packages that use debconf for configuration share a common look and feel. You can select the type of user interface they use.\n\nThe dialog frontend is a full-screen, character based interface, while the readline frontend uses a more traditional plain text interface, and both the gnome and kde frontends are modern X interfaces, fitting the respective desktops (but may be used in any X environment). The editor frontend lets you configure things using your favorite text editor. The noninteractive frontend never asks you any questions.
Type: select
Owners: debconf/frontend

Name: debconf-ldap/template-location
Type: select
Choices: Host, Site, Global
Default: Site
Description: Specify template save location:

Name: debconf-ldap/config-location
Type: select
Choices: Host, Site, Global
Default: Site
Description: Specify value save location:
};

	# Automagically works due to /etc/debconf.conf.pipe (needed as part
	# of the setup).
	{ no warnings 'once';
		open CIN,  '<', \$cin;
		open COUT, '>', \$cout;
		open TIN,  '<', \$tin;
		open TOUT, '>', \$tout;
	}

	# Okay, power it up
	Debconf::Db->load;

	$dc= Debconf::DbDriver->driver( Debconf::Config->config);
	$dt= Debconf::DbDriver->driver( Debconf::Config->templates);

	$df= Debconf::AutoSelect::make_frontend();

	$dm= Debconf::AutoSelect::make_confmodule();

	LDAP_SUCCESS
}


# Comparing attribute values. slapd passes the assertion as "attr=value".
# The entry is loaded with load(), so dynamic values are compared the same
# way as they would be returned by SEARCH, and matching is done in the
# same way as for search filters.
sub compare {
	my( $this, $dn, $avaStr)= @_;

	$this->setup_state( \@_);

	$this->normalize( \$dn);

	my( $attr, $value)= split /=/, $avaStr, 2;

	DEBUG and p "COMPARE '$dn' $attr";

	# Values of protected attributes can't be tested (see 'protectAttrs')
	return LDAP_INSUFFICIENT_ACCESS
		if $this->attr_in( $attr, $this->protected_attrs);

	my( $ret, undef, undef, $entry)= $this->load( $dn, qw/entry 1/);
	return $ret unless $ret== LDAP_SUCCESS;

	return LDAP_NO_SUCH_ATTRIBUTE unless $entry->exists( $attr);

	my $filter= Net::LDAP::Filter->new(
		"($attr=". escape_filter_value( $value). ')');
	return LDAP_OTHER unless $filter;

	$this->filter_match( decode_utf8_deep( $filter), $entry) ?
		LDAP_COMPARE_TRUE : LDAP_COMPARE_FALSE
}

# Renaming/moving entries. slapd passes DN, new RDN, deleteoldrdn flag, and
# optionally the new superior DN.
# Like DELETE, this operates on actual entries, not taking fallbacks into
# account. Only leaf entries can be renamed, since entries below would
# keep their old DNs.
sub modrdn {
	my( $this, $dn, $newrdn, $delFlag, $newsup)= @_;

	# RDN values as given, to be added to the entry in original case
	my @newavas= $this->rdn_avas( $newrdn);
	return LDAP_INVALID_DN_SYNTAX unless @newavas and $newrdn!~ /^\s*$/;

	$this->normalize( \$dn);
	$this->normalize( \$newrdn);

	my( $oldrdn, $parent)= split /,/, $dn, 2;
	if( defined $newsup and length $newsup) {
		$this->normalize( \$newsup);
		$parent= $newsup;
	}
	my $newdn= ( defined $parent and length $parent) ?
		"$newrdn,$parent" : $newrdn;

	DEBUG and p "MODRDN '$dn' -> '$newdn'";

	# Can't be moved under itself
	return LDAP_UNWILLING_TO_PERFORM
		if defined $parent and ( $parent eq $dn or $parent=~ /,\Q$dn\E\z/);

	# Same DN, i.e. with RDN value in other case: only values are updated
	my $same= $newdn eq $dn;

	my( $ret, %ret, %new);

	$ret= $this->dn2leaf( $dn, \%ret, qw/entry 1/);
	return $ret unless $ret== LDAP_SUCCESS;
	my( $entry, $file)= @ret{qw/entry file/};

	$ret= $this->dn2leaf( $dn, \%ret, qw/leaf 0 namesonly 1 verify 1/);
	return $ret unless $ret== LDAP_SUCCESS;
	my $directory= $ret{directory};

	if( defined $directory and !$same) {
		opendir my $dh, $directory or return LDAP_OPERATIONS_ERROR;
		my @children= grep { !/^\.\.?$/} readdir $dh;
		closedir $dh;
		return LDAP_NOT_ALLOWED_ON_NONLEAF if @children;
	}

	unless( $same) {
		$ret= $this->dn2leaf( $newdn, \%new, qw/leaf 0 namesonly 1 verify 1/);
		return $ret unless $ret== LDAP_SUCCESS;
		return LDAP_ALREADY_EXISTS if defined $new{file};
	}

	# Update RDN attribute values
	if( $delFlag) {
		for( $this->rdn_avas( $oldrdn)) {
			my( $oldattr, $oldval)= @$_;
			my @keep= $this->values_except( $entry, $oldattr, $oldval);
			if( @keep) { $entry->replace( $oldattr=> [ @keep]) }
			else       { $entry->delete( $oldattr) }
		}
	}

	for( @newavas) {
		my( $attr, $val)= @$_;
		$entry->add( $attr=> $val) unless
			$this->has_rdn_value( $entry, "$attr=". escape_dn_value( $val));
	}

	$entry->dn( $newdn);

	$ret= $this->save( $newdn, $entry, overwrite => $same);
	return $ret unless $ret== LDAP_SUCCESS;
	return LDAP_SUCCESS if $same;

	unlink $file or return LDAP_OPERATIONS_ERROR;
	rmdir $directory if defined $directory;

	LDAP_SUCCESS
}

# slapd (back-perl) terminates if the backend dies, so errors in operations
# called by slapd are caught here and returned as LDAP_OTHER. (Internal
# calls, marked by a trailing hashref, are not wrapped.)
for my $op( qw/config init search add modify delete modrdn compare bind/) {
	no strict 'refs';
	no warnings 'redefine';
	my $code= \&$op;
	*$op= sub {
		return $code->( @_) if @_> 1 and ref $_[-1] eq 'HASH';
		my @ret= eval { $code->( @_) };
		return wantarray ? @ret : $ret[0] unless $@;
		( my $err= $@)=~ s/\s+$//;
		warn "Internal error in $op: $err\n";
		LDAP_OTHER
	};
}

# Entry, as seen by Net::LDAP::FilterMatch in filter_match(): values that
# are valid UTF-8 are decoded into characters, and values of an attribute
# description include those of its subtypes with options (i.e. 'cn' those
# of 'cn;lang-en', RFC 4512 2.5.2).
package DynLDIF::CharEntry;

sub new    { my( $class, $entry)= @_; bless { entry=> $entry}, $class }
sub exists { scalar( () = $_[0]->raw_values( $_[1])) ? 1 : 0 }
sub dn     { DynLDIF::decode_utf8_deep( $_[0]{entry}->dn) }

sub get_value {
	my( $this, $attr)= @_;
	map { DynLDIF::decode_utf8_deep( $_)} $this->raw_values( $attr)
}

sub raw_values {
	my( $this, $attr)= @_;
	my $entry= $this->{entry};

	# (Usually there are no options in the entry)
	$this->{options}//= ( List::MoreUtils::any { index( $_, ';')>= 0} $entry->attributes) ? 1 : 0;
	return $entry->get_value( $attr) unless $this->{options};

	my( $type, @opts)= split /;/, lc $attr;
	my $all= $entry->get_value( $type, alloptions=> 1) or return;
	map { @{ $all->{$_}} } grep {
		my %has= map { lc $_=> 1} split /;/;
		List::MoreUtils::all { $has{$_}} @opts
	} sort keys %$all
}

1
