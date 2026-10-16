# slapd-perl-dynldif: Dynamic LDIF Backend for OpenLDAP

`slapd-perl-dynldif` is a flexible database backend for OpenLDAP. It has been in use since 2008.

It implements all the usual LDAP operations, as well as provides elaborate features for responding with dynamic and auto-computed data on a level not seen in traditional LDAP installations.

## Quick Start

1. Install system dependencies:

```sh
apt install slapd libfile-find-rule-perl libnet-ldap-perl libtext-csv-xs-perl liblist-moreutils-perl
```

2. Obtain and run DynLDIF with an example config file that provides suffix `dc=example,dc=com`:

```sh
cd /etc/ldap
git clone https://github.com/crystallabs/slapd-perl-dynldif

/usr/sbin/slapd -d 256 -f ./slapd-perl-dynldif/etc/ldap/slapd.conf
```

3. While the server is running, load example data into the tree:

```sh
ldapadd -x -D cn=admin,dc=example,dc=com -w nevairbe -c -f slapd-perl-dynldif/ldifs/example.ldif
```

4. And query the added data:

```sh
ldapsearch -x -b dc=example,dc=com
```

That's it for the most basic example.

## Overview

`slapd-perl-dynldif` is a custom backend for OpenLDAP built on top of OpenLDAP's `slapd-perl`.

It stores the directory tree in files and directories on disk, by default under `/var/lib/ldap/dynldif/`.

It can be used as a normal backend &mdash; reading and writing data is just the same as for any backend.
However, its primary use is for LDAP trees which contain highly dynamic data and where elaborate and configurable server-side behavior is needed.

Dynamic functions possible with `slapd-perl-dynldif` are:

1. ADD operation can overwrite existing entries without throwing an error
1. ADD operation can ignore adds for entries which already exist without throwing an error
1. DN of new entries can be modified (entries can be "relocated") before they are saved
1. When adding Debconf templates, a prompt can be opened on a remote machine, asking the admin for Debconf answer
1. When MODIFYing entries, no-ops can be detected and no changes made
1. When MODIFYing (and in combination with other functionality), Copy on Write is supported
1. DELETE can be allowed to delete whole subtrees if entries to delete are non-leaves
1. SEARCH queries can be arbitrarily rewritten
1. SEARCH can fallback to multiple other locations if no results are found
1. Attribute values can expand to content of disk files
1. Attribute values can expand to value of other entries and attributes
1. Attribute values can expand to value of another SEARCH
1. Attribute values can evaluate Perl code
1. Returned entries can be appened with additional attributes or values in various ways

## Configuration Reference

Each database backed by DynLDIF should be configured with something similar to the following block in `slapd.conf`:

```
database           perl
suffix             "dc=example,dc=com"
perlModulePath     "/etc/ldap/slapd-perl-dynldif"
perlModule         "DynLDIF"

directory          "/var/lib/ldap/dynldif/"
treesuffix         "dc=example,dc=com"
```

The first four lines are required by `slapd` and its `back-perl` backend
to configure the suffix and initialize DynLDIF.

The last two lines are required by the DynLDIF backend. The value of
`treesufix` must be equal to `suffix`.
This small duplication cannot
be avoided because `suffix` directive is consumed by `slapd` and is not
passed onto our backend.

After the above standard lines, the following directives can be used:

### Configuration Directives

The list is split into simple and complex directives, simple first.

Within each group, the list is sorted alphabetically, with each heading specifying configuration
directive name and its usage syntax.

Where applicable, the first value listed indicates the default value.

#### Simple Configuration Directives

##### addIgnoredups 0|1

Specify whether LDAP ADD operation should ignore adds on existing entries
without throwing LDAP_ALREADY_EXISTS error. Applicable if `addoverwrites` is 0.

##### addOverwrites 0|1

Specify whether LDAP ADD operation should overwrite existing entries
without throwing LDAP_ALREADY_EXISTS error.

##### cacheRead SPEC

Specify for how many LDAP operations to cache LDIF reads from disk.
No specification implies no cache.

SPEC can be:

```
X    - X LDAP operations
```

Overall best value, which minimizes risk of serving stale data while reaching
noticeable optimization improvement (up to 25%), is 1 operation, specified as `1`.

`cacheRead` and `overlayConfig` cache can be used together, amplifying the effect.

##### clean

Invoke removal of all saved stack files from disk.

##### deleteTrees 0|1

Specify whether DynLDIF should allow deleting non-leaf elements (deleting
the entry and everything under it in one go).

See notes for DELETE under "LDAP Operations - Notes".

##### enableBind 0|1

Whether to allow binding as entries under this suffix. By default this
is disabled.

See notes for BIND under "LDAP Operations - Notes".

##### extension .ldif

Specify file extension to use when storing server data on disk.

DynLDIF's data is kept in a directory tree that corresponds to the LDAP
tree, where DN components are directories, and leaf nodes are files.
Each file contains one LDAP entry in LDIF format.

File extension must be specified to make directories distinguishable
from files, and the default value should rarely be changed.

##### load FILE [PATTERN REPLACEMENT ...]

Load and process configuration stack from FILE.
FILE is always relative to suffix base directory.

If list of PATTERN REPLACEMENTS is specified, the s/PATTERN/REPLACEMENT/
substitution is done on all loaded lines before sending them to the
config processor.

Example: `load default_opts`

##### message TEXT

Print TEXT to the log. The log will be a console if slapd is started
with option -d (such as -d 256) to run in the foreground.

Example: `message Test`

##### modifyCopyOnWrite 1|0

When a MODIFY request is issued for an entry that does not really exist 
(i.e. it comes from a fallback), specify whether DynLDIF should copy the
entry to the expected location and then modify it, or return
LDAP_NO_SUCH_OBJECT.

##### modifySmarts 1|0

Specify whether DynLDIF should ignore MODIFY requests that do not result
in any real change within the entry.

This is useful to enable to detect "no-op" modifications and
avoid writing to disk, preserving meaningful modification timestamps
on existing entries.

##### parse 1|0

Specify whether in the lines that follow, variable and directive expansion
should be performed.

This includes expanding ${variable} to variable values and %{directive} to
configuration directive values.

##### reset

Reset current stack in memory to empty list.

##### save FILE

Save current stack to FILE, always relative to suffix base directory.

Example: `save default_opts`

##### schemaFatal 0|1

Specify whether a missing or inaccessible schemaLDIF file should trigger
a fatal error.

It is vital for DynLDIF to be aware of server's schema (which comes from
the `schemaLDIF` config option). The server won't work optimally if the schema
file in LDIF format is missing, or is not up to date with the server's schema.

However, we issue a warning and allow startup without it, because you are
then expected to use <i>scripts/schema.pl</i> to connect to the
server right away and obtain the schema in LDIF format, saving it to the
expected location. Then, restart the server to pick it up.

This must be done because the server's schema is not available to `slapd-perl`.

`schemaFatal` value should be set to 1 when you are sure you do
have the `schema.ldif` file in the correct location.

##### schemaLDIF FILE

Specify location of server's schema in a single file, in LDIF format.

See the previous option for more info.

Note that the schema in LDIF format does not eliminate the need to have the
real schema files in `/etc/ldap/schema/*.schema`. Schema files are read by
slapd, and schema LDIF file is read by DynLDIF. LDIF is created on the 
basis of real schema files, and at all times, DynLDIF's LDIF schema should
be in sync with slapd.

Example: `schemaLDIF /etc/ldap/schema/schema.ldif`

##### treeSuffix SUFFIX

This value should always match the value of `suffix` configured for the database.

This small duplication cannot
be avoided because `suffix` directive is consumed by `slapd` and is not
passed onto our backend.

##### var VARIABLE "VALUE STRING"

Assign "VALUE STRING" to variable VARIABLE. Variables, in this context,
are visible only within the suffix where they are defined, and their value
is expanded with ${variable} if option "parse" is enabled.

#### Complex Configuration Directives

##### addPrompt

##### addRelocate

##### entryAppend ATTRIBUTE PATTERN ... -&gt; attr ATTRIBUTE [ATTRATTR [ATTR...]]
##### entryAppend ATTRIBUTE PATTERN ... -&gt; append PATTERN REPLACEMENT [ATTR...]

Specify an `entryAppend` rule, allowing adding extra attributes into an entry
before returning it to the client.

When all ATTRIBUTE-PATTERN pairs match, DynLDIF looks to append the entry with
a set of default attributes.

The entry from which to import the attributes can be specified in two ways:

1. With "attr ATTRIBUTE" (usually "attr seeAlso"). In that case,
the attribute `seeAlso` is looked up in the current entry. It is expected
to contain the DN of the entry whose attributes should append the current entry.

If ATTRATTR and ATTRs are unspecified, the entry is appended with
all allowed attributes. Otherwise, it is appended only with attributes
listed in the ATTRATTR attribute within the entry and/or in the literal
list of ATTRs.

2. With "append PATTERN REPLACEMENT", where s/PATTERN/REPLACEMENT/ is
performed on the original DN, and the result is used as the entry from which
to pull the extra attributes.

With the 'append' method, there is no ATTRATTR field, so you cannot append
the entry with the values of attributes listed in the entry, but you do
have the option of specifying ATTRs to append with.

If left unspecified, the entry is appended with all allowed attributes.

Examples:

```
entryAppend  objectClass "^dhcpHost$"                      \
             ->                                            \
             append .+ cn=dhcpHost,ou=objectClasses,ou=defaults

entryAppend  objectClass "^dhcpSubnet$"                    \
             ->                                            \
             append .+ cn=dhcpSubnet,ou=objectClasses,ou=defaults

entryAppend  dn          "^cn=default,ou=networks"         \
             objectClass "^ipNetwork$"                     \
             ->                                            \
             attr seeAlso
```

##### exp MATCH_REGEX NON_MATCH_REGEX

Specify regexes that each entry DN must and must not match respectively, to have
overlay "exp" run on its attributes.

The "exp" overlay enables expansion into values of other attributes, in the
current or other entry.

Example which always matches, and so enables the `exp` overlay: `exp  .   ^$`

##### file MATCH_REGEX NON_MATCH_REGEX

Specify regexes that each entry DN must and must not match respectively, to have
overlay "file" run on its attributes.

The "file" overlay enables expansion into values of on-disk files, always
relative to the suffix base directory.

Example: `file  .   ^$`

##### find MATCH_REGEX NON_MATCH_REGEX

Specify regexes that each entry DN must and must not match respectively, to have
overlay "find" run on its attributes.

The "find" overlay enables internal re-invocation of the search function, 
and using the values retrieved in constructing the original value.

This overlay shares many similarities with "exp", but contains a crucial
difference -- with "exp", you generally know where the entry and attribute
to expand to are located. With "find", you generally don't, so you perform
a search to find them.

Example: `find  .   ^$`

##### loadDump FILE

THIS IS A DEBUG OPTION .

Load direct Perl Storable dump of configuration hash from FILE, always
relative to the suffix base directory.

This is an advanced option that should not be called from slapd.conf.

It is intended for scenarios where DynLDIF is at least once initialized by slapd
(and configured via slapd.conf), and config then dumped as Storable object
using saveDump.

After that, you can run DynLDIF "standalone", directly under the Perl
interpreter using <i>scripts/dynldif.pl</i>, and instead of re-parsing
slapd.conf for configuration, simply send "loadDump FILE" to the config
processor, to load the exact state as had by slapd/DynLDIF.

This is almost always needed only when you want to run DynLDIF under the Perl
interpreter directly, to specify Perl debug or profiling options.

##### overlayConfig OVERLAY OPTION VALUE ...

Specify default overlay options.

OVERLAY can be an overlay name (perl, exp, file, find) or "default".

OPTION can be "cache", "prefix" or "if".

	cache SPEC - specify cache expiry time.

	Caching overlay results improves performance enormously in situations
	where multiple entries are returned and all produce the same dynamic
	values for certain attributes.

	In such cases, operations of complexity O(n) are reduced to O(1) level.

	Syntax is the same as listed under "cacheRead", and 1o is again the
	overall best setting.

	NOTE: due to deficiencies in Memoize::Expire module, time- and
	uses-based methods of expiry do not work correctly when caching non-scalar
	values (such as multiple values for an attribute). It is therefore suggested
	to always use the number-of-operations cache (like 1o).

	Example: cache 1o

	prefix PREFIX - generic prefix option, used where applicable. Currently
	only the "file" overlay honors it, where it is a prefix to prepend on
	all file specifications.

	Directory separator is not added automatically,
	so to prefix with a directory, include "/" at the end.

	Example: prefix subdir/

##### perl MATCH_REGEX NON_MATCH_REGEX

Specify regexes that each entry DN must and must not match respectively, to have
overlay "perl" run on its attributes.

By default, Perl overlay is disabled as it is in fact an interface for
"eval", and is considered dangerous. To activate it, open DynLDIF.pm and
enable constant PERLEVAL.

Example: `perl  .   ^$`

##### saveDump FILE

THIS IS A DEBUG OPTION .

Save direct Perl Storable dump of configuration hash to FILE, always
relative to the suffix base directory.

This is an advanced option that should usually be called as the last
line of slapd.conf configuration for a particular suffix.

This is almost always needed only when you want to run DynLDIF under the Perl
interpreter directly, to specify Perl debug or profiling options.

##### searchFallback PATTERN REPLACEMENT

Specify search fallback rule, effectively implementing default entries.

When a specific search base is requested, and it does not exist in the searched
location, it is possible to fallback to a chain of default entries. The first
entry found wins.

Examples: defaulting to site-wide and global defaults

```
# Fallback 1: site defaults tree.
searchFallback  cn=.[^,\\s]+,ou=hosts         ou=hosts,ou=defaults
searchFallback  cn=.[^,\\s]+,ou=templates     ou=templates,ou=defaults

# Fallback 2: global defaults tree.
searchFallback  cn=.[^,\\s]+,ou=hosts,.+      ou=hosts,ou=defaults
searchFallback  cn=.[^,\\s]+,ou=templates,.+  ou=templates,ou=defaults
```

##### searchSubst KEY PATTERN ... -&gt; KEY PATTERN REPLACEMENT ...

Specify searchSubst rule, allowing rewrite of any part of the search
request.

When the incoming search request matches all KEY PATTERN pairs, DynLDIF
performs the specified KEY=~ s/PATTERN/REPLACEMENT/ actions to rewrite
the incoming search.

Search rewriting is completely free-form, and it is possible to rewrite searches to a completely different DynLDIF suffix, as long as both are located in the same base directory.

This is a legitimate feature of the rewrite model, and is officially used to
rewrite incoming DHCP search queries under ou=dhcp to appropriate places
and with appropriate options under ou=clients.

KEY can be one of base, scope, deref, size, time, filter, attrOnly. Rewriting
one last element of a search, the list of attributes to return, is currently
not possible, but the feature is on the way.

Examples: rewriting ou=dhcp to ou=clients

```
Example 1:

# Solve lack of flexibility in ISC DHCP3 LDAP patch by
# plainly specifying ldap-base-dn "ou=dhcp" in DHCP's
# config, and then here, rewriting DHCP ethernet address
# lookup to the ou=clients tree under which all clients
# are defined.

searchSubst  base        "^ou=dhcp$"                       \
             filter      "^\\(&\\(objectClass=dhcpHost\\)\\(dhcpHWAddress=ethernet [\\dabcdef:]+\\)\\)$" \
             -&gt;                                            \
             base   .+   ou=clients


Example 2:

# Solve lack of flexibility in ISC DHCP3 LDAP patch by
# rewriting a search in any shared network, tree
# ou=dhcp, to a proper location,

searchSubst  base        "^ou=\\w+,ou=dhcp$"                \
             scope       "^1$"                             \
             filter      "^\\(objectClass=\\*\\)$"         \
             -&gt;                                            \
             base   .+   "ou=clients"                      \
             filter .+   "(&amp;(objectClass=dhcpSubnet)(!(cn=default)))" \
             scope  .+   2
```


## LDAP Operations - Notes

1. BIND operation is supported, but only in a trivial way. Therefore, binding using a DN under this part of DIT is not encouraged nor enabled by default unless `enable_bind 1` is present in the config file. It is expected that users should authenticate using some other suffixes or via e.g. GSSAPI, so that this `bind()` is never called or needed.

1. DELETE operation is supported, but does not receive an indication from OpenLDAP whether subtree delete was requested or not. Therefore, currently the way to control whether a DELETE will delete whole subtrees or refuse to work on non-leaf values is controlled using the config option `deleteTrees`.
