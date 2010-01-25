use Test::More tests => 3;
BEGIN { use_ok('RDF::ACL') };
use Error qw(:try);

my $acl = RDF::ACL->new;

$acl->allow(
	'webid'     => ['http://example.com/joe#me'],
	'item'      => 'http://example.com/private/document',
	'level'     => ['read']
	);

$acl->i_am('http://example.com/joe#me');

is($acl->who_am_i, 'http://example.com/joe#me',
	"who_am_i works");

# This is supposed to fail!
try
{
	$acl->allow(
		'webid'     => ['http://example.com/joe#me'],
		'item'      => 'http://example.com/private/document',
		'level'     => ['write']
		);
}
catch Error::Simple with
{
	my $e = shift;
	ok($e, "$e");
}

$acl->i_am(undef);

# This is not supposed to fail!
ok($acl->allow(
		'webid'     => ['http://example.com/joe#me'],
		'item'      => 'http://example.com/private/document',
		'level'     => ['control']
		),
	"");
