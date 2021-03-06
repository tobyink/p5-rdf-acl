use Test::More tests => 8;
use RDF::ACL;

my $acl = RDF::ACL->new;

ok(!$acl->check(
		'http://example.com/joe#me',
		'http://example.com/private/document',
		'Read'),
	"by default, deny access"
	);

my $authid = $acl->allow(
	'webid' => ['http://example.com/joe#me'],
	'item'  => 'http://example.com/private/document',
	'level' => ['read']
	);

ok($acl->check(
		'http://example.com/joe#me',
		'http://example.com/private/document',
		'Read'),
	"allow and check seem to work"
	);

my $proper = <<CANON;
<$authid> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://www.w3.org/ns/auth/acl#Authorization> .
<$authid> <http://www.w3.org/ns/auth/acl#accessTo> <http://example.com/private/document> .
<$authid> <http://www.w3.org/ns/auth/acl#agent> <http://example.com/joe#me> .
<$authid> <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .
CANON
$proper =~ s/\r?\n/\r\n/g;

is($proper, $acl->save(RDF::Trine::Serializer::NTriples::Canonical->new), "graph generated by allow seems good");

my @reasons = $acl->why(
	'http://example.com/joe#me',
	'http://example.com/private/document',
	'Read'
	);

is(1, scalar @reasons, "why seems to work");

my $reason = $reasons[0];

is($authid, $reason, "why seems sane");

is(4, $acl->deny($reason), "deny seems to work");

is(0, $acl->model->count_statements, "deny removes triples");

ok(!$acl->check(
		'http://example.com/joe#me',
		'http://example.com/private/document',
		'Read'),
	"deny works"
	);
