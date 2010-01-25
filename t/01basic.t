use Test::More tests => 7;
BEGIN { use_ok('RDF::ACL') };

ok(my $acl = RDF::ACL->new, "creating ACL object");

ok($acl->can('check'), "ACL object can check");
ok($acl->can('why'), "ACL object can why");
ok($acl->can('allow'), "ACL object can allow");
ok($acl->can('deny'), "ACL object can deny");
ok($acl->can('save'), "ACL object can save");