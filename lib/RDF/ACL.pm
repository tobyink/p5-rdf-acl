package RDF::ACL;

=head1 NAME

RDF::ACL - access control lists for the semantic web

=head1 SYNOPSIS

  use RDF::ACL;
  
  my $acl  = RDF::ACL->new('access.ttl');
  my $auth = $acl->allow(
    webid => 'http://example.com/joe#me',
    item  => 'http://example.com/private/document',
    level => ['Read', 'Write'],
    );
  $acl->save('turtle', 'access.ttl');
  
  # later...
  
  if ($acl->check('http://example.com/joe#me',
                  'http://example.com/private/document',
                  'Read'))
  {
    print slurp("private/document");
  }
  else
  {
    print "Denied";
  }
  
  # later...
  
  foreach my $reason ($acl->why('http://example.com/joe#me',
                                'http://example.com/private/document',
                                'Read'))
  {
    $acl->deny($reason) if defined $reason;
  }
  $acl->save('turtle', 'access.ttl');

=cut

use strict;
use 5.008;

use Carp;
use Data::UUID;
use Error qw(:try);
use RDF::TrineShortcuts 0.03;
use URI;

use constant NS_ACL   => 'http://www.w3.org/ns/auth/acl#';
use constant NS_RDF   => 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';

=head1 VERSION

0.01

=cut

our $VERSION = '0.01';

=head1 DESCRIPTION

Note that this module provides access control and does not perform authentication!

=head2 Constructors

=over 4

=item C<< $acl->new($input, %args) >>

Creates a new access control list based on RDF data defined in
$input. $input can be a serialised string of RDF, a file name,
a URI or any other input accepted by the rdf_parse function
(see L<RDF::Trine::Shortcuts>).

C<< new() >> can be called with no arguments to create a
fresh, clean ACL containing no authorisations.

=cut

sub new
{
	my $class = shift;
	
	my $model = shift;
	unless (UNIVERSAL::isa($model, 'RDF::Trine::Model'))
	{
		$model = rdf_parse($model, @_);
	}
	
	my $self  = bless {
		'model' => $model,
		'i_am'  => undef ,
		}, $class;
	
	return $self;
}

=item C<< $acl->new_remote($endpoint) >>

Creates a new access control list based on RDF data accessed
via a remote SPARQL Protocol 1.0 endpoint.

=back

=cut

sub new_remote
{
	my $class = shift;
	my $ep    = shift;
	
	my $self  = bless {
		'endpoint' => $ep,
		}, $class;
	
	return $self;
}

=head2 Public Methods

=over 4

=item C<< $acl->check($webid, $item, $level, @data) >>

Checks an agent's authorisation to access an item.

$webid is the WebID (URI) of the agent requesting access to the item.

$item is the URL (URI) of the item being accessed.

$level is a URI identifying the type of access required. As special
cases, the case-insensitive string 'read' is expanded to the URI
E<lt>http://www.w3.org/ns/auth/acl#ReadE<gt>, 'write' to
E<lt>http://www.w3.org/ns/auth/acl#WriteE<gt> and 'control' to
E<lt>http://www.w3.org/ns/auth/acl#ControlE<gt>.

If the access control list is local (not remote), zero or more
additional RDF graphs can be passed (i.e. @data) containing
data to take into consideration when checking the agent's authorisation.
This data is trusted blindly, so should not include data that the
user has themselves supplied. If the access control list is remote,
then this method throws an error if any additional data is provided.
(A remote ACL cannot take into account local data.)

If $level is provided, this method returns a boolean.

If $level is undefined or omitted, this method returns a list
of URIs which each represent a type of access that the user is
authorised.

=cut

sub check
{
	my $self  = shift;
	my $webid = shift;
	my $item  = shift;
	my $level = shift;

	throw Error::Simple("Must provide WebID to be checked.")
		unless defined $webid;

	throw Error::Simple("Must provide item URI to be checked.")
		unless defined $item;

	my $model = $self->_union_model(@_);
	
	my $aclvocab = NS_ACL;
	
	if (defined $level)
	{
		if ($level =~ /^(access|read|write|control)$/i)
		{
			$level = $aclvocab . (ucfirst lc $level);
		}
		
		my $sparql = <<SPARQL;
PREFIX acl: <$aclvocab>
ASK WHERE {
	{
		{ ?authorisation acl:agentClass ?agentclass . <$webid> a ?agentclass . }
		UNION { ?authorisation acl:agent <$webid> . }
		UNION { ?authorisation acl:agentClass <http://xmlns.com/foaf/0.1/Agent> . }
	}
	{
		{ ?authorisation acl:accessToClass ?accessclass . <$item> a ?accessclass . }
		UNION { ?authorisation acl:accessTo <$item> . }
		UNION { ?authorisation acl:accessToClass <http://www.w3.org/2000/01/rdf-schema#Resource> . }
	}
	{
		?authorisation acl:mode <$level> .
	}
}
SPARQL

		return rdf_query($sparql, $model);
	}
	
	else
	{
		my $sparql = <<SPARQL;
PREFIX acl: <$aclvocab>
SELECT DISTINCT ?level
WHERE {
	{
		{ ?authorisation acl:agentClass ?agentclass . <$webid> a ?agentclass . }
		UNION { ?authorisation acl:agent <$webid> . }
		UNION { ?authorisation acl:agentClass <http://xmlns.com/foaf/0.1/Agent> . }
	}
	{
		{ ?authorisation acl:accessToClass ?accessclass . <$item> a ?accessclass . }
		UNION { ?authorisation acl:accessTo <$item> . }
		UNION { ?authorisation acl:accessToClass <http://www.w3.org/2000/01/rdf-schema#Resource> . }
	}
	{
		?authorisation acl:mode ?level .
	}
}
SPARQL

		my $iterator = rdf_query($sparql, $model);
		my @rv;
		while (my $result = $iterator->next)
		{
			push @rv, $result->{'level'}->uri
				if UNIVERSAL::can($result->{'level'}, 'uri');
		}
		return @rv;
	}
}

=item C<< $acl->why($webid, $item, $level, @data) >>

Investigates an agent's authorisation to access an item.

Arguments as per C<< check >>, however $level is required.

Returns a list of authorisations that justify a user's access to
the item with the given access level. These authorisations are
equivalent to $authid values provided by C<< allow() >>.

In some cases (especially if the authorisation was created
by hand, and not via C<< allow() >>) an authorisation may not
have an identifier. In these cases, the list will contain
undef.

=cut

sub why
{
	my $self  = shift;
	my $webid = shift;
	my $item  = shift;
	my $level = shift;

	throw Error::Simple("Must provide WebID to be checked.")
		unless defined $webid;

	throw Error::Simple("Must provide item URI to be checked.")
		unless defined $item;

	throw Error::Simple("Must provide item URI to be checked.")
		unless defined $item;

	my $model = $self->_union_model(@_);
	
	my $aclvocab = NS_ACL;
	
	if ($level =~ /^(access|read|write|control)$/i)
	{
		$level = $aclvocab . (ucfirst lc $level);
	}
		
	my $sparql = <<SPARQL;
PREFIX acl: <$aclvocab>
SELECT DISTINCT ?authorisation
WHERE {
	{
		{ ?authorisation acl:agentClass ?agentclass . <$webid> a ?agentclass . }
		UNION { ?authorisation acl:agent <$webid> . }
		UNION { ?authorisation acl:agentClass <http://xmlns.com/foaf/0.1/Agent> . }
	}
	{
		{ ?authorisation acl:accessToClass ?accessclass . <$item> a ?accessclass . }
		UNION { ?authorisation acl:accessTo <$item> . }
		UNION { ?authorisation acl:accessToClass <http://www.w3.org/2000/01/rdf-schema#Resource> . }
	}
	{
		?authorisation acl:mode <$level> .
	}
}
SPARQL

	my $iterator = rdf_query($sparql, $model);
	my @rv;
	while (my $result = $iterator->next)
	{
		if (UNIVERSAL::can($result->{'authorisation'}, 'uri'))
		{
			push @rv, $result->{'authorisation'}->uri;
		}
		else
		{
			push @rv, undef;
		}
	}
	return @rv;
}

=item C<< $acl->allow(%args) >>

Adds an authorisation to the ACL. The ACL must be mutable.

The method takes a hash of named arguments:

  my $authid = $acl->allow(
    webid => 'http://example.com/joe#me',
    item  => 'http://example.com/private/document',
    level => ['Read', 'Write'],
    );

'item' is the URI of the item to authorise access to. As an alternative,
'item_class' may be used to authorise access to an entire class of items
(using classes in the RDFS/OWL sense of the word). If neither of these
arguments is provided, then the method will throw an error. Both may be
provided. Either or both may be an arrayref, because an authorisation
may authorise access to more than one thing.

'container' is an alternative to using 'item' or 'item_class'. It
specifies the URI for a resource which in some way is a container for
other resources. Setting authorisations for a container allows you
to set a default authorisation for new items created within that
container. (You must use the C<< created() >> method to notify the ACL
about newly created items.)

'webid' is the WebID (URI) of the person or agent being granted access.
As an alternative, 'agent_class' may be used to authorise access to an
entire class of agents. If neither is provided, an agent_class of
E<lt>http://xmlns.com/foaf/0.1/AgentE<gt> is assumed. Both may be
provided. Either or both may be an arrayref, because an authorisation
may authorise access by more than one agent. (For consistency with 'item',
'agent' is supported as a synonym for 'webid'.)

'level' is the access level being granted. As with the C<< check >>
method, the shortcuts 'read', 'write' and 'control' may be used.
An arrayref may be used. If no level is specified, 'read' is assumed.

This authorisation is not automatically saved, so it is probably useful
to call C<< save() >> after adding authorisations.

The method returns an identifier for the authorisation. This identifier
may be needed again if you ever need to C<< deny() >> the authorisation.

This method is aware of C<< i_am() >>/C<< who_am_i() >>.

=cut

sub allow
{
	my $self = shift;
	my %args = @_;
	
	throw Error::Simple("This ACL is not mutable.")
		unless $self->is_mutable;

	throw Error::Simple("Must provide an 'item', 'item_class' or 'container' argument.")
		unless (defined $args{'item'} or defined $args{'item_class'} or defined $args{'container'});

	throw Error::Simple("Cannot provide 'container' with an 'item' or 'item_class' argument.")
		if ((defined $args{'container'}) and (defined $args{'item'} or defined $args{'item_class'}));

	$args{'agent_class'} = 'http://xmlns.com/foaf/0.1/Agent'
		unless (defined $args{'webid'} or defined $args{'agent'} or defined $args{'agent_class'});
	
	$args{'level'} = NS_ACL.'Read'
		unless defined $args{'level'};
	
	my $predicate_map = {
		'level'       => NS_ACL . 'mode' ,
		'item'        => NS_ACL . 'accessTo' ,
		'item_class'  => NS_ACL . 'accessToClass' ,
		'container'   => NS_ACL . 'defaultForNew' ,
		'agent'       => NS_ACL . 'agent' ,
		'agent_class' => NS_ACL . 'agentClass' ,
		'webid'       => NS_ACL . 'agent' ,
		};

	my $data = {};
	my $authid = $self->_uuid;
	
	$data->{$authid}->{NS_RDF.'type'} = [
		{ 'type'=>'uri', 'value'=>NS_ACL.'Authorization' },
		];
	
	foreach my $p (keys %$predicate_map)
	{
		next unless defined $args{$p};
		
		unless (ref $args{$p} eq 'ARRAY')
		{
			$args{$p} = [ $args{$p} ];
		}

		foreach my $val (@{$args{$p}})
		{
			if (defined $self->who_am_i and $p =~ /^(item|container)$/)
			{
				my $control = $self->check($self->who_am_i, $val, 'Control');
				throw Error::Simple("WebID <".$self->who_am_i."> does not have access control for resource <$val>.")
					unless $control;
			}

			if ($p eq 'level' and $val =~ /^(access|read|write|control)$/i)
			{
				$val = NS_ACL . (ucfirst lc $val);
			}
			
			push @{ $data->{$authid}->{$predicate_map->{$p}} },
				{ 'type'=>'uri', 'value'=>$val };
		}
	}
	
	$self->model->add_hashref($data);
	
	return $authid;
}

=item C<< $acl->deny($authid) >>

Completely removes all traces of an authorisation from the ACL.

The authorisation identifier can be found using C<< why() >> or
you may have remembered it when you first allowed the access.
In some cases (especially if the authorisation was created
by hand, and not via C<< allow() >>) an authorisation may not
have an identifier. In these cases, you will have to be creative
in figuring out how to deny access.

Returns the number of statements removed from the ACL's internal model
as a result of the removal. (This will normally be at least 3.)

This authorisation is not automatically saved, so it is probably useful
to call C<< save() >> after removing authorisations.

This method is aware of C<< i_am() >>/C<< who_am_i() >>.

=cut

sub deny
{
	my $self = shift;
	my $id   = shift;
	
	throw Error::Simple("This ACL is not mutable.")
		unless $self->is_mutable;
	
	if (defined $self->who_am_i)
	{
		my $aclvocab = NS_ACL;
		my $sparql = <<SPARQL;
PREFIX acl: <$aclvocab>
SELECT DISTINCT ?resource
WHERE
{
	{ <$id> acl:accessTo ?resource . }
	UNION { <$id> acl:accessTo ?resource . }
}
SPARQL
		my $iterator = rdf_query($sparql, $self->model);
		while (my $result = $iterator->next)
		{
			next unless $result->{'resource'}->is_resource;
			next if $self->check($self->who_am_i, $result->{'resource'}->uri, 'Control');
			
			throw Error::Simple("WebID <".$self->who_am_i."> does not have access control for resource <".$result->{'resource'}->uri.">.");
		}
	}
	
	my $auth  = RDF::Trine::Node::Resource->new($id);
	my $count = $self->model->count_statements($auth, undef, undef);
	$self->model->remove_statements($auth, undef, undef);
	return $count;
}

=item C<< $acl->created($item, $container) >>

Finds all authorisations which are the default for new items within
$container and clones each of them for newly created $item.

Returns a list of authorisation identifiers.

=cut

sub created
{
	my $self      = shift;
	my $item      = shift;
	my $container = shift;
	
	throw Error::Simple("This ACL is not mutable.")
		unless $self->is_mutable;
	
	my $aclvocab = NS_ACL;
	my $graph = rdf_query("
	PREFIX acl: <$aclvocab>
	CONSTRUCT { ?auth ?p ?o . }
	WHERE {
		?auth ?p ?o ;
			acl:defaultForNew <$container> .
		FILTER ( sameTerm(?p, acl:mode) || sameTerm(?p, acl:agent) || sameTerm(?p, acl:agentClass) || sameTerm(?p, <http://www.w3.org/1999/02/22-rdf-syntax-ns#type>) )
	}", $self->model);
	
	my $data = $graph->as_hashref;
	my $newdata = {};
	my @rv;
	foreach my $k (keys %$data)
	{
		my $authid = $self->_uuid;
		$newdata->{$authid} = $data->{$k};
		$newdata->{$authid}->{$aclvocab.'accessTo'} = [{
			'type' => 'uri', 'value' => $item
			}];
		push @rv, $authid;
	}
	$self->model->add_hashref($newdata);
	
	return @rv;
}

=item C<< $acl->i_am($webid) >>

Tells the ACL object to "act like" the agent with the given WebID.

If the ACL object is acting like you, then methods that make changes
to the ACL (e.g. C<< allow() >> and C<< deny() >>) will only work
if you have 'Control' permission over the resources specified.

$webid can be null to restore the usual behaviour.

Returns the previous WebID the ACL was acting like as a L<URI>
object.

=cut

sub i_am
{
	my $self = shift;
	my $old  = $self->who_am_i;
	$self->{'i_am'} = shift;
	return URI->new($old);
}

=item C<< $acl->who_am_i >>

Returns the WebID of the agent that ACL is acting like (if any).

=cut

sub who_am_i
{
	my $self = shift;
	return $self->{'i_am'};
}

=item C<< $acl->save($format, $filename) >>

Serialises a local (not remote) ACL.

$format can be any format supported by rdf_string (see
L<RDF::Trine::Shortcuts>).

If $filename is provided, this method writes to the file
and returns the new file size in bytes.

If $filename is omitted, this method does not attempt to write
to a file, and simply returns the string it would have written.

=cut

sub save
{
	my $self = shift;
	my $fmt  = shift || 'RDFXML';
	my $file = shift;
	
	throw Error::Simple("This ACL is not mutable.")
		unless $self->is_mutable;

	my $str = rdf_string($self->model, $fmt);
	
	if (defined $file)
	{
		open SAVE, ">$file";
		print SAVE $str;
		close SAVE;
		return -s $file;
	}
	
	return $str;
}

=item C<< $acl->is_remote >>

Returns true if the ACL is remote; false if local.

=cut

sub is_remote
{
	my $self = shift;
	return defined $self->endpoint;
}

=item C<< $acl->is_mutable >>

Can this ACL be modified?

=cut

sub is_mutable
{
	my $self = shift;
	return defined $self->model;
}

=item C<< $acl->model >>

The graph model against which authorisation checks are made.

Returned as an L<RDF::Trine::Model> object.

=cut

sub model
{
	my $self = shift;
	return $self->{'model'};
}

=item C<< $acl->endpoint >>

The endpoint URI for remote (non-local) ACL queries.

Returned as a L<URI> object.

=cut

sub endpoint
{
	my $self = shift;
	return undef unless defined $self->{'endpoint'};
	return URI->new(''.$self->{'endpoint'});
}

# PRIVATE METHODS

# * $acl->_uuid
#
#   Returns a unique throwaway URI.

sub _uuid
{
	my $self = shift;
	
	$self->{'uuid_generator'} = Data::UUID->new
		unless defined $self->{'uuid_generator'};
	
	return 'urn:uuid:' . $self->{'uuid_generator'}->create_str;
}

# * $acl->_union_model(@graphs)
#
#   Creates a temporary model that is the union of the ACL
#   object's default data source plus additional graphs.

sub _union_model
{
	my $self = shift;
	my $model;
	
	if ($self->is_remote)
	{
		$model = $self->endpoint;
		
		throw Error::Simple("Cannot provide additional data to consider for remote ACL.")
			if @_;
	}
	elsif (@_)
	{
		$model = rdf_parse($self->model);
		foreach my $given (@_)
		{
			rdf_parse($given, model=>$model);
		}
	}
	else
	{
		$model = $self->model;
	}
	
	return $model;
}

1;
__END__

=back

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 SEE ALSO

L<CGI::Auth::FOAF_SSL>.

L<http://www.w3.org/ns/auth/acl.n3>.

L<http://www.perlrdf.org/>, L<http://lists.foaf-project.org/mailman/listinfo/foaf-protocols>.

=head1 AUTHOR

Toby Inkster E<lt>tobyink@cpan.orgE<gt>.

=head1 COPYRIGHT

Copyright 2010 Toby Inkster

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut