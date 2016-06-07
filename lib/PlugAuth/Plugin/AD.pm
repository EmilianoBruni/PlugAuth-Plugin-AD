package PlugAuth::Plugin::AD;

our $VERSION = '0.01';

use strict;
use warnings;
use v5.10;
use Net::LDAP;
use Log::Log4perl qw/:easy/;
use Role::Tiny::With;

with 'PlugAuth::Role::Plugin';
with 'PlugAuth::Role::Auth';
with 'PlugAuth::Role::Authz';
with 'PlugAuth::Role::Welcome';

sub init {
	my ($s) = @_;
	
	# add this group to group list
	#$s->create_group('AD',[]);
}

sub welcome {
	my ($s,$c)	= @_;
	$c->render_message('welcome to plug auth + ' . __PACKAGE__);
}


sub check_credentials {
	my ($class, $user, $pw) = @_;
	$user = lc $user;

    my $ldap_config = $class->plugin_config;
    if (!$ldap_config or !$ldap_config->{authoritative}) {
        # Check files first.
        return 1 if $class->deligate_check_credentials($user, $pw);
    }
    return 0 unless $ldap_config;
    my $server = $ldap_config->server or LOGDIE "Missing ldap server";
    my $ad = Net::LDAP->new($server, timeout => 5) or do {
        ERROR "Could not connect to ldap server $server: $@";
        return 0;
    };

    my $orig = $user;
    my $extra = $user =~ tr/a-zA-Z0-9@._-//dc;
    WARN "Invalid username '$orig', turned into $user" if $extra;


	my $mdn 	= $ldap_config->{managerDN};
	my $secret 	= $ldap_config->{managerPassword};

	my $msg = $ad->bind($mdn,password => $secret)
		or LOGDIE "Wrong Manager DN or password";
	
	my $sbase	= $ldap_config->{searchBase};
	my $filter	= $ldap_config->{usernameAttribute};
	my $attrs	= ['distinguishedName'];

	$filter 	.= "=$user";

	my $results = $ad->search(base=>$sbase,filter=>$filter,attrs=>$attrs);

	return 0 if ($results->count == 0);

	my $dn		= $results->entry(0)->get_value("DistinguishedName");

	$msg 		= $ad->bind($dn, password => $pw);
    $msg->code or return 1;
    INFO "AD returned ".$msg->code." : ".$msg->error;
    return 0;
}

sub can_user_action_resource {}
sub match_resources {}
sub host_has_tag {}
sub actions {}
sub groups_for_user {
	my $s	= shift;
	my $ret = ['AD'];
	return $ret;
}
sub all_groups {
	return ('AD');
}
sub users_in_group {}

1;
__END__

=head1 NAME

PlugAuth::Plugin::AD - Perl extension for blah blah blah

=head1 SYNOPSIS

  use PlugAuth::Plugin::AD;

=head1 DESCRIPTION

Stub documentation for PlugAuth::Plugin::AD, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.


=head2 EXPORT

None by default.

=head1 SEE ALSO

=head1 AUTHOR

Emiliano Bruni, E<lt>info AT ebruni.it<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016 by root

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
