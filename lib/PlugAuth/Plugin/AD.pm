package PlugAuth::Plugin::AD;

our $VERSION = '0.02';

use strict;
use warnings;
use v5.10;
use Net::LDAP;
use Log::Log4perl qw/:easy/;
use Role::Tiny::With;
use PlugAuth::Plugin::FlatAuthz;

with 'PlugAuth::Role::Plugin';
with 'PlugAuth::Role::Auth';
with 'PlugAuth::Role::Authz';
with 'PlugAuth::Role::Welcome';
with 'PlugAuth::Role::Refresh';

use vars qw/$AUTOLOAD/;

sub init {
	my ($s) = @_;
	my $app = $s->app;
	$s->{flatauthz} = PlugAuth::Plugin::FlatAuthz->new($app->config, 
		Clustericious::Config->new({}), $app);
	return $s;
}

sub refresh {
	my $s	= shift;
	$s->{flatauthz}->refresh;
}

sub welcome {
	my ($s,$c)	= @_;
	$c->render_message('welcome to plug auth + ' . __PACKAGE__ . " ($VERSION)");
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

sub ad_users {
	my ($class) = @_;

    my $ldap_config = $class->plugin_config;
    return 0 unless $ldap_config;
    my $server = $ldap_config->server or LOGDIE "Missing ldap server";
    my $ad = Net::LDAP->new($server, timeout => 5) or do {
        ERROR "Could not connect to ldap server $server: $@";
        return 0;
    };

	my $mdn 	= $ldap_config->{managerDN};
	my $secret 	= $ldap_config->{managerPassword};

	my $msg = $ad->bind($mdn,password => $secret)
		or LOGDIE "Wrong Manager DN or password";
	
	my $sbase	= $ldap_config->{searchBase};
	my $filter	= '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))';
	my $results = $ad->search(base=>$sbase,filter=>$filter);

	my @ret;

	foreach my $entry ($results->entries) { 
		push @ret, $entry->get_value('sAMAccountName') ;
	}

	return @ret;
}

sub all_users {
	my $class	= shift;

	my @ret		= $class->ad_users;
	my $flat	= $class->next_auth;

	return (@ret, $flat->all_users);
}

sub create_user {
	# delegate to next plugin (plain??)
	my $next_auth = shift->next_auth;
	return 0 unless defined $next_auth;
	$next_auth->create_user(@_);
}

sub delete_user {
	# delegate to next plugin (plain??)
	my $next_auth = shift->next_auth;
	return 0 unless defined $next_auth;
	return $next_auth->delete_user(@_);
}

sub change_password {
	# delegate to next plugin (plain??)
	my $next_auth = shift->next_auth;
	return 0 unless defined $next_auth;
	return $next_auth->change_password(@_);
}

# Authz

sub can_user_action_resource {
	return shift->{flatauthz}->can_user_action_resource(@_);
}

sub match_resources {
	return shift->{flatauthz}->match_resources(@_);
}

sub host_has_tag {
	return shift->{flatauthz}->host_has_tag(@_);
}

sub actions {
	return shift->{flatauthz}->actions(@_);
}

sub groups_for_user {
	my $s		= shift;
	my $user	= shift;
	
	my @ret     = $s->ad_users;
	
	foreach my $ad (@ret) {
		return ['AD',$user] if ($ad eq $user);
	}
	return $s->{flatauthz}->groups_for_user($user);
}

sub all_groups {
	my $s	= shift;
	my @ret = $s->{flatauthz}->all_groups(@_);
	unshift @ret, 'AD';
	return @ret;
}

sub users_in_group {
	my $s		= shift;
	my $group	= shift;
	
	return [$s->ad_users] if ($group eq 'AD');
	return $s->{flatauthz}->users_in_group($group);
}

sub create_group {&routed_to_flatauthz(@_)};
sub delete_group {&routed_to_flatauthz(@_)};
sub grant {&routed_to_flatauthz(@_)};
sub revoke {&routed_to_flatauthz(@_)};
sub granted {&routed_to_flatauthz(@_)};
sub update_group {&routed_to_flatauthz(@_)};

sub routed_to_flatauthz {
	my $s		= shift;
	my @ref		= caller(1);
	my ($sub) 	= $ref[3]  =~ /([\w_]+)$/;
	return $s->{flatauthz}->$sub(@_);
}

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
