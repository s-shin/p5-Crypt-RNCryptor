package Crypt::RNCryptor;
use 5.008001;
use strict;
use warnings;
use Carp;

our $VERSION = '0.01';

our $DefaultRNCryptorVersion = '3';
our @SupportedRNCryptorVersions = qw(3);

sub new {
    my ($class, %opts) = @_;
    $opts{version} ||= $DefaultRNCryptorVersion;
    foreach my $v (@SupportedRNCryptorVersions) {
        if ($opts{version} eq $v) {
            my $Class = "Crypt::RNCryptor::V${v}";
            eval "require $Class";
            return $Class->new(%opts);
        }
    }
    my $v = $opts{version};
    confess "RNCryptor v$v is not supported.";
}

sub encrypt {
}

sub decrypt {
}

1;
__END__

=encoding utf-8

=head1 NAME

Crypt::RNCryptor - It's new $module

=head1 SYNOPSIS

        use Crypt::RNCryptor;

=head1 DESCRIPTION

Crypt::RNCryptor is ...

=head1 LICENSE

Copyright (C) Shintaro Seki.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Shintaro Seki E<lt>s2pch.luck@gmail.comE<gt>

=cut
