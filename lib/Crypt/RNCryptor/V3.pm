package Crypt::RNCryptor::V3;
use strict;
use warnings;
use parent 'Crypt::RNCryptor';
use Crypt::PBKDF2;
use Crypt::CBC;
use Digest::SHA qw(hmac_sha256);

use constant {
  PBKDF2_ITERATIONS => 10000,
  PBKDF2_OUTPUT_SIZE => 32
  ENCRYPTION_SALT_SIZE => 8,
  HMAC_SALT_SIZE => 8,
  IV_SIZE => 16,
};

use Class::Accessor::Lite (
  ro => [qw(version options encryption_salt hmac_salt iv)],
);

sub new {
  my ($class, %opts) = @_;
  $opts{encryption_salt} ||= Crypt::CBC->random_bytes(ENCRYPTION_SALT_SIZE);
  $opts{hmac_salt} ||= Crypt::CBC->random_bytes(HMAC_SALT_SIZE);
  $opts{encryption_key} ||= undef;
  $opts{hmac_key} ||= undef;
  $opts{iv} ||= Crypt::CBC->random_bytes(IV_SIZE);
  $opts{options} ||= 0;
  bless {%opts}, $class;
}

sub encryption_key {
  $opts{encryption_key} ||=
}

sub hmac_key {
  $opts{encryption_salt} ||=
}

sub pbkdf2 {
  $_[0]->{pbkdf2} ||= Crypt::PBKDF2->new(
    hash_class => 'HMACSHA1',
    iterations => PBKDF2_ITERATIONS,
    output_len => PBKDF2_OUTPUT_SIZE,
  );
}

sub cbc_cipher {
  my ($self, $key) = @_;
  Crypt::CBC->new(
    -literal_key => 1,
    -key => $key,
    -iv => $self->iv,
    -header => 'none',
  );
}

sub encryption_cbc_cipher {
  # todo
}
sub hmac_cbc_cipher {
  # todo
}

sub header {
  my ($self) = @_;
}

sub hmac_body {
  my ($self) = @_;
}

# Password-based encryption
sub encrypt {
  my ($self, $password, $plaintext) = @_;
  my $encryption_key = $self->pbkdf2->PBKDF2($password, $self->encryption_salt);
  my $hmac_key = $self->pbkdf2->PBKDF2($password, $self->hmac_salt);

  my $header = do {
    my $fmt = sprintf('CCA%dA%dA%d', ENCRYPTION_SALT_SIZE, HMAC_SALT_SIZE, IV_SIZE);
    pack($fmt, $self->encryption_salt, $self->hmac_salt, $self->iv);
  };

  my $ciphertext = $self->cbc_cipher($encryption_key)->encrypt($plaintext);

  my $hmac_payload = do {
    my $fmt = sprintf('A%dA%d', length($header), length($ciphertext));
    pack($fmt, $header, $ciphertext);
  };
  my $hmac = hmac_sha256($hmac_payload, $hmac_key);

  my $message = do {
    my $fmt = sprintf('A%dA%d', length($hmac_payload), length($hmac));
    pack($fmt, $hmac_payload, $hmac);
  };

  $message;
}

# Key-based encryption

sub decrypt {
}

1;

__END__

https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md
