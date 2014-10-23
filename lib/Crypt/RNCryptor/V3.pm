package Crypt::RNCryptor::V3;
use strict;
use warnings;
use parent 'Crypt::RNCryptor';
use Carp;
use Crypt::PBKDF2;
use Crypt::CBC;
use Digest::SHA qw(hmac_sha256);

use constant {
    VERSION => 3,
    # option
    OPTION_USE_PASSWORD => 1,
    OPTION_NOT_USE_PASSWORD => 0,
    # size
    IV_SIZE => 16,
    ENCRYPTION_SALT_SIZE => 8,
    HMAC_SALT_SIZE => 8,
    # PBKDF2
    PBKDF2_ITERATIONS => 10000,
    PBKDF2_OUTPUT_SIZE => 32
};

use Class::Accessor::Lite (
    ro => [qw(
        password
        encryption_key hmac_key
    )],
);

sub new {
    my ($class, %opts) = @_;
    if ($opts{password} && ($opts{encryption_key} || $opts{hmac_key})) {
        confess 'Cannot set the "password" option with "encryption_key" or "hmac_key" option.';
    }
    bless {
        password => $opts{password},
        encryption_key => $opts{encryption_key},
        hmac_key => $opts{hmac_key},
    }, $class;
}

sub pbkdf2 {
    $_[0]->{pbkdf2} ||= Crypt::PBKDF2->new(
        hash_class => 'HMACSHA1',
        iterations => PBKDF2_ITERATIONS,
        output_len => PBKDF2_OUTPUT_SIZE,
    );
}

sub encrypt {
    my $self = shift;
    return $self->encrypt_with_password(@_) if $self->password;
    return $self->encrypt_with_keys(@_) if $self->encryption_key && $self->hmac_key;
    confess 'Cannot encrypt.';
}

sub encrypt_with_password {
    my ($self, $plaintext, %opts) = @_;
    my $iv = $opts{iv} || Crypt::CBC->random_bytes(IV_SIZE);
    my $encryption_salt = $opts{encryption_salt} || Crypt::CBC->random_bytes(ENCRYPTION_SALT_SIZE);
    my $hmac_salt = $opts{hmac_salt} || Crypt::CBC->random_bytes(HMAC_SALT_SIZE);
    my $password = $opts{password} || $self->password;

    my $encryption_key = $self->pbkdf2->PBKDF2($password, $encryption_salt);
    my $hmac_key = $self->pbkdf2->PBKDF2($password, $hmac_salt);

    # Header = 3 || 1 || EncryptionSalt || HMACSalt || IV
    my $header = pack('CCA*A*A*', VERSION, OPTION_USE_PASSWORD, $encryption_salt, $hmac_salt, $iv);
    # Ciphertext = AES256(plaintext, ModeCBC, IV, EncryptionKey)
    my $ciphertext = Crypt::CBC->new(
        -literal_key => 1,
        -key => $encryption_key,
        -iv => $iv,
        -header => 'none',
        -cipher => 'Crypt::OpenSSL::AES',
    )->crypt($plaintext);
    my $cipherdata = pack('A*A*', $header, $ciphertext);
    # HMAC = HMAC(Header || Ciphertext, HMACKey, SHA-256)
    my $hmac = hmac_sha256($cipherdata, $hmac_key);
    # Message = Header || Ciphertext || HMAC
    pack('A*A*', $cipherdata, $hmac);
}

sub encrypt_with_keys {
    my ($self, $plaintext, %opts) = @_;
    my $iv = $opts{iv} || Crypt::CBC->random_bytes(IV_SIZE);
    my $encryption_key = $opts{encryption_key} || $self->encryption_key;
    my $hmac_key = $opts{hmac_key} || $self->hmac_key;
    # Header = 3 || 0 || IV
    my $header = pack('CCA*', VERSION, OPTION_NOT_USE_PASSWORD, $iv);
    # Ciphertext = AES256(plaintext, ModeCBC, IV, EncryptionKey)
    my $ciphertext = Crypt::CBC->new(
        -literal_key => 1,
        -key => $encryption_key,
        -iv => $iv,
        -header => 'none',
        -cipher => 'Crypt::OpenSSL::AES',
    )->crypt($plaintext);
    my $cipherdata = pack('A*A*', $header, $ciphertext);
    # HMAC = HMAC(Header || Ciphertext, HMACKey, SHA-256)
    my $hmac = hmac_sha256($cipherdata, $hmac_key);
    # Message = Header || Ciphertext || HMAC
    pack('A*A*', $cipherdata, $hmac);
}

sub decrypt {
    ...
}

sub decrypt_with_password {
    ...
}

sub decrypt_with_keys {
    ...
}

1;

__END__

https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md
