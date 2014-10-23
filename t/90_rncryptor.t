use strict;
use warnings;
use Test::More;
use Crypt::RNCryptor;

my $PLAIN_DATA = 'foobar';

{
    my $cryptor = RNCryptor->new(
        version => 3,
        password => 'foobar',
    );
    is $cryptor->decrypt($cryptor->encrypt($PLAIN_DATA)), $PLAIN_DATA;
}
{
    my $cryptor = RNCryptor->new(
        version => 3,
        encryption_key => pack('C*', [1..32]),
        hmac_key => pack('C*', [1..32]),
    );
    is $cryptor->decrypt($cryptor->encrypt($PLAIN_DATA)), $PLAIN_DATA;
}

done_testing;
