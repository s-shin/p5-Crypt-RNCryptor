use strict;
use warnings;
use Test::More;

my $PLAIN_DATA = 'foobar';

{
  my $cryptor = RNCryptor->new(
    version => 3,
    options => 1,
    encryption_salt => '12345678',
    hmac_salt => '12345678',
    iv => '1234567812345678',
  );
  $cryptor->decrypt($cryptor->encrypt($PLAIN_DATA));
}

done_testing;
