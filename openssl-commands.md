# Notes

## General

To use (`ring`)[https://docs.rs/ring/latest/ring/index.html] the keys have to be in the right format.
What works in combination with signing and verifying are the following (`openssl`)[https://www.openssl.org/] commands.
Note, that we explicitly pass the size, because `openssl` creates keys with size 1024 as default, which is a marked as "for legacy use only".

## Create Private RSA Key(pair) (in PEM-format) with length = 2048 bits (must be in range 2048 - 8192)

```
openssl genrsa -out test-keypair.pem 2048
```

## Convert Private-Key from PEM to DER

```
openssl pkey -in test-keypair.pem -inform pem -out test-private-key.der -outform der
```

## Extract/Generate Public-Key from Private Key(pair)

Note, that it is important to pass the `-RSAPublicKey_out` argument.  
Otherwise the public key will not work for verfication of the signature.

```
openssl rsa -in test-keypair.pem -inform PEM -RSAPublicKey_out -outform DER -out test-public-key.der
```
