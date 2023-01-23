# Errors

```bash
gcc -Wall -Wextra -Werror -std=c99 -g -lcrypto -lwebsockets  main.c -o app.out
main.c: In function ‘encryptMessage’:
main.c:127:41: error: passing argument 1 of ‘strlen’ makes pointer from integer without a cast [-Werror=int-conversion]
```
```c
     int res = RSA_public_encrypt(strlen(message_len), (unsigned char*)message, (unsigned char*)message, rsa, padding);
                                         ^~~~~~~~~~~
```
```bash
In file included from main.c:7:
/usr/include/string.h:384:35: note: expected ‘const char *’ but argument is of type ‘int’
 extern size_t strlen (const char *__s)
                       ~~~~~~~~~~~~^~~
main.c:109:76: error: unused parameter ‘ciphertext’ [-Werror=unused-parameter]
 int encryptMessage(unsigned char *message, int message_len, unsigned char *ciphertext) {
                                                             ~~~~~~~~~~~~~~~^~~~~~~~~~
main.c: In function ‘decryptMessage’:
main.c:152:38: error: passing argument 2 of ‘PEM_read_RSAPrivateKey’ from incompatible pointer type [-Werror=incompatible-pointer-types]
     rsa = PEM_read_RSAPrivateKey(fp, rsa, NULL, NULL);
                                      ^~~
In file included from /usr/include/openssl/ui.h:19,
                 from /usr/include/openssl/engine.h:24,
                 from main.c:2:
/usr/include/openssl/pem.h:300:1: note: expected ‘RSA **’ {aka ‘struct rsa_st **’} but argument is of type ‘RSA *’ {aka ‘struct rsa_st *’}
 DECLARE_PEM_rw_cb(RSAPrivateKey, RSA)
 ^~~~~~~~~~~~~~~~~
main.c:158:42: error: passing argument 1 of ‘strlen’ makes pointer from integer without a cast [-Werror=int-conversion]
     int res = RSA_private_decrypt(strlen(ciphertext_len), (unsigned char*)ciphertext, (unsigned char*)message, rsa, padding);
                                          ^~~~~~~~~~~~~~
In file included from main.c:7:
/usr/include/string.h:384:35: note: expected ‘const char *’ but argument is of type ‘int’
 extern size_t strlen (const char *__s)
                       ~~~~~~~~~~~~^~~
main.c: In function ‘authenticate’:
main.c:179:34: error: passing argument 1 of ‘PEM_read_RSAPrivateKey’ from incompatible pointer type [-Werror=incompatible-pointer-types]
     rsa = PEM_read_RSAPrivateKey(&pkf, &rsa, NULL, NULL);     // TODO: Implement passphrase?
                                  ^~~~
In file included from /usr/include/openssl/ui.h:19,
                 from /usr/include/openssl/engine.h:24,
                 from main.c:2:
/usr/include/openssl/pem.h:300:1: note: expected ‘FILE *’ {aka ‘struct _IO_FILE *’} but argument is of type ‘FILE **’ {aka ‘struct _IO_FILE **’}
 DECLARE_PEM_rw_cb(RSAPrivateKey, RSA)
 ^~~~~~~~~~~~~~~~~
main.c: In function ‘main’:
main.c:227:56: error: format ‘%s’ expects argument of type ‘char *’, but argument 3 has type ‘FILE’ {aka ‘struct _IO_FILE’} [-Werror=format=]
             fprintf(stderr, "Opened private key file: %s\n", *pkf);
                                                       ~^     ~~~~
main.c:228:31: error: passing argument 2 of ‘authenticate’ from incompatible pointer type [-Werror=incompatible-pointer-types]
             authenticate(rsa, &pkf);
                               ^~~~
main.c:168:34: note: expected ‘FILE *’ {aka ‘struct _IO_FILE *’} but argument is of type ‘FILE **’ {aka ‘struct _IO_FILE **’}
 int authenticate(RSA *rsa, FILE *pkf) {
                            ~~~~~~^~~
main.c:204:11: error: unused variable ‘bp_private’ [-Werror=unused-variable]
     char *bp_private[100];      // Private key file path
           ^~~~~~~~~~
cc1: all warnings being treated as errors
make: *** [makefile:9: chatapp] Error 1
```

