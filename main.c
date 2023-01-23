#include <stdio.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "wsclient.h"
#include <string.h>
#include <stdlib.h>

// Path: Makefile
// CC = gcc
// CFLAGS = -Wall -Wextra -Werror -std=c99 -g -lcrypto -lwebsockets 
// SRC = main.c
// OBJ = $(SRC:.c=.o)
// EXEC = app.out


// #define MSGLEN int = 1024;

//? Init with gcc main.c -o app.out -lcrypto

// -------------   Dokumentasjon   ------------------------

// https://www.openssl.org/docs/man1.0.2/man3/
// https://libwebsockets.org/

// --------------------------------------------------------

// For easy testing, just pass the same private and public key to all clients
int genKeyPair() {
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;                         // For doing multiprecision integer arithmetics
    BIO *bp_public = NULL, *bp_private = NULL;  // BIO: Basic Input Output 

    int bits = 4096;
    unsigned long e = RSA_F4;                   // RSA_F4 = 65537 / 0x10001 / 2^16 + 1. TODO: Figure out what this does

    bne = BN_new();                             // Make new BIGNUM
    int ret = BN_set_word(bne, e);              // Set the value of bne to e (65537)
    if (ret != 1) 
    {
        printf("Error setting bne");
        return -1;
    }

    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
    if (ret != 1) 
    {
        printf("Error generating key");
        return -1;
    }

    bp_public = BIO_new_file("public.pem", "w+");

    if(!bp_public)
    {
        printf("Error creating the file public.pem\n");
        return -1;
    }

    // Generate private key
    bp_private = BIO_new_file("private.pem", "w+");
    if(!bp_private)
    {
        printf("Error creating the file private.pem\n");
        return -1;
    }

    // char *bp_public_str = NULL;
    // char *bp_private_str = NULL;

    // bp_public_str = BIO_gets(bp_public, bp_public_str, 0);
    // bp_private_str = BIO_gets(bp_private, bp_private_str, 0);


    printf("Writing private key to file: private.pem");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);

    if(!ret)
    {
        printf("Error writing the private key to the file private.pem\n");
        return -1;
    }

    printf("Written private key to file: private.pem\n");

    printf("Writing public key to file public.pemn\n");
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);

    if(!ret)
    {
        printf("Error writing the public key to the file public.pem\n");
        return -1;
    }
    
    printf("Written public key to file: public.pem\n");

    BIO_free(bp_public);
    BIO_free(bp_private);

    return 0;
}


// On message send, pass the message to this function
// Message is encrypted with the public key of the client, and decrypted with the private key of the client
// - *cipertext is then the encrypted message, which is sent to the server
int encryptMessage(unsigned char *message, int message_len, unsigned char *ciphertext) {
    int padding = RSA_PKCS1_OAEP_PADDING;

    RSA *rsa = NULL;
    FILE *fp = fopen("public.pem", "r"); // This is the public key of the client, for testing purposes, it needs to be the public key of the server
    if (fp == NULL) {
        printf("Error opening public.pem");
        return -1;
    }

    rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    if (rsa == NULL) {
        printf("Error reading public key");
        return -1;
    }

    // TODO: Implement message encryption 

    int res = RSA_public_encrypt(message_len, (unsigned char*)message, (unsigned char*)message, rsa, padding);

    if (!res) {
        printf("Error reading public key");
        return -1;
    }


    fclose(fp);

    return res;
}

// On incoming message, pass the message to this function
// Message is encrypted with the public key of the client, and decrypted with the private key of the client
// - *message is then the decrypted message, which is displayed in the terminal
int decryptMessage(RSA *rsa, unsigned char *ciphertext, int ciphertext_len, unsigned char *message) {
    int padding = RSA_PKCS1_OAEP_PADDING;

    FILE *fp = fopen("private.pem", "r");
    if (fp == NULL) {
        printf("Error opening private.pem");
        return -1;
    }

    rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    if (rsa == NULL) {
        printf("Error reading private key");
        return -1;
    }

    int res = RSA_private_decrypt(ciphertext_len, (unsigned char*)ciphertext, (unsigned char*)message, rsa, padding);

    if (!res) {
        printf("Error reading private key");
        return -1;
    }

    return res;
}

int authenticate(RSA *rsa, FILE *pkf) {
    // RSA *rsa = NULL;
    // printf("Private key file: %s", private_key_file);
    // FILE *pkf = fopen(private_key_file, "r");
    // if (pkf == NULL) {
    //     printf("Error opening private key file %s", &private_key_file);
    //     return -1;
    // }

    fprintf(stderr, "Reading private key file\n");

    rsa = PEM_read_RSAPrivateKey(&pkf, &rsa, NULL, NULL);     // TODO: Implement passphrase?
    if (rsa == NULL) {
        printf("Error reading private key");
        return -1;
    }

    // Free
    // fclose(pkf);

    return 0;
}

int main() {

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // ---------------- Websockets stuff  --------------- //


    // ---------------- Encryption stuff --------------- // 

    RSA *rsa = NULL;            // RSA struct for doing RSA operations
    FILE *pkf = NULL;           // Private key file
    char *bp_private[100];      // Private key file path

    int userInput = 0;
    printf("1: Generate new key pair\n2: Authenticate with existing key:");
    scanf("%d", &userInput);
    if (userInput == 1) {
        genKeyPair();                                                           // "New user"
    } else if (userInput == 2) {
        // printf("Enter path to private key: ");
        // scanf("%s", &bp_private);                                            // READ: https://c-faq.com/stdio/scanfprobs.html

        // strncpy(bp_private, bp_private, strlen(bp_private)-1);
        // if (sizeof(*bp_private) > 100) {                                        // Check that we don't overflow the char array
        //     printf("Path too long, max 100 characters (including file name)");  // TODO: Implement dynamic array
        //     return -1;
        // } else 
        {
            fprintf(stderr, "Opening private key file private.pem\n");
            pkf = fopen("private.pem", "r");                                    // Open private key file
            if (pkf == NULL) {
                fprintf(stderr, "Error opening private key file\n");
                return -1;
            }
            fprintf(stderr, "Opened private key file: %s\n", *pkf);
            authenticate(rsa, &pkf);
        }

    } else {
        printf("Invalid input");
    }
    return 0;
}




