/**********************************************************************
 *
 * P2P with TLS
 *
 * Written by: Tyler Carroll, James Silvia, Tom Strott
 * In completion of: CS557 Project 2
 *
 * A secure P2P storage system
 *
 * crypto.cpp
 *
 **********************************************************************/
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

#define HASH    "0xE9ACF922012F6B4222ED1F2E0FD60E118FEE14BE69B48694938B240208E4BDE0"
#define KEY_MAX (2*SHA256_DIGEST_LENGTH)+1

char genRandom();
int create_sha256(string password, unsigned char *key);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);
