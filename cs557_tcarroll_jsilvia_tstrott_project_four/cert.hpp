/**********************************************************************
 *
 * P2P with TLS
 *
 * Written by: Tyler Carroll, James Silvia, Tom Strott
 * In completion of: CS557 Project 4
 *
 * A secure P2P storage system
 *
 * cert.hpp
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
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define CACERT  "./CA/ca-cert.pem"
#define CAKEY   "./CA/ca-key.pem"
 
using namespace std;

bool gen_X509Req(const char *szCountry, const char *szProvince, const char *szCity, const char *szOrganization, const char *szCommon, const char *szPath, const char *szPrivateKey);
bool create_signed_certificate(string peer);
