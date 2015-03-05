/**********************************************************************
 *
 * P2P with TLS
 *
 * Written by: Tyler Carroll, James Silvia, Tom Strott
 * In completion of: CS557 Project 4
 *
 * A secure P2P storage system
 *
 * cert.cpp
 *
 **********************************************************************/
#include <stdio.h>
#include <iostream>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>

#include "cert.hpp"

bool gen_X509Req(const char *szCountry, const char *szProvince, const char *szCity, const char *szOrganization, const char *szCommon, const char *szPath, const char *szPrivateKey)
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
 
    int             nVersion = 1;
    int             bits = 2048;
    unsigned long   e = RSA_F4;
 
    X509_REQ        *x509_req = NULL;
    X509_NAME       *x509_name = NULL;
    EVP_PKEY        *pKey = NULL;
    RSA             *tem = NULL;
    BIO             *out = NULL, *bio_err = NULL, *bp_private = NULL;
 
    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }
 
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }

    // 2. save private key
    bp_private = BIO_new_file(szPrivateKey, "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
 
    // 3. set version of x509 req
    x509_req = X509_REQ_new();
    ret = X509_REQ_set_version(x509_req, nVersion);
    if (ret != 1){
        goto free_all;
    }
 
    // 4. set subject of x509 req
    x509_name = X509_REQ_get_subject_name(x509_req);
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }   
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
 
    // 5. set public key of x509 req
    pKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pKey, r);
    r = NULL;   // will be free rsa when EVP_PKEY_free(pKey)
 
    ret = X509_REQ_set_pubkey(x509_req, pKey);
    if (ret != 1){
        goto free_all;
    }
 
    // 6. set sign key of x509 req
    ret = X509_REQ_sign(x509_req, pKey, EVP_sha1());    // return x509_req->signature->length
    if (ret <= 0){
        goto free_all;
    }
 
    out = BIO_new_file(szPath,"w");
    ret = PEM_write_bio_X509_REQ(out, x509_req);
 
    // 7. free
free_all:
    X509_REQ_free(x509_req);
    BIO_free_all(out);
 
    EVP_PKEY_free(pKey);
    BN_free(bne);
 
    return (ret == 1);
}

// load ca
bool loadCA(const char *f, X509 ** px509)
{
    bool ret;
    BIO *in = NULL;
 
    in = BIO_new_file(f,"r");
 
    ret = (PEM_read_bio_X509(in, px509, NULL, NULL) != NULL);
 
    BIO_free(in);
    return ret;
}
 
// load ca private key
bool loadCAPrivateKey(const char *f, EVP_PKEY **ppkey)
{
    bool ret;
    BIO *in = NULL;
    RSA *r = NULL;
    EVP_PKEY *pkey = NULL;
 
    in = BIO_new_file(f,"r");
    ret = (PEM_read_bio_RSAPrivateKey(in, &r, NULL, NULL) != NULL);
    if(!ret)
        goto free_;
 
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, r);
    *ppkey = pkey;
    r = NULL;
 
free_:
    BIO_free(in);
    return ret;
}
 
// load X509 Req
bool loadX509Req(const char *f, X509_REQ **ppReq)
{
    bool ret;
    BIO *in = NULL;
 
    in = BIO_new_file(f,"r");
    ret = (PEM_read_bio_X509_REQ(in, ppReq, NULL, NULL) != NULL);
 
free_:
    BIO_free(in);
    return ret;
}
 
// sign cert
int do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md)
{
    int rv;
    EVP_MD_CTX mctx;
    EVP_PKEY_CTX *pkctx = NULL;
 
    EVP_MD_CTX_init(&mctx);
    rv = EVP_DigestSignInit(&mctx, &pkctx, md, NULL, pkey);
 
    if (rv > 0)
        rv = X509_sign_ctx(cert, &mctx);
    EVP_MD_CTX_cleanup(&mctx);
    return rv > 0 ? 1 : 0;
}
 
bool sign_X509_withCA(const char *caFile, const char *caPrivateKeyFile, const char *x509ReqFile, const char *szUserCert)
{
    int ret = 0;
 
    int serial = 1;
    long days = 3650 * 24 * 3600; // 10 years
    char *md = NULL;
 
    X509 * ca = NULL;
    X509_REQ * req = NULL;
    EVP_PKEY *pkey = NULL, *pktmp = NULL;
 
    X509_NAME *subject = NULL, *tmpname = NULL;
    X509 * cert = NULL;
    BIO *out = NULL;
 
    if(!loadCA(caFile, &ca))
        goto free_all;
 
    if(!loadCAPrivateKey(caPrivateKeyFile, &pkey))
        goto free_all;
 
    if(!loadX509Req(x509ReqFile, &req))
        goto free_all;
 
    cert = X509_new();
    // set version to X509 v3 certificate
    if (!X509_set_version(cert,2)) 
        goto free_all;
 
    // set serial
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
 
    // set issuer name frome ca
    if (!X509_set_issuer_name(cert, X509_get_subject_name(ca)))
        goto free_all;
 
    // set time
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days);
 
    // set subject from req
    tmpname = X509_REQ_get_subject_name(req);
    subject = X509_NAME_dup(tmpname);
    if (!X509_set_subject_name(cert, subject)) 
        goto free_all;
 
    // set pubkey from req
    pktmp = X509_REQ_get_pubkey(req);
    ret = X509_set_pubkey(cert, pktmp);
    EVP_PKEY_free(pktmp);
    if (!ret) goto free_all;
 
    // sign cert
    if (!do_X509_sign(cert, pkey, EVP_sha1()))
        goto free_all;
 
    out = BIO_new_file(szUserCert,"w");
    ret = PEM_write_bio_X509(out, cert);
 
free_all:
 
    X509_free(cert);
    BIO_free_all(out);
 
    X509_REQ_free(req);
    X509_free(ca);
    EVP_PKEY_free(pkey);
 
    return (ret == 1);
} 

bool create_signed_certificate(string peer)
{
    bool done = false;
    int i;
    string temp;
    string country, province, city, organization, common, req_path, cert_path, key_path;

    //Ask them which country they are from 
    do {
        cout << "Please enter a country for your digital certificate (2 letter abbreviation): ";
        cout.flush();
        getline(cin, temp);
        if (temp.length() != 2) {
            cout << "Please enter the 2 letter country abbreviation!" << endl;
            continue;
        }
        for (i = 0; i < temp.length(); i++) {
            if (!isalpha(temp[i]) ) {
                cout << "Please enter alpha characters only!" << endl;
                done = false;
                break;
            }
            if (!temp.empty()) {
                done = true;
            }
        }
    } while (temp.empty() || !done);
    country = temp;
    
    //Ask them which province they are from 
    do {
        cout << "Please enter a province for your digital certificate: ";
        cout.flush();
        getline(cin, temp);
        for (i = 0; i < temp.length(); i++) {
            if (!isalpha(temp[i]) ) {
                cout << "Please enter alpha characters only!" << endl;
                done = false;
                break;
            }
            if (!temp.empty()) {
                done = true;
            }
        }
    } while (temp.empty() || !done);
    province = temp;
    
    //Ask them which city they are from 
    do {
        cout << "Please enter a city for your digital certificate: ";
        cout.flush();
        getline(cin, temp);
        for (i = 0; i < temp.length(); i++) {
            if (!isalpha(temp[i]) ) {
                cout << "Please enter alpha characters only!" << endl;
                done = false;
                break;
            }
            if (!temp.empty()) {
                done = true;
            }
        }
    } while (temp.empty() || !done);
    city = temp;

    //Ask them which organization they are from 
    do {
        cout << "Please enter an organization for your digital certificate: ";
        cout.flush();
        getline(cin, temp);
        for (i = 0; i < temp.length(); i++) {
            if (!isalpha(temp[i]) ) {
                cout << "Please enter alpha characters only!" << endl;
                done = false;
                break;
            }
            if (!temp.empty()) {
                done = true;
            }
        }
    } while (temp.empty() || !done);
    organization = temp;

    //Common names must be unique so form name from their peer
    common = peer + "cert";

    //Certificate request path must also be unique so form from name of peer
    req_path = "./PEM/" + peer + "-req.pem";
    
    //Signed certificate path must also be unique so form from name of peer
    cert_path = "./PEM/" + peer + "-cert.pem";
    
    //create private key path
    key_path = "./PEM/" + peer + "-key.pem";

    //generate certificate
    if(!gen_X509Req(country.c_str(), province.c_str(), city.c_str(), organization.c_str(), common.c_str(), req_path.c_str(), key_path.c_str()))
    {
        return false;
    }
    
    //sign certificate with CA
    if(!sign_X509_withCA(CACERT, CAKEY, req_path.c_str(), cert_path.c_str())) 
    {
        return false;
    }

    return true;
}

