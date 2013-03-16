/*
 * certgeneration.h
 *
 *  Created on: Mar 12, 2013
 *      Author: reschly
 */

#ifndef CERTGENERATION_H_
#define CERTGENERATION_H_

#include <openssl/x509.h>

#define TYPE_WWW_SERVER 1
#define TYPE_SMIME 2



X509* makeselfcert(EVP_PKEY *pkey, int days, char* commonname, const EVP_MD *hash);
X509_REQ* makereq(EVP_PKEY *pkey, char* commonname, const EVP_MD *hash);

#endif /* CERTGENERATION_H_ */
