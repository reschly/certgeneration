/*
 * utils.c
 *
 *  Created on: Mar 12, 2013
 *      Author: reschly
 *
 *  http://www.opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/demos/x509/mkcert.c used as a guide
 */

#include "certgeneration.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

int add_ext(X509 *cert, int nid, char *value);
int add_coulton(X509 *cert);

int commonname_type(char *cn)
{
	char* pos;

	pos = strchr(cn, '@');
	if (pos)
		return TYPE_SMIME;
	else
		return TYPE_WWW_SERVER;
}

X509* makeselfcert(EVP_PKEY *pkey, int days, char* commonname, const EVP_MD *hash)
{
	X509 *x;
	X509_NAME *name;
	char* cnField;
	char *eku;
	BIGNUM *bn;
	int type;
	char subjaltname[512];

	type = commonname_type(commonname);
	switch(type)
	{
		case TYPE_WWW_SERVER:
			cnField = "CN";
			eku = "serverAuth";
			strcpy(subjaltname, "DNS:");
			break;
		case TYPE_SMIME:
			cnField = "emailAddress";
			eku = "emailProtection";
			strcpy(subjaltname, "email:");
			break;
		default:
			return NULL;
	}

	x = X509_new();
	X509_set_version(x, 2);
	bn = BN_new();
	BN_rand(bn, 255, 1, 0);
	BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
	BN_free(bn);
	X509_gmtime_adj(X509_get_notBefore(x),(long)60*60*24*(-7));
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
	X509_set_pubkey(x, pkey);
	name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, cnField, MBSTRING_ASC, (unsigned char*)commonname, -1, -1, 0);
	X509_set_issuer_name(x, name);

	add_ext(x, NID_key_usage, "critical,digitalSignature,keyEncipherment,keyAgreement");
	add_ext(x, NID_ext_key_usage, eku);
	if (strlen(commonname) < 500)
	{
		strcat(subjaltname, commonname);
		add_ext(x, NID_subject_alt_name, subjaltname);
	}
	add_coulton(x);
	X509_sign(x,pkey,hash);

	return x;
}

X509_REQ* makereq(EVP_PKEY *pkey, char* commonname, const EVP_MD *hash)
{
	X509_REQ *req;
	X509_NAME *name;
	char* cnField;
	int type;

	type = commonname_type(commonname);

	switch(type)
	{
		case TYPE_WWW_SERVER:
			cnField = "CN";
			break;
		case TYPE_SMIME:
			cnField = "emailAddress";
			break;
		default:
			return NULL;
	}

	req = X509_REQ_new();
	X509_REQ_set_version(req, 2);
	X509_REQ_set_pubkey(req, pkey);
	name = X509_NAME_new();
	X509_NAME_add_entry_by_txt(name, cnField, MBSTRING_ASC, (unsigned char*) commonname, -1, -1, 0);
	X509_REQ_set_subject_name(req, name);

	X509_REQ_sign(req, pkey, hash);

	return req;
}

int add_ext(X509 *cert, int nid, char *value)
	{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
	}

/* The below two functions are inspired by:

                    There is nothing in any of these standards that would
                    prevent me from including a 1 gigabit MPEG movie of me
                    playing with my cat as one of the RDN components of the DN
                    in my certificate.
                        -- Bob Jueneman on IETF-PKIX

		Via http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt

	Ideally this would be Rick Astley's "Never gonna give you up", but I'm
	doubt it is licensed for such use.

	Fortunatly, Jonathan Coulton licenses his work CC-by-nc.  The associated data
	was taken from http://songs.jonathancoulton.com/free/mp3/Skullcrusher_Mountain.mp3 .
	Coulton has not endorsed me or my use of his song in this manner.

	Appropriately, this song came up on Pandora while writing this code

	1.3.6.1.4.1.40107 is my namespace.  I hereby declare 1.3.6.1.4.1.40107.1 to indicate
	an X509 Media Extension, the format of which shall be indicated by the magic numbers
	contained within the data (in other words, there is no explicit media format indicator)
 */
int add_media_extention(X509 *cert, unsigned char *data, int datalen)
{
	int mediaNID;
	ASN1_OCTET_STRING *octetString;
	X509_EXTENSION *ext;

	mediaNID = OBJ_create("1.3.6.1.4.1.40107.1", "Media", "Reschly's X509 Media Extension");
	octetString = ASN1_OCTET_STRING_new();

	ASN1_OCTET_STRING_set(octetString,(unsigned char*)data,datalen);
	ext = X509_EXTENSION_create_by_NID( NULL, mediaNID, 0, octetString );
	if (!ext)
		return 0;
	X509_add_ext(cert,ext,-1);
	return 1;
}

int add_coulton(X509 *cert)
{
	unsigned char* data;
	int datalen;
	int ret;
	FILE *f;

	f = fopen("Mandelbrot_Set.mp3", "rb");
	if (!f)
		return -1;
	fseek(f, 0, SEEK_END);
	datalen = ftell(f);
	fseek(f, 0, SEEK_SET);

	data = malloc(datalen);
	if (!data)
		return -1;
	fread(data, 1, datalen, f);
	fclose(f);

	ret = add_media_extention(cert, data, datalen);
	free(data);
	return ret;
}
