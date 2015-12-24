/*================================================================================================*/
/*!
    \file   wssl_oid.c

    \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

    \brief  OID (ASN.1 Object Identifiers)

  \version  $Version$
*/
/*
 * oid.c - OID (Asn.1 Object Identifiers)
 * --------------------------------------
 *
 * Last update: xx.01.2002 rsu
 * Reviewed:
 *
 * History
 *  16.01.2002  rsu  Created this file.
 *  xx.01.2002  rsu  Base implementation for certificate decoder
 *
 *
 *
 */

//#include "crypto_wrap.h"

//#include "crypto_iface.h"

#include "crypto_tomcrypt.h"

#include "ssl_oid.h"


/*** Defines ****************************************************************/
#define	LOGGER_ENABLE		DBG_SSL_OID
#include "logger.h"

/*** DER encoded object identifiers *****************************************/
/* static uint8_t [] = {  }; */

/* domainComponent */
static uint8_t SSL_OID_NR_0_9_2342_19200300_100_1_25[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 };

/* RSA DSI  1.2.840.113549... */
static uint8_t SSL_OID_NR_1_2_840_113549[]            = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D };
static uint8_t SSL_OID_NR_1_2_840_113549_1[]          = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01 };
static uint8_t SSL_OID_NR_1_2_840_113549_2_2[]        = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02 };
static uint8_t SSL_OID_NR_1_2_840_113549_2_5[]        = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05 };
static uint8_t SSL_OID_NR_1_2_840_113549_1_1_1[]      = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static uint8_t SSL_OID_NR_1_2_840_113549_1_1_2[]      = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02 };
static uint8_t SSL_OID_NR_1_2_840_113549_1_1_4[]      = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04 };
static uint8_t SSL_OID_NR_1_2_840_113549_1_1_5[]      = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 };
static uint8_t SSL_OID_NR_1_2_840_113549_1_1_11[]     = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
static uint8_t SSL_OID_NR_1_2_840_113549_1_1_12[]     = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
static uint8_t SSL_OID_NR_1_2_840_113549_1_1_13[]     = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
static uint8_t SSL_OID_NR_1_2_840_113549_1_9_1[]      = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01 };

/* PKIX certificate extensions */
static uint8_t SSL_OID_NR_1_3_6_1_5_5_7_1_1[]         = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
static uint8_t SSL_OID_NR_1_3_6_1_5_5_7_1_2[]         = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x02 };
static uint8_t SSL_OID_NR_1_3_6_1_5_5_7_1_3[]         = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x03 };

/* extended key purpose identifiers */
static uint8_t SSL_OID_NR_1_3_6_1_5_5_7_3_1[]         = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
static uint8_t SSL_OID_NR_1_3_6_1_5_5_7_3_2[]         = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };

/* IDEA */
static uint8_t SSL_OID_NR_1_3_6_1_4_1_188_7_1_1_1[]   = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0x3C, 0x07, 0x01, 0x01, 0x01 };
static uint8_t SSL_OID_NR_1_3_6_1_4_1_188_7_1_1_2[]   = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0x3C, 0x07, 0x01, 0x01, 0x02 };
static uint8_t SSL_OID_NR_1_3_6_1_4_1_188_7_1_1_3[]   = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0x3C, 0x07, 0x01, 0x01, 0x03 };
static uint8_t SSL_OID_NR_1_3_6_1_4_1_188_7_1_1_4[]   = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0x3C, 0x07, 0x01, 0x01, 0x04 };

/* DES */
static uint8_t SSL_OID_NR_1_3_14_3_2_6[]              = { 0x2B, 0x0E, 0x03, 0x02, 0x06 };
static uint8_t SSL_OID_NR_1_3_14_3_2_7[]              = { 0x2B, 0x0E, 0x03, 0x02, 0x07 };
static uint8_t SSL_OID_NR_1_3_14_3_2_8[]              = { 0x2B, 0x0E, 0x03, 0x02, 0x08 };
static uint8_t SSL_OID_NR_1_3_14_3_2_9[]              = { 0x2B, 0x0E, 0x03, 0x02, 0x09 };

/* SHA1 */
static uint8_t SSL_OID_NR_1_3_14_3_2_26[]             = { 0x2B, 0x0E, 0x03, 0x02, 0x1A };

/* OID for X.500 names */
static uint8_t SSL_OID_NR_2_5[]                       = { 0x55 };
static uint8_t SSL_OID_NR_2_5_4[]                     = { 0x55, 0x04 };
static uint8_t SSL_OID_NR_2_5_4_3[]                   = { 0x55, 0x04, 0x03 };
static uint8_t SSL_OID_NR_2_5_4_4[]                   = { 0x55, 0x04, 0x04 };
static uint8_t SSL_OID_NR_2_5_4_5[]                   = { 0x55, 0x04, 0x05 };
static uint8_t SSL_OID_NR_2_5_4_6[]                   = { 0x55, 0x04, 0x06 };
static uint8_t SSL_OID_NR_2_5_4_7[]                   = { 0x55, 0x04, 0x07 };
static uint8_t SSL_OID_NR_2_5_4_8[]                   = { 0x55, 0x04, 0x08 };
static uint8_t SSL_OID_NR_2_5_4_9[]                   = { 0x55, 0x04, 0x09 };
static uint8_t SSL_OID_NR_2_5_4_10[]                  = { 0x55, 0x04, 0x0A };
static uint8_t SSL_OID_NR_2_5_4_11[]                  = { 0x55, 0x04, 0x0B };
static uint8_t SSL_OID_NR_2_5_4_12[]                  = { 0x55, 0x04, 0x0C };
static uint8_t SSL_OID_NR_2_5_4_13[]                  = { 0x55, 0x04, 0x0D };
static uint8_t SSL_OID_NR_2_5_4_41[]                  = { 0x55, 0x04, 0x29 };
static uint8_t SSL_OID_NR_2_5_4_42[]                  = { 0x55, 0x04, 0x2A };
static uint8_t SSL_OID_NR_2_5_4_43[]                  = { 0x55, 0x04, 0x2B };
static uint8_t SSL_OID_NR_2_5_4_45[]                  = { 0x55, 0x04, 0x2D };

/* algorithm OID defined by X.509 */
static uint8_t SSL_OID_NR_2_5_8_1_1[]                 = { 0x55, 0x08, 0x01, 0x01 };


/* AES 128...256 */
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_1[]    = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x01 };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_2[]    = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_3[]    = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x03 };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_4[]    = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x04 };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_21[]   = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x15 };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_22[]   = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16 };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_23[]   = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x17 };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_24[]   = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x18 };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_41[]   = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x29 };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_42[]   = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_43[]   = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2B };
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_1_44[]   = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2C };

/* nistAlgorithms */
static uint8_t SSL_OID_NR_2_16_840_1_101_3_4_2_1[]   =  { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

/* certificate and CRL extensions */
static uint8_t SSL_OID_NR_2_5_29_9[]                  = { 0x55, 0x1D, 0x09 };
static uint8_t SSL_OID_NR_2_5_29_14[]                 = { 0x55, 0x1D, 0x0E };
static uint8_t SSL_OID_NR_2_5_29_15[]                 = { 0x55, 0x1D, 0x0F };
static uint8_t SSL_OID_NR_2_5_29_16[]                 = { 0x55, 0x1D, 0x10 };
static uint8_t SSL_OID_NR_2_5_29_17[]                 = { 0x55, 0x1D, 0x11 };
static uint8_t SSL_OID_NR_2_5_29_18[]                 = { 0x55, 0x1D, 0x12 };
static uint8_t SSL_OID_NR_2_5_29_19[]                 = { 0x55, 0x1D, 0x13 };
static uint8_t SSL_OID_NR_2_5_29_20[]                 = { 0x55, 0x1D, 0x14 };
static uint8_t SSL_OID_NR_2_5_29_27[]                 = { 0x55, 0x1D, 0x1B };
static uint8_t SSL_OID_NR_2_5_29_28[]                 = { 0x55, 0x1D, 0x1C };
static uint8_t SSL_OID_NR_2_5_29_30[]                 = { 0x55, 0x1D, 0x1E };
static uint8_t SSL_OID_NR_2_5_29_31[]                 = { 0x55, 0x1D, 0x1F };
static uint8_t SSL_OID_NR_2_5_29_32[]                 = { 0x55, 0x1D, 0x20 };
static uint8_t SSL_OID_NR_2_5_29_33[]                 = { 0x55, 0x1D, 0x21 };
static uint8_t SSL_OID_NR_2_5_29_35[]                 = { 0x55, 0x1D, 0x23 };
static uint8_t SSL_OID_NR_2_5_29_36[]                 = { 0x55, 0x1D, 0x24 };
static uint8_t SSL_OID_NR_2_5_29_37[]                 = { 0x55, 0x1D, 0x25 };

static uint8_t SSL_OID_NR_2_16_840_1_113730_1_1[]     = { 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01 };
static uint8_t SSL_OID_NR_2_16_840_1_113730_1_13[]    = { 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x0D };

/*** DER encode OID Info Table *****************************************/

typedef struct tagOidInfo
{
        //OLD-CW: rpcw_str_t    strName;        /* short object name                */
		const char* strName;
		//OLD-CW:rpcw_str_t    strOid;         /* dotted-name object identifier    */
        const char* strOid;
		int           cwt_len;        /* BER OID length                   */
const   uint8_t*      pDerOid;        /* BER encoded OID                  */
        int           iId;            /* internal ID                      */
} SSL_OID_INFO;

/*
 * Insert OID lines in aOidInfo, keep the following order:
 *      1. OID Arc (1.2 / 1.3 / 2.5 ...)
 *      2. cwt_len
 *      3. OID value/number
 */
static SSL_OID_INFO aOidInfo [] = {
    /* algorithem and objects base 1.2 */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"rsadsi",                  "1.2.840.113549",               6, &SSL_OID_NR_1_2_840_113549[0],                SSL_OID_RSADSI},
    {"pkcs",                    "1.2.840.113549.1",             7, &SSL_OID_NR_1_2_840_113549_1[0],              SSL_OID_PKCS},
    {"md2",                     "1.2.840.113549.2.2",           8, &SSL_OID_NR_1_2_840_113549_2_2[0],            SSL_OID_MD2},
    {"md5",                     "1.2.840.113549.2.5",           9, &SSL_OID_NR_1_2_840_113549_2_5[0],            SSL_OID_MD5},
    {"rsaEncryption",           "1.2.840.113549.1.1.1",         9, &SSL_OID_NR_1_2_840_113549_1_1_1[0],          SSL_OID_RSA_ENCRYPTION},
    {"md2WithRSAEncryption",    "1.2.840.113549.1.1.2",         9, &SSL_OID_NR_1_2_840_113549_1_1_2[0],          SSL_OID_MD2_WITH_RSA_ENC},
    {"md5WithRSAEncryption",    "1.2.840.113549.1.1.4",         9, &SSL_OID_NR_1_2_840_113549_1_1_4[0],          SSL_OID_MD5_WITH_RSA_ENC},
    {"sha1WithRSAEncryption",   "1.2.840.113549.1.1.5",         9, &SSL_OID_NR_1_2_840_113549_1_1_5[0],          SSL_OID_SHA1_WITH_RSA_ENC},
    {"sha256WithRSAEncryption", "1.2.840.113549.1.1.11",        9, &SSL_OID_NR_1_2_840_113549_1_1_11[0],         SSL_OID_SHA256_WITH_RSA_ENC},
    {"sha384WithRSAEncryption", "1.2.840.113549.1.1.12",        9, &SSL_OID_NR_1_2_840_113549_1_1_12[0],         SSL_OID_SHA384_WITH_RSA_ENC},
    {"sha512WithRSAEncryption", "1.2.840.113549.1.1.13",        9, &SSL_OID_NR_1_2_840_113549_1_1_13[0],         SSL_OID_SHA512_WITH_RSA_ENC},
    {"e-mailAdress",            "1.2.840.113549.1.9.1",         9, &SSL_OID_NR_1_2_840_113549_1_9_1[0],          SSL_OID_EMAIL_ADRESS},

    /* algorithem and objects base 1.3 */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"desECB",                  "1.3.14.3.2.6",                 5, &SSL_OID_NR_1_3_14_3_2_6[0],                  SSL_OID_DES_ECB},
    {"desCBC",                  "1.3.14.3.2.7",                 5, &SSL_OID_NR_1_3_14_3_2_7[0],                  SSL_OID_DES_CBC},
    {"desOFB",                  "1.3.14.3.2.8",                 5, &SSL_OID_NR_1_3_14_3_2_8[0],                  SSL_OID_DES_OFB},
    {"desCFB",                  "1.3.14.3.2.9",                 5, &SSL_OID_NR_1_3_14_3_2_9[0],                  SSL_OID_DES_CFB},
    {"sha1",                    "1.3.14.3.2.26",                5, &SSL_OID_NR_1_3_14_3_2_26[0],                 SSL_OID_SHA1},

    /* certificate and CRL extensions base 1.3 */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"AuthorityInfoAccess",     "1.3.6.1.5.5.7.1.1",            8, &SSL_OID_NR_1_3_6_1_5_5_7_1_1[0],             SSL_OID_AUTHORITY_INFO_ACCESS},
    {"BiometricInfo",           "1.3.6.1.5.5.7.1.2",            8, &SSL_OID_NR_1_3_6_1_5_5_7_1_2[0],             SSL_OID_BIOMETRIC_INFO},
    {"QCStatements",            "1.3.6.1.5.5.7.1.3",            8, &SSL_OID_NR_1_3_6_1_5_5_7_1_3[0],             SSL_OID_QC_STATEMENTS},

    /* extended key purpose identifiers */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"serverAuth",              "1.3.6.1.5.5.7.3.1",            8, &SSL_OID_NR_1_3_6_1_5_5_7_3_1[0],             SSL_OID_SERVER_AUTH},
    {"clientAuth",              "1.3.6.1.5.5.7.3.2",            8, &SSL_OID_NR_1_3_6_1_5_5_7_3_2[0],             SSL_OID_CLIENT_AUTH},

    /* algorithem and objects base 1.3 */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"ideaECB",                 "1.3.6.1.4.1.188.7.1.1.1",     11, &SSL_OID_NR_1_3_6_1_4_1_188_7_1_1_1[0],       SSL_OID_IDEA128_ECB},
    {"ideaCBC",                 "1.3.6.1.4.1.188.7.1.1.2",     11, &SSL_OID_NR_1_3_6_1_4_1_188_7_1_1_2[0],       SSL_OID_IDEA128_CBC},
    {"ideaCFB",                 "1.3.6.1.4.1.188.7.1.1.3",     11, &SSL_OID_NR_1_3_6_1_4_1_188_7_1_1_3[0],       SSL_OID_IDEA128_CFB},
    {"ideaOFB",                 "1.3.6.1.4.1.188.7.1.1.4",     11, &SSL_OID_NR_1_3_6_1_4_1_188_7_1_1_4[0],       SSL_OID_IDEA128_OFB},

    /* name attributes base 2.5 */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"X500",                    "2.5",                          1, &SSL_OID_NR_2_5[0],                           SSL_OID_X500},
    {"X509",                    "2.5.4",                        2, &SSL_OID_NR_2_5_4[0],                         SSL_OID_X509},
    {"commonName",              "2.5.4.3",                      3, &SSL_OID_NR_2_5_4_3[0],                       SSL_OID_COMMON_NAME},
    {"surename",                "2.5.4.4",                      3, &SSL_OID_NR_2_5_4_4[0],                       SSL_OID_SURENAME},
    {"serialNumber",            "2.5.4.5",                      3, &SSL_OID_NR_2_5_4_5[0],                       SSL_OID_SERIAL_NUMBER},
    {"countryName",             "2.5.4.6",                      3, &SSL_OID_NR_2_5_4_6[0],                       SSL_OID_COUNTRY_NAME},
    {"localityName",            "2.5.4.7",                      3, &SSL_OID_NR_2_5_4_7[0],                       SSL_OID_LOCALITY_NAME},
    {"stateOrProvinceName",     "2.5.4.8",                      3, &SSL_OID_NR_2_5_4_8[0],                       SSL_OID_STATE_OR_PROVINCE_NAME},
    {"streetAdress",            "2.5.4.9",                      3, &SSL_OID_NR_2_5_4_9[0],                       SSL_OID_STREET_ADRESS},
    {"organisationName",        "2.5.4.10",                     3, &SSL_OID_NR_2_5_4_10[0],                      SSL_OID_ORGANISATION_NAME},
    {"organisationalUnitName",  "2.5.4.11",                     3, &SSL_OID_NR_2_5_4_11[0],                      SSL_OID_ORGANISATIONAL_UNIT_NAME},
    {"title",                   "2.5.4.12",                     3, &SSL_OID_NR_2_5_4_12[0],                      SSL_OID_TITLE},
    {"description",             "2.5.4.13",                     3, &SSL_OID_NR_2_5_4_13[0],                      SSL_OID_DESCRIPTION},
    {"name",                    "2.5.4.41",                     3, &SSL_OID_NR_2_5_4_41[0],                      SSL_OID_NAME},
    {"givenName",               "2.5.4.42",                     3, &SSL_OID_NR_2_5_4_42[0],                      SSL_OID_GIVEN_NAME},
    {"initials",                "2.5.4.43",                     3, &SSL_OID_NR_2_5_4_43[0],                      SSL_OID_INITIALS},
    {"uniqueIdentifier",        "2.5.4.45",                     3, &SSL_OID_NR_2_5_4_45[0],                      SSL_OID_UNIQE_IDENTIFIER},

    /* certificate and CRL extensions base 2.5.29 */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"SubjectDirectoryAttrib",  "2.5.29.9",                     3, &SSL_OID_NR_2_5_29_9[0],                      SSL_OID_SUB_DIR_ATTR},
    {"SubjectKeyIdentifier",    "2.5.29.14",                    3, &SSL_OID_NR_2_5_29_14[0],                     SSL_OID_SUB_KEY_ID},
    {"KeyUsage",                "2.5.29.15",                    3, &SSL_OID_NR_2_5_29_15[0],                     SSL_OID_KEY_USAGE},
    {"PrivateKeyUsagePeriod",   "2.5.29.16",                    3, &SSL_OID_NR_2_5_29_16[0],                     SSL_OID_KEY_USAGE_PERIOD},
    {"SubjectAltName",          "2.5.29.17",                    3, &SSL_OID_NR_2_5_29_17[0],                     SSL_OID_SUB_ALT_NAME},
    {"IssuerAltame",            "2.5.29.18",                    3, &SSL_OID_NR_2_5_29_18[0],                     SSL_OID_ISSUER_ALT_NAME},
    {"BasicConstrains",         "2.5.29.19",                    3, &SSL_OID_NR_2_5_29_19[0],                     SSL_OID_BASIC_CONSTRAINS},
    {"CRLNumber",               "2.5.29.20",                    3, &SSL_OID_NR_2_5_29_20[0],                     SSL_OID_CRL_NUMBER},
    {"DeltaCRLIndicator",       "2.5.29.27",                    3, &SSL_OID_NR_2_5_29_27[0],                     SSL_OID_DELTA_CRL_INDICATOR},
    {"IssuingDistributionPoint","2.5.29.28",                    3, &SSL_OID_NR_2_5_29_28[0],                     SSL_OID_ISSUING_DISTR_POINT},
    {"NameConstrains",          "2.5.29.30",                    3, &SSL_OID_NR_2_5_29_30[0],                     SSL_OID_NAME_CONSTRAINS},
    {"CRLDistributionPoints",   "2.5.29.31",                    3, &SSL_OID_NR_2_5_29_31[0],                     SSL_OID_CRL_DISTR_POINTS},
    {"CertificatePolicies",     "2.5.29.32",                    3, &SSL_OID_NR_2_5_29_32[0],                     SSL_OID_CERT_POLICIES},
    {"PolicyMappings",          "2.5.29.33",                    3, &SSL_OID_NR_2_5_29_33[0],                     SSL_OID_POLICY_MAP},
    {"AuthorityKeyIdentifier",  "2.5.29.35",                    3, &SSL_OID_NR_2_5_29_35[0],                     SSL_OID_AUTHORITY_KEY_ID},
    {"PolicyConstrains",        "2.5.29.36",                    3, &SSL_OID_NR_2_5_29_36[0],                     SSL_OID_POLICY_CONSTRAINS},
    {"ExtendedKeyUsage",        "2.5.29.37",                    3, &SSL_OID_NR_2_5_29_37[0],                     SSL_OID_EXTEND_KEY_USAGE},

    /* algorithem OID base 2.5 */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"rsa",                     "2.5.8.1.1",                    4, &SSL_OID_NR_2_5_8_1_1[0],                     SSL_OID_X509_RSA_ENC},

    /* algorithem base 2.16 - AES */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"aes128-ECB",              "2.16.840.1.101.3.4.1.1",       9, &SSL_OID_NR_2_16_840_1_101_3_4_1_1[0],        SSL_OID_AES128_ECB},
    {"aes128-CBC",              "2.16.840.1.101.3.4.1.2",       9, &SSL_OID_NR_2_16_840_1_101_3_4_1_2[0],        SSL_OID_AES128_CBC},
    {"aes128-OFB",              "2.16.840.1.101.3.4.1.3",       9, &SSL_OID_NR_2_16_840_1_101_3_4_1_3[0],        SSL_OID_AES128_OFB},
    {"aes128-CFB",              "2.16.840.1.101.3.4.1.4",       9, &SSL_OID_NR_2_16_840_1_101_3_4_1_4[0],        SSL_OID_AES128_CFB},
    {"aes192-ECB",              "2.16.840.1.101.3.4.1.21",      9, &SSL_OID_NR_2_16_840_1_101_3_4_1_21[0],       SSL_OID_AES192_ECB},
    {"aes192-CBC",              "2.16.840.1.101.3.4.1.22",      9, &SSL_OID_NR_2_16_840_1_101_3_4_1_22[0],       SSL_OID_AES192_CBC},
    {"aes192-OFB",              "2.16.840.1.101.3.4.1.23",      9, &SSL_OID_NR_2_16_840_1_101_3_4_1_23[0],       SSL_OID_AES192_OFB},
    {"aes192-CFB",              "2.16.840.1.101.3.4.1.24",      9, &SSL_OID_NR_2_16_840_1_101_3_4_1_24[0],       SSL_OID_AES192_CFB},
    {"aes256-ECB",              "2.16.840.1.101.3.4.1.41",      9, &SSL_OID_NR_2_16_840_1_101_3_4_1_41[0],       SSL_OID_AES256_ECB},
    {"aes256-CBC",              "2.16.840.1.101.3.4.1.42",      9, &SSL_OID_NR_2_16_840_1_101_3_4_1_42[0],       SSL_OID_AES256_CBC},
    {"aes256-OFB",              "2.16.840.1.101.3.4.1.43",      9, &SSL_OID_NR_2_16_840_1_101_3_4_1_43[0],       SSL_OID_AES256_OFB},
    {"aes256-CFB",              "2.16.840.1.101.3.4.1.44",      9, &SSL_OID_NR_2_16_840_1_101_3_4_1_44[0],       SSL_OID_AES256_CFB},

    /* algorithem base 2.16 - nistAlgorithms */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"sha-256",                 "2.16.840.1.101.3.4.2.1",       9, &SSL_OID_NR_2_16_840_1_101_3_4_2_1[0],        SSL_OID_SHA256},

    /* netscape certificate extensions */
    /* strName                  strOid                       cwt_len  pDerOid                                      iId */
    {"certificateType",         "2.16.840.1.113730.1.1",        9, &SSL_OID_NR_2_16_840_1_113730_1_1[0],         SSL_OID_NETSCAPE_CERT_TYPE},
    {"certificateComment",      "2.16.840.1.113730.1.13",       9, &SSL_OID_NR_2_16_840_1_113730_1_13[0],        SSL_OID_NETSCAPE_COMMENT},

    {"domainComponent",         "0.9.2342.19200300.100.1.25",  10, &SSL_OID_NR_0_9_2342_19200300_100_1_25[0],    SSL_OID_DOMAIN_COMPONENT},

    /* end of table mark */
    {"undef",                   NULL,                        0, NULL,                                             SSL_OID_UNDEF}
};


/*** Global Variables *******************************************************/



/*** Local Variables ********************************************************/



/*** Forward declarations ***************************************************/



/*** Local Functions ********************************************************/



/*** Global Functions *******************************************************/

/****************************************************************************
 * OID - get ID from Asn.1 OID
 ****************************************************************************/
int sslOid_fromDer (const uint8_t pOid[], int cwt_len)
{
    int      res     = SSL_OID_UNDEF;
    uint16_t     i       = 0;
    uint8_t     match   = FALSE;
    int      c1, c2;
    int     j;

    assert(pOid != NULL);

    /* search root class of OID */
    while ((aOidInfo[i].pDerOid[0] != *pOid) && (aOidInfo[i].iId != SSL_OID_UNDEF))
    {
        i++;
    }

    /* check the length */
    while ((aOidInfo[i].cwt_len != cwt_len) && (aOidInfo[i].iId != SSL_OID_UNDEF))
    {
        i++;
    }

    /* compare the OID's with the same length */
    while (!match && (aOidInfo[i].cwt_len == cwt_len) && (aOidInfo[i].iId != SSL_OID_UNDEF))
    {
        j = 0;
        do
        {
            c1 = aOidInfo[i].pDerOid[j];
            c2 = pOid[j];
        }
        while ((c1==c2) && (++j < cwt_len));

        match  = (c1==c2);
        if (match)
        {
            res = aOidInfo[i].iId;
        }
        else
        {
            i++;
        }
    }

    return res;
}



/****************************************************************************
 * OID - get ID from LDAP (text) format OID string
 ****************************************************************************/
//OLD-CW: int sslOid_fromText (pcw_str_t pOid)
int sslOid_fromText (const char* pOid)
{
    int  res = SSL_OID_UNDEF;
    int  i = 0;

    assert(pOid != NULL);

    /*
     * Compare with all entry, is not perfomance optimised, but the use of
     * this function is now not sure. Later optimising is prohblay necessary.
     */
    while ((res == SSL_OID_UNDEF) && (aOidInfo[i].iId != SSL_OID_UNDEF))
    {
        if (strcmp(pOid, aOidInfo[i].strOid) == 0)
        {
            res = aOidInfo[i].iId;
        }
        i++;
    }
    return res;
}



/****************************************************************************
 * OID - get ID-Text description from OID
 ****************************************************************************/
//OLD-CW: rpcw_str_t sslOid_toName ( int iOid )
const char* sslOid_toName ( int iOid )
{
    int      zhl = 0;

    while ( (aOidInfo[zhl].iId != iOid) &&
            (aOidInfo[zhl].iId != SSL_OID_UNDEF))
    {
        zhl++;
    }
    return aOidInfo[zhl].strName;
}


/****************************************************************************
 * OID - get DER OID from OID
 ****************************************************************************/
const uint8_t *sslOid_toDer ( int16_t iOid , int16_t *piLen)
{
    int      zhl = 0;

    assert(piLen != NULL);

    while ( (aOidInfo[zhl].iId != iOid) &&
            (aOidInfo[zhl].iId != SSL_OID_UNDEF))
    {
        zhl++;
    }
    *piLen  = aOidInfo[zhl].cwt_len;
    return ( aOidInfo[zhl].pDerOid );
}



/****************************************************************************
 * OID - get text OID from OID
 ****************************************************************************/
//OLD-CW: rpcw_str_t sslOid_toText ( int iOid )
const char* sslOid_toText ( int iOid )
{
    int      zhl = 0;

    while ( (aOidInfo[zhl].iId != iOid) &&
            (aOidInfo[zhl].iId != SSL_OID_UNDEF))
    {
        zhl++;
    }
    return ( aOidInfo[zhl].strOid );
}
