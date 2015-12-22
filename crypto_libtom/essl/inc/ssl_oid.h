/*================================================================================================*/
/*!
    \file   ssl_oid.h

    \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

    \brief  Object Identifiers

  \version  $Version$

*/
/*
 * oid.h - Object Identifiers
 * --------------------------
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
 * Description
 * -----------
 *
 * This module alows the conversion between different representations of
 * object identifiers. This are:
 *      a) DER encoded
 *      b) internal representation as int
 *      c) dotted-decimal string form (used primary with LDAP)
 *      d) as text description
 *
 *
 *
 * Usage
 * -----
 *
 *
 *
 * Limitations and boundaries
 * --------------------------
 *
 * If an OBJECT IDENTIFIER or an OID is unknown, the generatet error
 * information ist in the return value of the function:
 * -for numeric values = SSL_OID_UNDEF
 * -for string values  = string length is 0 (exeption: SSL_ToidToName returns "undef")
 *
 */

#ifndef __OID_H
#define __OID_H

#ifdef __cplusplus
extern "C" {
#endif

//#include "crypto_wrap.h"
#include <stdint.h>
#include <string.h>

/*** Defines ****************************************************************/



#define SSL_OID_UNDEF                    0

/*
 *  ASN.1 tags/types as object identifiers
 */
#define SSL_OID_BOOLEAN			        SSL_DER_ASN1_BOOLEAN			
#define SSL_OID_INTEGER			        SSL_DER_ASN1_INTEGER			
#define SSL_OID_BIT_STRING		        SSL_DER_ASN1_BIT_STRING		
#define SSL_OID_OCTET_STRING		    SSL_DER_ASN1_OCTET_STRING
#define SSL_OID_NULL			        SSL_DER_ASN1_NULL
#define SSL_OID_OBJECT			        SSL_DER_ASN1_OBJECT			
#define SSL_OID_OBJECT_DESCRIPTOR	    SSL_DER_ASN1_OBJECT_DESCRIPTOR
#define SSL_OID_EXTERNAL			    SSL_DER_ASN1_EXTERNAL
#define SSL_OID_REAL			        SSL_DER_ASN1_REAL
#define SSL_OID_ENUMERATED		        SSL_DER_ASN1_ENUMERATED		
#define SSL_OID_UTF8STRING		        SSL_DER_ASN1_UTF8STRING		

#define SSL_OID_SEQUENCE			    SSL_DER_ASN1_SEQUENCE
#define SSL_OID_SET			            SSL_DER_ASN1_SET			
#define SSL_OID_NUMERICSTRING		    SSL_DER_ASN1_NUMERICSTRING	
#define SSL_OID_PRINTABLESTRING		    SSL_DER_ASN1_PRINTABLESTRING	
#define SSL_OID_T61STRING		        SSL_DER_ASN1_T61STRING		
#define SSL_OID_TELETEXSTRING		    SSL_DER_ASN1_TELETEXSTRING	
#define SSL_OID_VIDEOTEXSTRING		    SSL_DER_ASN1_VIDEOTEXSTRING	
#define SSL_OID_IA5STRING		        SSL_DER_ASN1_IA5STRING		
#define SSL_OID_UTCTIME			        SSL_DER_ASN1_UTCTIME			
#define SSL_OID_GENERALIZEDTIME		    SSL_DER_ASN1_GENERALIZEDTIME	
#define SSL_OID_GRAPHICSTRING		    SSL_DER_ASN1_GRAPHICSTRING	
#define SSL_OID_ISO64STRING		        SSL_DER_ASN1_ISO64STRING		
#define SSL_OID_VISIBLESTRING		    SSL_DER_ASN1_VISIBLESTRING	
#define SSL_OID_GENERALSTRING		    SSL_DER_ASN1_GENERALSTRING	
#define SSL_OID_UNIVERSALSTRING		    SSL_DER_ASN1_UNIVERSALSTRING	
#define SSL_OID_BMPSTRING		        SSL_DER_ASN1_BMPSTRING		


/*
 *  Supported / known object identifiers of the OID
 */
#define SSL_OID_SHA1                     100
#define SSL_OID_RSADSI                   200
#define SSL_OID_PKCS                     (SSL_OID_RSADSI + 1)
#define SSL_OID_MD2                      (SSL_OID_PKCS + 1)
#define SSL_OID_MD5                      (SSL_OID_PKCS + 2)
#define SSL_OID_RSA_ENCRYPTION           (SSL_OID_PKCS + 3)
#define SSL_OID_MD2_WITH_RSA_ENC         (SSL_OID_PKCS + 4)
#define SSL_OID_MD5_WITH_RSA_ENC         (SSL_OID_PKCS + 5)
#define SSL_OID_SHA1_WITH_RSA_ENC        (SSL_OID_PKCS + 6)
#define SSL_OID_SHA256_WITH_RSA_ENC      (SSL_OID_PKCS + 7)
#define SSL_OID_SHA384_WITH_RSA_ENC      (SSL_OID_PKCS + 8)
#define SSL_OID_SHA512_WITH_RSA_ENC      (SSL_OID_PKCS + 9)
#define SSL_OID_EMAIL_ADRESS             (SSL_OID_PKCS + 10)

#define SSL_OID_X509_RSA_ENC             (SSL_OID_PKCS + 11)

#define SSL_OID_AES                      300
#define SSL_OID_AES128_ECB               (SSL_OID_AES + 1)
#define SSL_OID_AES128_CBC               (SSL_OID_AES + 2)
#define SSL_OID_AES128_OFB               (SSL_OID_AES + 3)
#define SSL_OID_AES128_CFB               (SSL_OID_AES + 4)
#define SSL_OID_AES192_ECB               (SSL_OID_AES + 21)
#define SSL_OID_AES192_CBC               (SSL_OID_AES + 22)
#define SSL_OID_AES192_OFB               (SSL_OID_AES + 23)
#define SSL_OID_AES192_CFB               (SSL_OID_AES + 24)
#define SSL_OID_AES256_ECB               (SSL_OID_AES + 41)
#define SSL_OID_AES256_CBC               (SSL_OID_AES + 42)
#define SSL_OID_AES256_OFB               (SSL_OID_AES + 43)
#define SSL_OID_AES256_CFB               (SSL_OID_AES + 44)

#define SSL_OID_HASH                     350
#define SSL_OID_SHA256                   (SSL_OID_HASH + 1)
#define SSL_OID_SHA384                   (SSL_OID_HASH + 2)
#define SSL_OID_SHA512                   (SSL_OID_HASH + 3)

#define SSL_OID_IDEA                     400
#define SSL_OID_IDEA128_ECB              (SSL_OID_IDEA + 1)
#define SSL_OID_IDEA128_CBC              (SSL_OID_IDEA + 2)
#define SSL_OID_IDEA128_OFB              (SSL_OID_IDEA + 3)
#define SSL_OID_IDEA128_CFB              (SSL_OID_IDEA + 4)

#define SSL_OID_DES                      420
#define SSL_OID_DES_ECB                  (SSL_OID_DES + 1)
#define SSL_OID_DES_CBC                  (SSL_OID_DES + 2)
#define SSL_OID_DES_OFB                  (SSL_OID_DES + 3)
#define SSL_OID_DES_CFB                  (SSL_OID_DES + 4)

#define SSL_OID_X500                     500
#define SSL_OID_X509                     (SSL_OID_X500 + 1)
#define SSL_OID_COMMON_NAME              (SSL_OID_X509 + 3)
#define SSL_OID_SURENAME                 (SSL_OID_X509 + 4)
#define SSL_OID_SERIAL_NUMBER            (SSL_OID_X509 + 5)
#define SSL_OID_COUNTRY_NAME             (SSL_OID_X509 + 6)
#define SSL_OID_LOCALITY_NAME            (SSL_OID_X509 + 7)
#define SSL_OID_STATE_OR_PROVINCE_NAME   (SSL_OID_X509 + 8)
#define SSL_OID_STREET_ADRESS            (SSL_OID_X509 + 9)
#define SSL_OID_ORGANISATION_NAME        (SSL_OID_X509 + 10)
#define SSL_OID_ORGANISATIONAL_UNIT_NAME (SSL_OID_X509 + 11)
#define SSL_OID_TITLE                    (SSL_OID_X509 + 12)
#define SSL_OID_DESCRIPTION              (SSL_OID_X509 + 13)
#define SSL_OID_NAME                     (SSL_OID_X509 + 41)
#define SSL_OID_GIVEN_NAME               (SSL_OID_X509 + 42)
#define SSL_OID_INITIALS                 (SSL_OID_X509 + 43)
#define SSL_OID_UNIQE_IDENTIFIER         (SSL_OID_X509 + 45)

#define SSL_OID_DOMAIN_COMPONENT         600

#define SSL_OID_EXT                      700
#define SSL_OID_SUB_DIR_ATTR             (SSL_OID_EXT + 9)
#define SSL_OID_SUB_KEY_ID               (SSL_OID_EXT + 14)
#define SSL_OID_KEY_USAGE                (SSL_OID_EXT + 15)
#define SSL_OID_KEY_USAGE_PERIOD         (SSL_OID_EXT + 16)
#define SSL_OID_SUB_ALT_NAME             (SSL_OID_EXT + 17)
#define SSL_OID_ISSUER_ALT_NAME          (SSL_OID_EXT + 18)
#define SSL_OID_BASIC_CONSTRAINS         (SSL_OID_EXT + 19)
#define SSL_OID_CRL_NUMBER               (SSL_OID_EXT + 20)
#define SSL_OID_DELTA_CRL_INDICATOR      (SSL_OID_EXT + 27)
#define SSL_OID_ISSUING_DISTR_POINT      (SSL_OID_EXT + 28)
#define SSL_OID_NAME_CONSTRAINS          (SSL_OID_EXT + 30)
#define SSL_OID_CRL_DISTR_POINTS         (SSL_OID_EXT + 31)
#define SSL_OID_CERT_POLICIES            (SSL_OID_EXT + 32)
#define SSL_OID_POLICY_MAP               (SSL_OID_EXT + 33)
#define SSL_OID_AUTHORITY_KEY_ID         (SSL_OID_EXT + 35)
#define SSL_OID_POLICY_CONSTRAINS        (SSL_OID_EXT + 36)
#define SSL_OID_EXTEND_KEY_USAGE         (SSL_OID_EXT + 37)

#define SSL_OID_PEXT                     800
#define SSL_OID_AUTHORITY_INFO_ACCESS    (SSL_OID_PEXT + 1)
#define SSL_OID_BIOMETRIC_INFO           (SSL_OID_PEXT + 2)
#define SSL_OID_QC_STATEMENTS            (SSL_OID_PEXT + 3)
#define SSL_OID_SERVER_AUTH              (SSL_OID_PEXT + 4)
#define SSL_OID_CLIENT_AUTH              (SSL_OID_PEXT + 5)

#define SSL_OID_NETSCAPE                 900
#define SSL_OID_NETSCAPE_CERT_TYPE       (SSL_OID_NETSCAPE + 1)
#define SSL_OID_NETSCAPE_COMMENT         (SSL_OID_NETSCAPE + 2)

/*** Prototypes *************************************************************/

/*
 * Get tOOlkit object identifier from DER encoded Asn.1 OID string
 *
 * Parameters
 *   pOid       : IN  - pointer to the DER encoded Asn.1 OID string
 *   cwt_len       : IN  - length of the DER encoded Asn.1 OID string
 * Return
 *   object and algorithm identifier
 */

int sslOid_fromDer ( const uint8_t pOid[], int cwt_len );




/*
 * Get object identifier from text (LDAP) format OID string
 *
 *
 * Parameters
 *   pOid       : IN  - pointer to the LDAP format '0' terminated OID string
 *                      (dotted-decimal OID like "2.5.4.10")
 * Return
 *   object and algorithm identifier
 */

//OLD-CW: int sslOid_fromText ( pcw_str_t pstrOid ) ;
int sslOid_fromText ( const char* pstrOid );



/*
 * Get OID-Text description from object identifier
 *
 *   Example result string:  "md5WithRSAEncryption"
 *
 * Parameters
 *   iOid       : IN  - object and algorithm identifier
 * Return
 *   - pointer to the string with the ID-text.
 *   - pointer to "undef" if the input OID is undefined.
 */

//OLD-CW: rpcw_str_t sslOid_toName ( int iOid );
const char* sslOid_toName ( int iOid );




/*
 * Get DER encoded OID from object identifier
 *
 *   Example result octet string:  0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x04
 *
 * Parameters
 *   iOid       : IN  - object and algorithm identifier
 *   piLen      : OUT - length of the DER OID (0 if the input OID is not defined)
 * Return
 *   - pointer to a octet string with the DER encoded object identifier.
 *   - NULL if the input OID is not defined.
 */

const uint8_t *sslOid_toDer ( int16_t iOid , int16_t *piLen);




/*
 * Get text object identifier from OID
 *
 *   Example result string:  "1.2.840.113549.1.1.4"
 *
 * Parameters
 *   iOid      : IN  - object and algorithm identifier
 * Return
 *   - pointer to a '0' terminatet string of the object identifier.
 *   - NULL if the input OID is not defined.
 */

//OLD-CW: rpcw_str_t sslOid_toText ( int iOid );
const char* sslOid_toText ( int iOid );



/*** Global Variables *******************************************************/



#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* already included */
