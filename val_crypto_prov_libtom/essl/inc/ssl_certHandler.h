/*================================================================================================*/
/*!
 \file   ssl_certHandler.h

 \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  Certificate handling API

 \version  $Version$

 */
/*
 * ssl_certHandler.h - Certificate
 * --------------------
 *
 * Last update: 15.02.2002 rsu
 * Reviewed:
 *
 * History
 *  16.01.2002  rsu  Created this file.
 *  xx.xx.2002  rsu  Base implementation for certificate decoder
 *
 *
 *
 * Description
 * -----------
 *
 *  Decoding of a DER encoded X.509v3 certificate to the
 *  C-struct s_sslKeyCertInfo_t.
 *
 *
 * Usage
 * -----
 *
 *  s_sslOctetStr_t *        pOctet;    = pointer to a Asn.1 DER encoded X.509v3  certificate.
 *  s_sslKeyCertInfo_t *    pCertInfo;
 *  s_pubKey_t *      pCaPubKey; = public key of the s_octIssuer CA of the certificate.
 *
 *  Calling sequnce to create a complet s_sslKeyCertInfo_t *:
 *      1  sslCert_decodeInit ( pCertInfo , pOctet )
 *      2  sslCert_decodeCert ( pCertInfo )
 *      3  sslCert_decodeTbsCert ( pCertInfo )
 *
 *  Calling sequnce to verify the signature of a certificate:
 *      1  sslCert_decodeInit ( pCertInfo, pOctet )
 *      2  sslCert_decodeCert ( pCertInfo )
 *      3  ssl_verifyCertSign ( pCertInfo, pCaPubKey )
 *
 *
 * Limitations and boundaries
 * --------------------------
 *
 *  After execution of one of this function, some or all pointers in the
 *  s_sslKeyCertInfo_t * struct points to address in the original
 *  s_sslOctetStr_t * pOctet!
 *  The pointer pOctet can be destroyed but the allocatetd memory may not
 *  be deallocated! This will be done later with the pointer
 *  "Certificate.pc_data" in the s_sslKeyCertInfo_t * struct before deleting
 *  the struct.
 *
 */

#ifndef __CERT_HANDLER_H
#define __CERT_HANDLER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "crypto_wrap.h"
#include "ssl_der.h"
#include "ssl_derd.h"

#include "ssl_cert.h"

//#include "ssl.h"
/*** Defines ****************************************************************/

/*** Prototypes *************************************************************/

/*============================================================================*/
/*!

 \brief     Decode a DER encoded certificate

 \sa sslCert_decodeInit
 \sa sslCert_decodeCert
 \sa sslCert_decodeTbsCert

 \param     ps_certInfo         Pointer to the certificate structure
 \param     ps_octDerStr        Octet string with the DER encoded data

 \return E_SSL_DER_OK                 Decoding succeeded
 \return E_SSL_DER_RETURNVALUES       See DER Error Codes
 */
/*============================================================================*/
e_derdRet_t sslCert_decode(s_sslKeyCertInfo_t *ps_certInfo,
        s_sslOctetStr_t *ps_octDerStr);

/*
 * Initialize the certificate structure for DER decoding
 *
 * Parameters:
 *   ps_certInfo   : Pointer to the certificate structure
 *   ps_octStr     : Octet string with the DER encoded data
 *
 * Returns:
 *   nothing
 */

void sslCert_decodeInit(s_sslKeyCertInfo_t *ps_certInfo,
        s_sslOctetStr_t *ps_octStr);

/*
 * Decoding the following DER certificate structure
 *
 *  Certificate ::= SEQUENCE {
 *      tbsCertificate      TBSCertificate,         --> s_sslOctetStr_t
 *      signatureAlgorithm  AlgorithmIdentifier,    --> int
 *      signature           BIT STRING }            --> s_sslBitStr_t
 *
 *
 * Parameters:
 *   ps_certInfo  : Pointer to an initilised certificate structure
 *
 * Returns:
 *   success       :  E_SSL_DER_OK
 *   or error      :  error codes from E_SSL_DER_RV
 */

e_derdRet_t sslCert_decodeCert(s_sslKeyCertInfo_t *ps_certInfo);

/*
 * Decoding the following DER certificate structure
 *
 *  TBSCertificate ::= SEQUENCE {
 *      version                 [0] EXPLICIT Version DEFAULT v1,        --> uint32_t
 *      serialNumber                INTEGER,                            --> uint32_t
 *      signature                   AlgorithmIdentifier,                --> int
 *      s_octIssuer                 Name,                               --> s_sslOctetStr_t
 *      s_validity                  s_validity,                         --> s_sslDerValid_t
 *      subject                     Name,                               --> s_sslOctetStr_t
 *      subjectPublicKeyInfo        subjectPublicKeyInfo,               --> s_pubKey_t
 *      s_octIssuerUId          [1] IMPLICIT UniqueIdentifier OPTIONAL, --> s_sslOctetStr_t
 *      subjectUniqueID         [2] IMPLICIT UniqueIdentifier OPTIONAL, --> s_sslOctetStr_t
 *      extensions              [3] IMPLICIT s_octExts OPTIONAL}        --> s_sslOctetStr_t
 *
 *
 * Parameters:
 *   ps_certInfo: Pointer to an initilised certificate structure
 *
 * Returns:
 *   success    :  E_SSL_DER_OK
 *   or error   :  error codes from E_SSL_DER_RV
 */

e_derdRet_t sslCert_decodeTbsCert(s_sslKeyCertInfo_t *ps_certInfo);

/*============================================================================*/
/*!

 \brief     Initialisation of an extension structure

 \param     ps_certExts   Pointer to the extension structure that will be initialized

 */
/*============================================================================*/
void sslCert_initExtens(s_sslKeyCertExt_t * ps_certExts);

/*============================================================================*/
/*!

 \brief     Decoding of the s_octExts in the TBC Certificate

 \param     ps_certInfo         Pointer to an initilised certificate structure
 \param     ps_certExts		  Pointer to an extension structure

 \return \ref E_SSL_CERT_OK                         Decoding succeeded
 \return \ref E_SSL_CERT_ERR_EXT_BC_CA_MISSING      The CA field is missing in the s_basicConstr field
 \return \ref E_SSL_CERT_ERR_EXT_BC_PATHLEN_ERR     The l_pathLenConstr field in s_basicConstr was too long for an int
 \return \ref E_SSL_CERT_ERR_EXT_BASIC_CONSTRAINTS  Something else went wrong when decoding the s_basicConstr field
 \return \ref E_SSL_CERT_ERR_EXT_KEYUSAGE           Something went wrong when decodeing the s_keyUsage field
 */
/*============================================================================*/
int sslCert_decodeExtens(s_sslKeyCertInfo_t *ps_certInfo,
        s_sslKeyCertExt_t *ps_certExts);

/*============================================================================*/
/*!

 \brief     Initialisation of the decoding context for subject decoding

 \param     ps_certInfo   Pointer to an initilised certificate structure
 \param     ps_derdCtx     Pointer to an empty decoding context

 */
/*============================================================================*/
void sslCert_decodeSubjInit(s_sslKeyCertInfo_t *ps_certInfo,
                            s_derdCtx_t *ps_derdCtx);

/*============================================================================*/
/*!
 \brief     Decodes the Subject field in the TBS certificate adn returns a commonName

 \param     ps_derdCtx        Pointer to an initilised decoding context
 \param     ps_certSubj       Pointer to a certificate-subject context

 \return \ref E_SSL_CERT_OK                        Decoding succeeded and finished
 \return \ref E_SSL_CERT_MORE_ELEMENTS_AVAILABLE   Decoding succeeded and there are more elements available
 \return \ref E_SSL_CERT_ERR_STRUCT_FAIL           There was an error in the structure of the Subject field
 \return \ref E_SSL_CERT_ERR_NO_OBJECT             The OID is missing, so this can't be processed
 */
/*============================================================================*/
e_sslCertErr_t sslCert_decodeSubjGetNext(s_derdCtx_t        *ps_derdCtx,
                                         s_sslKeyCertSubj_t *ps_certSubj);

/*
 * Delete the certificate structure
 *
 * The memory defined by the pointer pCertInfo->s_octCert.pc_data will not
 * be deallocated. This must be done outside of this function!
 *
 * Parameters:
 *   ps_certInfo  : Pointer to the certificate structure
 * Returns:
 *   nothing
 */

void sslCert_delInfo(s_sslKeyCertInfo_t * ps_certInfo);

/*============================================================================*/
/*!
 \brief     Verify the signature of the s_octTbsCert in the certificate structure

 \param     ps_certInfo         Pointer to an initialised certificate structure
 \param     ps_caRSAPubKey         Pointer to the RSA public key that can verify the certificate, NULL if no RSA is used
 \param     ps_caECCPubKey		        Pointer to the ECC public key that can verify the certificate, NULL if no ECC is used


 \return \ref E_SSL_CERT_OK                        Decoding succeeded and finished
 \return \ref E_SSL_CERT_ERR_INVALID_HASH          The hashtype that is used for signature, is not supported
 \return \ref E_SSL_CERT_ERR_PROCESS_FAILED        There was an error in the verification process
 \return \ref E_SSL_CERT_ERR_VERIFICATION_FAILED   The verification itself failed
 */
/*============================================================================*/
e_sslCertErr_t ssl_verifyCertSign(s_sslKeyCertInfo_t *ps_certInfo, Key_t *p_Key);

/****************************************************************************
 * Convert public key to publicKeyStruct
 * Extracts public key from octet string and save it in the public key
 * structure. PubKey will be stored in "bignum" pool!
 * This function is not threadsafe, if bignum pool is not threadsafe
 ****************************************************************************/

e_derdRet_t sslCert_prepPubKey(s_pubKey_t       *ps_pubKeyInfo,
                               s_sslOctetStr_t  *ps_pubKeyStr);

/****************************************************************************
 * Deletes the public key in a publicKeyStruct
 * The public key will be destroyed (which is not as critical as a
 * private key) and the memory space occupied by the public key in the
 * "bignum"-pool will be freed.
 ****************************************************************************/

void sslCert_delPubKey(s_pubKey_t * pPubKeyInfo);

/****************************************************************************
 ****************************************************************************/

/*** Global Variables *******************************************************/

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* already included */
