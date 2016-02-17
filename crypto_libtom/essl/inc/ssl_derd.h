/*================================================================================================*/
/*!
 \file   ssl_derd.h

 \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  DER (ASN.1) decoder types and functions

 \version  $Version$

 */
/*
 * derd.h - DER (ASN.1) decodeder types and functions
 * --------------------------------------------------
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
 * The DERD (DER decoder) mudule contains the functions to parse a DER
 * encoded octet string. The functions to convert the basic Asn.1 types (tags)
 * to 'C' conforme internal data structures are also in this module.
 *
 * The basic DER types are imported from the file: der.h
 *
 *
 * Usage
 * -----
 *
 *
 * Limitations and boundaries
 * --------------------------
 *
 */

#ifndef __DERD_H
#define __DERD_H

#ifdef __cplusplus
extern "C"
{
#endif

//#include "crypto_wrap.h"

#include "crypto_tomcrypt.h"

#include "ssl_der.h"

/*** Defines ****************************************************************/

#define SSL_DERD_MAXSCANTAGS     10

typedef struct sslDerd_context
{
    s_sslOctetStr_t s_octBuf; /* the decoding DER buffer */
    s_sslOctetStr_t s_octDer; /* current DER encoded octet string */
    s_sslOctetStr_t s_octVal; /* current DER value */
    uint8_t c_tag; /* current DER type (tag) */
    int32_t l_pos; /* current decoding position */
    uint8_t c_EOS; /* if TRUE last DER element in octet string reached */
} s_derdCtx_t;

/*** Prototypes *************************************************************/

/*
 * Initialize the DER decoding context.
 *
 * Parameters:
 *   ps_derdCtx        : Pointer to the decoding context
 *   ps_octStr         : Octet string with the DER encoded data
 *
 * Returns:
 *   Nothing
 */

int16_t sslDerd_initDecCtx(s_derdCtx_t *ps_derdCtx, s_sslOctetStr_t *ps_octStr);

/*
 * Initialize the DER encoding context.
 *
 * Parameters:
 *   ps_derdCtx        : Pointer to the encoded context
 *   ps_octStr         : Octet string with the pure data data
 *
 * Returns:
 *   Nothing
 */
void sslDerd_initEncCtx(s_derdCtx_t *ps_derdCtx, s_sslOctetStr_t *ps_octStr);

/*
 * Put particular tag.
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to the decoding context
 *   c_derTag       : DERd tag
 *   pc_lenOff		: length offset
 *
 * Returns:
 *   success        : >= 1  no error
 *   or error       :    0  if an error in the context has detected
 *
 */
int16_t sslDerd_setTag(s_derdCtx_t * ps_derdCtx, uint8_t c_tag, size_t* psz_lenOff);

/*
 * Get the next DER tag and moves the decoding pointer to the VALUE of
 * the DER value. This function can be used to decode a basic or structed
 * Asn.1 (DER) type.
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to an initialised decoding context
 *
 * Return
 *   success        : >= 1  the next DER Tag (type) in the context
 *   or error       :    0  if an encoding error in the context has detected
 *                          (0 = SSL_DER_ASN1_UNDEF)
 */

int16_t sslDerd_getNextValue(s_derdCtx_t *ps_derdCtx);

/*
 * Get the next DER tag/element and moves the decoding pointer to the END
 * of the DER value. This function jumps over a structed Asn.1 (DER) type.
 * (get a SEQUENCE, SET ... as one element)
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to an initialised decoding context
 *
 * Return
 *   success        : >= 1  the next DER Tag (type) in the context
 *   or error       :    0  if an encoding error in the context has detected
 *                          (0 = SSL_DER_ASN1_UNDEF)
 */

e_derdRet_t sslDerd_getNextEnd(s_derdCtx_t *ps_derdCtx);

/*
 * Get the next BIT STRING tag an moves the the decoding pointer to the VALUE
 * of the bit string. This function must be used to decode a structed bit
 * string!
 *
 * Parameters:
 *   ps_derdCtx           : Pointer to an initialised decoding context
 *
 * Return
 *   success        : >= 1  the next DER Tag (type) in the context
 *   or error       :    0  if an encoding error in the context has detected
 *                          (0 = SSL_DER_ASN1_UNDEF)
 */

e_derdRet_t sslDerd_getNextBitStr(s_derdCtx_t * ps_derdCtx);

/*
 * Scan the DER context for the tag list and move the context pointer
 * at the end of the last tag in the list.
 *
 * Parameters:
 *   ps_derdCtx      : Pointer to an initialised decoding context
 *   rac_tagList     : a '0' terminated tag list
 *                     The list has a max size of SSL_DERD_MAXSCANTAGS !
 *
 * Return
 *   success        : E_SSL_DER_OK
 *   or error       : E_SSL_DER_ERR_WRONGTAG, not all tag in the list has matched!
 */

e_derdRet_t sslDerd_scanTag(s_derdCtx_t *ps_derdCtx,
        const uint8_t rac_tagList[]);

/*
 * Get a unsigend integer from the DER context with a value
 * less ore equal than 0xFFFFFFFF (4294967296)
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to an initialised decoding context.
 *                    The following values of the context will be checked:
 *                    pCtx->c_tag      == SSL_DER_ASN1_INTEGER
 *                    pCtx->s_octVal.cwt_len <= 5
 *   pl_value       : points to the resulting  uint32_t value
 *
 * Return
 *   success        : E_SSL_DER_OK
 *   or error       : E_SSL_DER_ERR_NO_UI32, the context has wrong values
 *
 * Example INTEGER:
 *  Type Len  s_octVal
 *  0x02 0x04 0x7F 0xFF 0xFF 0xFF           =  2147483647 = MAX_SI32
 *  0x02 0x04 0xFF 0xFF 0xFF 0xFF           = -2147483648 = MIN_SI32
 *  0x02 0x05 0x00 0xFF 0xFF 0xFF 0xFF      =  4294967295 = MAX_UI32
 */

e_derdRet_t sslDerd_getUI32(s_derdCtx_t * ps_derdCtx, uint32_t *pl_value);

/*
 * Get a boolean value from the DER context
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to an initialised decoding context.
 *                    The following values of the context will be checked:
 *                    pCtx->c_tag      == SSL_DER_ASN1_BOOLEAN
 *                    pCtx->s_octVal.cwt_len == 1
 *   pc_value       : points to the resulting uint8_t value
 *
 * Return
 *   success        : E_SSL_DER_OK
 *   or error       : E_SSL_DER_ERR_NO_BOOLEAN, the context has wrong values
 *
 * Example BOOLEAN encoding:
 *  Type Len  Value
 *  0x01 0x01 0x00 = FALSE
 *  0x01 0x01 0x01 = TRUE
 *  0x01 0x01 0xFF = TRUE
 */

e_derdRet_t sslDerd_getBool(s_derdCtx_t *ps_derdCtx, uint8_t *pc_value);

/*
 * Get a unsigend (positive) integer from the DER context to a cw_bigNum_t
 * with a max length defined by SSL_DER_MAX_INTEGER_LEN.
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to an initialised decoding context.
 *                    The following values of the context will be checked:
 *                    pCtx->c_tag      == SSL_DER_ASN1_INTEGER
 *                    pCtx->s_octVal.cwt_len <= SSL_DER_MAX_INTEGER_LEN
 *   ppcwt_val      : points to the resulting cw_bigNum_t value
 *
 * Return
 *   success        : E_SSL_DER_OK
 *   or error       : E_SSL_DER_ERR_NO_BIGNUM
 *
 * Example INTEGER:
 *  Type Len            Value
 *  0x02 0x82 0x01 0x00 0x7F 0xFF 0xFF ... a positive INTEGER length 2047 bit
 *  0x02 0x82 0x01 0x01 0x00 0xFF 0xFF ... a positive INTEGER length 2048 bit
 *  0x02 0x82 0x01 0x00 0xFF 0xFF 0xFF ... a negative INTEGER length 2047 bit
 */

//OLD-CW: e_derdRet_t sslDerd_getBigNum(s_derdCtx_t *ps_derdCtx, gci_bigNum_t **ppcwt_val);
e_derdRet_t sslDerd_getBigNum(s_derdCtx_t *ps_derdCtx, st_gciBigInt_t *ppcwt_val);

/*
 * Get a Time string from the DER context
 *
 *  The Asn.1 Definition is:
 *      Time ::= CHOICE {
 *          utcTime     UTCTime,            --   YYMMDDhhmmssZ
 *          generalTime GeneralizedTime }   -- YYYYMMDDhhmmssZ
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to an initialised decoding context.
 *                    The following values of the context will be checked:
 *                    pCtx->c_tag      == SSL_DER_ASN1_UTCTIME or SSL_DER_ASN1_GENERALIZEDTIME
 *                    pCtx->s_octVal.cwt_len <= 16
 *   cwt_strTime    : points to the resulting  time as a string in the format
 *                      = YYYYMMDDhhmmss
 *
 * Return
 *   success        :  E_SSL_DER_OK
 *   or error       :  E_SSL_DER_ERR_NO_TIME, the context has wrong values
 *
 */
e_derdRet_t sslDerd_getTime(s_derdCtx_t *ps_derdCtx,
        ac_sslDerd_utcTime_t cwt_strTime);

/*
 * Decode the Validiy  from a DER string.
 *
 *  The Asn.1 Definition is:
 *      AlgorithmIdentifier ::= SEQUENCE {
 *          notBefore   Time,
 *          notAfter    Time }
 *
 * Parameters:
 *   pCtx           : Pointer to an initialised decoding context.
 *   pValidity      : points to the resulting s_validity structure
 *
 * Return
 *   success        : E_SSL_DER_OK
 *   or error       : E_SSL_DER_ERR_NO_VALIDITYSEQ
 *                    E_SSL_DER_ERR_NO_NOTBEFORE
 *                    E_SSL_DER_ERR_NO_NOTAFTER
 *                    E_SSL_DER_ERR_NO_TIME
 */
e_derdRet_t sslDerd_getValidity(s_derdCtx_t *ps_derdCtx,
        s_sslDerValid_t *ps_validity);

/*
 * Get a primitive BIT STRING from a DER string.
 * (This function does not support the constructed form of a BIT STRING.)
 *
 * Parameters:
 *   ps_derdCtx       : Pointer to an initialised decoding context.
 *   pc_bitStr        : points to the resulting bit string
 *
 * Return
 *   success        :  E_SSL_DER_OK
 *   or error       :  E_SSL_DER_ERR_NO_BITSTR, the context has wrong values
 *
 * Example BIT STRING:
 *  Type Len  Value[0]        Value[1]   Value[2]
 *            = unsused bits  (----- binary -----)
 *                          bit 0           bit 13
 *                            |                |
 *                            1001 0010  0101 11xx
 *                                |          |
 *  0x03 0x03 0x02              0x49       0x3A
 *
 *  x = unused bits, could be 0 or 1
 */

e_derdRet_t sslDerd_getBitStr(s_derdCtx_t *ps_derdCtx, s_sslBitStr_t *pc_bitStr);

/*
 * Get a primitive OCTET STRING from a DER string.
 *
 * Parameters:
 *   ps_derdCtx       : Pointer to an initialised decoding context.
 *   ppc_encSign      : points to the resulting data area
 *   pi_encSignLen    : length of a data
 *
 * Return
 *   success        :  E_SSL_DER_OK
 *   or error       :  E_SSL_DER_ERR_NO_OCTETSTR, the context has wrong values
 *
 */
e_derdRet_t sslDerd_getOctStr(s_derdCtx_t *ps_derdCtx,
                              uint8_t*     pc_encSign, size_t* pi_encSignLen);

/*
 * Decode the signature from a DER string.
 *
 *  The Asn.1 Definition is:
 *       Signature ::= SEQUENCE {
 *           SignHashAlgorithm   OBJECT IDENTIFIER,
 *           Signature           OCTET STRING }
 *
 *  NULL value must following as end of the sequence! ((0x)05 00)
 *
 *  Only the the supported/known hash algorithms are valid:
 *       sha-256    = SSL_OID_SHA256
 *       sha-384    = SSL_OID_SHA384
 *       sha-512    = SSL_OID_SHA512
 *  The check of new supported algorithms must be added in this function!
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to an initialised decoding context.
 *   pe_hashAlg		: Pointer to the variable where hashalg should be stored
 *   ppc_encSign    : Points to the data array where result signature should be
 *   pi_encSignLen  : Length of the extracted signature
 *
 * Return
 *   success        : E_SSL_DER_OK
 *   or error       : E_SSL_DER_ERR_NO_SIGNATURE
 */
// OLD-CW: e_derdRet_t sslDerd_getSign(s_derdCtx_t* 	ps_derdCtx,
//							e_sslHashAlg_t*	pe_hashAlg,
//                            uint8_t*     	pc_decSign, size_t* pi_decSignLen);

sslDerd_getSign(s_derdCtx_t* 	ps_derdCtx,
							en_gciHashAlgo_t*	pe_hashAlg,
                            uint8_t*     	pc_decSign, size_t* pi_decSignLen);


/*
 * Encode the signature to a DER string.
 *
 *  The Asn.1 Definition is:
 *       Signature ::= SEQUENCE {
 *           SignHashAlgorithm   OBJECT IDENTIFIER,
 *           Signature           OCTET STRING }
 *
 *  NULL value must following as end of the sequence! ((0x)05 00)
 *
 *  Only the the supported/known hash algorithms are valid:
 *       sha-256    = SSL_OID_SHA256
 *       sha-384    = SSL_OID_SHA384
 *       sha-512    = SSL_OID_SHA512
 *  The check of new supported algorithms must be added in this function!
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to an initialised decoding context.
 *   e_hashAlg      : Required hash algorithm
 *   s_sign         : Signature to input
 *   sz_signLen     : Signatures length
 *
 * Return
 *   success        : E_SSL_DER_OK
 *   or error       : E_SSL_DER_ERR
 */
e_derdRet_t sslDerd_setSign(s_derdCtx_t *ps_derdCtx, uint8_t c_hashAlg,
                            uint8_t* pc_sign, size_t sz_signLen);

/*
 * Decode the signature algorithm identifier from a DER string.
 *
 *  The Asn.1 Definition is:
 *       AlgorithmIdentifier ::= SEQUENCE {
 *           algorithm   OBJECT IDENTIFIER,
 *           parameters  ANY DEFINED BY algorithm }
 *
 *  For RSA, RSA with MD2, MD5 or SHA1 there are no algorithem parameters
 *  defined, a NULL value must following as end of the sequence!
 *  The implementation decodes only the following structure:
 *       AlgorithmIdentifier ::= SEQUENCE {
 *           algorithm   OBJECT IDENTIFIER,
 *           parameters  NULL }
 *
 *  Only the the supported/known algorithms are valid:
 *       md2WithRSAEncryption    = SSL_OID_MD2_WITH_RSA_ENC
 *       md5WithRSAEncryption    = SSL_OID_MD5_WITH_RSA_ENC
 *       sha1WithRSAEncryption   = SSL_OID_SHA1_WITH_RSA_ENC
 *  The check of new supported algorithms must be added in this function!
 *
 * Parameters:
 *   pCtx           : Pointer to an initialised decoding context.
 *   piSigAlg       : points to the resulting signatur algorithm identifier
 *
 * Return
 *   success        : E_SSL_DER_OK
 *   or error       : E_SSL_DER_ERR_NO_ALGSEQOID
 *                    E_SSL_DER_ERR_UNKNOWN_ALGORITHM
 *                    E_SSL_DER_ERR_NO_ALGNULLPAR
 */
e_derdRet_t sslDerd_getSigAlg(s_derdCtx_t *ps_derdCtx, int32_t *pl_sigAlg);

/*
 * Decode the public key algorithm identifier from a DER string.
 *
 *  The Asn.1 Definition is:
 *       AlgorithmIdentifier ::= SEQUENCE {
 *           algorithm   OBJECT IDENTIFIER,
 *           parameters  ANY DEFINED BY algorithm }
 *
 *  The implementation decodes only the following parameters structure:
 *            parameters  NULL            -- rsaEncryption, defined by RSA Labs
 *            keySize     INTEGER         -- rsa encryption, defined by X.509
 *
 *  Only the the supported/known algorithms are valid:
 *       rsaEncryption           = SSL_OID_RSA_ENCRYPTION
 *       rsa                     = SSL_OID_X509_RSA_ENC
 *  The check of new supported algorithms must be added in this function!
 *
 * Parameters:
 *   ps_derdCtx     : Pointer to an initialised decoding context.
 *   pl_sigAlg      : points to the resulting signatur algorithm identifier
 *   pl_keyLen      : points to the key length (mdulus length) if the algorithm
 *                    is SSL_OID_X509_RSA_ENC, otherwise  = 0
 *
 * Return
 *   success        : E_SSL_DER_OK
 *   or error       : E_SSL_DER_ERR_NO_ALGSEQOID
 *                    E_SSL_DER_ERR_UNKNOWN_ALGORITHM
 *                    E_SSL_DER_ERR_NO_ALGNULLPAR
 *                    E_SSL_DER_ERR_NO_INTEGER
 */
e_derdRet_t sslDerd_getPubKeyAlg(s_derdCtx_t *ps_derdCtx, int32_t *pl_sigAlg,
        uint32_t *pl_keyLen);

/*** Global Variables *******************************************************/

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* already included */
