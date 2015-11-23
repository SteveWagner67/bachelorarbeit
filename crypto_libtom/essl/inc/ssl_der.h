/*================================================================================================*/
/*!
 \file   ssl_der.h

 \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  DER (ASN.1) basic types definition

 \version  $Version$

 */
/*
 * der.h - DER (ASN.1) basic types definition
 * ------------------------------------------
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
 *
 * Usage
 * -----
 *
 *
 *
 * Limitations and boundaries
 * --------------------------
 *
 */

#ifndef __DER_H
#define __DER_H

#ifdef __cplusplus
extern "C"
{
#endif

/*** Defines ****************************************************************/

/*
 * Project specific range bounderies for the DER encoder/decoder
 */
#define SSL_DER_ASN1_MAX_SIZE_OCTET          2       /* max size octets in of an asn.1 type */

#define SSL_DER_MAX_INTEGER_LEN          (SSL_RSA_MAX_KEY_SIZE / 8)
#define SSL_DER_ASN1_MAX_BITSTR_OCTET        512
#define SSL_DER_ASN1_MAX_TIME_OCTET          15
#define SSL_DER_ASN1_MAX_OID_OCTET           9
#define SSL_DER_ASN1_MAX_NULL_OCTET          0
#define SSL_DER_ASN1_MAX_STRING_OCTET        128
#define SSL_DER_ASN1_MAX_SEQUENCE_OCTET      8192 /*2048*/

/*! RFC 3447:
 * the DER encoding T of the DigestInfo value is equal to the following:
 *  SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
 *  with a length of 19 bytes*/
#define SSL_DER_ASN1_OID_SHA256_LEN          19
#define SSL_DER_ASN1_OID_HASH_MAX_LEN        SSL_DER_ASN1_OID_SHA256_LEN

/*
 * Asn.1 - Classes flags
 */
#define SSL_DER_ASN1_UNIVERSAL		        0x00
#define	SSL_DER_ASN1_APPLICATION		    0x40
#define SSL_DER_ASN1_CONTEXT_SPECIFIC		0x80
#define SSL_DER_ASN1_PRIVATE			    0xC0

/*
 * Asn.1 - Constructed type flags
 */
#define SSL_DER_ASN1_CONSTRUCTED            0x20
#define SSL_DER_ASN1_PRIMITIVE_TAG          0x1F

/*
 * Asn.1 / DER - universal tags - type identifier
 */
#define SSL_DER_ASN1_NEG			        0x100	/* negative flag */
#define SSL_DER_ASN1_UNDEF                  0
#define SSL_DER_ASN1_EOC			        0

#define SSL_DER_ASN1_BOOLEAN			    0x01
#define SSL_DER_ASN1_INTEGER			    0x02
#define SSL_DER_ASN1_BIT_STRING		        0x03
#define SSL_DER_ASN1_OCTET_STRING		    0x04
#define SSL_DER_ASN1_NULL			        0x05
#define SSL_DER_ASN1_OBJECT			        0x06
#define SSL_DER_ASN1_OBJECT_DESCRIPTOR	    0x07
#define SSL_DER_ASN1_EXTERNAL			    0x08
#define SSL_DER_ASN1_REAL			        0x09
#define SSL_DER_ASN1_ENUMERATED		        0x0A
#define SSL_DER_ASN1_UTF8STRING		        0x0C

#define SSL_DER_ASN1_SEQUENCE			    0x10
#define SSL_DER_ASN1_SET			        0x11
#define SSL_DER_ASN1_NUMERICSTRING		    0x12
#define SSL_DER_ASN1_PRINTABLESTRING		0x13
#define SSL_DER_ASN1_T61STRING		        0x14
#define SSL_DER_ASN1_TELETEXSTRING		    SSL_DER_ASN1_T61STRING
#define SSL_DER_ASN1_VIDEOTEXSTRING		    0x15
#define SSL_DER_ASN1_IA5STRING		        0x16
#define SSL_DER_ASN1_UTCTIME			    0x17
#define SSL_DER_ASN1_GENERALIZEDTIME		0x18
#define SSL_DER_ASN1_GRAPHICSTRING		    0x19
#define SSL_DER_ASN1_ISO64STRING		    0x1A
#define SSL_DER_ASN1_VISIBLESTRING		    SSL_DER_ASN1_ISO64STRING
#define SSL_DER_ASN1_GENERALSTRING		    0x1B
#define SSL_DER_ASN1_UNIVERSALSTRING		0x1C
#define SSL_DER_ASN1_BMPSTRING		        0x20

#define SSL_DER_ASN1_IS_STRPRINT(x) 			(((x) == SSL_DER_ASN1_PRINTABLESTRING) || \
                                            ((x) == SSL_DER_ASN1_IA5STRING)       || \
                                            ((x) == SSL_DER_ASN1_UTF8STRING))

#define SSL_DER_ASN1_IS_STRING(x)           (((x) == SSL_DER_ASN1_PRINTABLESTRING) || \
                                            ((x) == SSL_DER_ASN1_IA5STRING)       || \
                                            ((x) == SSL_DER_ASN1_UTF8STRING)      || \
                                            ((x) == SSL_DER_ASN1_TELETEXSTRING)   || \
                                            ((x) == SSL_DER_ASN1_VIDEOTEXSTRING)  || \
                                            ((x) == SSL_DER_ASN1_ISO64STRING)     || \
                                            ((x) == SSL_DER_ASN1_GENERALSTRING)   || \
                                            ((x) == SSL_DER_ASN1_UNIVERSALSTRING) || \
                                            ((x) == SSL_DER_ASN1_BMPSTRING))
/*
 * Asn.1 - DER constructed tags
 */
#define SSL_DER_ASN1_CSEQUENCE			    (SSL_DER_ASN1_SEQUENCE | SSL_DER_ASN1_CONSTRUCTED)
#define SSL_DER_ASN1_CSET			        (SSL_DER_ASN1_SET | SSL_DER_ASN1_CONSTRUCTED)

#define SSL_DER_ASN1_CCONTEXTSPEC			(SSL_DER_ASN1_CONTEXT_SPECIFIC | SSL_DER_ASN1_CONSTRUCTED)

/*
 * Asn.1 - Length flag
 */
#define SSL_DER_ASN1_BIGLENTHG               0x7F

#define SSL_DER_ASN1_NEGATIV_INTEGER         0x80

#define SSL_DER_ASN1_UTCTIME_LEN             13
#define SSL_DER_ASN1_GENERALIZEDTIME_LEN     15

/*
 * Asn.1 / DER - BIT STRING position
 *
 */
#define SSL_DER_ASN1_BITSTR_BIT0             0x80
#define SSL_DER_ASN1_BITSTR_BIT1             0x40
#define SSL_DER_ASN1_BITSTR_BIT2             0x20
#define SSL_DER_ASN1_BITSTR_BIT3             0x10
#define SSL_DER_ASN1_BITSTR_BIT4             0x08
#define SSL_DER_ASN1_BITSTR_BIT5             0x04
#define SSL_DER_ASN1_BITSTR_BIT6             0x02
#define SSL_DER_ASN1_BITSTR_BIT7             0x01

/*
 *  DER Steps for parsing certificate
 *  ---------------
 */
typedef enum E_SSL_DER_STEPS
{
    E_SSL_DER_INIT = 0x00,
    E_SSL_DER_GET_VERSION,
    E_SSL_DER_GET_CERTSERNUM,
    E_SSL_DER_GET_TBSALGID,
    E_SSL_DER_GET_ISSUERNAME,
    E_SSL_DER_GET_VALIDITY,
    E_SSL_DER_GET_SUBJNAME,
    E_SSL_DER_GET_PUBKEY,
    E_SSL_DER_GET_OPTIONAL,

    E_SSL_DER_GET_TBSCERT,
    E_SSL_DER_GET_SIGNATURE,

} e_sslCertDecStep_t;

/*
 *  DER Error Codes
 *  ---------------
 */
typedef enum E_DERD_RETCODES
{
    E_SSL_DER_OK = 0, E_SSL_DER_ERR = 0x100, /* offset ??? Unspecified DER error*/
    /*                                                                          */
    E_SSL_DER_ERR_RESBUF_SIZE, /* Size of the result buffer to small            */
    /*                                                                          */
    E_SSL_DER_ERR_DECODING, /* Unspecified DER decoding error                                       */
    E_SSL_DER_ERR_ENCODING, /* Unspecified DER encoding error                                       */
    E_SSL_DER_ERR_WRONGTAG, /* a wrong DER tag was found                                            */
    /* ---------------------------------------------------------------------------------------------*/
    /* general decoding erros:                                                                              */
    E_SSL_DER_ERR_NO_BOOLEAN, /* no or incorrect BOOLEAN                                                                      */
    E_SSL_DER_ERR_NO_INTEGER, /* no or incorrect INTEGER                                              */
    E_SSL_DER_ERR_NO_UI32, /* the INTEGER is negative or greater than MAX_UI32                  */
    E_SSL_DER_ERR_NO_BIGNUM, /* the INTEGER is negative or to long for the Bignum                    */
    E_SSL_DER_ERR_NO_BITSTR, /* BIT STRING is not correct                                            */
    E_SSL_DER_ERR_NO_BITSTRUCT, /* no DER structure in the bit string                                   */
    E_SSL_DER_ERR_NO_OCTETSTR, /*                                                                      */
    E_SSL_DER_ERR_NO_NULL, /* no or incorrect NULL encoding                                        */
    E_SSL_DER_ERR_NO_OBJECT, /* no or incorrect OBJECT IDENTIFIER                                    */
    E_SSL_DER_ERR_NO_OBJECT_DESC, /*                                                                      */
    E_SSL_DER_ERR_NO_EXTERNAL, /*                                                                      */
    E_SSL_DER_ERR_NO_UTF8STR, /*                                                                      */
    /*                                                                      */
    E_SSL_DER_ERR_NO_CSEQUENCE, /* no or incorrect SEQUENCE                                             */
    E_SSL_DER_ERR_NO_CSET, /* no or incorrect SET                                                  */
    E_SSL_DER_ERR_NO_NUMERICSTR, /*                                                                      */
    E_SSL_DER_ERR_NO_PRINTABLESTR, /*                                                                      */
    E_SSL_DER_ERR_NO_T61STR, /*                                                                      */
    E_SSL_DER_ERR_NO_TELETEXSTR, /*                                                                      */
    E_SSL_DER_ERR_NO_VIDEOTEXSTR, /*                                                                      */
    E_SSL_DER_ERR_NO_IA5STR, /*                                                                      */
    /*                                                                      */
    E_SSL_DER_ERR_NO_UTCTIME, /* no or incorrect UTCTIME                                              */
    E_SSL_DER_ERR_NO_GENERALIZEDTIME, /* no or incorrect GENERALIZEDTIME                                      */
    E_SSL_DER_ERR_NO_TIME, /* no UTC Time or Generalized Time                                      */
    /*                                                                      */
    E_SSL_DER_ERR_NO_GRAPHICSTR, /*                                                                      */
    E_SSL_DER_ERR_NO_ISO64STR, /*                                                                      */
    E_SSL_DER_ERR_NO_VISIBLESTR, /*                                                                      */
    E_SSL_DER_ERR_NO_GENERALSTR, /*                                                                      */
    E_SSL_DER_ERR_NO_UNIVERSALSTR, /*                                                                      */
    E_SSL_DER_ERR_NO_BMPSTR, /*                                                                      */
    /*                                                                      */
    E_SSL_DER_ERR_NO_DSTR, /* no or incorrect DirectoryString                                      */
    /*    ---------------------------------------------------------------------------------------------------- */
    /*    decoding errors by:              Certificate ::= SEQUENCE {                                          */
    /*      tbsCertificate      TBSCertificate,                             */
    /*      signatureAlgorithm  AlgorithmIdentifier,                        */
    /*      signature           BIT STRING }                                */
    E_SSL_DER_ERR_NO_CERT, /* start of certificate decoding fail because                           */
    /* DER record starts not with a SEQUENCE                                */
    E_SSL_DER_ERR_NO_TBSCERT, /* SEQUNCE tag for the tbsCertificate not found                         */
    E_SSL_DER_ERR_NO_SIGALG, /* SEQUNCE tag for the signatureAlgorithm not found                      */
    E_SSL_DER_ERR_NO_SIGNATURE, /* BIT STRING tag for the signatur not found                            	   */
    E_SSL_DER_ERR_NO_HASHALG, /* OID tag for the hash algorithm not found                            	   */
    /*    ---------------------------------------------------------------------------------------------------- */
    /*    decoding errors by:              AlgorithmIdentifier ::= SEQUENCE {                                  */
    /*      algorithm   OBJECT IDENTIFIER,                                  */
    /*      parameters  NULL }                                              */
    E_SSL_DER_ERR_NO_ALGSEQOID, /* tag for SEQUENCE or tag for                                          */
    /* OBJECT IDENTIFIER for algorithm not found                            */
    E_SSL_DER_ERR_NO_ALGNULLPAR, /* algorithm parameter are not equal to NULL                            */
    /*                                                                      */
    E_SSL_DER_ERR_UNKNOWN_ALGORITHM, /* algorithm not known, not supported                                   */
    E_SSL_DER_ERR_UNKNOWN_OBJECT, /* unknown OBJECT IDENTIFIER                                            */
    /* ---------------------------------------------------------------------------------------------------- */
    /* decoding errors by:              s_validity ::= SEQUENCE {                                             */
    /*      notBefore   Time,                                               */
    /*      notAfter    Time }                                              */
    E_SSL_DER_ERR_NO_VALIDITYSEQ, /* SEQUNCE tag for the s_validity not found                               */
    E_SSL_DER_ERR_NO_NOTBEFORE, /* tag for notBefore Time not found                                     */
    E_SSL_DER_ERR_NO_NOTAFTER, /* tag for notAfter Time not found                                      */
    /* ---------------------------------------------------------------------------------------------------- */
    /* decoding errors by:              TBSCertificate ::= SEQUENCE {                                       */
    /*      version                 [0] EXPLICIT Version DEFAULT v1,        */
    /*      serialNumber                INTEGER,                            */
    /*      signature                   AlgorithmIdentifier,                */
    /*      s_octIssuer                      Name,                               */
    /*      s_validity                    s_validity,                           */
    /*      subject                     Name,                               */
    /*      subjectPublicKeyInfo        subjectPublicKeyInfo,               */
    /*      s_octIssuerUId          [1] IMPLICIT UniqueIdentifier OPTIONAL, */
    /*      subjectUniqueID         [2] IMPLICIT UniqueIdentifier OPTIONAL, */
    /*      extensions              [3] IMPLICIT s_octExts OPTIONAL }      */
    E_SSL_DER_ERR_DIFSIGALG, /* The signature algorithm in the TBSCertificate                        */
    /* is different to the algorithm in the signature.                      */
    /* This may be only a warning...?                                       */
    E_SSL_DER_ERR_NO_ISSUERNAME, /* SEQUNCE tag for s_octIssuer not found                                     */
    E_SSL_DER_ERR_NO_SUBJECTNAME, /* SEQUNCE tag for subject not found                                    */
    E_SSL_DER_ERR_NO_PUBKEYINFO, /* SEQUNCE tag for public key info not found                            */
    /* ---------------------------------------------------------------------------------------------------- */
    /* decoding errors by:              SubjectPublicKeyInfo ::= SEQUENCE {                                 */
    /*      algorithm           AlgorithmIdentifier,                        */
    /*      subjectPublicKey    BIT STRING }                                */
    E_SSL_DER_ERR_NO_PUBKEYSEQ, /* incorrect PublicKeyInfo SEQUENCE                                     */
    E_SSL_DER_ERR_NO_PUBKEYBITSTR, /* BIT STRING tag for publicKey not found                               */
    /* ---------------------------------------------------------------------------------------------------- */
    /* decoding errors by:              RSAPublicKey ::= SEQUENCE {                                         */
    /*      modulus         INTEGER,                                        */
    /*      publicExponent  INTEGER }                                       */
    E_SSL_DER_ERR_NO_MODULUS, /* INTEGER tag for modulus not found                                    */
    E_SSL_DER_ERR_NO_PUBEXP, /* INTEGER tag for public exponent not found                            */
    /* ---------------------------------------------------------------------------------------------------- */
    E_SSL_DER_MAX_RVS /* Maximum number of return values                                      */
} e_derdRet_t; /* DER Error Codes                                                                                       */

#define     UTC_STRING_SIZE               20
typedef char ac_sslDerd_utcTime_t[UTC_STRING_SIZE];
/*
 * OCTET STRING
 * A char string with a length element as base for the
 * data buffers in the DER decoding.
 */
typedef struct ssl_octetStr
{
    size_t cwt_len; /* length of the OCTET STRING in octets */
    uint8_t *pc_data; /* pointer to the OCTET STRING */
} s_sslOctetStr_t;

/*
 * INTEGER STRING
 * Structure for integers with variable length.
 */
typedef struct sslDer_integerStr
{
    size_t cwt_len; /* length of the INTEGER STRING in octets */
    uint8_t *pc_data; /* pointer to the INTEGER STRING */
} s_sslIntStr_t;

/*
 * BIT STRING
 * Structure for a bit string with a bit length unequal of a multiple of 8 bit.
 */
typedef struct sslDer_bitStr
{
    size_t cwt_len; /* length of the signature BIT STRING in octets */
    uint8_t *pc_bitStr; /* pointer to the BIT STRING */
    uint8_t c_unused; /* Number of unused bits in the last octet of  */
/* the BIT STRING */
} s_sslBitStr_t;

/*
 * VALIDITY
 * Structure for a period of s_validity.
 */
typedef struct sslDer_validity
{
    ac_sslDerd_utcTime_t cwt_strNotBefore;
    ac_sslDerd_utcTime_t cwt_strNotAfter;
} s_sslDerValid_t;

typedef struct sslDer_genericString
{
    int iStringType;
    int cwt_len;
    uint8_t *pc_data;
} s_sslGenStr_t;
/*** Prototypes *************************************************************/

/*
 * No prototypes in this file, this headerfile has no implementation file.
 */

/*** Global Variables *******************************************************/

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* already included */
