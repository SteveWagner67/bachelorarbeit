/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl.h                                                      */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*! \file
 *     Main header file of the Embetter SSL implementation.\n
 *     Everything which needs to be defined and has no other header file yet
 *     is defined temporarly in this file.                                   */
/*                                                                           */
/*  CAUTIONS:                                                                */
/*     Non                                                                   */
/*                                                                           */
/*  LANGUAGE:        ANSI C                 COMPILER:                        */
/*  TARGET SYSTEM:                                                           */
/*                                                                           */
/*****************************************************************************/
/*                                                                           */
/*  MODIFICATION HISTORY:                                                    */
/*                                                                           */
/*  Date        Person        Change                                         */
/*  ====        ======        ======                                         */
/*  17.03.03    WAM           Initial version                                */
/*  01.11.04   	Th. Gillen    Revised version, support for socket layer IF   */
/*  23.09.14    A. Yushev     Revised version, wssl->ssl                     */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*                                                                           */
/*****************************************************************************/


#ifndef    FILE_SSL_H
  #define    FILE_SSL_H

#ifdef __cplusplus
extern "C" {
#endif /* begin C prototype in C++ */
#include "ssl_certHandler.h"
#include "cert_db.h"
#include "ssl3.h"
#include "timeout.h"




/***** Defines ****************************************************************/

#ifndef SSL_DBG_STRING
/*!
 * This is the default format string when a printf is called.
 * It will print "filename; line; SSLcontext;"
 */
#define SSL_DBG_STRING "\n %16.16s; %5d; %9p; "
#endif

#ifndef SSL_WAIT_FOR_SHUTDOWN
/*! This Macro is per default set to false, caused by the behavior of the
 *  Internet Explorer. When switching it to true, sslSoc_shutdown will send a
 *  close_notify alert and wait until the close_notify from the communication
 *  partner is received or the socket has been closed in another way
 *  When it's set to false, sslSoc_shutdown returns OK after the close_notify alert
 *  has been sent - mozilla/openssl like behavior
 */
#define SSL_WAIT_FOR_SHUTDOWN       0
#endif

#ifndef SSL_NO_SSLV2_HELLO
/* usually SSL Version2 ClientHello is allowed */
#define SSL_NO_SSLV2_HELLO          FALSE
#endif

#ifndef SSL_MAX_SSL_CTX
/* Maximum number of coexistent SSL context */
#define SSL_MAX_SSL_CTX             10
#endif

#ifndef SSL_KM_DHE_MAX_REUSE
/* how often a DHE key can be reused for a handshake */
#define SSL_KM_DHE_MAX_REUSE        20
#endif

#ifndef SSL_DEFAULT_DHE_KEYSIZE
/* Default keysize for Diffie-Hellman Ephemeral key in bytes */
#define SSL_DEFAULT_DHE_KEYSIZE     192
#endif

#ifndef SSL_DEFAULT_SESSION_TIMEOUT
/* A default session timeout of 10minutes(600seconds) is used */
#define SSL_DEFAULT_SESSION_TIMEOUT 600
#endif

#ifndef SSL_DEFAULT_CLIENTAUTH_LEVEL
/* The default level for client authentication is E_SSL_SHOULD_AUTH */
/* see typedef of type e_sslAuthLevel_t for details  */
#define SSL_DEFAULT_CLIENTAUTH_LEVEL E_SSL_SHOULD_AUTH
#endif

#ifndef SSL_DEFAULT_SSL_TLS_VERSION
/* TLS1.1 is supported but TLS1.0 is used as default. */
/* This field must not be E_VER_DCARE. */
#define SSL_DEFAULT_SSL_TLS_VERSION E_TLS_1_0
#endif

#ifndef SSL_MIN_SSL_TLS_VERSION
/* SSL3.0 is set as minimal version in a General SSL Context */
#define SSL_MIN_SSL_TLS_VERSION     E_SSL_3_0
#endif

#ifndef SSL_MAX_SSL_TLS_VERSION
/* TLS1.1 is set as maximal version in a General SSL Context */
#define SSL_MAX_SSL_TLS_VERSION     E_TLS_1_1
#endif

#ifndef SSL_DEFAULT_RENEGOTIATION_BEHAVIOR
/* Per default, renegotiation is allowed */
#define SSL_DEFAULT_RENEGOTIATION_BEHAVIOR TRUE
#endif

#ifndef SSL_SESSION_CACHE_SIZE
/* Maximum number of cached sessions */
#define SSL_SESSION_CACHE_SIZE      10
#endif

#ifndef SSL_HANDSHAKE_BUFFER_SIZE
/* Size of the buffer used during client authentication */
#define SSL_HANDSHAKE_BUFFER_SIZE   530
#endif

#ifndef SSL_MAX_EXTS
/* Number of supported extensions (this number is used the size of a
 * static array keeping track of presented extensions) */
#define SSL_MAX_EXTS                2
#endif

#ifndef SSL_SUBJECT_STORAGE_SIZE
/*!
 * Default size of the subject storage.
 * This storage is required for processing of received certificate chains.
 * There will be 2 Buffers allocated with this size!
 */
#define SSL_SUBJECT_STORAGE_SIZE   256
#endif

#ifndef SSL_SOCKET_BUF_SIZE
/*!
 * We define the required size to hold the maximum recordlength
 *
 * struct {
 *     ContentType type;
 *     ProtocolVersion version;
 *     uint16 length;
 *     select (SecurityParameters.cipher_type) {
 *         case stream: GenericStreamCipher;
 *         case block:  GenericBlockCipher;
 *         case aead:   GenericAEADCipher;
 *     } fragment;
 * } TLSCiphertext;
 *
 * struct {
 *     opaque IV[SecurityParameters.record_iv_length];
 *     block-ciphered struct {
 *         opaque content[TLSCompressed.length];
 *         opaque MAC[SecurityParameters.mac_length];
 *         uint8 padding[GenericBlockCipher.padding_length];
 *         uint8 padding_length;
 *     };
 * } GenericBlockCipher;
 *
 */

/*!
 * current largest blocksize of a blockcipher is 16bytes for AES
 * opaque IV[SecurityParameters.record_iv_length];
 */
#define SSL_TLS_MAX_BLOCKLEN       16

/*!
 * the maximum plaintext length allowed
 * since compression is not supported is
 * TLSPlaintext.length equal to TLSCompressed.length
 * opaque content[TLSCompressed.length];
 */
#define SSL_TLS_MAX_PLAINTEXTLEN   16384

/*!
 * currently we support SHA1 as 'largest' hash with 20bytes digest
 * opaque MAC[SecurityParameters.mac_length];
 */
#define SSL_TLS_MAX_MACLEN         20

/*!
 * per definition we must be able to hold 256bytes for padding
 * 255byte padding + 1byte padding_length
 * uint8 padding[GenericBlockCipher.padding_length];
 * uint8 padding_length;
 */
#define SSL_TLS_MAX_PADLEN         256

/* Maximum record len, simplified calculation by using all worst cases!  */
#define SSL_TLS_MAX_RECORDLEN   REC_HEADERLEN            \
                                 + SSL_TLS_MAX_BLOCKLEN      \
                                 + SSL_TLS_MAX_PLAINTEXTLEN  \
                                 + SSL_TLS_MAX_PADLEN        \
                                 + SSL_TLS_MAX_MACLEN

/* Size of the buffer per SSL Socket */
#define SSL_SOCKET_BUF_SIZE     SSL_TLS_MAX_RECORDLEN
#else
/*
 * until TLS Hello extension "Maximum Fragment Length" is implemented
 * the maximum size should be available
 */
#warning Please consider the documentation and then remove this warning
/*
 * verify that SSL_TLS_MAX_BLOCKLEN has been defined
 */
#ifndef SSL_TLS_MAX_BLOCKLEN
#error Missing define SSL_TLS_MAX_BLOCKLEN
#endif
/*
 * verify that SSL_TLS_MAX_PLAINTEXTLEN has been defined
 */
#ifndef SSL_TLS_MAX_PLAINTEXTLEN
#error Missing define SSL_TLS_MAX_PLAINTEXTLEN
#endif
/*
 * verify that SSL_TLS_MAX_PADLEN has been defined
 */
#ifndef SSL_TLS_MAX_PADLEN
#error Missing define SSL_TLS_MAX_PADLEN
#endif
/*
 * verify that SSL_TLS_MAX_MACLEN has been defined
 */
#ifndef SSL_TLS_MAX_MACLEN
#error Missing define SSL_TLS_MAX_MACLEN
#endif
/*
 * verify that SSL_TLS_MAX_RECORDLEN has been defined
 */
#ifndef SSL_TLS_MAX_RECORDLEN
#error Missing define SSL_TLS_MAX_RECORDLEN
#endif
#endif

#ifndef SSL_WRITE_BLOCK_LEN
/* Maximum write limit
 * this is the initial size of the mtu of every ssl socket
 * by calling sslSoc_setCtxMtu(s, v) can this value be adjusted to your needs
 */
#define SSL_WRITE_BLOCK_LEN         SSL_TLS_MAX_PLAINTEXTLEN
#endif

#define SEND 0
#define RCVR 1


typedef enum E_SSL_ERROR_CODES
{
    E_SSL_NO_ERROR         = 0,
    E_SSL_NO_ERROR_SHDOWN  = 10,
    E_SSL_ERROR_GENERAL    = -10,
    E_SSL_ERROR_BUFFEROFLOW= -11,
    E_SSL_ERROR_WOULDBLOCK = -12,
    E_SSL_ERROR_DECRYT     = -13,
    E_SSL_ERROR_ENCRYPT    = -14,
    E_SSL_ERROR_BADMAC     = -15,
    E_SSL_ERROR_VERSION    = -16,
    E_SSL_ERROR_SOCKET     = -17,
    E_SSL_ERROR_SOCSTATE   = -18,
    E_SSL_ERROR_SM         = -19,
    E_SSL_ERROR_PROTO      = -20,
    E_SSL_ERROR_CRYPTO     = -21,
    E_SSL_ERROR_LENGTH     = -22
} e_sslError_t;


/*!
 * This type defines the behaviour of the SSL handshake concerning
 * client authentication.
 * The resulting behaviour is different when acting as server or client
 */
typedef enum E_SSL_AUTH_LEVEL
{
   /*!
    * Client: There won't be sent a certificate even if one exists and
    *          a CertificateRequest has been received
    *
    * Server: The CertificateRequest won't be sent
    */
   E_SSL_NO_AUTH                = 0x01,

   /*!
    * Client: If we receive a CertificateRequest
    *         we will send our Certificate and the CertificateVerify
    *
    * Server: The CertificateRequest will be sent and if the client
    *         sends his certificate the further handshake handling
    *         for client authentication will be processed.
    *         If the client sends no certificate the handshake will
    *         go on without client authentication.
    */
   E_SSL_SHOULD_AUTH            = 0x02,

   /*!
    * Client: If we receive a CertificateRequest
    *         we will send our Certificate and the CertificateVerify.
    *         If we do not receive a CertificateRequest the handshake
    *         will be cancelled.
    *
    * Server: The CertificateRequest will be sent and if the client
    *         doesn't send his certificate the handshake will be cancelled.
    */
   E_SSL_MUST_AUTH              = 0x04,

   /*!
    * Client: This enables verification of the Certificate that
    *         has been sent by the server.
    *
    * Server: No change in behaviour.
    */
   E_SSL_MUST_VERF_SRVCERT      = 0x10,

   /*!
    * Combination of \ref E_SSL_NO_AUTH and \ref E_SSL_MUST_VERF_SRVCERT
    */
   E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_NO_AUTH       = E_SSL_MUST_VERF_SRVCERT | E_SSL_NO_AUTH,
   /*!
    * Combination of \ref E_SSL_SHOULD_AUTH and \ref E_SSL_MUST_VERF_SRVCERT
    */
   E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_SHOULD_AUTH   = E_SSL_MUST_VERF_SRVCERT | E_SSL_SHOULD_AUTH,
   /*!
    * Combination of \ref E_SSL_MUST_AUTH and \ref E_SSL_MUST_VERF_SRVCERT
    */
   E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_MUST_AUTH     = E_SSL_MUST_VERF_SRVCERT | E_SSL_MUST_AUTH,
} e_sslAuthLevel_t;



/*************************************************************************/

typedef enum E_SSL_SM_STATUS
{
    E_SSL_SM_WAIT_INIT                = 0,
    E_SSL_SM_WAIT_CLIENT_HELLO        = 1,
    E_SSL_SM_WAIT_CLIENT_CERTIFICATE  = 2,
    E_SSL_SM_WAIT_CLIENT_KEYEXCHANGE  = 3,
    E_SSL_SM_WAIT_CLIENT_CERT_VERIFY  = 4,
    E_SSL_SM_WAIT_CLIENT_FINISH       = 5,

    E_SSL_SM_SEND_SERVER_HELLO_FINISH = 16,
    E_SSL_SM_SEND_SERVER_HELLO        = 17,
    E_SSL_SM_SEND_SERVER_FINISH       = 18,
    E_SSL_SM_SEND_WARN_ALERT          = 19,
    E_SSL_SM_SEND_FATAL_ALERT         = 20,

    E_SSL_SM_SEND_CLIENT_HELLO        = 32,
    E_SSL_SM_SEND_CLIENT_FINISH       = 33,

    E_SSL_SM_WAIT_SERVER_HELLO        = 48,
    E_SSL_SM_WAIT_CERT                = 49,
    E_SSL_SM_WAIT_SERVER_KEYEXCHANGE  = 50,
    E_SSL_SM_WAIT_CERT_REQUEST        = 51,
    E_SSL_SM_WAIT_SERVER_HELLO_DONE   = 52,
    E_SSL_SM_WAIT_CHANGE_CIPHERSPEC   = 53,
    E_SSL_SM_WAIT_SERVER_FINISH       = 54,

    E_SSL_SM_SEND_SHUTDOWN            = 64,
    E_SSL_SM_SHUTDOWN_SENT            = 65,
    E_SSL_SM_SHUTDOWN_COMPLETE        = 66,

    E_SSL_SM_APPDATA_EXCHANGE         = 255
} e_sslSmStatus_t;

typedef enum E_SSL_ASM_CONTROL
{
    E_SSL_ASM_START         = 0,
    E_SSL_ASM_STEP1         = 1,
    E_SSL_ASM_STEP2         = 2,
    E_SSL_ASM_STEP3         = 3,
    E_SSL_ASM_STEP4         = 4,
    E_SSL_ASM_FINISH        = 5
} e_sslAsmControl_t;



typedef enum E_PENDACT_TYPE
{
	E_PENDACT_GEN_START              = 0x00,
	E_PENDACT_GEN_WAIT_EVENT         = 0x01,

	E_PENDACT_SRV_START              = 0x10,
	E_PENDACT_SRV_RECORD             = 0x11,
	E_PENDACT_SRV_APPRESP            = 0x12,
	E_PENDACT_SRV_PKCS1_VERIFY       = 0x14,
	E_PENDACT_SRV_PKCS1_DECRYPT      = 0x13,
	E_PENDACT_SRV_CERTVERIFY         = 0x15,
	E_PENDACT_SRV_CLICERTCHAIN       = 0x16,
	E_PENDACT_SRV_WARNING            = 0x17,
	E_PENDACT_SRV_FATAL_ERROR        = 0x18,
	E_PENDACT_SRV_SCACHE             = 0x19,

	E_PENDACT_CLI_PKCS1_ENCRYPT      = 0x1A,
	E_PENDACT_CLI_PKCS1_SIGN         = 0x1B,
	E_PENDACT_CLI_SRVCERTCHAIN       = 0x1C,

	E_PENDACT_SRV_DHECALCSHARED      = 0x1D,
	E_PENDACT_SRV_ECDHECALCSHARED	 = 0x1E,

	E_PENDACT_COM_START              = 0x20,
	E_PENDACT_COM_CIPHER_LENERROR    = 0x21,
	E_PENDACT_COM_CIPHER_TX          = 0x22,
	E_PENDACT_COM_CIPHER_TXCLOSE     = 0x23,
	E_PENDACT_COM_CIPHER_CLOSE       = 0x24,
	E_PENDACT_COM_CIPHER_RX          = 0x25,
	E_PENDACT_COM_PLAIN_TX           = 0x26,

	E_PENDACT_APP_START              = 0x30,
	E_PENDACT_APP_REQUEST            = 0x31,
	E_PENDACT_APP_WRITE              = 0x32,

	E_PENDACT_SCACHE_START           = 0x40,
	E_PENDACT_SCACHE_GET             = 0x41,
	E_PENDACT_SCACHE_INS             = 0x42,
	E_PENDACT_SCACHE_RM              = 0x43,
	E_PENDACT_SCACHE_FIND            = 0x44,

	E_PENDACT_ASYM_START             = 0x50,
	E_PENDACT_ASYM_PKCS1_DECRYPT     = 0x51,
	E_PENDACT_ASYM_PKCS1_VERIFY      = 0x52,
	E_PENDACT_ASYM_CERTVERIFY        = 0x53,
	E_PENDACT_ASYM_PKCS1_ENCRYPT     = 0x54,
	E_PENDACT_ASYM_PKCS1_SIGN        = 0x55,
	E_PENDACT_ASYM_CLICERTCHAIN      = 0x56,
	E_PENDACT_ASYM_SRVCERTCHAIN      = 0x57,
	E_PENDACT_ASYM_DHECALCSHARED     = 0x60,
	E_PENDACT_ASYM_ECDHECALCSHARED	 = 0x61, //vpy

	E_PENDACT_EXTERNAL_ACTION        = 0x7F,
	E_PENDACT_INTERNAL_START         = 0x80,

	E_PENDACT_INCOMING_REC           = 0x81,
	E_PENDACT_APPRESP                = 0x82,
	E_PENDACT_PKCS1_DECRYPT          = 0x82,
	E_PENDACT_PKCS1_VERIFY           = 0x83,
	E_PENDACT_CERTVERIFY             = 0x84,
	E_PENDACT_SEND_WARNING           = 0x85,
	E_PENDACT_SEND_FATAL_ERROR       = 0x86,
	E_PENDACT_UNKNOWN                = 0x87,
	E_PENDACT_HANDSHAKE              = 0x88,
	E_PENDACT_DISPATCH_MSG           = 0x89,
	E_PENDACT_ERROR_MAC_FAIL         = 0x8A,
	E_PENDACT_RESPREC                = 0x8B,
	E_PENDACT_MSG_ASM                = 0x8C,
	E_PENDACT_MAC_ENCRYPT_REC        = 0x8D,
	E_PENDACT_PROTORESPGEN           = 0x8E,
	E_PENDACT_DECRYPT_MAC_CHECK      = 0x8F,
	E_PENDACT_PROTOHANDLER           = 0x90,
	E_PENDACT_V2UPWARDHANDLER        = 0x91,
	E_PENDACT_PROTOERR               = 0x93,
	E_PENDACT_MAC_ENCRYPT_HANDSHAKE  = 0x95,
	E_PENDACT_PKCS1_ENCRYPT          = 0x96,

	E_PENDACT_END                    = 0xFF
} e_sslPendAct_t;

typedef enum E_SSL_RESULT
{
	E_SSL_ERROR           = -3,
	E_SSL_WANT_AGAIN      = -2,
	E_SSL_WANT_WRITE      = -1,
	E_SSL_AGAIN           = 0,
	E_SSL_OK              = 1,
	E_SSL_LEN             = 2
} e_sslResult_t;

typedef enum E_SSL_SOCKET_RESULT
{
	E_SSL_SOCKET_AGAIN    = 0,
	E_SSL_SOCKET_ERROR    = -1,
	E_SSL_SOCKET_CLOSED   = -2
} e_sslSocResult_t;

typedef int (*fp_ssl_readHandler)(int handle, void *buf, unsigned int count);

typedef int (*fp_ssl_writeHandler)(int handle, void *buf, unsigned int count);

typedef unsigned long (*fp_ssl_getCurrentTime)(void);

typedef enum E_SSL_SOCKET_STATE
{
	E_SSL_SOCKET_CLOSE   = 0x00,
	E_SSL_SOCKET_IDLE    = 0x01,
	E_SSL_SOCKET_RXBUFF  = 0x02,
	E_SSL_SOCKET_READOUT = 0x03,
	E_SSL_SOCKET_TXBUFF  = 0x04,
	E_SSL_SOCKET_READIN  = 0x05,
	E_SSL_SOCKET_UNUSED  = 0x06
} e_sslSocState_t;

#define SSL_VERSION_READ(a)     (e_sslVer_t)(((*(a)) & 0x0FF) << 8 | ((*((a)+1)) & 0x0FF))
#define SSL_VERSION_GET_MAJ(a)  (uint8_t)(((a) >> 8) & 0x0FF)
#define SSL_VERSION_GET_MIN(a)  (uint8_t)((a) & 0x0FF)

typedef enum E_SSL_VERSION
{
  E_SSL_3_0     = 0x0300,
  E_TLS_1_0     = 0x0301,
  E_TLS_1_1     = 0x0302,
  E_TLS_1_2		= 0x0303,
  E_VER_DCARE   = 0xFFFF
} e_sslVer_t;

#define SSL_MIN_SSL_TLS_VERSION_SUPPORTED  E_SSL_3_0
#define SSL_MAX_SSL_TLS_VERSION_SUPPORTED  E_TLS_1_2

/*
 * The enumeration of signature algorithms (SignatureAlgorithm)
 * used by TLS >= v1.2 for digitally-signed elements
 * (see RFC 5246, p. 46)
 */

//TODO sw - replace this enum with GciSignAlgo_t
typedef enum {
	E_SSL_SIGN_ANONY	= 0,
	E_SSL_SIGN_RSA		= 1,
	E_SSL_SIGN_DSA		= 2,
	E_SSL_SIGN_ECDSA	= 3,
	E_SSL_SIGN_INVALID  = 0xFF,
} e_sslSignAlg_t;

typedef struct ssl_signatureAndHashAlgorithms {
    //OLD-CW: uint8_t     c_sign;
	en_gciSignAlgo_t	c_sign;
    //OLD-CW: uint8_t     c_hash;
	en_gciHashAlgo_t	c_hash;
}s_sslSignHashAlg_t;

typedef enum ssl_psudoRandomFunctionType {
    E_SSL_PRF_MD5_SHA1,
    E_SSL_PRF_SHA256,
    E_SSL_PRF_UNDEF
}e_sslPrf_t;

//TODO sw - replace this enum with GciCipherAlgo_t
typedef enum ssl_cipherTypes
{
	UNDEF_SYM            = 0x00,
	RC4_STREAM           = 0x01,
	TDES_BLOCK           = 0x02,
	AES_BLOCK            = 0x03,
	INVALID_SYM          = 0xFF
} SYM_CIPHER;

//TODO sw - replace this enum with GciKeyPairType_t
typedef enum ssl_keyShareTypes
{
	E_SSL_KST_UNDEF           = 0x00,
    E_SSL_KST_RSA             = 0x01,
	E_SSL_KST_DHE_RSA         = 0x02,
	E_SSL_KST_DHE_DSS         = 0x03,
	//begin vpy
	E_SSL_KST_ECDHE_RSA		  = 0x04,
	E_SSL_KST_ECDHE_ECDSA	  = 0x05,
	//end vpy
	E_SSL_KST_INVALID         = 0xFF
} E_SSL_KST;


typedef enum {
	E_SSL_KEY_RSA,
	E_SSL_KEY_EC,
	E_SSL_KEY_UNDEFINED
} e_sslKeyType_t;

typedef enum ssl_verificationResults
{
  E_SSL_VERIFRES_UNDEF,
  E_SSL_VERIFRES_SUCCESS,
  E_SSL_VERIFRES_SKIPPED,
  E_SSL_VERIFRES_FAILED,
  E_SSL_VERIFRES_INVALID
} E_SSL_VERIFRES;

#define VERIFICATION_RESULT_INIT(in, out) do { out = (E_SSL_VERIFRES*)in; *out = E_SSL_VERIFRES_INVALID; } while(0)
#define VERIFICATION_RESULT_SET(in, res) do { E_SSL_VERIFRES *out = (E_SSL_VERIFRES*)in; *out = res; } while(0)
#define E_SSL_VERIFRES_SUCCESS(in) VERIFICATION_RESULT_SET(in, E_SSL_VERIFRES_SUCCESS)
#define E_SSL_VERIFRES_SKIPPED(in) VERIFICATION_RESULT_SET(in, E_SSL_VERIFRES_SKIPPED)
#define E_SSL_VERIFRES_FAILED(in)  VERIFICATION_RESULT_SET(in, E_SSL_VERIFRES_FAILED)

/* *********************************************************************** */


typedef struct ssl_certificate
{
   /* Public Key of the certificate */
	//OLD-CW: gci_rsaPubKey_t        gci_caPubKey;
	GciKeyId_t 			 gci_caPubKey;
   /* Indicates if the certificate is a CA certificate */
   uint8_t               c_isCa;
   /* pathLenConstraint defines the maximum number of CA's following */
   int32_t               l_pathLenConstr;
   /* The subject name of the CA */
   s_sslOctetStr_t       s_caSubject;
} s_sslCert_t;


typedef struct ssl_certList
{
   /* Pointer to the certificate that belongs to this list element */
   s_sslCert_t         *ps_caCert;
   /* Pointer to a cert_db element that belongs to this list element */
   s_cdbCert_t         *ps_cdbCert;
   /* The next element in the list */
   struct ssl_certList  *next;
} s_sslCertList_t;

typedef int32_t l_sslSess_t;

#define SSL_INVALID_SESSION  (l_sslSess_t)0

typedef struct ssl_sessionElement
{
    /* SSL Internal Session Identifier */
    l_sslSess_t          s_desc;
    /* SSL/TLS Session ID - MUST NOT change for successful session resumption */
    uint8_t              ac_id[SESSID_SIZE];
    /* The master secret that is needed for session resumption */
    uint8_t              ac_msSec[MSSEC_SIZE];
    /* Formerly authenticated "Session ID" see wssl_conf.c:sslConf_certHook() */
    uint32_t             l_authId;
    /* The formerly used SSL/TLS version - MUST NOT change for successful session resumption */
    e_sslVer_t           e_lastUsedVer;
    /* The formerly negotiated e_cipSpec - MUST NOT change for successful session resumption */
    e_sslCipSpec_t       e_cipSpec;
    /* The formerly negotiated sign hash algorithm. For TLS version prior 1.2 md5+sha1 used */
    s_sslSignHashAlg_t   s_signAlg;
}s_sslSessElem_t;



typedef struct ssl_sessionCache
{
   /* Security attributes of the saved session */
   s_sslSessElem_t      s_sessElem;
   /* counter to realise LRU mechanism */
   uint16_t             i_lruCounter;
   /* timer to realise session timeout */
   s_tot2_Tmr_t         s_sessTimeout;
}s_sslSessCache_t;

typedef struct ssl_md5sha1HashCombination
{
    //OLD-CW: gci_sha1Ctx_t          gci_sha1Ctx;
    GciCtxId_t			   gci_sha1Ctx;
    //OLD-CW: gci_md5Ctx_t           gci_md5Ctx;
    GciCtxId_t			   gci_md5Ctx;

}s_md5Sha1_t;

typedef struct ssl_handshakeElements
{
   /* There's one SSL session element per session handshake element */
   s_sslSessElem_t      s_sessElem;
   /*!
    * Storage for the peers' public key
    * In client mode it's the public key for generation of the ClientKeyExchange
    * In server mode it's the public key to perform the client authentication
    */

   //OLD-CW: gci_rsaPubKey_t        gci_peerPubKey;
   GciKeyId_t			gci_rsaPeerKey;

   /* TODO adjust memory usage for dhe key exchange
    * the private key if diffie hellman is used and we act as client */
   //OLD-CW: gci_dhKey_t            gci_dheCliPrivKey;
   //OLD-CW: GciKeyId_t 			gci_dheCliPrivKey;

   /* the public key if dh is used and we act as server */
   //OLD-CW: gci_dhKey_t            gci_dheSrvPubKey;

   GciKeyId_t			gci_dheSrvPubKey;
   GciKeyId_t			gci_dheCliPubKey;


   //TODO sw - shared secret key?
   /* pointer to memory address where p will be stored when we act as client */
   //OLD-CW: gci_bigNum_t*          pgci_dheP;
   //GciBigInt_t*			pgci_dheP;
   //Shared secret key
   GciKeyId_t			gci_dheSecKey;
   GciKeyId_t			gci_ecdheSecKey;

   /* We've to save the offered version of the Client Hello to verify the
    * PreMasterSecret
    */

   //When ECC is used, the public key  of the peer is stored here after client/server key exchange
   //OLD-CW: gci_eccKey_t			eccPubKeyPeer;
   GciKeyId_t			eccPubKeyPeer;
   //Name of the curve which is proposed by peer (server) when acting as a client.
   //OLD-CW: uint16_t				eccCurve;
   en_gciNamedCurve_t		eccCurve;

   e_sslVer_t           e_offerVer;
   /* The two random values of Server and Client */
   uint8_t              ac_srvRand[SRV_RANDSIZE];
   uint8_t              ac_cliRand[CLI_RANDSIZE];
   /* The handshake buffer when performing composite
    * handling at client authentication
    */
   uint8_t              ac_hsBuf[SSL_HANDSHAKE_BUFFER_SIZE];
   /* Sha1 and MD5 context for verification of the handshake messages */
   //TODO: delete this union after written hashCtx instead of it
//   union {
       s_md5Sha1_t      s_md5Sha1;
	   GciCtxId_t 		md5Ctx;
       //OLD-CW: gci_hashCtx_t    gci_hashCtx;
	   GciCtxId_t		sha1Ctx;
	   GciCtxId_t		hashCtx;

 //  }u_hashCtx;

   size_t               gci_hsBufLen;

   /* keep a list of hello extension types present in the ClientHello
    * message to compare list in ServerHello message to */
   //TODO vpy: when writing client hello: add extension in this pe_reqExts[]
   e_tlsExt_t 			 pe_reqExts[SSL_MAX_EXTS];
   size_t			     gci_nReqExts;

}s_sslHsElem_t;



typedef struct ssl_peerGlobalSettings
{
   /* Standard read function */
   fp_ssl_readHandler       fp_stdRead;
   /* Standard write function */
   fp_ssl_writeHandler      fp_stdWrite;
   /* Read the current time of day */
   fp_ssl_getCurrentTime    fp_getCurTime;
   /*!
    * Allow insecure connections.
    * This concerns the \ref fp_getCurTime function pointer.
    */
   int8_t                   c_allowInsecure;
   /* Pointer to the session cache  */
   s_sslSessCache_t*        ps_sessCache;
   /* Type of signature and hash pair used to sign certificate */
   s_sslSignHashAlg_t       s_certSignHashAlg;
   /* Pointer to the CA certificate list */
   s_sslCertList_t*         ps_caCertsListHead;
   /* Pointer to the 'certificate chain' list */
   s_sslCertList_t*         ps_certChainListHead;
   /* Pointer to \ref cwt_rsaMyPrivKey */
   //OLD-CW: gci_rsaPrivKey_t*         pgci_rsaMyPrivKey;
   GciKeyId_t				pgci_rsaMyPrivKey;


   /* Pointer to \ref cwt_rsaMyPrivKey */
   //OLD-CW: ecc_key*			        p_ECCMyPrivKey; //vpy
   GciKeyId_t				p_ECCMyPrivKey; //TODO sw - hierarchy of p_ECCMyPrivKey
   //OLD-CW: ltc_ecc_set_type			ltc_ECC_curvesParameters;
   en_gciNamedCurve_t 			gci_curveName;

   /* Behaviour of the SSL context pertaining to Client Authentication */
   e_sslAuthLevel_t         e_authLvl;
   /* Maximum timespan when session resumption is possible */
   uint32_t                 l_sessTimespan;
   /* These are the min/max versions of the derived SSL/TLS sockets */
   e_sslVer_t               e_minVer;
   e_sslVer_t               e_maxVer;
   /* This flag indicates if derived SSL/TLS sockets shall allow renegotiation */
   uint8_t                  c_isRenegOn;
} s_sslSett_t;




/*! \brief Encryption context for the actual connection.
 *
 * Should be realised as a union, if more than one
 * cipher must be supported.
 */

typedef struct ssl_securityParameters
{
   /* algorithm used to perform handshake */
   //OLD-CW: E_SSL_KST            e_kst;
	en_gciKeyPairType_t	e_kst;
   /* Supported sognature and hash algorithm. For TLS version prior 1.2 md5+sha1 used */
   s_sslSignHashAlg_t   s_signAlg;
   /* the key if diffie hellman is used as handshake algorithm and we act as server */
   //OLD-CW: gci_dhKey_t*       	pgci_dheKey;
   GciKeyId_t			dhePeerPubKey;
   GciCtxId_t			dheCtx;
   uint8_t             	c_useDheKey;

   //vpy: the ECC key used when ECDHE is used
   //TODO vpy: change and use a pointer for eccKey;

   //OLD-CW: uint16_t				eccChoosenCurve;
   en_gciNamedCurve_t		eccChoosenCurve;
   //OLD-CW: ecc_key				eccKey;


   GciKeyId_t			ecdhCliPubKey;
   GciKeyId_t			ecdhSrvPubKey;
   GciKeyId_t			ecdhSecKey;
   GciCtxId_t			eccCtx;


   //uint8_t				c_useEccKey;

   /* the symmetric cipher algorithm used to encrypt application data */
   //OLD-CW: SYM_CIPHER       	e_cipType;
   en_gciCipherAlgo_t		e_cipType;
   /* Indicates whether this key's for a Stream(FALSE) or Blockcipher(TRUE) */
   uint8_t             	b_isBlkCip;
   /* the Blocklen of the used BlockCipher */
   uint8_t              c_blockLen;
   /* de- and encryption key union */
   union
   {
	   //OLD-CW: gci_rc4Ctx_t      gci_cliRc4Ctx;
	   GciCtxId_t 		cliRc4Ctx;
	   //OLD-CW: gci_aesCtx_t      gci_cliAesCtx;
	   GciCtxId_t		cliAesCtx;
	   //OLD-CW: gci_3desCtx       gci_cli3DesCtx;
	   GciCtxId_t		cli3DesCtx;

   } u_cliKey;
   union
   {
	   //OLD-CW: gci_rc4Ctx_t      gci_srvRc4Ctx;
	   GciCtxId_t 		srvRc4Ctx;
	   //OLD-CW: gci_aesCtx_t      gci_srvAesCtx;
	   GciCtxId_t		srvAesCtx;
	   //OLD-CW: gci_3desCtx       gci_srv3DesCtx;
	   GciCtxId_t		srv3DesCtx;

   } u_srvKey;
   /* Length of a used key material*/
   uint8_t              c_keyLen;
   e_sslPrf_t           e_prf;
   /* type of the MAC algorithm used for message authentication */
   //OLD-CW: e_sslHashAlg_t       e_hmacType;
   en_gciHashAlgo_t 		e_hmacType;
   /* length of the output produced by the MAC algorithm */
   uint8_t              c_hmacLen;
   /* storage for the MAC secrets. Maximum Possible amount of bytes */
   uint8_t              ac_cliSecret[GCI_MAX_HASHSIZE_BYTES];
   uint8_t              ac_srvSecret[GCI_MAX_HASHSIZE_BYTES];
}s_sslSecParams_t;


/* WAMs DevNote: a quick hack. Clean this structure later */
typedef struct ssl_internalGuts
{
   e_sslSmStatus_t      e_smState;
   e_sslAsmControl_t    e_asmCtrl;
   e_sslRecType_t       e_recordType;
   e_sslAlertType_t     e_alertType;

   s_sslKeyCertInfo_t   s_peerCertInfo;

   uint8_t              b_isComposite;
   uint8_t              b_isCertReqReceived;

   e_sslCipSpec_t       e_rxCipSpec;
   e_sslCipSpec_t       e_txCipSpec;
   e_sslCipSpec_t       e_pendCipSpec;
   e_sslCipSpec_t       ae_cipSpecs[SSL_CIPSPEC_COUNT];

   uint32_t             l_pendCliAuthId;

   uint8_t              ac_cliSeqNum[8];
   uint8_t              ac_srvrSeqNum[8];

   uint8_t              c_verifyDataLen;
   uint8_t              ac_cliVerifyData[VERIF_HASHSIZE];
   uint8_t              ac_srvVerifyData[VERIF_HASHSIZE];
}s_sslGut_t;


/* Structure that holds connection specific context data */
typedef struct ssl_connectionContextStruct {
  e_sslSocState_t       e_socState;   /* 0 means this context is not in use ...  */
  uint16_t              i_socNum;	/* 255 means not used, all other: socket number */
  fp_ssl_readHandler    read;
  fp_ssl_writeHandler   write;
  uint8_t               b_isCli; /* FALSE means Server, TRUE means Client */
  int32_t               l_hsCtx;
  int32_t               l_writeOff;
  int32_t               l_readOff;
  int32_t               l_buffLen;
  uint32_t              l_mtu;
  e_sslPendAct_t        e_event;
  e_sslPendAct_t        e_nextAction;
  e_sslError_t          e_lastError;
  s_sslSett_t           *ps_sslSett;
  s_sslHsElem_t         *ps_hsElem;
  s_sslSecParams_t      s_secParams;
  s_sslGut_t     		s_sslGut;
  uint8_t               c_isResumed;
  uint8_t               c_isRenegOn;
  /* Secure renegotiation */
  uint8_t               c_secReneg;
  e_sslAuthLevel_t      e_authLvl;
  e_sslVer_t            e_ver;
  /*!
   * This is used when a CertificateRequest message has been received
   * it indicates the last certificate of the available certificate chain that is
   * known to the server we want to connect to
   */
  s_sslCertList_t       *ps_lastCliAuthCertChain;
  uint8_t               ac_socBuf[SSL_SOCKET_BUF_SIZE];
} s_sslCtx_t;



/* *********************************************************************** */

/* WAMs DevNote: Only used in the wSSL_ssl.c module */
/* This types were used to control the message assembly */


/* *********************************************************************** */


/* *********************************************************************** */


/*** Prototypes *************************************************************/

/****************************************************************************/
/* ssl_verifyHash                                                          */
/****************************************************************************/

/*! \brief Verify of the verification hash encrypted by the private key of the peer.
 *
 * \param aucVerifyHash    : Pointer to the verification hash octet string
 * \param uiVerifyHashLen  : Length of aucMessage in octets
 * \param aucSignature     : Signature as octet string
 * \param uiSigLen         : Length of aucSignature in octets
 * \param pPubKey          : Pointer to RSA public key
 *
 * \return Status          : Status of operation
 *                           E_SSL_OK, SSL_FAIL
 *
 * \sa CL_Pkcs1VerifyV1_5, CL_Pkcs1DecryptV1_5
 */

/*OLD-CW: int  ssl_verifyHash(const uint8_t          aucVerifyHash[],
                              size_t         uiVerifyHashLen,
                        const uint8_t          aucSignature[],
                              size_t         uiSigLen,
                              rpgci_rsaPubKey_t  pPubKey);
*/
int  ssl_verifyHash(const uint8_t          aucVerifyHash[],
                              size_t         uiVerifyHashLen,
                        const uint8_t          aucSignature[],
                              size_t         uiSigLen,
                              GciKeyId_t  pPubKey);


/****************************************************************************/
/* ssl_getCliAuthID                                             */
/****************************************************************************/
/*! \brief Retrieves the authentication identifier from the connection context.
 *
 * \param pCtx : Pointer to the connection context
 *
 * \return Authentication identifier (32 bit value)
 *
 * \sa SSL_ClientCertHook
 */
uint32_t  ssl_getCliAuthID(s_sslCtx_t * pCtx);



/* *********************************************************************** */
/* *********************************************************************** */
/* Binary data search algorithm (according to "brutesearch" from           */
/* Sedgewick: Algorithms in C) */

uint16_t CL_MemSearch(uint8_t *memory, uint16_t memoryLen, uint8_t *pattern,
                     uint16_t patternLen);


/****************************************************************************/
/* ssl_initCtx                                                   */
/****************************************************************************/
/*! \brief Initialises a new connection context to be used for a particular
 * SSL-connection.
 *
 * This function is used to initialise a connection context when a new SSL
 * connection is established. The connection context holds all information
 * necessary for a particular SSL connection.
 *
 * \param pCtx              : Pointer to the SSL connection context
 * \param pWsslAppCtx       : Pointer to the SSL application context
 * \param pHandshakeElement : Pointer to a handshake element
 * \param iSocket           : Socket handle to the incoming socket
 *
 * \return
 * E_SSL_OK  : Function finished sucessfully\n
 * SSL_FAIL: Function encountered problems
 *
 * \sa destroyConnectionCtx
 */

int   ssl_initCtx(s_sslCtx_t * pCtx, s_sslSett_t *ps_sslSett,
                  s_sslHsElem_t *ps_sslHsElem );

/* *********************************************************************** */
/* *********************************************************************** */
/* *******  Util functions for SSL use ********************************** */
/* *********************************************************************** */
/* *********************************************************************** */


/* *********************************************************************** */
/* *********************************************************************** */
/* *********************************************************************** */
/* *********************************************************************** */

/*! \brief Generates a given number of 4,3,2 or 1 bytes long length information
 * in the given buffer area. */

uint8_t  *ssl_writeInteger(uint8_t *pucBuffer, uint32_t ulLen,
                                  int iBytes);

/*============================================================================*/
/*!

   \brief     Read in the length information of variable length

                Equivalent to ssl_genLenStr()

   \param     pucBuffer     The start of the length field
   \param     iBytes        The number of bytes that should be used

   \return    The following 'iBytes' after 'pucBuffer' as uint32_t
*/
/*============================================================================*/
uint32_t ssl_readInteger( uint8_t *pucBuffer, int iBytes );

/*! \brief Implementation of the SSLv3 server protocol machine.
 *
 *  The function provides the protocol functionality needed for a server
 *  implementation. It handles all incoming events and processes them. Depending
 *  on the event and the internal status a response is created and the
 *  appropriate action is reported as the result.
 *
 *  \param ps_sslCtx         : Pointer to the context of the connection.
 *  \param e_event        : Type of event provided to the function. Allowed are
 *                          all events from the SERVER-group
 *  \param *pc_eventData  : Pointer to octet string with the event data
 *  \param cwt_eventDataLen : Length of the event data in octets
 *  \param *pc_actData    : Pointer to a octet string which holds the result
 *  \param *pcwt_actDataLen: Pointer to size variable which holds the length
 *                              of the octet string\n
 *                              On calling: maximum length of the buffer provided\n
 *                              On return: data length
 *  \return The return values are grouped to make it easier to find the
 *  appropriate handler. The return of an action from the server group is an
 *  error and should never happen.
 *  \return
 * \e SERVER: \n
 *  E_PENDACT_SRV_RECORD         : Process record from the communication interface\n
 *  E_PENDACT_SRV_APPRESP   : Process response from the application\n
 *  SRV_PKCS1DECRSYPT  : Process result from the private key decryption\n
 *  E_PENDACT_SRV_PKCS1_VERIFY    : Process result of the public key verification\n
 *  E_PENDACT_SRV_CERTVERIFY     : Process result of the public key verification of an
 *                       encrypted verify hash\n
 *  E_PENDACT_SRV_WARNING        : Generate a warning record\n
 *  E_PENDACT_SRV_FATAL_ERROR    : Generate a fatal error\n
 *  E_PENDACT_SRV_SCACHE         : Process result from cache\n
 *  E_PENDACT_SRV_CLICERTCHAIN  : Verify client certification chain\n
 *  \n
 *  \e COM: \n
 *  COM_TXMIT          : Transmit data for the communication interface.\n
 *  COM_TXMIT_CLOSE    : Transmit data for the communication interface. Close the
 *                       connection after transmission and free the context.\n
 *  COM_CLOSE          : Close the connection and free the context\n
 *  \n
 *  \e APP: \n
 *  E_PENDACT_APP_REQUEST        : Request data for the application\n
 *  \n
 *  \e ASYM: \n
 *  E_PENDACT_ASYM_PKCS1_DECRYPT  : Decrypt a ciphertext using the private key\n
 *  E_PENDACT_ASYM_PKCS1_VERIFY   : Verify a signature of a given data using the public key\n
 *  E_PENDACT_ASYM_CERTVERIFY    : Verify the given signature with a given hash value using
 *                       the public key\n
 *  E_PENDACT_ASYM_CLICERTCHAIN : Verify client certification chain\n
 *  \n
 *  \e SCACHE: \n
 *  E_PENDACT_SCACHE_INS      : Inserts/updates a given data element\n
 *  E_PENDACT_SCACHE_GET         : Gets the content for a key provided\n
 *  E_PENDACT_SCACHE_RM     : Clears the content of a data element \n
 *  \n
 *  \e GENERAL: \n
 *  GEN_ERROR_RECLEN   : The length of the input record is incorrect\n
 *  E_PENDACT_GEN_WAIT_EVENT : There is no further action, wait for the next external event\n
 *  GEN_ERROR          : Unspecified error
 */

e_sslPendAct_t ssl_serverFSM(s_sslCtx_t *ps_sslCtx, e_sslPendAct_t e_event,
                             uint8_t *pc_eventData,size_t gci_eventDataLen,
                             uint8_t *pc_actData, size_t *pgci_actDataLen);

void ssl_destroyKeys ( s_sslCtx_t * ps_sslCtx );

/*** Global Variables *******************************************************/

/* No-Error Codes */
#define E_SSL_NO_ERROR_SHDOWN     10
/* Error Codes */


/* Your stuff ends here */
#ifdef __cplusplus
} /* extern "C" */
#endif /* end C prototype in C++ */


#endif /* file already included */
