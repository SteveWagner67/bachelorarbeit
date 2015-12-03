/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl3.h                                                 */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*! \file
 *     This header file defines things which are SSL version 3 specific.     */
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
/*  17.03.03     WAM           Initial version                               */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*                                                                           */
/*****************************************************************************/



#ifndef    FILE_SSL3_H
  #define    FILE_SSL3_H

#ifdef __cplusplus
extern "C" {
#endif /* begin C prototype in C++ */

//TODO sw - this define was in crypto_wrap.h
#define AES_AND_3DES_ENABLED

/*** Defines ****************************************************************/

#define VERIF_HASHSIZE          36      /*!< Verify hash = MD5 + SHA1 concatenated */
#define VERIF_HASHSIZE_TLS      12
#define MSSEC_SIZE              48      /*!< Master Secret is always 48 bytes */
#define PREMSSEC_SIZE           48      /*!< Pre Master Secret is 48 bytes too */
#define SESSID_SIZE             32      /*!< Length of the session identifier */
#define CLI_RANDSIZE            32      /*!< Length of the client random */
#define SRV_RANDSIZE            32      /*!< Length of the server random */


#define REC_HEADERLEN           5       /*!< Length of a SSL / TLS header */
#define HS_HEADERLEN            4       /*!< Length of a handshake header */

/* see ISBN 0-201-61598-3
 * Eric Rescorla
 * SSL and TLS - Designing and Building Secure Systems - Page 79:
 * Due to an implementation bug in the example implementation
 * of SSL 3.0 by netscape there's a lengthfield missing.
 * It has to be included in TLS!
 */
#define IFSSL30_LENOFF(x)       (x == E_SSL_3_0 ? 0:2)




/*! \brief Definition of the SSL message types.
 *
 *  The SSL Record Protocol can carry different message types (i.e. Handshake
 *  messages, Alert messages, Change Cipher Spec messages or Application data
 *  messages). The Content Type field in the SSL Record Header is used to
 *  specify, to which message type the data belongs which is carried in the
 *  payload of the SSL Record Layer Protocol.
 *
 *  This enumerator defines the values of the Content Type field in the SSL
 *  Record Header.
 */
typedef enum ssl_recordType
{
   E_SSL_RT_NOTEXIST       =  0,
   E_SSL_RT_CHANGE_CIPSPEC = 20, /* 0x14 */
   E_SSL_RT_ALERT          = 21, /* 0x15 */
   E_SSL_RT_HANDSHAKE      = 22, /* 0x16 */
   E_SSL_RT_APPDATA        = 23  /* 0x17 */
} e_sslRecType_t;




/*! \brief Definition of the alert levels used in the SSL Alert Protocol.
 *
 *  Every SSL alert message consists of an alert level and an alert description.
 *  The level specifies the severity of the alert message. An alert message
 *  with a level of FATAL must terminate the particular connection immediately
 *  and invalidate the SessionID in the session cache, preventing new
 *  connections to resume the failed session. The server and the client are
 *  required to forget all security critical parameters of the session
 *  (session identifier) and the failed connection (keys and other secrets).
 */
typedef enum AlertLevel
{
   WARNING  = 1,
   FATAL    = 2
} SSL_ALERT_LEVEL;


/*!
 * \brief A list of the types of certificate types that the client may offer.
 *
 *    rsa_sign        a certificate containing an RSA key
 *    dss_sign        a certificate containing a DSA key
 *    rsa_fixed_dh    a certificate containing a static DH key
 *    dss_fixed_dh    a certificate containing a static DH key
 */
typedef enum ssl_clientCertificateTypes
{
  RSA_SIGN      = 1,
  DSS_SIGN      = 2,
  RSA_FIXED_DH  = 3,
  DSS_FIXED_DH  = 4,
} e_sslCliCertType_t;


/*! \brief Definition of the alert descriptions used in the SSL Alert Protocol.
 *
 *  An alert message consist of an alert level and an alert description. The
 *  description indicates the reason of the alert message. The alert messages
 *  whose level is always FATAL are explicitly defined in the standard. The
 *  alert level of the remaining messages is not defined.
 *
 *  This enumerator defines all the alert descriptions which can be sent to
 *  the communication partner in an SSL alert message.
 */
typedef enum ssl_alertTypes
{
   E_SSL_ALERT_CLOSE_NOTIFY      =  0,     /*!< connection closed normaly      */
   E_SSL_ALERT_UNEXP_MSG         = 10,     /*!< always fatal */
   E_SSL_ALERT_BAD_RECORD_MAC    = 20,     /*!< always fatal */
   /*
    * decryption_failed_RESERVED
    * This alert was used in some earlier versions of TLS, and may have
    * permitted certain attacks against the CBC mode [CBCATT].  It MUST
    * NOT be sent by compliant implementations.
    */
   E_SSL_ALERT_DECR_FAILED       = 21,
   E_SSL_ALERT_REC_OFLOW         = 22,     /*!< Record overflow */
   E_SSL_ALERT_DECOMPR_FAIL      = 30,     /*!< always fatal */
   E_SSL_ALERT_HANDSH_FAIL       = 40,     /*!< always fatal */
   /*
    * no_certificate_RESERVED
    * This alert was used in SSLv3 but not any version of TLS.  It MUST
    * NOT be sent by compliant implementations.
    */
   E_SSL_ALERT_NO_CERT           = 41,     /*!< sending this alert is optional */
   E_SSL_ALERT_BAD_CERT          = 42,     /*!< alert level not specified      */
   E_SSL_ALERT_UNSUP_CERT        = 43,     /*!< alert level not specified      */
   E_SSL_ALERT_CERT_REVOKED      = 44,     /*!< alert level not specified      */
   E_SSL_ALERT_CERT_EXPIRED      = 45,     /*!< alert level not specified      */
   E_SSL_ALERT_CERT_UNKNOWN      = 46,     /*!< alert level not specified      */
   E_SSL_ALERT_ILLEGAL_PARAM     = 47,     /*!< always fatal */
   E_SSL_ALERT_UNKNOWN_CA        = 48,
   E_SSL_ALERT_ACCESS_DENIED     = 49,
   E_SSL_ALERT_DECODE_ERR        = 50,
   E_SSL_ALERT_DECR_ERR          = 51,
   E_SSL_ALERT_EXPORT_RESTR      = 60,
   E_SSL_ALERT_PROTO_VER         = 70,
   E_SSL_ALERT_PUNSUFF_SEC       = 71,
   E_SSL_ALERT_INTERNAL_ERR      = 80,
   E_SSL_ALERT_USER_CANCELED     = 90,
   E_SSL_ALERT_NO_RENEG          = 100,
   E_SSL_ALERT_UNSUP_EXT         = 110     /*!< always fatal */
} e_sslAlertType_t;




/*! \brief Definition of the handshake types used in the SSL Handshake Protocol.
 *
 *  During the establishment of a secure connection between the server and the
 *  client a set of handshake messages are exchanged. The handshake messages
 *  are used to negotiate the security attributes of a session. Once a session
 *  is established a client can open several simultaneous connections to the
 *  server without carrying out the handshake phase again. This is called
 *  session resumption. The new connection is based on the security attributes
 *  of its session.
 *
 *  This enumerator defines all the possible handshake message types which can
 *  be exchanged between the client and the server during the SSL Handshake
 *  Protocol.
 */
typedef enum HandshakeType
{
   HELLO_REQUEST           =  0, /* 0x00 */
   CLIENT_HELLO            =  1, /* 0x01 */
   SERVER_HELLO            =  2, /* 0x02 */
   CERTIFICATE             = 11, /* 0x0b */
   SERVER_KEY_EXCHANGE     = 12, /* 0x0c */
   CERTIFICATE_REQUEST     = 13, /* 0x0d */
   SERVER_HELLO_DONE       = 14, /* 0x0e */
   CERTIFICATE_VERIFY      = 15, /* 0x0f */
   CLIENT_KEY_EXCHANGE     = 16, /* 0x10 */
   FINISHED                = 20  /* 0x14 */
} SSL_HANDSHAKE_TYPE;




/*! \brief Definitions for Ciphersuites.
 *
 * Due to the fact that all supported ciphersuites have the first byte
 * equal to zero, only the second byte will be used.
 * vpy: false!! ECC: first byte !=0
 * Only one of the supported Algorithms uses MD5 for message authentication,
 * all other use SHA1.
 * NB: when adding new ciphersuites make sure that the macro SSL_CIPSPEC_COUNT
 *     is adjusted and that they're initialized in wssl_record.c:ssl_initCtx()
 */

typedef enum E_SSL_CIPHERSPEC
{
   TLS_NULL_WITH_NULL_NULL                  = 0x0000,
   TLS_RSA_WITH_RC4_128_MD5                 = 0x0004,
   TLS_RSA_WITH_RC4_128_SHA                 = 0x0005,
   #ifdef AES_AND_3DES_ENABLED
   TLS_RSA_WITH_3DES_EDE_CBC_SHA            = 0x000A,
   TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA        = 0x0016,
   TLS_RSA_WITH_AES_128_CBC_SHA             = 0x002F,
   TLS_DHE_RSA_WITH_AES_128_CBC_SHA         = 0x0033,
   TLS_RSA_WITH_AES_256_CBC_SHA             = 0x0035,
   TLS_DHE_RSA_WITH_AES_256_CBC_SHA         = 0x0039,
   TLS_RSA_WITH_AES_128_CBC_SHA256          = 0x003C,
   TLS_RSA_WITH_AES_256_CBC_SHA256          = 0x003D,
   TLS_DHE_RSA_WITH_AES_128_CBC_SHA256      = 0x0067,
   TLS_DHE_RSA_WITH_AES_256_CBC_SHA256      = 0x006B,

   //begin vpy
   //add new cipher suites here
   TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  	= 0xC008,
   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   	= 0xC009,
   TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   	= 0xC00A,
   TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    	= 0xC012,
   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     	= 0xC013,
   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     	= 0xC014,
   //end vpy

   #endif
   TLS_EMPTY_RENEGOTIATION_INFO_SCSV        = 0x00FF,
   TLS_UNDEFINED                            = 0xFFFF     /* This is special case */
} e_sslCipSpec_t;

#ifdef AES_AND_3DES_ENABLED
#define SSL_CIPSPEC_COUNT 21 //13
#else
#define SSL_CIPSPEC_COUNT 3
#endif

#define TLS_NULL_WITH_NULL_NULL_NAME              "TLS_NULL_WITH_NULL_NULL"
#define TLS_RSA_WITH_RC4_128_MD5_NAME             "TLS_RSA_WITH_RC4_128_MD5"
#define TLS_RSA_WITH_RC4_128_SHA_NAME             "TLS_RSA_WITH_RC4_128_SHA"
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA_NAME        "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_NAME    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
#define TLS_RSA_WITH_AES_128_CBC_SHA_NAME         "TLS_RSA_WITH_AES_128_CBC_SHA"
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA_NAME     "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
#define TLS_RSA_WITH_AES_256_CBC_SHA_NAME         "TLS_RSA_WITH_AES_256_CBC_SHA"
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA_NAME     "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
#define TLS_RSA_WITH_AES_128_CBC_SHA256_NAME      "TLS_RSA_WITH_AES_128_CBC_SHA256"
#define TLS_RSA_WITH_AES_256_CBC_SHA256_NAME      "TLS_RSA_WITH_AES_256_CBC_SHA256"
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256_NAME  "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256_NAME  "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"

//begin vpy
#define TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA_NAME	"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_NAME	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_NAME	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA_NAME	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_NAME		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_NAME		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
//end vpy


/* We do not support RC2 as well as all EXPORT-Ciphers with 40 bit key.
 * ----- Explanation -----
 * TODO vpy: update list with supported ciphers
 * Ciphers actually supported are marked by an *
 *
 * Ciphers to be supported soon are marked by an @
 *
 * Ciphers to be supported in the future are marked F
 *
 * Ciphers to be supported perhaps in the future are marked Q
 *
 * All Ciphers can be implemented on request
 *
 * -----------------------
 *
 *
 *  * CipherSuite TLS_NULL_WITH_NULL_NULL              = { 0x00,0x00 };
 *  This CipherSuite is established at connection startup and not allowed for
 *  application data exchange.

    CipherSuite TLS_RSA_WITH_NULL_MD5                  = { 0x00,0x01 };
    CipherSuite TLS_RSA_WITH_NULL_SHA                  = { 0x00,0x02 };
  * CipherSuite TLS_RSA_WITH_RC4_128_MD5               = { 0x00,0x04 };
  * CipherSuite TLS_RSA_WITH_RC4_128_SHA               = { 0x00,0x05 };
    CipherSuite TLS_RSA_WITH_IDEA_CBC_SHA              = { 0x00,0x07 };
    CipherSuite TLS_RSA_WITH_DES_CBC_SHA               = { 0x00,0x09 };
  * CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA          = { 0x00,0x0A };
  * CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA           = { 0x00,0x2F };
  * CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA           = { 0x00,0x35 };
  * CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256        = { 0x00,0x3C };
  * CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256        = { 0x00,0x3D };

    CipherSuite TLS_DH_DSS_WITH_DES_CBC_SHA            = { 0x00,0x0C };
    CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       = { 0x00,0x0D };
    CipherSuite TLS_DH_RSA_WITH_DES_CBC_SHA            = { 0x00,0x0F };
    CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       = { 0x00,0x10 };
    CipherSuite TLS_DHE_DSS_WITH_DES_CBC_SHA           = { 0x00,0x12 };
  * CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x13 };
    CipherSuite TLS_DHE_RSA_WITH_DES_CBC_SHA           = { 0x00,0x15 };
  * CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x16 };
    CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA        = { 0x00,0x30 };
    CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA        = { 0x00,0x31 };
    CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA       = { 0x00,0x32 };
  * CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA       = { 0x00,0x33 };
    CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA        = { 0x00,0x36 };
    CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA        = { 0x00,0x37 };
    CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA       = { 0x00,0x38 };
  * CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA       = { 0x00,0x39 };
  * CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA256    = { 0x00,0x67 };
  * CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA256    = { 0x00,0x6B };

// Completely Anonymous DH Communications won't be supported because
// they are vulnerable to man-in-the-middle attacks

    CipherSuite TLS_DH_anon_WITH_RC4_128_MD5           = { 0x00,0x18 };
    CipherSuite TLS_DH_anon_WITH_DES_CBC_SHA           = { 0x00,0x1A };
    CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x1B };
    CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA       = { 0x00,0x34 };
    CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA       = { 0x00,0x3A };

// Export Ciphers MUST NOT been negotiated in versions after SSL3.0

    CipherSuite TLS_RSA_EXPORT_WITH_RC4_40_MD5         = { 0x00,0x03 };
    CipherSuite TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     = { 0x00,0x06 };
    CipherSuite TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      = { 0x00,0x08 };
    CipherSuite TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   = { 0x00,0x0B };
    CipherSuite TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   = { 0x00,0x0E };
    CipherSuite TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x11 };
    CipherSuite TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x14 };
    CipherSuite TLS_DH_anon_EXPORT_WITH_RC4_40_MD5     = { 0x00,0x17 };
    CipherSuite TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x19 };

// Kerberos won't be implemented in the foreseeable future - only on request

    CipherSuite TLS_KRB5_WITH_DES_CBC_SHA              = { 0x00,0x1E };
    CipherSuite TLS_KRB5_WITH_3DES_EDE_CBC_SHA         = { 0x00,0x1F };
    CipherSuite TLS_KRB5_WITH_RC4_128_SHA              = { 0x00,0x20 };
    CipherSuite TLS_KRB5_WITH_IDEA_CBC_SHA             = { 0x00,0x21 };
    CipherSuite TLS_KRB5_WITH_DES_CBC_MD5              = { 0x00,0x22 };
    CipherSuite TLS_KRB5_WITH_3DES_EDE_CBC_MD5         = { 0x00,0x23 };
    CipherSuite TLS_KRB5_WITH_RC4_128_MD5              = { 0x00,0x24 };
    CipherSuite TLS_KRB5_WITH_IDEA_CBC_MD5             = { 0x00,0x25 };

    CipherSuite TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA    = { 0x00,0x26 };
    CipherSuite TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA    = { 0x00,0x27 };
    CipherSuite TLS_KRB5_EXPORT_WITH_RC4_40_SHA        = { 0x00,0x28 };
    CipherSuite TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5    = { 0x00,0x29 };
    CipherSuite TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5    = { 0x00,0x2A };
    CipherSuite TLS_KRB5_EXPORT_WITH_RC4_40_MD5        = { 0x00,0x2B };

// PreSharedKey CipherSuites

    CipherSuite TLS_PSK_WITH_NULL_SHA                  = { 0x00,0x2C };
    CipherSuite TLS_DHE_PSK_WITH_NULL_SHA              = { 0x00,0x2D };
    CipherSuite TLS_RSA_PSK_WITH_NULL_SHA              = { 0x00,0x2E };

    CipherSuite TLS_PSK_WITH_RC4_128_SHA               = { 0x00,0x8A };
    CipherSuite TLS_PSK_WITH_3DES_EDE_CBC_SHA          = { 0x00,0x8B };
    CipherSuite TLS_PSK_WITH_AES_128_CBC_SHA           = { 0x00,0x8C };
    CipherSuite TLS_PSK_WITH_AES_256_CBC_SHA           = { 0x00,0x8D };
    CipherSuite TLS_DHE_PSK_WITH_RC4_128_SHA           = { 0x00,0x8E };
    CipherSuite TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x8F };
    CipherSuite TLS_DHE_PSK_WITH_AES_128_CBC_SHA       = { 0x00,0x90 };
    CipherSuite TLS_DHE_PSK_WITH_AES_256_CBC_SHA       = { 0x00,0x91 };
    CipherSuite TLS_RSA_PSK_WITH_RC4_128_SHA           = { 0x00,0x92 };
    CipherSuite TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x93 };
    CipherSuite TLS_RSA_PSK_WITH_AES_128_CBC_SHA       = { 0x00,0x94 };
    CipherSuite TLS_RSA_PSK_WITH_AES_256_CBC_SHA       = { 0x00,0x95 };

// Camellia CipherSuites

    CipherSuite TLS_RSA_WITH_CAMELLIA_128_CBC_SHA      = { 0x00,0x41 };
    CipherSuite TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA   = { 0x00,0x42 };
    CipherSuite TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA   = { 0x00,0x43 };
    CipherSuite TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA  = { 0x00,0x44 };
    CipherSuite TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA  = { 0x00,0x45 };
    CipherSuite TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA  = { 0x00,0x46 };

    CipherSuite TLS_RSA_WITH_CAMELLIA_256_CBC_SHA      = { 0x00,0x84 };
    CipherSuite TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA   = { 0x00,0x85 };
    CipherSuite TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA   = { 0x00,0x86 };
    CipherSuite TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA  = { 0x00,0x87 };
    CipherSuite TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA  = { 0x00,0x88 };
    CipherSuite TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA  = { 0x00,0x89 };

// Secure Remote Password CipherSuites

    CipherSuite TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA      = { 0xC0,0x1A };
    CipherSuite TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA  = { 0xC0,0x1B };
    CipherSuite TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA  = { 0xC0,0x1C };
    CipherSuite TLS_SRP_SHA_WITH_AES_128_CBC_SHA       = { 0xC0,0x1D };
    CipherSuite TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA   = { 0xC0,0x1E };
    CipherSuite TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA   = { 0xC0,0x1F };
    CipherSuite TLS_SRP_SHA_WITH_AES_256_CBC_SHA       = { 0xC0,0x20 };
    CipherSuite TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA   = { 0xC0,0x21 };
    CipherSuite TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA   = { 0xC0,0x22 };

// EllipticCurveCryptography CipherSuites

    CipherSuite TLS_ECDH_ECDSA_WITH_NULL_SHA           = { 0xC0,0x01 };
    CipherSuite TLS_ECDH_ECDSA_WITH_RC4_128_SHA        = { 0xC0,0x02 };
    CipherSuite TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA   = { 0xC0,0x03 };
    CipherSuite TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA    = { 0xC0,0x04 };
    CipherSuite TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA    = { 0xC0,0x05 };

    CipherSuite TLS_ECDHE_ECDSA_WITH_NULL_SHA          = { 0xC0,0x06 };
    CipherSuite TLS_ECDHE_ECDSA_WITH_RC4_128_SHA       = { 0xC0,0x07 };
  * CipherSuite TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA  = { 0xC0,0x08 };
  * CipherSuite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA   = { 0xC0,0x09 };
  * CipherSuite TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA   = { 0xC0,0x0A };

    CipherSuite TLS_ECDH_RSA_WITH_NULL_SHA             = { 0xC0,0x0B };
  F CipherSuite TLS_ECDH_RSA_WITH_RC4_128_SHA          = { 0xC0,0x0C };
    CipherSuite TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA     = { 0xC0,0x0D };
  F CipherSuite TLS_ECDH_RSA_WITH_AES_128_CBC_SHA      = { 0xC0,0x0E };
  F CipherSuite TLS_ECDH_RSA_WITH_AES_256_CBC_SHA      = { 0xC0,0x0F };

    CipherSuite TLS_ECDHE_RSA_WITH_NULL_SHA            = { 0xC0,0x10 };
    CipherSuite TLS_ECDHE_RSA_WITH_RC4_128_SHA         = { 0xC0,0x11 };
  * CipherSuite TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA    = { 0xC0,0x12 };
  * CipherSuite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA     = { 0xC0,0x13 };
  * CipherSuite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA     = { 0xC0,0x14 };

    CipherSuite TLS_ECDH_anon_WITH_NULL_SHA            = { 0xC0,0x15 };
    CipherSuite TLS_ECDH_anon_WITH_RC4_128_SHA         = { 0xC0,0x16 };
    CipherSuite TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA    = { 0xC0,0x17 };
    CipherSuite TLS_ECDH_anon_WITH_AES_128_CBC_SHA     = { 0xC0,0x18 };
    CipherSuite TLS_ECDH_anon_WITH_AES_256_CBC_SHA     = { 0xC0,0x19 };
*/

typedef enum TlsExtension
{
    /* [RFC4366]
     * 3.1.  Server Name Indication
     *
     *  TLS does not provide a mechanism for a client to tell a server the
     *  name of the server it is contacting.  It may be desirable for clients
     *  to provide this information to facilitate secure connections to
     *  servers that host multiple 'virtual' servers at a single underlying
     *  network address.
     *
     */
    TLS_EXTENSION_SERVER_NAME               = 0,

    /* [RFC4366]
     * 3.2.  Maximum Fragment Length Negotiation
     *
     *  Without this extension, TLS specifies a fixed maximum plaintext
     *  fragment length of 2^14 bytes.  It may be desirable for constrained
     *  clients to negotiate a smaller maximum fragment length due to memory
     *  limitations or bandwidth limitations.
     *
     */
    TLS_EXTENSION_MAX_FRAGMENT_LENGTH       = 1,

    /* [RFC4366]
     * 3.3.  Client Certificate URLs
     *
     *  Without this extension, TLS specifies that when client authentication
     *  is performed, client certificates are sent by clients to servers
     *  during the TLS handshake.  It may be desirable for constrained
     *  clients to send certificate URLs in place of certificates, so that
     *  they do not need to store their certificates and can therefore save
     *  memory.
     *
     */
    TLS_EXTENSION_CLIENT_CERTIFICATE_URL    = 2,

    /* [RFC4366]
     * 3.4.  Trusted CA Indication
     *
     *  Constrained clients that, due to memory limitations, possess only a
     *  small number of CA root keys may wish to indicate to servers which
     *  root keys they possess, in order to avoid repeated handshake
     *  failures.
     *
     */
    TLS_EXTENSION_TRUSTED_CA_KEYS           = 3,

    /* [RFC4366]
     * 3.5.  Truncated HMAC
     *
     *  Currently defined TLS cipher suites use the MAC construction HMAC
     *  with either MD5 or SHA-1 [HMAC] to authenticate record layer
     *  communications.  In TLS, the entire output of the hash function is
     *  used as the MAC tag.  However, it may be desirable in constrained
     *  environments to save bandwidth by truncating the output of the hash
     *  function to 80 bits when forming MAC tags.
     *
     */
    TLS_EXTENSION_TRUNCATED_HMAC            = 4,

    /* [RFC4366]
     * 3.6.  Certificate Status Request
     *
     *  Constrained clients may wish to use a certificate-status protocol
     *  such as OCSP [OCSP] to check the s_validity of server certificates, in
     *  order to avoid transmission of CRLs and therefore save bandwidth on
     *  constrained networks.  This extension allows for such information to
     *  be sent in the TLS handshake, saving roundtrips and resources.
     *
     */
    TLS_EXTENSION_STATUS_REQUEST            = 5,

    TLS_EXTENSION_ELLIPTIC_CURVES           = 10,

    TLS_EXTENSION_EC_POINT_FORMATS          = 11,

    /* [RFC5246]
     * 7.4.1.4. Hello Extensions
     *
     * An extension type MUST NOT appear in the ServerHello unless the same
     * extension type appeared in the corresponding ClientHello. If a
     * client receives an extension type in ServerHello that it did not
     * request in the associated ClientHello, it MUST abort the handshake
     * with an unsupported_extension fatal alert.
     *
     */
    TLS_EXTENSION_SIGNATURE_ALGORITHMS      = 13,

    TLS_EXTENSION_SESSIONTICKET_TLS         = 35,

    /* [RFC5746]
     * TLS Renegotiation Extension
     *
     *  This document defines a new TLS extension, "renegotiation_info" (with
     *  extension type 0xff01), which contains a cryptographic binding to the
     *  enclosing TLS connection (if any) for which the renegotiation is
     *  being performed.
     */
    TLS_EXTENSION_RENEGOTIATION_INFO        = 65281,	/* = 0xFF01 */
    TLS_EXTENSION_UNDEFINED                 = 65535
} e_tlsExt_t;
/*** Prototypes *************************************************************/




/*** Global Variables *******************************************************/




/* Your stuff ends here */
#ifdef __cplusplus
} /* extern "C" */
#endif /* end C prototype in C++ */


#endif /* file already included */
