#ifndef _CRYPTO_WRAP_H_
#define _CRYPTO_WRAP_H_
/*============================================================================*/
/*!
    \file   crypto_wrap.h

    \author ??? by STZ-EDN, Loerrach, Germany, http://www.embetter.de

    \brief  API definitions for crypto wrapper

  \version  $Version$

*/
/*=============================================================================
                                 INCLUDE FILES
 ============================================================================*/
#define DESC_DEF_ONLY
#include "netGlobal.h"
#ifdef ASCOM_CRYPTO
#include "crypto.h"
#include "wrc4.h"
#include "cert.h"
#elif defined(TOMLIB_CRYPTO)
#include "tomcrypt.h"
#include "tommath.h"
#endif
#ifdef EMBETTER_DMA
#include "drv_hw.h"
#endif

ltc_math_descriptor ltc_mp;

/*==============================================================================
                                   CONSTANTS
==============================================================================*/
/*! Size in bits for md5 digest */
#define     CW_MD5_DSIZE_BITS             128
/*! Size in bytes for sha1 digest */
#define     CW_MD5_DSIZE                  (CW_MD5_DSIZE_BITS / 8)

/*! Size in bits for sha1 digest */
#define     CW_SHA1_DSIZE_BITS            160
/*! Size in bytes for sha1 digest */
#define     CW_SHA1_DSIZE                 (CW_SHA1_DSIZE_BITS / 8)

/*! Size in bits for sha1 digest */
#define     CW_SHA224_DSIZE_BITS          224
/*! Size in bytes for sha1 digest */
#define     CW_SHA224_DSIZE               (CW_SHA224_DSIZE_BITS / 8)

/*! Size in bits for sha1 digest */
#define     CW_SHA256_DSIZE_BITS          256
/*! Size in bytes for sha1 digest */
#define     CW_SHA256_DSIZE               (CW_SHA256_DSIZE_BITS / 8)

/*! Size in bytes for md5+sha1 digest */
#define     CW_MD5_SHA1_DSIZE             CW_SHA1_DSIZE + CW_MD5_DSIZE

/*! Maximum size in bits for a digest */
#define     CW_MAX_HASHSIZE               CW_SHA256_DSIZE

#define     CW_PKCS1_MAX_KEYSIZE          4096
#define     SSL_RSA_MAX_KEY_SIZE          CW_PKCS1_MAX_KEYSIZE
#define     MAX_MSG_SIZE                  (CW_PKCS1_MAX_KEYSIZE / 8)


/*==============================================================================
                                    MACROS
==============================================================================*/
#ifndef DBG_CRYPT_WRAP
/*  usually debug mode is switched off
multiple debug levels possible! '#define DBG_CRYPT_WRAP 2' will print more details */
#define DBG_CRYPT_WRAP 1
#endif

#ifndef _SYS_HAS_MALLOC_H_
/*  has to be adjusted for every system where malloc.h is available */
#define _SYS_HAS_MALLOC_H_   0
#endif

#define     CW_OK             (0)
#define     CW_ERROR          (-1)

#ifdef ASCOM_CRYPTO
#define     CW_MEMSET         CL_MemSet
#define     CW_MEMMOVE        CL_MemMove
#define     CW_MEMCOPY        CL_MemCopy
#define     CW_MEMSEARCH      CL_MemSearch
#define     CW_MEMCMP         CL_MemCmp
#define     CW_STRLEN         CL_StrLen
#define     CW_STRCMP         CL_StrCmp
#elif defined(TOMLIB_CRYPTO)
#define     CW_MEMSET         memset
#define     CW_MEMMOVE        memmove
# if DBG_CRYPT_WRAP
#  define   CW_MEMCOPY        cw_memcopy
# else
#  define   CW_MEMCOPY        MEMCPY
# endif
#define     CW_MEMSEARCH      CL_MemSearch
#define     CW_MEMCMP         memcmp
#define     CW_STRLEN         strlen
#define     CW_STRCMP         strcmp
#define     CW_STRNCMP        strncmp
#define     CW_STRCHR         strchr
#define     AES_AND_3DES_ENABLED

#define     CR_PRNG_NAME      "fortuna"
#define     CR_AES_NAME       "aes"
#define     CR_3DES_NAME      "3des"
#define     CR_MD5_NAME       "md5"
#define     CR_SHA1_NAME      "sha1"
#define     CR_SHA256_NAME    "sha256"
#define     CR_INVALID        "invalid"

#endif

/*==============================================================================
                         STRUCTURES AND OTHER TYPEDEFS
==============================================================================*/
typedef     char*             pcw_str_t;                           /* Pointer to string             */
typedef     const char*       rpcw_str_t;                          /* Pointer to a constant string  */

#ifdef ASCOM_CRYPTO

/*============= RETURN =============*/
typedef     CL_RSA_RV         cw_rsaRet_t;
/*=============  PKI   =============*/
typedef     CL_RSAPRIVKEY     cw_rsaPrivKey_t;
typedef     CL_PRSAPRIVKEY    cw_rsaPrivKey_t *;
typedef     CL_RSAPUBKEY      cw_rsaPubKey_t;
typedef     CL_PRSAPUBKEY     cw_rsaPubKey_t *;
typedef     CL_PCRSAPUBKEY    rpcw_rsaPubKey_t;
/*=============  MATH  =============*/
typedef     CL_BIGNUM         cw_bigNum_t;
typedef     CL_PBIGNUM        cw_bigNum_t *;
/*============= HASHES =============*/
typedef     CL_SHA1CTX        cw_sha1Ctx_t;
typedef     CL_MD5CTX         cw_md5Ctx_t;
/*============= CRYPTO =============*/
typedef     CL_WRC4CTX        cw_rc4Ctx_t;
typedef     CL_AESCTX         cw_aesCtx_t;

#elif defined(TOMLIB_CRYPTO)
/* we define an own type for the RC4 context to save memory */
typedef struct rc4_prng_state {
    int x, y;
    unsigned char buf[256];
} prng_state_rc4;

/*============= RETURN =============*/
typedef     int               cw_rsaRet_t;
/*=============  PKI   =============*/
typedef     dh_key            cw_dhKey_t;
typedef     rsa_key           cw_rsaPrivKey_t;
typedef     rsa_key           cw_rsaPubKey_t;
typedef const rsa_key*        rpcw_rsaPubKey_t;

/*=============  MATH  =============*/
typedef     mp_int            cw_bigNum_t;
/*============= HASHES =============*/
typedef     hash_state        cw_sha1Ctx_t;
typedef     hash_state        cw_md5Ctx_t;
typedef     hash_state        cw_hashCtx_t;
/*=============  HMAC  =============*/
typedef     hmac_state        cw_sha1HmacCtx_t;
typedef     hmac_state        cw_md5HmacCtx_t;
typedef     hmac_state        cw_hmacCtx_t;
/*============= CRYPTO =============*/
typedef     prng_state_rc4    cw_rc4Ctx_t;
typedef     symmetric_CBC     cw_aesCtx_t;
typedef     symmetric_CBC     cw_3desCtx;
typedef     symmetric_CBC     cw_cbcCtx;
typedef     symmetric_CBC     cw_symCbcCtx;
#endif

typedef enum
{
    /**Invalid key*/
    KEY_INVALID,
    /**ECDSA public key*/
    KEY_ECC_PUB,
    /**ECDSA private key*/
    KEY_ECC_PRIV,
    /**RSA public key*/
    KEY_RSA_PUB,
    /**RSA private key*/
    KEY_RSA_PRIV,
    /**No key*/
    KEY_NONE=0xFF
} KeyType_t;

//Temporary structs to store key, inspired by Steve Wagner. As its interface is not ready, it should be replaced in the future.
typedef struct
{
	/**
	 * KEY_INVALID
	 * KEY_DSA_PRIV
	 * KEY_ECDSA_PUB
	 * KEY_ECDSA_PRIV
	 * KEY_RSA_PUB
	 * KEY_RSA_PRIV
	 * KEY_NONE
	 */
	KeyType_t type;

	union keyData
	{
		/**Elliptic Curve DSA Public Key*/
		ecc_key eccPub;
		/**Elliptic Curve DSA Private Key*/
		ecc_key eccPriv;
		/**RSA Public Key*/
		rsa_key rsaPub;
		/**RSA Private Key*/
		rsa_key rsaPriv;
	} key;
} Key_t;

typedef struct tagPublicKey
{
    int     iAlgorithm;
    uint32_t    uiKeyLen;
    cw_bigNum_t * pE;      /* ptr to public exponent   */
    cw_bigNum_t * pM;      /* ptr to modulus           */
    uint8_t * eccKeyRaw;	//ptr to ECC public key
    uint16_t eccCurve;		//Curve used in certificate if ECDSA
} s_pubKey_t;

/* This holds the key settings.  ***MUST*** be organized by size from smallest to largest. */
static const struct {
    int size;
    char *name, *base, *prime;
} sets[] = {
{
   128,
   "DH-1024",
   "4",
   "F///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////m3C47"
},
{
   192,
   "DH-1536",
   "4",
   "F///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////m5uqd"
},
{
   256,
   "DH-2048",
   "4",
   "3///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "/////////////////////////////////////////m8MPh"
},
{
   512,
   "DH-4096",
   "4",
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "/////////////////////m8pOF"
},
{
   0,
   NULL,
   NULL,
   NULL
}
};

/*
 * The enumeration of hash algorithms (HashAlgorithm)
 * used by TLS >= v1.2 for digitally-signed elements
 * (see RFC 5246, p. 46)
 */
typedef enum {
    E_SSL_HASH_NONE     = 0x00,
    E_SSL_HASH_MD5      = 0x01,
    E_SSL_HASH_SHA1     = 0x02,
    E_SSL_HASH_SHA256   = 0x04,
    E_SSL_HASH_INVALID  = 0xFF
} e_sslHashAlg_t;

/*==============================================================================
                               GLOBAL VARIABLES
==============================================================================*/


/*==============================================================================
                        FUNCTION PROTOTYPES OF THE API
==============================================================================*/
/*============================================================================*/
/*!

   \brief     Print malloc information to stdout

*/
/*============================================================================*/
void cw_mem_printUsage(void);


/*============================================================================*/
/*!

   \brief     memcpy wrapping to support debugging


   \param     dest   destinationadress

   \param     src   sourceadress

   \param     n   number of bytes to copy

   \return    malloc returnvalue

*/
/*============================================================================*/
void* cw_memcopy(void *dest, const void *src, int n);


/*============================================================================*/
/*!

   \brief     Argument checking

              We've implemented our own argument checking function.
              Edit this to your desired behavior.
              usage is: 'assert(logical operation);'
              for example 'assert(p_pointer != NULL);'
              or          'assert(i_integer < i_otherInt);'
              Typecasts have to be done on Macro call!

   \param     v   the callvector that triggered the call of this function

   \param     s   pointer to the filename where the callvector has been triggered

   \param     d   line number where the callvector has been triggered

   \return    nothing

*/
/*============================================================================*/
void cw_argchk(char *v, char *s, int d);


/*============================================================================*/
/*!

   \brief     Convert error codes to human readable strings


   \param     err  the errorcode that has to be converted

   \return    a pointer to the beginning of the specific string

*/
/*============================================================================*/
const char* cw_error2string(int err);


/*============================================================================*/
/*!

   \brief     This function handles the initialization of the crypto API, if needed!

              In case of libtomcrypt(ltc) there is the need to register
              the used ciphers for example!
              In case of ASCOM Crypto(AC) there is nothing to do.

   \return    nothing

*/
/*============================================================================*/
void cw_crypto_init(void);



/*==================================  PKI   ==================================*/



/*============================================================================*/
/*

   \brief     Free a public key

   \param     a pointer on a public key (RSA/ECC) of type Key_t

   \retun	  0 if free was successful
   	   	   	  -1 else
*/
/*============================================================================*/
int cw_publickey_free(Key_t* p_pubKey);



/*============================================================================*/
/*
 *
   \brief     Allocate a new key of the type p_pubKey->type.

   \param     a pointer on a public key of type Key_t, with p_pubKey->type field already defined (KEY_RSA_PUB/KEY_ECC_PUB)

   \retun	  0 if successful
   	   	   	  -1 else

*/
/*============================================================================*/
int cw_publickey_init(Key_t* p_pubKey);


/*============================================================================*/
/*

   \brief     Convert Name of curve into the corresponding number
   	   	   	   specified in RFC 4492 (5.1.1.) and RFC 7027 (2.)

   \param     curveName	Null terminated string containing the name of the curve

   \retun		the number of the curve
   	   	   	   -1 if failed to find the curve

*/
/*============================================================================*/
int16_t cw_ecc_convert_curveName_curveNumer(char* curveName);


/*============================================================================*/
/*

   \brief     Generation of a Elliptical curve Diffie Hellman private Keypair

   \param     p_privKey      Pointer to the newly generated ECC key
   \param	  curve			 RFC 4492 5.1.1: identifier of the curve

   \return    CW_ERROR failed to generate
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_ecc_makeKey(ecc_key* p_privKey, uint16_t curve);


/*============================================================================*/
/*!

   \brief     Export an ECC key as a binary packet, as a public key

   \param     p_dest      Pointer where to write

   \param     pcwt_destLen  Pointer to [in] maximum available size
                          [out] really written size

   \param     p_privKey   DH privatekey to export

   \return    CW_ERROR failed to export
   \return    CW_OK all went fine

*/
int cw_ecc_export_public(uint8_t* p_dest, size_t* pcwt_destLen, ecc_key* p_key);


/*============================================================================*/
/*!

   \brief     Import Public key of peer

   \param     pc_in			From where to read

   \param     cwt_inLen   	available length

   \param     p_key    		pointer to the newly initialised ECDH key

   \return    CW_ERROR failed to import
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_ecc_import_public(uint8_t* pc_in, size_t cwt_inLen, ecc_key* p_key);


/*============================================================================*/
/*!

   \brief     Post process the bitstring got from an ASN1 sequence containing a ECC public key

   \param     pwsslt_pubKey     Pointer to the SSL key that was modified
   \param     p_pubKey       	Pointer to the ECC key that should have been modified

*/
/*============================================================================*/
void cw_ecc_publickey_post(s_pubKey_t * pwsslt_pubKey, ecc_key * p_pubKey);


/*============================================================================*/
/*!

   \brief     Return a pointer over a ltc_ecc_set that constains the curve parameters specified by ecc_curve_OID got from certificate parsing

   \param     ecc_curve_OID     value of the curve name we want to search. Defined in ssl_oid.h.
   \param     dp		       	Pointer to set we found and we return

   \return    CW_ERROR failed to find a dp
   \return    CW_OK all went fine
*/
/*============================================================================*/
int cw_ecc_dp_from_OID_defined_curve_name(uint16_t ecc_curve_OID ,ltc_ecc_set_type **dp);


/*============================================================================*/
/*
   \brief     Allocate a ECC public key

   \return    CW_ERROR failed to allocate
   \return    CW_OK all went fine
*/
/*============================================================================*/
int cw_ecc_publickey_init(ecc_key *p_eccKey);


/*============================================================================*/
/*!

   \brief     free a formerly generated ECDH key

   \param     p_key pointer to the key

*/
/*============================================================================*/
void cw_ecc_free(ecc_key* p_key);


/*============================================================================*/
/*!

   \brief     Generate the shared secret

   \param     p_privateKey private key to use

   \param     p_publicKey  public key to use

   \param     p_outData    where to write the shared secret

   \param     pcwt_outLen  pointer to [in] maximum available size
                           [out] really written size

   \return    CW_ERROR failed to import
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_ecc_sharedSecret(ecc_key* p_privateKey, ecc_key* p_publicKey, uint8_t* p_outData, size_t* cwp_outLen);


/*============================================================================*/
/*!

   \brief     Wrapper function to sign a Message and to EC encode

   \param     p_inMessage       Pointer to the incoming message that shall be verified
   \param     cwt_inMsgLen      Length of the incoming message
   \param     p_signature       Pointer to the signature that should verify the authenticity
   \param     cwt_sigLen        Length of the signature
   \param     p_key          	Pointer to the EC Key

   \return    CW_OK             all went fine
   \return    CW_ERROR          an error occurred while decoding

*/
/*============================================================================*/
int cw_ecc_sign_encode(uint8_t* p_inMessage, size_t cwt_inMsgLen,
          uint8_t* p_signature, size_t* cwt_sigLen, ecc_key * p_key);



/*============================================================================*/
/*!

   \brief     Wrapper function to verify a ECDSA encrypted signature

   \param     pc_sig            Pointer to the incoming message that shall be verified
   \param     cwt_siglen        Length of the incoming message
   \param     pc_hash           Pointer to the hash that has to be compared
   \param     cwt_hashlen       Length of the signature
   \param     res               result - 1 on success, 0 on fail
   \param     ecc_pubkey        Pointer to the Public RSA Key needed for verification

   \return    CW_OK             all went fine, but res is showing real result
   \return    CW_ERROR          an error occurred while decoding

*/
/*============================================================================*/
int cw_ecc_hash_verify_ltc(uint8_t* pc_sig, size_t cwt_siglen,
        uint8_t* pc_hash, size_t cwt_hashlen, int* res,
        ecc_key * ecc_pubkey);

/*!

   \brief     Return the number of supported curves and their indentificator

   \param     p_outData    where to write the identificators (array)

   \return	  The number of supported curves

*/
/*============================================================================*/
int cw_ecc_getSupportedCurves(uint16_t* p_outData);


/*============================================================================*/
/*!

   \brief     This handles the import of a ECC Private Key.

   \param     p_buffer      Pointer to the Buffer where the private key is stored

   \param     l_strlen      length of the data in the buffer

   \param     pcwt_privKey  Pointer to a private key usable for the plugged-in crypto lib

   \param	  dp			Pointer to a struct that will be filled by curves' parameters

   \return    ERROR_TYPES from libtomcrypt
   \return    CRYPT_OK is fine, the rest can be analysed by cw_error2string(err)

*/
/*============================================================================*/
int cw_ecc_privatekey_init(unsigned char* p_buffer, size_t l_strlen,
		ecc_key* pcwt_privKey, ltc_ecc_set_type* dp);

/*============================================================================*/
/*!

   \brief     Generation of a Diffie Hellman private Keypair

   \param     p_privKey      Pointer to the newly generated DH key

   \return    CW_ERROR failed to generate
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_dhe_makeKey(cw_dhKey_t* p_privKey);


/*============================================================================*/
/*!

   \brief     Export the formerly generated Yc

   \param     p_dest        Pointer where to write

   \param     pcwt_destLen  [in] maximum available size
                            [out] really written size

   \param     p_privKey     DH privatekey to export

   \return    CW_ERROR failed to export
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_dhe_export_Y(uint8_t* p_dest, size_t* pcwt_destLen, cw_dhKey_t* p_privKey);


/*============================================================================*/
/*!

   \brief     Export p, q and Ys as binary data

   \param     p_dest      Pointer where to write

   \param     pcwt_destLen  Pointer to [in] maximum available size
                          [out] really written size

   \param     p_privKey   DH privatekey to export

   \return    CW_ERROR failed to export
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_dhe_export_pgY(uint8_t*      p_dest,    size_t*       pcwt_destLen,
                      cw_dhKey_t*   p_privKey, cw_bigNum_t**     pcwt_dheP);


/*============================================================================*/
/*!

   \brief     Import Yc of the communication counterpart

   \param     p_input     From where to read

   \param     cwt_inLen   available length

   \param     p_dheKey    pointer to the newly initialised DH key

   \param     index       index of DH group that was used to generate the privatekey

   \return    CW_ERROR failed to import
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_dhe_import_Y(uint8_t* p_input, size_t cwt_inLen, cw_dhKey_t* p_dheKey);


/*============================================================================*/
/*!

   \brief     Import p, q and Y of the communication counterpart

   \param     pc_input      From where to read

   \param     cwt_inLen     available length

   \param     p_privateKey  pointer to the privatekey that will be generated

   \param     p_publicKey   pointer to the publickey of the communication counterpart

   \param     pp_dh_p       p for the diffie hellman shared secret computation

   \return    CW_ERROR failed to import
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_dhe_import_make_privKey(uint8_t* pc_input, size_t cwt_inLen,
                               cw_dhKey_t* p_privateKey, cw_dhKey_t* p_publicKey,
                               cw_bigNum_t** pp_dh_p);


/*============================================================================*/
/*!

   \brief     Generate the shared secret

   \param     p_privateKey private key (p, q, Ys) to use

   \param     p_publicKey  public key (Yc) to use

   \param     p_outData    where to write the shared secret

   \param     pcwt_outLen  pointer to [in] maximum available size
                           [out] really written size

   \return    CW_ERROR failed to import
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_dhe_sharedSec(cw_dhKey_t* p_privateKey, cw_dhKey_t* p_publicKey, uint8_t* p_outData, size_t* pcwt_outLen);


/*============================================================================*/
/*!

   \brief     Generate the shared secret with given p

   \param     p_privateKey private key (Yc) to use

   \param     p_publicKey  public key (Ys) to use

   \param     pp_dh_p      p

   \param     p_outData    where to write the shared secret

   \param     pcwt_outLen  Pointer to [in] maximum available size
                           [out] really written size

   \return    CW_ERROR failed to import
   \return    CW_OK all went fine

*/
/*============================================================================*/
int cw_dhe_sharedSec_with_p(cw_dhKey_t* p_privateKey, cw_dhKey_t* p_publicKey, cw_bigNum_t** pp_dheP, uint8_t* p_outData, size_t* pcwt_outLen);


/*============================================================================*/
/*!

   \brief     free a formerly generated DH key

   \param     pdh_key pointer to the key

*/
/*============================================================================*/
void cw_dh_free(cw_dhKey_t* pdh_key);


/*============================================================================*/
/*!

   \brief     free a memmory allocated for bn

   \param     pointer to the bignumber

*/
/*============================================================================*/
void cw_bn_free(cw_bigNum_t* pcwt_bn);


/*============================================================================*/
/*!

   \brief     Wrapper function for storing an OctetString in a BigNumber(BN)/MultiPrecisionInteger(MPI)

              OctetString2IntegerPointer

   \param     pbn_num     Pointer to a BN/MPI
   \param     p_raw       Pointer to the octet string which shall be extracted
   \param     cwt_rawLen  length of the octet string

   \return    CW_OK       all went fine
   \return    CW_ERROR    an error occurred while import

*/
/*============================================================================*/
int cw_rsa_os2ip(cw_bigNum_t * pbn_num, uint8_t* p_raw, size_t cwt_rawLen);


/*============================================================================*/
/*!

   \brief     Wrapper function for exporting an OctetString from a BN/MPI

              Integer2OctetStringPointer
              !! Important !!
              The usage of this function implies
              that the needed size for storage of data has been allocated before

   \param     pbn_num     Pointer to a BN/MPI
   \param     cwt_numLen  length of the BN/MPI
   \param     p_outData   Pointer to the address where the data has to be stored

   \return    CW_OK       all went fine
   \return    CW_ERROR    an error occurred while export

*/
/*============================================================================*/
int cw_rsa_i2osp(cw_bigNum_t * pbn_num, size_t cwt_numLen, uint8_t* p_outData);


/*============================================================================*/
/*!

   \brief     Process a Modular Exponentiation on 'Signature'

   \param     Message     Pointer to the BN/MPI that will hold the result
   \param     Signature   Pointer to the BN/MPI that holds the Signature to verify
   \param     pPubKey     Pointer to a RSA Public Key

   \return    CW_OK       all went fine
   \return    CW_ERROR    an error occurred while calculation

*/
/*============================================================================*/
int cw_rsa_verify (cw_bigNum_t * Message, cw_bigNum_t * Signature, rpcw_rsaPubKey_t pPubKey);


/*============================================================================*/
/*!

   \brief     Wrapper function to decrypt a RSA encrypted, PKCS#1 V1.5 padded message

   \param     p_outData       Pointer where the decrypted data shall be stored
   \param     cwt_outDataLen  [in] Pointer to the available buffer
                              [out] Length of written data
   \param     p_inData        Pointer to the encrypted data
   \param     cwt_inDataLen   Length of the ecrypted data
   \param     p_privkey       Pointer to the Private RSA Key needed for decryption

   \return    CW_OK           all went fine
   \return    CW_ERROR        an error occurred while decoding

*/
/*============================================================================*/
int cw_pkcs1_v15_decrypt(uint8_t* p_inData, size_t cwt_inDataLen,
        uint8_t* p_outData, size_t* cwt_outDataLen, cw_rsaPrivKey_t * p_privkey);



/*============================================================================*/
/*!

   \brief     Wrapper function to PKCS#1 V1.5 pad and RSA encrypt a message

   \param     p_outData       Pointer where the encrypted data shall be stored
   \param     cwt_outDataLen  [in] Pointer to the available buffer
                              [out] Length of written data
   \param     p_inData        Pointer to the plaintext
   \param     cwt_inDataLen   Length of the plaintext
   \param     p_pubkey        Pointer to the Public RSA Key needed for encryption

   \return    CW_OK           all went fine
   \return    CW_ERROR        an error occurred while decoding

*/
/*============================================================================*/
int cw_rsa_encrypt(uint8_t* p_inData, size_t cwt_inDataLen,
        uint8_t* p_outData, size_t* cwt_outDataLen, cw_rsaPubKey_t * p_pubkey);


/*============================================================================*/
/*!

   \brief     Wrapper function to decrypt and decode a RSA encrypted signature

   \param     pc_encSign        Pointer to the encrypted signature (in)
   \param     sz_encSignLen     Length of the encrypted signature
   \param     pc_decSign        Pointer to the decrypted and decoded signature (out)
   \param     sz_decSignLen     Pointer to the length of the decrypted signature
   \param     p_pubkey          Pointer to the Public RSA Key needed for verification

   \return    CW_OK             all went fine
   \return    CW_ERROR          an error occurred while decoding

*/
/*============================================================================*/
int cw_rsa_sign_decode(uint8_t* pc_encSign, size_t sz_encSignLen,
                       uint8_t* pc_decSign, size_t* sz_decSignLen,
                       cw_rsaPubKey_t * p_pubkey);


/*============================================================================*/
/*!

   \brief     Wrapper function to verify a rsa encrypted signature

   \param     pc_sig            Pointer to the incoming message that shall be verified
   \param     cwt_siglen        Length of the incoming message
   \param     pc_hash           Pointer to the hash that has to be compared
   \param     cwt_hashlen       Length of the signature
   \param     hash_idx          hash algorithm that has been used
   \param     res               result - 1 on success, 0 on fail
   \param     rsa_pubkey        Pointer to the Public RSA Key needed for verification

   \return    CW_OK             all went fine, but res is showing real result
   \return    CW_ERROR          an error occurred while decoding

*/
/*============================================================================*/
int cw_rsa_hash_verify_ltc(uint8_t* pc_sig, size_t cwt_siglen,
          uint8_t* pc_hash, size_t cwt_hashlen, int hash_idx, int* res, cw_rsaPubKey_t * rsa_pubkey);


/*============================================================================*/
/*!

   \brief     Wrapper function to PKCS#1 sign a Message and RSA encode it

              The Message won't be signed with the PKCS#1 OID's but with DER OID's!

   \param     p_inMessage       Pointer to the incoming message that shall be verified
   \param     cwt_inMsgLen      Length of the incoming message
   \param     p_signature       Pointer to the signature that should verify the authenticity
   \param     cwt_sigLen        Length of the signature
   \param     p_pubkey          Pointer to the Public RSA Key needed for verification

   \return    CW_OK             all went fine
   \return    CW_ERROR          an error occurred while decoding

*/
/*============================================================================*/
int cw_rsa_sign_encode(uint8_t* p_inMessage, size_t cwt_inMsgLen,
          uint8_t* p_signature, size_t* cwt_sigLen, cw_rsaPubKey_t * p_pubkey);


/*============================================================================*/
/*!

   \brief     This handles the import of a RSA Private Key.

   \param     p_buffer      Pointer to the Buffer where the privatekey is stored

   \param     l_strlen      length of the data in the buffer

   \param     pcwt_privKey  Pointer to a private key usable for the plugged-in crypto lib

   \return    ERROR_TYPES from libtomcrypt
   \return    CRYPT_OK is fine, the rest can be analysed by cw_error2string(err)

*/
/*============================================================================*/
int cw_rsa_privatekey_init(unsigned char* p_buffer, size_t l_strlen, cw_rsaPrivKey_t* pcwt_privKey);


/*============================================================================*/
/*!

   \brief     Shrink the formerly initialised RSA key

   \param     pcwt_privKey       Pointer to the rsa private key

*/
/*============================================================================*/
void cw_rsa_privatekey_shrink(cw_rsaPrivKey_t* pcwt_privKey);


/*============================================================================*/
/*!

   \brief     Free a private RSA key

   \param     pcwt_privKey       Pointer to the rsa key that has to be freed

*/
/*============================================================================*/
void cw_rsa_privatekey_free(cw_rsaPubKey_t* pcwt_privKey);


/*============================================================================*/
/*!

   \brief     Init a RSA public key - reserve memory and init structure

   \param     pcwt_pubKey       Pointer to the rsa public key

   \return    ERROR_TYPES from libtomcrypt

*/
/*============================================================================*/
int cw_rsa_publickey_init(cw_rsaPubKey_t* pcwt_pubKey);


/*============================================================================*/
/*!

   \brief     Shrink the formerly initialised RSA key

   \param     pcwt_pubKey       Pointer to the rsa public key

*/
/*============================================================================*/
void cw_rsa_publickey_shrink(cw_rsaPubKey_t* pcwt_pubKey);


/*============================================================================*/
/*!

   \brief     Free a public RSA key

   \param     pcwt_pubKey       Pointer to the rsa key that has to be freed

*/
/*============================================================================*/
void cw_rsa_publickey_free(cw_rsaPubKey_t* pcwt_pubKey);


/*============================================================================*/
/*!

   \brief     Prepare a crypto-lib dependant public key to work with SSL

   \param     pcwt_pubKey       Pointer to the rsa key that should be modified
   \param     pwsslt_pubKey     Pointer to the SSL key that will be modified

*/
/*============================================================================*/
void cw_rsa_publickey_prep(cw_rsaPubKey_t * pcwt_pubKey, s_pubKey_t * pwsslt_pubKey);


/*============================================================================*/
/*!

   \brief     Post process the crypto-lib dependant public key after work with SSL

   \param     pwsslt_pubKey     Pointer to the SSL key that was modified
   \param     pcwt_pubKey       Pointer to the rsa key that should have been modified

*/
/*============================================================================*/
void cw_rsa_publickey_post(s_pubKey_t * pwsslt_pubKey, cw_rsaPubKey_t * pcwt_pubKey);


/*==================================  MATH  ==================================*/
/*============================================================================*/
/*!

   \brief     Initialization function for the Buffer System Provided by ASCOM Crypto library

   \param     p_bnBuffer    pointer to the start of the BigNumber Buffer System
   \param     cwt_bufLen    available size in bytes

   \return    nothing

*/
/*============================================================================*/
void cw_bn_init(uint8_t* p_bnBuffer, size_t cwt_bufLen);


/*============================================================================*/
/*!

   \brief     This function initializes a BN/MPI with the given size

   \param     pbn_number    Pointer to the BN/MPI to initialize
   \param     cwt_size      size needed for the BN/MPI in Bits

   \return    Pointer to the initialized BN/MPI
   \return    NULL  if the initialization crashed
*/
/*============================================================================*/
cw_bigNum_t * cw_bn_create(cw_bigNum_t * pbn_number, size_t cwt_size);


/*============================================================================*/
/*!

   \brief     Destroys a BN/MPI and free's also its formerly reserved memory

   \param     pbn_number    Pointer to the BN/MPI to destroy/free

   \return    nothing

*/
/*============================================================================*/
void cw_bn_freefree(void* pbn_number);


/*============================================================================*/
/*!

   \brief     Set the value of a big number.

              The initial data in p_data is organized in bytes, that are stored
              in big endian format (most significant byte at lowest memory address).

   \param     pbn_number      Pointer to the BN/MPI where to store the data
   \param     p_data          Pointer to the data
   \param     cwt_dataSize    Length of data to load in bytes

   \return    nothing

*/
/*============================================================================*/
void cw_bn_set(cw_bigNum_t * pbn_number, void* p_data, size_t cwt_dataSize);


/*============================================================================*/
/*!

   \brief     Makes an addition of 2 BN/MPI

              pbn_number1 + pbn_number2 = pbn_dest

   \param     pbn_dest      Pointer to the BN/MPI where to store the result
   \param     pbn_number1   summand nr. 1
   \param     pbn_number2   summand nr. 2

   \return    CW_OK         all went fine
   \return    CW_ERROR      an error occured

*/
/*============================================================================*/
int cw_bn_add(cw_bigNum_t * pbn_dest, cw_bigNum_t * pbn_number1, cw_bigNum_t * pbn_number2);


/*============================================================================*/
/*!

   \brief     Makes a subtraction of 2 BN/MPI

              pbn_number1 - pbn_number2 = pbn_dest

   \param     pbn_dest      Pointer to the BN/MPI where to store the result
   \param     pbn_number1   the minuend
   \param     pbn_number2   the subtrahend

   \return    CW_OK         all went fine
   \return    CW_ERROR      an error occured

*/
/*============================================================================*/
int cw_bn_sub(cw_bigNum_t * pbn_dest, cw_bigNum_t * pbn_number1, cw_bigNum_t * pbn_number2);


/*============================================================================*/
/*!

   \brief     Makes a multiplication of 2 BN/MPI

              pbn_number1 * pbn_number2 = pbn_dest

   \param     pbn_dest      Pointer to the Product
   \param     pbn_number1   factor 1
   \param     pbn_number2   factor 2

   \return    CW_OK         all went fine
   \return    CW_ERROR      an error occured

*/
/*============================================================================*/
int cw_bn_mul(cw_bigNum_t * pbn_dest, cw_bigNum_t * pbn_number1, cw_bigNum_t * pbn_number2);


/*============================================================================*/
/*!

   \brief     Makes a division and a modulo operation of 2 BN/MPI

              pbn_numerator / pbn_denominator = pbn_quotient
              pbn_numerator % pbn_denominator = pbn_remainder

   \param     pbn_quotient      Pointer to the BN/MPI where to store the quotient
   \param     pbn_remainder     Pointer to the BN/MPI where to store the remainder
   \param     pbn_numerator     Pointer to the numerator
   \param     pbn_denominator   Pointer to the denominator

   \return    CW_OK             all went fine
   \return    CW_ERROR          an error occured

*/
/*============================================================================*/
int cw_bn_div(cw_bigNum_t * pbn_quotient, cw_bigNum_t * pbn_remainder,
              cw_bigNum_t * pbn_numerator, cw_bigNum_t * pbn_denominator);


/*==================================  PRNG  ==================================*/
/*============================================================================*/
/*!

   \brief     Initialisation of the Pseudo Random Number Generator

   \param     p_seed            pointer to the "seed" that is used to initialise the prng
   \param     ul_seedLen        length of the seed

   \return    CW_OK             all went fine
   \return    CW_ERROR          an error occured

*/
/*============================================================================*/
int cw_prng_init(uint8_t* p_seed, size_t cwt_seedLen);


/*============================================================================*/
/*!

   \brief     This function reads from the prng

   \param     p_dest    Pointer to the area where to store the read data
   \param     cwt_len   number of bytes to read

   \return    CW_OK     on success
   \return    CW_ERROR  on error

*/
/*============================================================================*/
int cw_prng_read(uint8_t* p_dest, size_t cwt_len);


/*============================================================================*/
/*!

   \brief     This function seeds the prng

   \param     p_src     Pointer to the seeding data
   \param     cwt_len   number of bytes to seed

   \return    nothing

*/
/*============================================================================*/
void cw_prng_seed(uint8_t* p_src, size_t cwt_len);


/*============================================================================*/
/*!

   \brief     Export the current prng state

   \param     pc_out     Where to write the data
   \param     pl_outlen  [in]  number of bytes available
                         [out] number of bytes written

   \return    CW_OK on success

*/
/*============================================================================*/
int cw_prng_export(uint8_t* pc_out, size_t* pcwt_outlen);


/*============================================================================*/
/*!

   \brief     Import a formerly saved prng state

   \param     pc_in     Where to read the data
   \param     l_inlen   number of bytes to read

   \return    CW_OK on success

*/
/*============================================================================*/
int cw_prng_import(uint8_t* pc_in, size_t cwt_inlen);


/*=================================  HASHES  =================================*/

/*============================================================================*/
/*!

   \brief     Maps an Object ID to a hash index

   \param     i_oid      an oid, see ssl_oid.h

   \return    -1         Object ID is not known
   \return    >-1        hash index of the oid

*/
/*============================================================================*/
int cw_oidIdent2HashIDX(int i_oid);


/*============================   HMAC/HASH   =================================*/

/*============================================================================*/
/*!

   \brief     Maps the name of a hash algorith to a hash index

   \param     pc_name    Name of the hash algorithm

   \return    -1         hash algorithm is not known
   \return    >-1        hash index of the hash algorithm

*/
/*============================================================================*/
int cw_getHashIndex(const char* pc_name);


/*============================================================================*/
/*!

   \brief     Calculate the hash over the data given as attributes

   \param     hash_idx      index of the hash algorithm desired to use
   \param     pc_in         pointer to data block to hash
   \param     ul_inLen      length of data block
   \param     pc_out        pointer where to write the output
   \param     pul_outlen    [in]  space available
                            [out] number of bytes written

   \return    CW_OK         all went fine
   \return    CW_ERROR      an error occured

*/
/*============================================================================*/
int cw_hash_memory(int hash_idx, uint8_t* pc_in, size_t cwt_inLen, uint8_t* pc_out, size_t* pcwt_outlen);


/*============================================================================*/
/*!

   \brief     Calculate the hash over the data given as attributes

   \param     hash_idx      index of the hash algorithm desired to use
   \param     pc_out        pointer where to write the output
   \param     pul_outlen    [in]  space available
                            [out] number of bytes written
   \param     pc_inX        pointer to Xth data block
   \param     ul_inXlen     length of Xth data block

   \return    CW_OK         all went fine
   \return    CW_ERROR      an error occured

*/
/*============================================================================*/
int cw_hash_memory_multi(int hash_idx, uint8_t* pc_out, size_t* pcwt_outlen,
                          uint8_t* pc_in1, size_t cwt_in1len,
                          uint8_t* pc_in2, size_t cwt_in2len,
                          uint8_t* pc_in3, size_t cwt_in3len);


/*============================================================================*/
/*!

   \brief     Makes the typical digest initialization needed
              before you can build the Hash value

   \param     p_ctx   Pointer to the Context to init

   \return    nothing

*/
/*============================================================================*/
int8_t cr_digestInit( void*     p_ctx,   const uint8_t*   pc_key,
                      size_t l_keyLen,e_sslHashAlg_t     e_hashType);


/*============================================================================*/
/*!

   \brief     Calculates the hash of the input data

   \param     p_ctx         Pointer to the context where to hash context stored
   \param     rpc_in        pointer to the data to be hashed
   \param     cwt_len       length of the data
   \param     e_hashType    Hash type

   \return    CW_OK         all went fine
   \return    CW_ERROR      an error occured

*/
/*============================================================================*/
int8_t cr_digestUpdate(void*     p_ctx,  const uint8_t* rpc_in,
                       size_t cwt_len,e_sslHashAlg_t     e_hashType);


/*============================================================================*/
/*!

   \brief     typical digest finish function which ends the hash
              calculation and stores the hash value

   \param     p_ctx         Pointer to the hash context that has to be finished
   \param     pc_out        Address where the Hhsh value has to be stored
   \param     pc_outLen     Length pointer. If length is NULL we a computing HMAC
   \param     e_hashType    Hash type

   \return    CW_OK         all went fine
   \return    CW_ERROR      an error occured

*/
/*============================================================================*/
int8_t cr_digestFinish(void* p_ctx, uint8_t* pc_out, size_t* pc_outLen,
                       e_sslHashAlg_t e_hashType);

int cw_hmac(e_sslHashAlg_t e_hashType,
            const uint8_t* pc_key,   size_t   l_keyLen,
            const uint8_t* pc_in,    size_t   l_inLen,
            uint8_t*       pc_out,   size_t*  pl_outLen);


/*=================================  CIPHERS  ================================*/
/*============================================================================*/
/*!

   \brief     Initialize the RC4 streamcipher

   \param     p_ctx           Pointer to the RC4 context to initialize
   \param     p_key           Pointer to the key which shall be used
   \param     cwt_keyLength   length of the key supplied

   \return    CW_OK           all went fine
   \return    CW_ERROR        an error occured

*/
/*============================================================================*/
int cw_rc4_init(cw_rc4Ctx_t* p_ctx, uint8_t* p_key, size_t cwt_keyLength);


/*============================================================================*/
/*!

   \brief     RC4 de/encrypt a stream of data

   \param     p_ctx           Pointer to the RC4 context that shall be used to de/encrypt
   \param     p_inBuffer      Pointer to the Input Buffer
   \param     p_outBuffer     Pointer to the Output Buffer
   \param     cwt_bufLength   Length that shall be de/encrypted

   \return    CW_OK           all went fine
   \return    CW_ERROR        an error occured

*/
/*============================================================================*/
int cw_rc4(cw_rc4Ctx_t* p_ctx, uint8_t* p_inBuffer, uint8_t* p_outBuffer, size_t cwt_bufLength);


/*============================================================================*/
/*!

   \brief     Initialize the 3DES Blockcipher

   \param     p_ctx         Pointer to the 3DES context that will be initialized
   \param     p_keyData     Pointer to the key that shall be used
   \param     cwt_keyLen    Length of the key
   \param     p_initVect    Pointer to the initialization vector needed by CBC mode of 3DES
   \param     cwt_IVLen     Length of the IV
   \param     c_direction   for ASCOM only: the direction, de- or encryption, is needed in initialization

   \return    CW_OK         all went fine
   \return    CW_ERROR      an error occured

*/
/*============================================================================*/
int cw_3des_init(cw_3desCtx* p_ctx, uint8_t* p_keyData, size_t cwt_keyLen,
                uint8_t* p_initVect, size_t cwt_IVLen, uint8_t c_direction);


/*============================================================================*/
/*!

   \brief     Initialize the AES Blockcipher

   \param     p_ctx         Pointer to the AES context that will be initialized
   \param     p_keyData     Pointer to the key that shall be used
   \param     cwt_keyLen    Length of the key
   \param     p_initVect    Pointer to the initialization vector needed by CBC mode of AES
   \param     cwt_IVLen     Length of the IV
   \param     c_direction   for ASCOM only: the direction, de- or encryption, is needed in initialization

   \return    CW_OK         all went fine
   \return    CW_ERROR      an error occured

*/
/*============================================================================*/
int cw_aes_init(cw_aesCtx_t* p_ctx, uint8_t* p_keyData, size_t cwt_keyLen,
                uint8_t* p_initVect, size_t cwt_IVLen, uint8_t c_direction);


/*============================================================================*/
/*!

	TODO: write description

   \return    CW_OK           all went fine
   \return    CW_ERROR        an error occured

*/
/*============================================================================*/
int cw_cbc_setiv(cw_cbcCtx* p_cbc, const uint8_t* IV, size_t len);


/*============================================================================*/
/*!

   \brief     CBC encrypt an array of data

   \param     p_ctx           Pointer to the CBC context that shall be used for encryption
   \param     p_inBuffer      Pointer to the input buffer
   \param     p_outBuffer     Pointer to the buffer where the ouput shall be stored
   \param     cwt_bufLength   length of the data to encrypt

   \return    CW_OK           all went fine
   \return    CW_ERROR        an error occured

*/
/*============================================================================*/
int cw_cbc_encrypt(cw_cbcCtx* p_ctx, uint8_t* p_inBuffer, uint8_t* p_outBuffer, size_t cwt_bufLength);


/*============================================================================*/
/*!

   \brief     CBC decrypt an array of data

   \param     p_ctx           Pointer to the CBC context that shall be used for decryption
   \param     p_inBuffer      Pointer to the input buffer
   \param     p_outBuffer     Pointer to the buffer where the decrypted data shall be stored
   \param     cwt_bufLength   length of data to decrypt

   \return    CW_OK           all went fine
   \return    CW_ERROR        an error occured

*/
/*============================================================================*/
int cw_cbc_decrypt(cw_cbcCtx* p_ctx, uint8_t* p_inBuffer, uint8_t* p_outBuffer, size_t cwt_bufLength);


#if _CW_TEST_
/*==============================  TEST SECTION ===============================*/

#if _CW_TEST_ == 2
  #define CW_AES_TEST 2
#else
  #define CW_AES_TEST TRUE
#endif

void _aes_test(void);

#endif /* _CW_TEST_ */

#endif /*_CRYPTO_WRAP_H_ */
