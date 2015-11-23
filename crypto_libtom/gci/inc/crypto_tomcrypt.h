/**
 * \file 				crypto_tomcrypt.h
 * \brief 				principals functions of the development of the new interface with tomcrypt library(Generic Crypto Interface)
 * \author				Steve Wagner
 * \date 				02/11/2015
 */

#ifndef CRYPTO_DEV_H_
#define CRYPTO_DEV_H_

/**********************************************************************************************************************/
/*		      										INCLUDE			 				      							  */
/**********************************************************************************************************************/
#include "crypto_iface.h"
#include "tommath.h"
#include "tomcrypt.h"





//TODO sw new[13/11/2015] - Add constant
/**********************************************************************************************************************/
/*		      										CONSTANT		 				      							  */
/**********************************************************************************************************************/
/*! Size of the context array */
#define 	GCI_NB_CTX_MAX				16
/*! Size of the key array */
#define 	GCI_NB_KEY_MAX				255
/*! Size in bits for md5 digest */
#define     GCI_MD5_SIZE_BITS           128
/*! Size in bytes for sha1 digest */
#define     GCI_MD5_SIZE                (GCI_MD5_SIZE_BITS / 8)

/*! Size in bits for sha1 digest */
#define     GCI_SHA1_SIZE_BITS          160
/*! Size in bytes for sha1 digest */
#define     GCI_SHA1_SIZE               (GCI_SHA1_SIZE_BITS / 8)

/*! Size in bits for sha1 digest */
#define     GCI_SHA224_SIZE_BITS        224
/*! Size in bytes for sha1 digest */
#define     GCI_SHA224_SIZE             (GCI_SHA224_SIZE_BITS / 8)

/*! Size in bits for sha1 digest */
#define     GCI_SHA256_SIZE_BITS        256
/*! Size in bytes for sha1 digest */
#define     GCI_SHA256_SIZE             (GCI_SHA256_SIZE_BITS / 8)

/*! Size in bytes for md5+sha1 digest */
#define     GCI_MD5_SHA1_SIZE           GCI_SHA1_SIZE + GCI_MD5_SIZE

/*! Maximum size in bits for a digest */
#define     GCI_MAX_HASHSIZE             GCI_SHA256_SIZE

#define     GCI_PKCS1_MAX_KEYSIZE        4096
#define     SSL_RSA_MAX_KEY_SIZE        GCI_PKCS1_MAX_KEYSIZE
#define     MAX_MSG_SIZE                (GCI_PKCS1_MAX_KEYSIZE / 8)




//TODO sw new[13/11/2015] - Add global typedef (change from cw_*** to gci_xxx)
/**********************************************************************************************************************/
/*		      										GLOBAL			 				      							  */
/**********************************************************************************************************************/
typedef struct rc4_prng_state {
    int x, y;
    unsigned char buf[256];
} prng_state_rc4;
/*============= RETURN =============*/
typedef     int               gci_rsaRet_t;
/*=============  PKI   =============*/
typedef     dh_key            gci_dhKey_t;
typedef     rsa_key           gci_rsaPrivKey_t;
typedef     rsa_key           gci_rsaPubKey_t;
typedef const rsa_key*        rpgci_rsaPubKey_t;
/*=============  MATH  =============*/
typedef     mp_int            gci_bigNum_t;
/*============= HASHES =============*/
typedef     hash_state        gci_sha1Ctx_t;
typedef     hash_state        gci_md5Ctx_t;
typedef     hash_state        gci_hashCtx_t;
/*=============  HMAC  =============*/
typedef     hmac_state        gci_sha1HmacCtx_t;
typedef     hmac_state        gci_md5HmacCtx_t;
typedef     hmac_state        gci_hmacCtx_t;
/*============= CRYPTO =============*/
typedef     prng_state_rc4    gci_rc4Ctx_t;
typedef     symmetric_CBC     gci_aesCtx_t;
typedef     symmetric_CBC     gci_3desCtx;
typedef     symmetric_CBC     gci_cbcCtx;
typedef     symmetric_CBC     gci_symCbcCtx;
/*============= ECC =============*/
typedef		ecc_key			  gci_eccKey_t;


/**********************************************************************************************************************/
/*		      										CONTEXT			 				      							  */
/**********************************************************************************************************************/

/*!
 * \enum 					GciCtxType_t
 * \brief					Enumeration for all type of data that could be store in the context's array
 */
typedef enum
{
	/**No type - empty context*/
	TYPE_NONE,
	/**Hash context type*/
	TYPE_HASH,
	/**Signature context type*/
	TYPE_SIGN,
	/**Cipher context type*/
	TYPE_CIPHER,
	/**Diffie-Hellman context type*/
	TYPE_DH
}GciCtxType_t;



/*!
 * \struct 					GciCtxConfig_t
 *  \brief					Structure for the configuration of each context
 */
typedef struct
{
	/**
	 *
	 * TYPE_NONE
	 * TYPE_HASH
	 * TYPE_SIGN
	 * TYPE_CIPHER
	 * TYPE_DH
	 */
	GciCtxType_t type;

	/*!
	 * union				data
	 * \brief				Union of all type of data that could be store in the context's array
	 */
	union
	{
		GciCipherConfig_t ciph;
		GciHashAlgo_t hash;
		GciSignConfig_t sign;
		GciDhConfig_t dh;
	}data;

	union
	{
		hash_state* hash;
	}tcData;

}GciCtxConfig_t;



/**********************************************************************************************************************/
/*		      										KEY				 				      							  */
/**********************************************************************************************************************/



/*!
 * \struct 					GciKeyConfig_t
 * \brief					Structure of the configuration of a key
 */
typedef struct
{
	/**
	 * KEY_NONE
	 * KEY_AES
	 * KEY_TDES
	 * KEY_RC4
	 * KEY_RSA_PUB
	 * KEY_RSA_PRIV
	 * KEY_RSA_PRIV_CRT
	 * KEY_ECDSA_PUB
	 * KEY_ECDSA_PRIV
	 * KEY_DH_PUB
	 * KEY_DH_PRIV
	 * KEY_DH_SECRET
	 * KEY_ECDHE_PUB
	 * KEY_ECDHE_PRIV
	 * KEY_ECDHE_SECRET
	 */
	GciKeyType_t type;

	/**Length of the key*/
	size_t keyLen;

	/**Key*/
	uint8_t* key;
}GciKeyConfig_t;

#endif /* CRYPTO_DEV_H_ */
