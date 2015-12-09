/**
 * \file 				crypto_def.h
 * \brief 				Definition for the structures and enumeration used in crypto_iface's functions
 * \author				Steve Wagner
 * \date 				21/10/2015
 */

/**********************************************************************************************************************/
/*		      										INCLUDE			 				      							  */
/**********************************************************************************************************************/
#ifndef CRYPTO_DEF
#define CRYPTO_DEF
#include "stdint.h"
#include "stdlib.h"


/**********************************************************************************************************************/
/*		      										DEFINE			  				     							  */
/**********************************************************************************************************************/

/**
 * \typedef 				GciCtxId_t
 * \brief					Context's ID
 */
typedef int GciCtxId_t;



/**
 * \typedef 				GciKeyId_t
 * \brief					Key's ID
 */
typedef int GciKeyId_t;



/**********************************************************************************************************************/
/*		      										GLOBAL						      							  	  */
/**********************************************************************************************************************/

/*!
 * \enum 					GciResult_t
 * \brief					Enumeration for the error management
 */
typedef enum
{
	/**No error*/
	GCI_OK,
	/**Overflow of IDs*/
	GCI_ID_OVERFLOW,
	/**Error of hash algorithm*/
	GCI_HASH_ALGO_ERR,
	/**Error in hash initialization*/
	GCI_HASH_INIT_ERR,
	/**Global error*/
	GCI_ERR
} GciResult_t;



/*!
 * \enum 					GciInfo_t
 * \brief					Enumeration for informations that should be needed to become during the process
 */
typedef enum
{
	/**Invalid information*/
	GCI_INFO_INVALID,
	/**Information of Elliptic Curve Name*/
	GCI_INFO_ECNAME
} GciInfo_t;



/*!
 * \struct 					GciBigInt_t
 * \brief					Structure representing an arbitrary-length integer
 */
typedef struct
{
	/**Big number length in bytes*/
	size_t len;
	/**Big number (data)*/
	uint8_t* data;

} GciBigInt_t;



/*!
 * \struct 					GciBuffer_t
 * \brief					Structure representing an arbitrary-length buffer
 */
typedef struct
{
	/**Buffer length in bytes*/
	size_t len;
	/**Pointer to buffer (data)*/
	uint8_t* data;

} GciBuffer_t;



/**********************************************************************************************************************/
/*		      										HASH		 				      							  	  */
/**********************************************************************************************************************/

/*! Size of the context array */
#define 	GCI_NB_CTX_MAX				16
/*! Size of the key array */
#define 	GCI_NB_KEY_MAX				255
/*! Size in bits for md5 digest */
#define     GCI_MD5_SIZE_BITS           128
/*! Size in bytes for md5 digest */
#define     GCI_MD5_SIZE_BYTES          (GCI_MD5_SIZE_BITS / 8)

/*! Size in bits for sha1 digest */
#define     GCI_SHA1_SIZE_BITS          160
/*! Size in bytes for sha1 digest */
#define     GCI_SHA1_SIZE_BYTES         (GCI_SHA1_SIZE_BITS / 8)

/*! Size in bits for sha224 digest */
#define     GCI_SHA224_SIZE_BITS        224
/*! Size in bytes for sha224 digest */
#define     GCI_SHA224_SIZE_BYTES      (GCI_SHA224_SIZE_BITS / 8)

/*! Size in bits for sha256 digest */
#define     GCI_SHA256_SIZE_BITS        256
/*! Size in bytes for sha256 digest */
#define     GCI_SHA256_SIZE_BYTES      (GCI_SHA256_SIZE_BITS / 8)

/*! Size in bits for sha384 digest */
#define     GCI_SHA384_SIZE_BITS        384
/*! Size in bytes for sha384 digest */
#define     GCI_SHA384_SIZE_BYTES      (GCI_SHA384_SIZE_BITS / 8)

/*! Size in bits for sha512 digest */
#define     GCI_SHA512_SIZE_BITS        512
/*! Size in bytes for sha512 digest */
#define     GCI_SHA512_SIZE_BYTES      (GCI_SHA512_SIZE_BITS / 8)

/*! Size in bytes for md5+sha1 digest */
#define     GCI_MD5_SHA1_SIZE_BYTES     GCI_SHA1_SIZE_BYTES + GCI_MD5_SIZE_BYTES

/*! Maximum size in bits for a digest */
#define     GCI_MAX_HASHSIZE_BITS       GCI_SHA512_SIZE_BITS
/*! Maximum size in bits for a digest */
#define     GCI_MAX_HASHSIZE_BYTES      GCI_SHA512_SIZE_BYTES


#define     GCI_PKCS1_MAX_KEYSIZE        4096
#define     SSL_RSA_MAX_KEY_SIZE        GCI_PKCS1_MAX_KEYSIZE
#define     MAX_MSG_SIZE                (GCI_PKCS1_MAX_KEYSIZE / 8)



/*!
 * \enum 					GciHashAlgo_t
 * \brief					Enumeration for Hash algorithms
 */
typedef enum
{
	/** Invalid Hash */
	GCI_HASH_INVALID,
	/** MD5 */
	GCI_HASH_MD5,
	/** SHA 1 */
	GCI_HASH_SHA1,
	/** SHA 224 */
	GCI_HASH_SHA224,
	/** SHA 256 */
	GCI_HASH_SHA256,
	/** SHA 384 */
	GCI_HASH_SHA384,
	/** SHA 512 */
	GCI_HASH_SHA512,
	/** No hash algorithm used */
	GCI_HASH_NONE=0xFF
} GciHashAlgo_t;



/**********************************************************************************************************************/
/*		      										SYMMETRIC CIPHER			      							  	  */
/**********************************************************************************************************************/

/*!
 * \enum 					GciBlockMode_t
 * \brief					Enumeration for all block mode
 */
typedef enum
{
	/** Invalid block mode*/
	GCI_BLOCK_MODE_INVALID,
	/** CBC mode */
	GCI_BLOCK_MODE_CBC,
	/** ECB mode*/
	GCI_BLOCK_MODE_ECB,
	/** CFB mode*/
	GCI_BLOCK_MODE_CFB,
	/** OFB mode*/
	GCI_BLOCK_MODE_OFB,
	/** GCM mode */
	GCI_BLOCK_MODE_GCM,
	/** No block mode used*/
	GCI_BLOCK_MODE_NONE=0xFF
} GciBlockMode_t;



/*!
 * \enum 					GciPadding_t
 * \brief					Enumeration for all padding
 */
typedef enum
{
	/**Invalid padding*/
	GCI_PADDING_INVALID,
	/** ISO9797 padding */
	GCI_PADDING_ISO9797_METHOD2,
	/** PKCS1 padding */
	GCI_PADDING_PKCS1,
	/** PKCS5 padding */
	GCI_PADDING_PKCS5,
	/** PKCS7 padding */
	GCI_PADDING_PKCS7,
	/** None padding */
	GCI_PADDING_NONE=0xFF
} GciPadding_t;



/*!
 * \enum 					GciCipherAlgo_t
 * \brief					Enumeration for all symmetric cipher algorithm
 */
typedef enum
{
	/** Cipher type invalid*/
	GCI_CIPH_INVALID,
	/** Stream cipher RC4 */
	GCI_CIPH_RC4,
	/** Block cipher Triple DES */
	GCI_CIPH_TDES,
	/** Block cipher AES */
	GCI_CIPH_AES,
	/** Block cipher DES*/
	GCI_CIPH_DES,
	/**No cipher*/
	GCI_CIPH_NONE=0xFF
} GciCipherAlgo_t;



/*!
 * \struct 					GciCipherConfig_t
 * \brief					Structure for all symmetric cipher data
 */
typedef struct
{
	/**
	 * GCI_CIPH_INVALID
	 * GCI_CIPH_RC4 - No block mode and padding possible
	 * GCI_CIPH_TDES
	 * GCI_CIPH_AES
	 * GCI_CIPH_DES
	 * GCI_CIPH_NONE=0xFF
	 */
	GciCipherAlgo_t algo;

	/**
	 * GCI_BLOCK_MODE_INVALID
	 * GCI_BLOCK_MODE_CBC
 	 * GCI_BLOCK_MODE_ECB
	 * GCI_BLOCK_MODE_CFB
	 * GCI_BLOCK_MODE_OFB
	 * GCI_BLOCK_MODE_GCM
	 * GCI_BLOCK_MODE_NONE=0xFF
 	 */
	GciBlockMode_t blockMode;

	/**
	 * GCI_PADDING_INVALID
	 * GCI_PADDING_ISO9797_METHOD2
	 * GCI_PADDING_PKCS5
	 * GCI_PADDING_PKCS7
	 * GCI_PADDING_NONE=0xFF
	 */
	GciPadding_t padding;



	/**Initialization vector (IV) */
	GciBuffer_t iv;
} GciCipherConfig_t;


/**********************************************************************************************************************/
/*		      										DOMAIN + KEY PAIR			      							  	  */
/**********************************************************************************************************************/

/*!
 * \struct 					GciDsaDomainParam_t
 * \brief					Structure for the DSA domain parameters
 */
typedef struct
{
	/**Prime number*/
	GciBigInt_t p;
	/**Divisor*/
	GciBigInt_t q;
	/**Generator*/
	GciBigInt_t g;
} GciDsaDomainParam_t;



/*!
 * \struct 					GciDhDomainParam_t
 * \brief					Structure for the Diffie-Hellman domain parameters
 */
typedef struct
{
	/**Prime*/
	GciBigInt_t p;
	/**Generator*/
	GciBigInt_t g;
} GciDhDomainParam_t;



/*!
 * \struct 					GciEcPoint_t
 * \brief					Structure for the coordinates of an Elliptic Curve
 */
typedef struct
{
	/**x-coordinate*/
	GciBigInt_t x;
	/**y-coordinate*/
	GciBigInt_t y;
} GciEcPoint_t;



/*!
 * \enum 					GciNamedCurve_t
 * \brief					Enumeration of the Elliptic Curve
 * \brief					RFC4492 + RFC7027
 */
typedef enum
{
	/**Invalid Elliptic Curve*/
	GCI_EC_INVALID,
	/**SECT163K1 Elliptic Curve*/
	GCI_EC_SECT163K1,
	/**SECT163R1 Elliptic Curve*/
	GCI_EC_SECT163R1,
	/**SECT163R2 Elliptic Curve*/
	GCI_EC_SECT163R2,
	/**SECT193R1 Elliptic Curve*/
	GCI_EC_SECT193R1,
	/**SECT193R2 Elliptic Curve*/
	GCI_EC_SECT193R2,
	/**SECT233K1 Elliptic Curve*/
	GCI_EC_SECT233K1,
	/**SECT233R1 Elliptic Curve*/
	GCI_EC_SECT233R1,
	/**SECT239K1 Elliptic Curve*/
	GCI_EC_SECT239K1,
	/**SECT283K1 Elliptic Curve*/
	GCI_EC_SECT283K1,
	/**SECT283R1 Elliptic Curve*/
	GCI_EC_SECT283R1,
	/**SECT409K1 Elliptic Curve*/
	GCI_EC_SECT409K1,
	/**SECT409R1 Elliptic Curve*/
	GCI_EC_SECT409R1,
	/**SECT571K1 Elliptic Curve*/
	GCI_EC_SECT571K1,
	/**SECT571R1 Elliptic Curve*/
	GCI_EC_SECT571R1,
	/**SECP160K1 Elliptic Curve*/
	GCI_EC_SECP160K1,
	/**SECP160R1 Elliptic Curve*/
	GCI_EC_SECP160R1,
	/**SECP160R2 Elliptic Curve*/
	GCI_EC_SECP160R2,
	/**SECP192K1 Elliptic Curve*/
	GCI_EC_SECP192K1,
	/**SECP192R1 (SECG) / PRIME192V1 (ANSI X9.62) Elliptic Curve*/
	GCI_EC_SECP192R1,
	/**SECP224K1 Elliptic Curve*/
	GCI_EC_SECP224K1,
	/**SECP224R1 Elliptic Curve*/
	GCI_EC_SECP224R1,
	/**SECP256K1 Elliptic Curve*/
	GCI_EC_SECP256K1,
	/**SECP256R1 (SECG) / PRIME256V1 (ANSI X9.62) Elliptic Curve*/
	GCI_EC_SECP256R1,
	/**SECP384R1 Elliptic Curve*/
	GCI_EC_SECP384R1,
	/**SECP521R1 Elliptic Curve*/
	GCI_EC_SECP521R1,
	/**BRAINPOOLP256R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP256R1,
	/**BRAINPOOLP384R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP384R1,
	/**RAINPOOLP512R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP512R1
} GciNamedCurve_t;



/*!
 * \struct 					GciEcDomainParam_t
 * \brief					Structure of the EC domain parameters to create an eventual EC
 */
typedef struct
{
	/**Coefficient a*/
	GciBigInt_t a;
	/**Coefficient b*/
	GciBigInt_t b;
	/**Generator*/
	GciEcPoint_t g;
	/**Prime number group*/
	GciBigInt_t p;
	/**EC group*/
	GciBigInt_t N;
	/**Subgroup of EC group generated by g (generator)*/
	GciBigInt_t h;
} GciEcDomainParam_t;



/**********************************************************************************************************************/
/*		      										SIGNATURE	 				      							  	  */
/**********************************************************************************************************************/

/*!
 * \enum 					GciSignAlgo_t
 * \brief					Enumeration for Signature algorithms
 */
typedef enum
{
	/**Invalid signature*/
	GCI_SIGN_INVALID,
	/** RSA */
	GCI_SIGN_RSA,
	/** DSA */
	GCI_SIGN_DSA,
	/** ECDSA */
	GCI_SIGN_ECDSA,
	/** ISO9797 ALG1 */
	GCI_SIGN_MAC_ISO9797_ALG1,
	/** ISO9797 ALG3 */
	GCI_SIGN_MAC_ISO9797_ALG3,
	/** CMAC AES */
	GCI_SIGN_CMAC_AES,
	/** HMAC */
	GCI_SIGN_HMAC,
	/** RSA SSA PSS */
	GCI_SIGN_RSASSA_PSS,
	/** RSA SSA PKCS */
	GCI_SIGN_RSASSA_PKCS,
	/** RSA SSA X509 */
	GCI_SIGN_RSASSA_X509,
	/** ECDSA GFP */
	GCI_SIGN_ECDSA_GFP,
	/** ECDSA GF2M */
	GCI_SIGN_ECDSA_GF2M,
	/**No algorithm*/
	GCI_SIGN_NONE = 0xFF
} GciSignAlgo_t;



/*!
 * \struct 					GciSignRsaConfig_t
 * \brief					Structure for the configuration of a RSA signature
 */
typedef struct
{
	/**RSA domain parameters*/
	GciPadding_t padding;
} GciSignRsaConfig_t;



/*!
 * \struct 					GciSignCmacConfig_t
 * \brief					Structure for the configuration of a CMAC signature
 */
typedef struct
{

	/**
	 * GCI_BLOCK_MODE_INVALID
	 * GCI_BLOCK_MODE_CBC
	 * GCI_BLOCK_MODE_ECB
	 * GCI_BLOCK_MODE_CFB
	 * GCI_BLOCK_MODE_OFB
	 * GCI_BLOCK_MODE_GCM
	 * GCI_BLOCK_MODE_NONE=0xFF
	 */
	GciBlockMode_t block;

	/**
	 * GCI_PADDING_INVALID
	 * GCI_PADDING_ISO9797_METHOD2
	 * GCI_PADDING_PKCS5
	 * GCI_PADDING_PKCS7
	 * GCI_PADDING_NONE=0xFF
	 */
	GciPadding_t padding;

	/**Initialization vector (IV) */
	GciBuffer_t iv;
} GciSignCmacConfig_t;



/*!
 * \struct 					GciSignConfig_t
 * \brief					Structure for the configuration of a signature
 */
typedef struct
{
	/**
	 * GCI_SIGN_INVALID
	 * GCI_SIGN_RSA
	 * GCI_SIGN_DSA
	 * GCI_SIGN_ECDSA
	 * GCI_SIGN_MAC_ISO9797_ALG1
	 * GCI_SIGN_MAC_ISO9797_ALG3
	 * GCI_SIGN_CMAC_AES
	 * GCI_SIGN_HMAC
	 * GCI_SIGN_RSASSA_PKCS
	 * GCI_SIGN_RSASSA_PSS
	 * GCI_SIGN_RSASSA_X509
	 * GCI_SIGN_RSA_CRT
	 * GCI_SIGN_ECDSA_GFP
	 * GCI_SIGN_ECDSA_GF2M
	 * GCI_SIGN_NONE=0xFF
	 */
	GciSignAlgo_t algo;


	/**
	 * GCI_HASH_INVALID
	 * GCI_HASH_MD5
	 * GCI_HASH_SHA1
	 * GCI_HASH_SHA224
	 * GCI_HASH_SHA256
	 * GCI_HASH_SHA384
	 * GCI_HASH_SHA512
	 * GCI_HASH_NONE = 0xFF
	 */
	GciHashAlgo_t hash;

	/**
	 * \union 				signConfig
	 * \brief				Union for the configuration of each signature
	 */
	union signConfig
	{
		/** RSA Configuration */
		GciSignRsaConfig_t rsa;

		/** CMAC Configuration */
		GciSignCmacConfig_t cmac;
	} config;
} GciSignConfig_t;



/**********************************************************************************************************************/
/*		      										KEY GENERATOR			      							  		  */
/**********************************************************************************************************************/

/*!
 * \enum 					GciKeyPairType_t
 * \brief					Enumeration for all type of key pair algorithm
 */
typedef enum
{
	/**Invalid key pair*/
	GCI_KEY_PAIR_INVALID,
	/**RSA key pair*/
	GCI_KEY_PAIR_RSA,
	/**RSA key pair - sign*/
	GCI_KEY_PAIR_RSA_SSA,
	/**RSA key pair - encrypt*/
	GCI_KEY_PAIR_RSA_ES,
	/**DH key pair */
	GCI_KEY_PAIR_DH,
	/**ECDH key pair */
	GCI_KEY_PAIR_ECDH,
	/**DSA key pair*/
	GCI_KEY_PAIR_DSA,
	/**EC DSA key pair*/
	GCI_KEY_PAIR_ECDSA,
	/**No key pair */
	GCI_KEY_PAIR_NONE=0xFF
} GciKeyPairType_t;



/*!
 * \struct 					GciRsaKeyGenConfig_t
 * \brief					Structure holding the configuration parameters for an RSA key generation operation
 */
typedef struct
{
    /** Length of the modulus to generate (in bits) */
	size_t modulusLen;
} GciRsaKeyGenConfig_t;



/**********************************************************************************************************************/
/*		      										Diffie-Hellman	Key Generator     							  	  */
/**********************************************************************************************************************/

/*!
 * \enum 					GciDhType_t
 * \brief					Enumeration of the Diffie-Hellman type
 */
typedef enum
{
	/**Invalid Diffie-Hellman*/
	GCI_DH_INVALID,
	/**Diffie Hellman*/
	GCI_DH,
	/**Elliptic curve Diffie-Helmann*/
	GCI_ECDH
} GciDhType_t;



/**********************************************************************************************************************/
/*		      										KEYS						      							  	  */
/**********************************************************************************************************************/

/*!
 * \struct 					GciRsaPubKey_t
 * \brief					Structure representing a RSA public key
 */
typedef struct
{
	/**Prime number*/
	GciBigInt_t n;
	/**Public exponent*/
	GciBigInt_t e;
}GciRsaPubKey_t;


/*!
 * \struct 					GciRsaCrtPrivKey_t
 * \brief					Structure representing a RSA CRT private key
 */
typedef struct
{
	/**First prime number p*/
	GciBigInt_t p;
	/**Second prime number q*/
	GciBigInt_t q;
	/**dP = d mod (p-1)*/
	GciBigInt_t dP;
	/**dQ = d mod (q-1)*/
	GciBigInt_t dQ;
	/**qInv = q^-1 mod p*/
	GciBigInt_t qInv;
} GciRsaCrtPrivKey_t;



/*!
 * \struct 					GciRsaPrivKey_t
 * \brief					Structure representing a RSA private key
 */
typedef struct
{
	/**Prime number*/
	GciBigInt_t n;
	/**Private exponent*/
	GciBigInt_t d;
	/**Private CRT*/
	GciRsaCrtPrivKey_t* crt;
} GciRsaPrivKey_t;



/*!
 * \struct 					GciDsaKey_t
 * \brief					Structure representing a DSA key (public or private)
 */
typedef struct
{
	/**DSA domain parameters*/
	GciDsaDomainParam_t* param;
	/**Big number of the key*/
	GciBigInt_t key;
}GciDsaKey_t;



/*!
 * \struct 					GciDhKey_t
 * \brief					Structure representing a DH key (public or private)
 */
typedef struct
{
	/**Diffie-Hellman domain parameters*/
	GciDhDomainParam_t* param;
	/**Big number of the key*/
	GciBigInt_t key;
}GciDhKey_t;



/*!
 * \struct 					GciEcdhPubKey_t
 * \brief					Structure representing a ECDH public key
 */
typedef struct
{
	/**
	 * GCI_EC_SECT163K1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT233K1
	 * GCI_EC_SECT233R1
	 * GCI_EC_SECT239K1
	 * GCI_EC_SECT283K1
	 * GCI_EC_SECT283R1
	 * GCI_EC_SECT409K1
	 * GCI_EC_SECT409R1
	 * GCI_EC_SECT571K1
	 * GCI_EC_SECT571R1
	 * GCI_EC_SECP160K1
	 * GCI_EC_SECP160R1
	 * GCI_EC_SECP160R2
	 * GCI_EC_SECP192K1
	 * GCI_EC_SECP192R1
	 * GCI_EC_SECP224K1
	 * GCI_EC_SECP224R1
	 * GCI_EC_SECP256K1
	 * GCI_EC_SECP256R1
	 * GCI_EC_SECP384R1
	 * GCI_EC_SECP521R1
	 * GCI_EC_BRAINPOOLP256R1
	 * GCI_EC_BRAINPOOLP384R1
	 * GCI_EC_BRAINPOOLP512R1
	 */
	GciNamedCurve_t* curve;
	/**coordinate (x,y) of the curve*/
	GciEcPoint_t coord;
}GciEcdhPubKey_t;



/*!
 * \struct 					GciEcdhPrivKey_t
 * \brief					Structure representing a ECDH priv key
 */
typedef struct
{
	/**
	 * GCI_EC_SECT163K1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT233K1
	 * GCI_EC_SECT233R1
	 * GCI_EC_SECT239K1
	 * GCI_EC_SECT283K1
	 * GCI_EC_SECT283R1
	 * GCI_EC_SECT409K1
	 * GCI_EC_SECT409R1
	 * GCI_EC_SECT571K1
	 * GCI_EC_SECT571R1
	 * GCI_EC_SECP160K1
	 * GCI_EC_SECP160R1
	 * GCI_EC_SECP160R2
	 * GCI_EC_SECP192K1
	 * GCI_EC_SECP192R1
	 * GCI_EC_SECP224K1
	 * GCI_EC_SECP224R1
	 * GCI_EC_SECP256K1
	 * GCI_EC_SECP256R1
	 * GCI_EC_SECP384R1
	 * GCI_EC_SECP521R1
	 * GCI_EC_BRAINPOOLP256R1
	 * GCI_EC_BRAINPOOLP384R1
	 * GCI_EC_BRAINPOOLP512R1
	 */
	GciNamedCurve_t* curve;
	/**Big number of the key*/
	GciBigInt_t key;
}GciEcdhPrivKey_t;



/*!
 * \struct 					GciEcdsaPubKey_t
 * \brief					Structure representing a ECDSA public key
 */
typedef struct
{
	/**
	 * GCI_EC_SECT163K1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT233K1
	 * GCI_EC_SECT233R1
	 * GCI_EC_SECT239K1
	 * GCI_EC_SECT283K1
	 * GCI_EC_SECT283R1
	 * GCI_EC_SECT409K1
	 * GCI_EC_SECT409R1
	 * GCI_EC_SECT571K1
	 * GCI_EC_SECT571R1
	 * GCI_EC_SECP160K1
	 * GCI_EC_SECP160R1
	 * GCI_EC_SECP160R2
	 * GCI_EC_SECP192K1
	 * GCI_EC_SECP192R1
	 * GCI_EC_SECP224K1
	 * GCI_EC_SECP224R1
	 * GCI_EC_SECP256K1
	 * GCI_EC_SECP256R1
	 * GCI_EC_SECP384R1
	 * GCI_EC_SECP521R1
	 * GCI_EC_BRAINPOOLP256R1
	 * GCI_EC_BRAINPOOLP384R1
	 * GCI_EC_BRAINPOOLP512R1
	 */
	GciNamedCurve_t* curve;
	/**coordinate (x,y) of the curve*/
	GciEcPoint_t coord;
}GciEcdsaPubKey_t;



/*!
 * \struct 					GciEcdsaPrivKey_t
 * \brief					Structure representing a ECDSA private key
 */
typedef struct
{
	/**
	 * GCI_EC_SECT163K1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT163R1
	 * GCI_EC_SECT233K1
	 * GCI_EC_SECT233R1
	 * GCI_EC_SECT239K1
	 * GCI_EC_SECT283K1
	 * GCI_EC_SECT283R1
	 * GCI_EC_SECT409K1
	 * GCI_EC_SECT409R1
	 * GCI_EC_SECT571K1
	 * GCI_EC_SECT571R1
	 * GCI_EC_SECP160K1
	 * GCI_EC_SECP160R1
	 * GCI_EC_SECP160R2
	 * GCI_EC_SECP192K1
	 * GCI_EC_SECP192R1
	 * GCI_EC_SECP224K1
	 * GCI_EC_SECP224R1
	 * GCI_EC_SECP256K1
	 * GCI_EC_SECP256R1
	 * GCI_EC_SECP384R1
	 * GCI_EC_SECP521R1
	 * GCI_EC_BRAINPOOLP256R1
	 * GCI_EC_BRAINPOOLP384R1
	 * GCI_EC_BRAINPOOLP512R1
	 */
	GciNamedCurve_t* curve;
	/**Big number of the key*/
	GciBigInt_t key;
}GciEcdsaPrivKey_t;



/*!
 * \enum 					GciKeyType_t
 * \brief					Enumeration for all type of key
 */
typedef enum
{
	/**Invalid key*/
	GCI_KEY_INVALID,
	/**Symmetric key*/
	GCI_KEY_SYM,
	/**Diffie-Hellman public key*/
	GCI_KEY_DH_PUB,
	/**Diffie-Hellman private key*/
	GCI_KEY_DH_PRIV,
	/**Diffie-Hellman shared secret key*/
	GCI_KEY_DH_SECRET,
	/**Elliptic Curve Diffie-Hellman public key*/
	GCI_KEY_ECDH_PUB,
	/**Elliptic Curve Diffie-Hellman private key*/
	GCI_KEY_ECDH_PRIV,
	/**Elliptic Curve Diffie-Hellman shared secret key*/
	GCI_KEY_ECDH_SECRET,
	/**DSA public key*/
	GCI_KEY_DSA_PUB,
	/**DSA private key*/
	GCI_KEY_DSA_PRIV,
	/**ECDSA public key*/
	GCI_KEY_ECDSA_PUB,
	/**ECDSA private key*/
	GCI_KEY_ECDSA_PRIV,
	/**RSA public key - general*/
	GCI_KEY_RSA_PUB,
	/**RSA private key - general*/
	GCI_KEY_RSA_PRIV,
	/**RSA private key - signing*/
	GCI_KEY_RSA_PRIV_SSA,
	/**RSA private key - signing*/
	GCI_KEY_RSA_PUB_SSA,
	/**RSA public key - encrypt*/
	GCI_KEY_RSA_PUB_ES,
	/**RSA private key - encrypt*/
	GCI_KEY_RSA_PRIV_ES,
	/**HMAC key*/
	GCI_KEY_HMAC,
	/**No key*/
	GCI_KEY_NONE=0xFF
} GciKeyType_t;



/*!
 * \struct 					GciKey_t
 * \brief					Structure for the parameters to each key object
 */
typedef struct
{
	/**
	 * GCI_KEY_INVALID
	 * GCI_KEY_SYM
	 * GCI_KEY_DH_PUB
	 * GCI_KEY_DH_PRIV
	 * GCI_KEY_DH_SECRET
	 * GCI_KEY_ECDH_PUB
	 * GCI_KEY_ECDH_PRIV
	 * GCI_KEY_ECDH_SECRET
	 * GCI_KEY_DSA_PUB
	 * GCI_KEY_DSA_PRIV
	 * GCI_KEY_ECDSA_PUB
	 * GCI_KEY_ECDSA_PRIV
	 * GCI_KEY_RSA_PUB
	 * GCI_KEY_RSA_PRIV
	 * GCI_KEY_RSA_PRIV_SSA
	 * GCI_KEY_RSA_PUB_SSA
	 * GCI_KEY_RSA_PUB_ES
	 * GCI_KEY_RSA_PRIV_ES
	 * GCI_KEY_HMAC
	 * GCI_KEY_NONE=0xFF
	 */
	GciKeyType_t type;

   /*!
	* union 					keyData
	* \brief					Union for the key/key-pair data of each key
	*/
	union keyData
	{
		/**Symmetric key*/
		GciBuffer_t sym;
		/**Diffie-Hellman Public Key*/
		GciDhKey_t dhPub;
		/**Diffie-Hellman Private Key*/
		GciDhKey_t dhPriv;
		/**Diffie-Hellman Secret Key*/
		GciBuffer_t dhSecret;
		/**Elliptic Curve Diffie-Hellman Public Key*/
		GciEcdhPubKey_t ecdhPub;
		/**Elliptic Curve Diffie-Hellman Private Key*/
		GciEcdhPrivKey_t ecdhPriv;
		/**Elliptic Curve Diffie-Hellman Secret Key*/
		GciBuffer_t ecdhSecret;
		/**DSA Public Key*/
		GciDsaKey_t dsaPub;
		/**DSA Private Key*/
		GciDsaKey_t dsaPriv;
		/**Elliptic Curve DSA Public Key*/
		GciEcdsaPubKey_t ecdsaPub;
		/**Elliptic Curve DSA Private Key*/
		GciEcdsaPrivKey_t ecdsaPriv;
		/**RSA Public Key*/
		GciRsaPubKey_t rsaPub;
		/**RSA Private Key*/
		GciRsaPrivKey_t rsaPriv;
	} key;
} GciKey_t;




#endif
