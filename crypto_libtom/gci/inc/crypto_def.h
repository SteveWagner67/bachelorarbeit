/**
 * \file 				crypto_def.h
 * \author				Steve Wagner
 * \date 				21/10/2015
 * \version				1.0
 *
 * \brief 				Definition of the structures and enumerations used in crypto_iface's functions
 */

/*--------------------------------------------------Include--------------------------------------------------------------*/
#ifndef CRYPTO_DEF
#define CRYPTO_DEF
#include "stdint.h"
#include "stdlib.h"



/*-------------------------------------------------Variables-------------------------------------------------------------*/


/*----------------------------------------------Macro Definitions--------------------------------------------------------*/

/** Size of the context array */
#define 	GCI_NB_CTX_MAX				100
/** Size of the key array */
#define 	GCI_NB_KEY_MAX				100
/** Size in bits for md5 digest */
#define     GCI_MD5_SIZE_BITS           128
/** Size in bytes for md5 digest */
#define     GCI_MD5_SIZE_BYTES          (GCI_MD5_SIZE_BITS / 8)

/** Size in bits for sha1 digest */
#define     GCI_SHA1_SIZE_BITS          160
/** Size in bytes for sha1 digest */
#define     GCI_SHA1_SIZE_BYTES         (GCI_SHA1_SIZE_BITS / 8)

/** Size in bits for sha224 digest */
#define     GCI_SHA224_SIZE_BITS        224
/** Size in bytes for sha224 digest */
#define     GCI_SHA224_SIZE_BYTES      (GCI_SHA224_SIZE_BITS / 8)

/** Size in bits for sha256 digest */
#define     GCI_SHA256_SIZE_BITS        256
/** Size in bytes for sha256 digest */
#define     GCI_SHA256_SIZE_BYTES      (GCI_SHA256_SIZE_BITS / 8)

/** Size in bits for sha384 digest */
#define     GCI_SHA384_SIZE_BITS        384
/** Size in bytes for sha384 digest */
#define     GCI_SHA384_SIZE_BYTES      (GCI_SHA384_SIZE_BITS / 8)

/** Size in bits for sha512 digest */
#define     GCI_SHA512_SIZE_BITS        512
/** Size in bytes for sha512 digest */
#define     GCI_SHA512_SIZE_BYTES      (GCI_SHA512_SIZE_BITS / 8)

/** Size in bytes for md5+sha1 digest */
#define     GCI_MD5_SHA1_SIZE_BYTES     GCI_SHA1_SIZE_BYTES + GCI_MD5_SIZE_BYTES

/** Maximum size in bits for a digest */
#define     GCI_MAX_HASHSIZE_BITS       GCI_SHA512_SIZE_BITS
/** Maximum size in bits for a digest */
#define     GCI_MAX_HASHSIZE_BYTES      GCI_SHA512_SIZE_BYTES

/** Maximum size in bits for a PKCS1 key */
#define     GCI_PKCS1_MAX_KEYSIZE       4096
/** Maximum size in bits for a RSA key */
#define     GCI_RSA_MAX_KEY_SIZE        GCI_PKCS1_MAX_KEYSIZE
/** Maximum size in bytes for a PKCS1 message */
#define     GCI_MAX_MSG_SIZE            (GCI_PKCS1_MAX_KEYSIZE / 8)

/** Max size for a buffer in bytes */
#define 	GCI_BUFFER_MAX_SIZE			255



/*----------------------------------------------Type Definitions--------------------------------------------------------*/


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

/**
 * \enum 					en_gciResult
 * \brief					Enumeration for the error management
 */
typedef enum en_gciResult
{
	/** No error */
	en_gciResult_Ok,
	/** Error */
	en_gciResult_Err
} en_gciResult_t;



/**
 * \enum 					en_gciInfo
 * \brief					Enumeration for informations that should be needed to become during the process
 */
typedef enum en_gciInfo
{
	/** Invalid information */
	en_gciInfo_Invalid,
	/** Information of Elliptic Curve Name */
	en_gciInfo_CurveName
} en_gciInfo_t;



/**
 * \struct 					st_gciBigInt
 * \brief					Structure representing an arbitrary-length integer
 */
typedef struct st_gciBigInt
{
	/** Big number length in bytes */
	size_t len;
	/** Big number (data) */
	uint8_t* data;

} st_gciBigInt_t;



/**
 * \struct 					st_gciBuffer
 * \brief					Structure representing an arbitrary-length buffer
 */
typedef struct st_gciBuffer
{
	/** Buffer length in bytes */
	size_t len;
	/** Pointer to buffer (data) */
	uint8_t* data;

} st_gciBuffer_t;



/**********************************************************************************************************************/
/*		      										HASH		 				      							  	  */
/**********************************************************************************************************************/

/**
 * \enum 					en_GciHashAlgo
 * \brief					Enumeration for Hash algorithms
 */
typedef enum en_GciHashAlgo
{
	/** Invalid Hash */
	en_gciHashAlgo_Invalid,
	/** MD5 Hash */
	en_gciHashAlgo_MD5,
	/** SHA1 Hash */
	en_gciHashAlgo_SHA1,
	/** SHA224 Hash */
	en_gciHashAlgo_SHA224,
	/** SHA256 Hash */
	en_gciHashAlgo_SHA256,
	/** SHA384 Hash */
	en_gciHashAlgo_SHA384,
	/** SHA512 Hash */
	en_gciHashAlgo_SHA512,
	/** No hash algorithm used */
	en_gciHashAlgo_None=0xFF
} en_gciHashAlgo_t;



/**********************************************************************************************************************/
/*		      										SYMMETRIC CIPHER			      							  	  */
/**********************************************************************************************************************/

/**
 * \enum 					en_GciBlockMode
 * \brief					Enumeration for all block mode
 */
typedef enum en_GciBlockMode
{
	/** Invalid block mode */
	en_gciBlockMode_Invalid,
	/** CBC block mode */
	en_gciBlockMode_CBC,
	/** ECB block mode */
	en_gciBlockMode_ECB,
	/** CFB block mode */
	en_gciBlockMode_CFB,
	/** OFB block mode */
	en_gciBlockMode_OFB,
	/** GCM block mode */
	en_gciBlockMode_GCM,
	/** No block mode used*/
	en_gciBlockMode_None=0xFF
} en_gciBlockMode_t;



/**
 * \enum 					en_gciPadding
 * \brief					Enumeration for all padding
 */
typedef enum en_gciPadding
{
	/**Invalid padding */
	en_gciPadding_Invalid,
	/** ISO9797 padding */
	en_gciPadding_ISO9797,
	/** PKCS1 padding */
	en_gciPadding_PKCS1,
	/** PKCS5 padding */
	en_gciPadding_PKCS5,
	/** PKCS7 padding */
	en_gciPadding_PKCS7,
	/** None padding */
	en_gciPadding_None=0xFF
} en_gciPadding_t;



/**
 * \enum 					en_gciCipherAlgo
 * \brief					Enumeration for all symmetric cipher algorithm
 */
typedef enum en_gciCipherAlgo
{
	/** Cipher type invalid */
	en_gciCipherAlgo_Invalid,
	/** Stream cipher RC4 */
	en_gciCipherAlgo_RC4,
	/** Block cipher Triple DES */
	en_gciCipherAlgo_3DES,
	/** Block cipher AES */
	en_gciCipherAlgo_AES,
	/** Block cipher DES */
	en_gciCipherAlgo_DES,
	/** No cipher used */
	en_gciCipherAlgo_None=0xFF
} en_gciCipherAlgo_t;



/**
 * \struct 					st_gciCipherConfig
 * \brief					Structure for all symmetric cipher data
 */
typedef struct st_gciCipherConfig
{
	/**
	 * en_gciCipherAlgo_Invalid
	 * en_gciCipherAlgo_RC4
	 * en_gciCipherAlgo_3DES
	 * en_gciCipherAlgo_AES
	 * en_gciCipherAlgo_DES
	 * en_gciCipherAlgo_None=0xFF
	 */
	en_gciCipherAlgo_t algo;

	/**
	 * en_gciBlockMode_Invalid
	 * en_gciBlockMode_CBC
	 * en_gciBlockMode_ECB
	 * en_gciBlockMode_CFB
	 * en_gciBlockMode_OFB
	 * en_gciBlockMode_GCM
	 * en_gciBlockMode_None=0xFF
 	 */
	en_gciBlockMode_t blockMode;

	/**
	 * en_gciPadding_Invalid
	 * en_gciPadding_ISO9797
	 * en_gciPadding_PKCS1
	 * en_gciPadding_PKCS5
	 * en_gciPadding_PKCS7
	 * en_gciPadding_None=0xFF
	 */
	en_gciPadding_t padding;

	/**Initialization vector (IV) */
	st_gciBuffer_t iv;
} st_gciCipherConfig_t;


/**********************************************************************************************************************/
/*		      										DOMAIN + KEY PAIR			      							  	  */
/**********************************************************************************************************************/

/**
 * \struct 					st_gciDsaDomainParam
 * \brief					Structure for the DSA domain parameters
 */
typedef struct st_gciDsaDomainParam
{
	/** Prime number */
	st_gciBigInt_t p;
	/** Divisor */
	st_gciBigInt_t q;
	/** Generator */
	st_gciBigInt_t g;
} st_gciDsaDomainParam_t;



/**
 * \struct 					st_gciDhDomainParam
 * \brief					Structure for the Diffie-Hellman domain parameters
 */
typedef struct st_gciDhDomainParam
{
	/** Prime */
	st_gciBigInt_t p;
	/** Generator */
	st_gciBigInt_t g;
} st_gciDhDomainParam_t;



/**
 * \struct 					st_gciEcPoint
 * \brief					Structure for the coordinates of an Elliptic Curve
 */
typedef struct st_gciEcPoint
{
	/** x-coordinate */
	st_gciBigInt_t x;
	/** y-coordinate */
	st_gciBigInt_t y;
} st_gciEcPoint_t;



/**
 * \enum 					en_gciNamedCurve
 * \brief					Enumeration of the Elliptic Curve
 * \brief					RFC4492 + RFC7027
 */
typedef enum en_gciNamedCurve
{
	/** Invalid Elliptic Curve */
	en_gciNamedCurve_Invalid,
	/** SECT163K1 Elliptic Curve */
	en_gciNamedCurve_SECT163K1,
	/** SECT163R1 Elliptic Curve */
	en_gciNamedCurve_SECT163R1,
	/** SECT163R2 Elliptic Curve */
	en_gciNamedCurve_SECT163R2,
	/** SECT193R1 Elliptic Curve */
	en_gciNamedCurve_SECT193R1,
	/** SECT193R2 Elliptic Curve */
	en_gciNamedCurve_SECT193R2,
	/** SECT233K1 Elliptic Curve */
	en_gciNamedCurve_SECT233K1,
	/** SECT233R1 Elliptic Curve */
	en_gciNamedCurve_SECT233R1,
	/** SECT239K1 Elliptic Curve */
	en_gciNamedCurve_SECT239K1,
	/** SECT283K1 Elliptic Curve */
	en_gciNamedCurve_SECT283K1,
	/** SECT283R1 Elliptic Curve */
	en_gciNamedCurve_SECT283R1,
	/** SECT409K1 Elliptic Curve */
	en_gciNamedCurve_SECT409K1,
	/** SECT409R1 Elliptic Curve */
	en_gciNamedCurve_SECT409R1,
	/** SECT571K1 Elliptic Curve */
	en_gciNamedCurve_SECT571K1,
	/** SECT571R1 Elliptic Curve */
	en_gciNamedCurve_SECT571R1,
	/** SECP160K1 Elliptic Curve */
	en_gciNamedCurve_SECP160K1,
	/** SECP160R1 Elliptic Curve */
	en_gciNamedCurve_SECP160R1,
	/** SECP160R2 Elliptic Curve */
	en_gciNamedCurve_SECP160R2,
	/** SECP192K1 Elliptic Curve */
	en_gciNamedCurve_SECP192K1,
	/** SECP192R1 (SECG) / PRIME192V1 (ANSI X9.62) Elliptic Curve */
	en_gciNamedCurve_SECP192R1,
	/** SECP224K1 Elliptic Curve */
	en_gciNamedCurve_SECP224K1,
	/** SECP224R1 Elliptic Curve */
	en_gciNamedCurve_SECP224R1,
	/** SECP256K1 Elliptic Curve */
	en_gciNamedCurve_SECP256K1,
	/** SECP256R1 (SECG) / PRIME256V1 (ANSI X9.62) Elliptic Curve */
	en_gciNamedCurve_SECP256R1,
	/** SECP384R1 Elliptic Curve */
	en_gciNamedCurve_SECP384R1,
	/** SECP521R1 Elliptic Curve */
	en_gciNamedCurve_SECP521R1,
	/** BRAINPOOLP256R1 Elliptic Curve */
	en_gciNamedCurve_BRAINPOOLP256R1,
	/** BRAINPOOLP384R1 Elliptic Curve */
	en_gciNamedCurve_BRAINPOOLP384R1,
	/** BRAINPOOLP512R1 Elliptic Curve */
	en_gciNamedCurve_BRAINPOOLP512R1
} en_gciNamedCurve_t;



/**
 * \struct 					st_gciEcDomainParam
 * \brief					Structure of the EC domain parameters to create an eventual EC
  */
typedef struct st_gciEcDomainParam
{
	/**Coefficient a*/
	st_gciBigInt_t a;
	/**Coefficient b*/
	st_gciBigInt_t b;
	/**Generator*/
	st_gciEcPoint_t g;
	/**Prime number group*/
	st_gciBigInt_t p;
	/**EC group*/
	st_gciBigInt_t N;
	/**Subgroup of EC group generated by g (generator)*/
	st_gciBigInt_t h;
} st_gciEcDomainParam_t;



/**********************************************************************************************************************/
/*		      										SIGNATURE	 				      							  	  */
/**********************************************************************************************************************/

/**
 * \enum 					en_gciSignAlgo
 * \brief					Enumeration for Signature algorithms
 */
typedef enum en_gciSignAlgo
{
	/** Invalid signature */
	en_gciSignAlgo_Invalid,
	/** RSA signature */
	en_gciSignAlgo_RSA,
	/** DSA signature */
	en_gciSignAlgo_DSA,
	/** ECDSA signature */
	en_gciSignAlgo_ECDSA,
	/** ISO9797 ALG1 signature */
	en_gciSignAlgo_MAC_ISO9797_ALG1,
	/** ISO9797 ALG3 signature */
	en_gciSignAlgo_MAC_ISO9797_ALG3,
	/** CMAC AES signature */
	en_gciSignAlgo_CMAC_AES,
	/** HMAC signature */
	en_gciSignAlgo_HMAC,
	/** RSA SSA PSS signature */
	en_gciSignAlgo_RSASSA_PSS,
	/** RSA SSA PKCS signature */
	en_gciSignAlgo_RSASSA_PKCS,
	/** RSA SSA X509 signature */
	en_gciSignAlgo_RSASSA_X509,
	/** ECDSA GFP signature */
	en_gciSignAlgo_ECDSA_GFP,
	/** ECDSA GF2M signature */
	en_gciSignAlgo_ECDSA_GF2M,
	/**No algorithm signature*/
	en_gciSignAlgo_None = 0xFF
} en_gciSignAlgo_t;



/**
 * \struct 					st_gciSignRsaConfig
 * \brief					Structure for the configuration of a RSA signature
 */
typedef struct st_gciSignRsaConfig
{
	/**
	 * en_gciPadding_Invalid
	 * en_gciPadding_ISO9797
	 * en_gciPadding_PKCS1
	 * en_gciPadding_PKCS5
	 * en_gciPadding_PKCS7
	 * en_gciPadding_None=0xFF
	 */
	en_gciPadding_t padding;
} st_gciSignRsaConfig_t;



/**
 * \struct 					st_gciSignCmacConfig
 * \brief					Structure for the configuration of a CMAC signature
 */
typedef struct st_gciSignCmacConfig
{

	/**
	 * en_gciBlockMode_Invalid
	 * en_gciBlockMode_CBC
	 * en_gciBlockMode_ECB
	 * en_gciBlockMode_CFB
	 * en_gciBlockMode_OFB
	 * en_gciBlockMode_GCM
	 * en_gciBlockMode_None=0xFF
	 */
	en_gciBlockMode_t block;

	/**
	 * en_gciPadding_Invalid
	 * en_gciPadding_ISO9797
	 * en_gciPadding_PKCS1
	 * en_gciPadding_PKCS5
	 * en_gciPadding_PKCS7
	 * en_gciPadding_None=0xFF
	 */
	en_gciPadding_t padding;

	/**Initialization vector (IV) */
	st_gciBuffer_t iv;
} st_gciSignCmacConfig_t;



/**
 * \struct 					st_gciSignConfig
 * \brief					Structure for the configuration of a signature
 */
typedef struct st_gciSignConfig
{
	/**
	 * en_gciSignAlgo_Invalid
	 * en_gciSignAlgo_RSA
	 * en_gciSignAlgo_DSA
	 * en_gciSignAlgo_ECDSA
	 * en_gciSignAlgo_MAC_ISO9797_ALG1
	 * en_gciSignAlgo_MAC_ISO9797_ALG3
	 * en_gciSignAlgo_CMAC_AES
	 * en_gciSignAlgo_HMAC
	 * en_gciSignAlgo_RSASSA_PSS
	 * en_gciSignAlgo_RSASSA_PKCS
	 * en_gciSignAlgo_RSASSA_X509
	 * en_gciSignAlgo_ECDSA_GFP
	 * en_gciSignAlgo_ECDSA_GF2M
	 * en_gciSignAlgo_None = 0xFF
	 */
	en_gciSignAlgo_t algo;


	/**
	 * en_gciHashAlgo_Invalid
	 * en_gciHashAlgo_MD5
	 * en_gciHashAlgo_SHA1
	 * en_gciHashAlgo_SHA224
	 * en_gciHashAlgo_SHA256
	 * en_gciHashAlgo_SHA384
	 * en_gciHashAlgo_SHA512
	 * en_gciHashAlgo_None=0xFF
	 */
	en_gciHashAlgo_t hash;

	/**
	 * \union 				un_signConfig
	 * \brief				Union for the configuration of each signature
	 */
	union un_signConfig
	{
		/** RSA Configuration */
		st_gciSignRsaConfig_t signConfigRsa;

		/** CMAC Configuration */
		st_gciSignCmacConfig_t signConfigCmac;
	} un_signConfig;
} st_gciSignConfig_t;



/**********************************************************************************************************************/
/*		      										KEY GENERATOR			      							  		  */
/**********************************************************************************************************************/

/**
 * \enum 					en_gciKeyPairType
 * \brief					Enumeration for all type of key pair algorithm
 */
typedef enum en_gciKeyPairType
{
	/**Invalid key pair*/
	en_gciKeyPairType_Invalid,
	/**RSA key pair*/
	en_gciKeyPairType_RSA,
	/**RSA key pair - sign*/
	en_gciKeyPairType_RSA_SSA,
	/**RSA key pair - encrypt*/
	en_gciKeyPairType_RSA_ES,
	/**DH key pair */
	en_gciKeyPairType_DH,
	/**ECDH key pair */
	en_gciKeyPairType_ECDH,
	/**DSA key pair*/
	en_gciKeyPairType_DSA,
	/**EC DSA key pair*/
	en_gciKeyPairType_ECDSA,
	/**No key pair */
	en_gciKeyPairType_None=0xFF
} en_gciKeyPairType_t;



/**
 * \struct 					st_gciRsaKeyGenConfig
 * \brief					Structure holding the configuration parameters for an RSA key generation operation
 */
typedef struct st_gciRsaKeyGenConfig
{
    /** Length of the modulus to generate (in bits) */
	size_t modulusLen;
} st_gciRsaKeyGenConfig_t;



/**
 * \struct 					st_gciKeyPairConfig_t
 * \brief					Structure for the configuration of all key pair type
 */
typedef struct st_gciKeyPairConfig_t
{
	/**
	 * en_gciKeyPairType_Invalid
	 * en_gciKeyPairType_RSA
	 * en_gciKeyPairType_RSA_SSA
	 * en_gciKeyPairType_RSA_ES
	 * en_gciKeyPairType_DH
	 * en_gciKeyPairType_ECDH
	 * en_gciKeyPairType_DSA
	 * en_gciKeyPairType_ECDSA
	 * en_gciKeyPairType_None=0xFF
	 */
	en_gciKeyPairType_t keyType;

	/**
	 * union 				un_keyPairParam
	 * \brief				Union for all type of key pair configuration
	 */
	union un_keyPairParam
	{
		/**RSA modulus length configuration*/
		st_gciRsaKeyGenConfig_t* keyPairParamRsa;

		/**
		 * en_gciNamedCurve_Invalid
		 * en_gciNamedCurve_SECT163K1
		 * en_gciNamedCurve_SECT163R1
		 * en_gciNamedCurve_SECT163R2
		 * en_gciNamedCurve_SECT193R1
		 * en_gciNamedCurve_SECT193R2
		 * en_gciNamedCurve_SECT233K1
		 * en_gciNamedCurve_SECT233R1
		 * en_gciNamedCurve_SECT239K1
		 * en_gciNamedCurve_SECT283K1
		 * en_gciNamedCurve_SECT283R1
		 * en_gciNamedCurve_SECT409K1
		 * en_gciNamedCurve_SECT409R1
		 * en_gciNamedCurve_SECT571K1
		 * en_gciNamedCurve_SECT571R1
		 * en_gciNamedCurve_SECP160K1
		 * en_gciNamedCurve_SECP160R1
		 * en_gciNamedCurve_SECP160R2
		 * en_gciNamedCurve_SECP192K1
		 * en_gciNamedCurve_SECP192R1
		 * en_gciNamedCurve_SECP224K1
		 * en_gciNamedCurve_SECP224R1
		 * en_gciNamedCurve_SECP256K1
		 * en_gciNamedCurve_SECP256R1
		 * en_gciNamedCurve_SECP384R1
		 * en_gciNamedCurve_SECP521R1
		 * en_gciNamedCurve_BRAINPOOLP256R1
		 * en_gciNamedCurve_BRAINPOOLP384R1
		 * en_gciNamedCurve_BRAINPOOLP512R1
		 */
		en_gciNamedCurve_t* keyPairParamEcdsa;

		/**DSA domain parameter configuration*/
		st_gciDsaDomainParam_t* keyPairParamDsa;
	}un_keyPairParam;

} st_gciKeyPairConfig_t;



/**********************************************************************************************************************/
/*		      										Diffie-Hellman	Key Generator     							  	  */
/**********************************************************************************************************************/

/**
 * \enum 					en_gciDhType
 * \brief					Enumeration of the Diffie-Hellman type
 */
typedef enum en_gciDhType
{
	/**Invalid Diffie-Hellman*/
	en_gciDhType_Invalid,
	/**Diffie Hellman*/
	en_gciDhType_Dh,
	/**Elliptic curve Diffie-Helmann*/
	en_gciDhType_Ecdh
} en_gciDhType_t;



/**
 * \struct 					st_gciDhConfig
 * \brief					Structure for the configuration of all Diffie-Hellman key pair type
 */
typedef struct st_gciDhConfig
{
	/**
	 * en_gciDhType_Invalid
	 * en_gciDhType_Dh
	 * en_gciDhType_Ecdh
	 */
	en_gciDhType_t type;


	/**
	 * union 				un_dhParam
	 * \brief				Union for all type of Diffie-Hellman parameters
	 */
	union un_dhParam
	{
		/**Diffie-Hellman domain parameters configuration*/
		st_gciDhDomainParam_t* dhParamDomain;

		/**
		 * en_gciNamedCurve_Invalid
		 * en_gciNamedCurve_SECT163K1
		 * en_gciNamedCurve_SECT163R1
		 * en_gciNamedCurve_SECT163R2
		 * en_gciNamedCurve_SECT193R1
		 * en_gciNamedCurve_SECT193R2
		 * en_gciNamedCurve_SECT233K1
		 * en_gciNamedCurve_SECT233R1
		 * en_gciNamedCurve_SECT239K1
		 * en_gciNamedCurve_SECT283K1
		 * en_gciNamedCurve_SECT283R1
		 * en_gciNamedCurve_SECT409K1
		 * en_gciNamedCurve_SECT409R1
		 * en_gciNamedCurve_SECT571K1
		 * en_gciNamedCurve_SECT571R1
		 * en_gciNamedCurve_SECP160K1
		 * en_gciNamedCurve_SECP160R1
		 * en_gciNamedCurve_SECP160R2
		 * en_gciNamedCurve_SECP192K1
		 * en_gciNamedCurve_SECP192R1
		 * en_gciNamedCurve_SECP224K1
		 * en_gciNamedCurve_SECP224R1
		 * en_gciNamedCurve_SECP256K1
		 * en_gciNamedCurve_SECP256R1
		 * en_gciNamedCurve_SECP384R1
		 * en_gciNamedCurve_SECP521R1
		 * en_gciNamedCurve_BRAINPOOLP256R1
		 * en_gciNamedCurve_BRAINPOOLP384R1
		 * en_gciNamedCurve_BRAINPOOLP512R1
		 */
		en_gciNamedCurve_t* dhParamCurveName;
	} un_dhParam;
} st_gciDhConfig_t;



/**********************************************************************************************************************/
/*		      										KEYS						      							  	  */
/**********************************************************************************************************************/

/**
 * \struct 					st_gciRsaPubKey_t
 * \brief					Structure representing a RSA public key
 */
typedef struct st_gciRsaPubKey_t
{
	/**Prime number*/
	st_gciBigInt_t n;
	/**Public exponent*/
	st_gciBigInt_t e;
}st_gciRsaPubKey_t;


/**
 * \struct 					st_gciRsaCrtPrivKey
 * \brief					Structure representing a RSA CRT private key
 */
typedef struct st_gciRsaCrtPrivKey
{
	/**First prime number p*/
	st_gciBigInt_t p;
	/**Second prime number q*/
	st_gciBigInt_t q;
	/**dP = d mod (p-1)*/
	st_gciBigInt_t dP;
	/**dQ = d mod (q-1)*/
	st_gciBigInt_t dQ;
	/**qInv = q^-1 mod p*/
	st_gciBigInt_t qInv;
} st_gciRsaCrtPrivKey_t;



/**
 * \struct 					st_gciRsaPrivKey
 * \brief					Structure representing a RSA private key
 */
typedef struct st_gciRsaPrivKey
{
	/**Prime number*/
	st_gciBigInt_t n;
	/**Private exponent*/
	st_gciBigInt_t d;
	/**Private CRT*/
	st_gciRsaCrtPrivKey_t* crt;
} st_gciRsaPrivKey_t;



/**
 * \struct 					st_gciDsaKey
 * \brief					Structure representing a DSA key (public or private)
 */
typedef struct st_gciDsaKey
{
	/**DSA domain parameters*/
	st_gciDsaDomainParam_t* param;
	/**Big number of the key*/
	st_gciBigInt_t key;
}st_gciDsaKey_t;



/**
 * \struct 					st_gciDhKey
 * \brief					Structure representing a DH key (public or private)
 */
typedef struct st_gciDhKey
{
	/**Diffie-Hellman domain parameters*/
	st_gciDhDomainParam_t* param;
	/**Big number of the key*/
	st_gciBigInt_t key;
}st_gciDhKey_t;



/**
 * \struct 					st_gciEcdhPubKey
 * \brief					Structure representing a ECDH public key
 */
typedef struct st_gciEcdhPubKey
{
	/**
	 * en_gciNamedCurve_Invalid
	 * en_gciNamedCurve_SECT163K1
	 * en_gciNamedCurve_SECT163R1
	 * en_gciNamedCurve_SECT163R2
	 * en_gciNamedCurve_SECT193R1
	 * en_gciNamedCurve_SECT193R2
	 * en_gciNamedCurve_SECT233K1
	 * en_gciNamedCurve_SECT233R1
	 * en_gciNamedCurve_SECT239K1
	 * en_gciNamedCurve_SECT283K1
	 * en_gciNamedCurve_SECT283R1
	 * en_gciNamedCurve_SECT409K1
	 * en_gciNamedCurve_SECT409R1
	 * en_gciNamedCurve_SECT571K1
	 * en_gciNamedCurve_SECT571R1
	 * en_gciNamedCurve_SECP160K1
	 * en_gciNamedCurve_SECP160R1
	 * en_gciNamedCurve_SECP160R2
	 * en_gciNamedCurve_SECP192K1
	 * en_gciNamedCurve_SECP192R1
	 * en_gciNamedCurve_SECP224K1
	 * en_gciNamedCurve_SECP224R1
	 * en_gciNamedCurve_SECP256K1
	 * en_gciNamedCurve_SECP256R1
	 * en_gciNamedCurve_SECP384R1
	 * en_gciNamedCurve_SECP521R1
	 * en_gciNamedCurve_BRAINPOOLP256R1
	 * en_gciNamedCurve_BRAINPOOLP384R1
	 * en_gciNamedCurve_BRAINPOOLP512R1
	 */
	en_gciNamedCurve_t* curve;
	/**coordinate (x,y) of the curve*/
	st_gciEcPoint_t coord;
}st_gciEcdhPubKey_t;



/**
 * \struct 					st_gciEcdhPrivKey
 * \brief					Structure representing a ECDH priv key
 */
typedef struct st_gciEcdhPrivKey
{
	/**
	 * en_gciNamedCurve_Invalid
	 * en_gciNamedCurve_SECT163K1
	 * en_gciNamedCurve_SECT163R1
	 * en_gciNamedCurve_SECT163R2
	 * en_gciNamedCurve_SECT193R1
	 * en_gciNamedCurve_SECT193R2
	 * en_gciNamedCurve_SECT233K1
	 * en_gciNamedCurve_SECT233R1
	 * en_gciNamedCurve_SECT239K1
	 * en_gciNamedCurve_SECT283K1
	 * en_gciNamedCurve_SECT283R1
	 * en_gciNamedCurve_SECT409K1
	 * en_gciNamedCurve_SECT409R1
	 * en_gciNamedCurve_SECT571K1
	 * en_gciNamedCurve_SECT571R1
	 * en_gciNamedCurve_SECP160K1
	 * en_gciNamedCurve_SECP160R1
	 * en_gciNamedCurve_SECP160R2
	 * en_gciNamedCurve_SECP192K1
	 * en_gciNamedCurve_SECP192R1
	 * en_gciNamedCurve_SECP224K1
	 * en_gciNamedCurve_SECP224R1
	 * en_gciNamedCurve_SECP256K1
	 * en_gciNamedCurve_SECP256R1
	 * en_gciNamedCurve_SECP384R1
	 * en_gciNamedCurve_SECP521R1
	 * en_gciNamedCurve_BRAINPOOLP256R1
	 * en_gciNamedCurve_BRAINPOOLP384R1
	 * en_gciNamedCurve_BRAINPOOLP512R1
	 */
	en_gciNamedCurve_t* curve;
	/**Big number of the key*/
	st_gciBigInt_t key;
}st_gciEcdhPrivKey_t;



/**
 * \struct 					st_gciEcdsaPubKey
 * \brief					Structure representing a ECDSA public key
 */
typedef struct st_gciEcdsaPubKey
{
	/**
	 * en_gciNamedCurve_Invalid
	 * en_gciNamedCurve_SECT163K1
	 * en_gciNamedCurve_SECT163R1
	 * en_gciNamedCurve_SECT163R2
	 * en_gciNamedCurve_SECT193R1
	 * en_gciNamedCurve_SECT193R2
	 * en_gciNamedCurve_SECT233K1
	 * en_gciNamedCurve_SECT233R1
	 * en_gciNamedCurve_SECT239K1
	 * en_gciNamedCurve_SECT283K1
	 * en_gciNamedCurve_SECT283R1
	 * en_gciNamedCurve_SECT409K1
	 * en_gciNamedCurve_SECT409R1
	 * en_gciNamedCurve_SECT571K1
	 * en_gciNamedCurve_SECT571R1
	 * en_gciNamedCurve_SECP160K1
	 * en_gciNamedCurve_SECP160R1
	 * en_gciNamedCurve_SECP160R2
	 * en_gciNamedCurve_SECP192K1
	 * en_gciNamedCurve_SECP192R1
	 * en_gciNamedCurve_SECP224K1
	 * en_gciNamedCurve_SECP224R1
	 * en_gciNamedCurve_SECP256K1
	 * en_gciNamedCurve_SECP256R1
	 * en_gciNamedCurve_SECP384R1
	 * en_gciNamedCurve_SECP521R1
	 * en_gciNamedCurve_BRAINPOOLP256R1
	 * en_gciNamedCurve_BRAINPOOLP384R1
	 * en_gciNamedCurve_BRAINPOOLP512R1
	 */
	en_gciNamedCurve_t* curve;
	/**coordinate (x,y) of the curve*/
	st_gciEcPoint_t coord;
} st_gciEcdsaPubKey_t;



/**
 * \struct 					st_gciEcdsaPrivKey
 * \brief					Structure representing a ECDSA private key
 */
typedef struct st_gciEcdsaPrivKey
{
	/**
	 * en_gciNamedCurve_Invalid
	 * en_gciNamedCurve_SECT163K1
	 * en_gciNamedCurve_SECT163R1
	 * en_gciNamedCurve_SECT163R2
	 * en_gciNamedCurve_SECT193R1
	 * en_gciNamedCurve_SECT193R2
	 * en_gciNamedCurve_SECT233K1
	 * en_gciNamedCurve_SECT233R1
	 * en_gciNamedCurve_SECT239K1
	 * en_gciNamedCurve_SECT283K1
	 * en_gciNamedCurve_SECT283R1
	 * en_gciNamedCurve_SECT409K1
	 * en_gciNamedCurve_SECT409R1
	 * en_gciNamedCurve_SECT571K1
	 * en_gciNamedCurve_SECT571R1
	 * en_gciNamedCurve_SECP160K1
	 * en_gciNamedCurve_SECP160R1
	 * en_gciNamedCurve_SECP160R2
	 * en_gciNamedCurve_SECP192K1
	 * en_gciNamedCurve_SECP192R1
	 * en_gciNamedCurve_SECP224K1
	 * en_gciNamedCurve_SECP224R1
	 * en_gciNamedCurve_SECP256K1
	 * en_gciNamedCurve_SECP256R1
	 * en_gciNamedCurve_SECP384R1
	 * en_gciNamedCurve_SECP521R1
	 * en_gciNamedCurve_BRAINPOOLP256R1
	 * en_gciNamedCurve_BRAINPOOLP384R1
	 * en_gciNamedCurve_BRAINPOOLP512R1
	 */
	en_gciNamedCurve_t* curve;
	/**Big number of the key*/
	st_gciBigInt_t un_key;
}st_gciEcdsaPrivKey_t;



/**
 * \enum 					en_gciKeyType
 * \brief					Enumeration for all type of key
 */
typedef enum en_gciKeyType
{
	/** Invalid key */
	en_gciKeyType_Invalid,
	/** Symmetric key */
	en_gciKeyType_Sym,
	/** Diffie-Hellman public key */
	en_gciKeyType_DhPub,
	/** Diffie-Hellman private key */
	en_gciKeyType_DhPriv,
	/** Diffie-Hellman shared secret key */
	en_gciKeyType_DhSecret,
	/** Elliptic Curve Diffie-Hellman public key */
	en_gciKeyType_EcdhPub,
	/** Elliptic Curve Diffie-Hellman private key */
	en_gciKeyType_EcdhPriv,
	/** Elliptic Curve Diffie-Hellman shared secret key */
	en_gciKeyType_EcdhSecret,
	/** DSA public key */
	en_gciKeyType_DsaPub,
	/** DSA private key */
	en_gciKeyType_DsaPriv,
	/** ECDSA public key */
	en_gciKeyType_EcdsaPub,
	/** ECDSA private key */
	en_gciKeyType_EcdsaPriv,
	/** RSA public key - general */
	en_gciKeyType_RsaPub,
	/** RSA private key - general */
	en_gciKeyType_RsaPriv,
	/** RSA public key - signing */
	en_gciKeyType_RsaPubSsa,
	/** RSA private key - signing */
	en_gciKeyType_RsaPrivSsa,
	/** RSA public key - encrypt */
	en_gciKeyType_RsaPubEs,
	/** RSA private key - encrypt */
	en_gciKeyType_RsaPrivEs,
	/** HMAC key */
	en_gciKeyType_Hmac,
	/** No key */
	en_gciKeyType_None=0xFF
} en_gciKeyType_t;



/**
 * \struct 					st_gciKey
 * \brief					Structure for the parameters to each key object
 */
typedef struct st_gciKey
{
	/**
	 * en_gciKeyType_Invalid
	 * en_gciKeyType_Sym
	 * en_gciKeyType_DhPub
	 * en_gciKeyType_DhPriv
	 * en_gciKeyType_DhSecret
	 * en_gciKeyType_EcdhPub
	 * en_gciKeyType_EcdhPriv
	 * en_gciKeyType_EcdhSecret
	 * en_gciKeyType_DsaPub
	 * en_gciKeyType_DsaPriv
	 * en_gciKeyType_EcdsaPub
	 * en_gciKeyType_EcdsaPriv
	 * en_gciKeyType_RsaPub
	 * en_gciKeyType_RsaPriv
	 * en_gciKeyType_RsaPubSsa
	 * en_gciKeyType_RsaPrivSsa
	 * en_gciKeyType_RsaPubEs
	 * en_gciKeyType_RsaPrivEs
	 * en_gciKeyType_Hmac
	 * en_gciKeyType_None=0xFF
	 */
	en_gciKeyType_t type;

   /**
	* union 					un_keyData
	* \brief					Union for the key/key-pair data of each key
	*/
	union un_key
	{
		/** Symmetric key */
		st_gciBuffer_t keysym;
		/** Diffie-Hellman Public Key*/
		st_gciDhKey_t keyDhPub;
		/**Diffie-Hellman Private Key*/
		st_gciDhKey_t keyDhPriv;
		/** Diffie-Hellman Secret Key*/
		st_gciBuffer_t keyDhSecret;
		/** Elliptic Curve Diffie-Hellman Public Key*/
		st_gciEcdhPubKey_t keyEcdhPub;
		/** Elliptic Curve Diffie-Hellman Private Key*/
		st_gciEcdhPrivKey_t keyEcdhPriv;
		/** Elliptic Curve Diffie-Hellman Secret Key*/
		st_gciBuffer_t keyEcdhSecret;
		/** DSA Public Key*/
		st_gciDsaKey_t keyDsaPub;
		/** DSA Private Key*/
		st_gciDsaKey_t keyDsaPriv;
		/** Elliptic Curve DSA Public Key*/
		st_gciEcdsaPubKey_t keyEcdsaPub;
		/** Elliptic Curve DSA Private Key*/
		st_gciEcdsaPrivKey_t keyEcdsaPriv;
		/** RSA Public Key*/
		st_gciRsaPubKey_t keyRsaPub;
		/** RSA Private Key*/
		st_gciRsaPrivKey_t keyRsaPriv;
	} un_key;
} st_gciKey_t;


/*----------------------------------------------Functions Definitions--------------------------------------------------------*/




#endif
/*-------------------------------------------------------EOF-----------------------------------------------------------------*/
