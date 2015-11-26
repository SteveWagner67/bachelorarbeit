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



/*!
 * \enum 					GciHashAlgo_t
 * \brief					Enumeration for Hash algorithms
 */
typedef enum
{
	/** No hash algorithm used */
	GCI_HASH_NONE,
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
	/** Invalid Hash */
	GCI_HASH_INVALID = 0xFF,
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
	/** No block mode used*/
	GCI_BLOCK_MODE_NONE,
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
	/** Invalid block mode*/
	GCI_BLOCK_MODE_INVALID=0xFF
} GciBlockMode_t;



/*!
 * \enum 					GciPadding_t
 * \brief					Enumeration for all padding
 */
typedef enum
{
	/** None padding */
	GCI_PADDING_NONE,
	/** ISO9797 padding */
	GCI_PADDING_ISO9797_METHOD2,
	/** PKCS5 padding */
	GCI_PADDING_PKCS5,
	/** PKCS7 padding */
	GCI_PADDING_PKCS7,
	/**Invalid padding*/
	GCI_PADDING_INVALID=0xFF
} GciPadding_t;



/*!
 * \enum 					GciCipherAlgo_t
 * \brief					Enumeration for all symmetric cipher algorithm
 */
typedef enum
{
	/**No cipher*/
	GCI_CIPH_NONE,
	/** Stream cipher RC4 */
	GCI_CIPH_RC4,
	/** Block cipher Triple DES */
	GCI_CIPH_TDES,
	/** Block cipher AES */
	GCI_CIPH_AES,
	/** Block cipher DES*/
	GCI_CIPH_DES,
	/** Cipher type invalid*/
	GCI_CIPH_INVALID=0xFF
} GciCipherAlgo_t;



/*!
 * \struct 					GciCipherConfig_t
 * \brief					Structure for all symmetric cipher data
 */
typedef struct
{
	/**
	 * GCI_CIPH_NONE
	 * GCI_CIPH_RC4
	 * GCI_CIPH_TDES
	 * GCI_CIPH_AES
	 * GCI_CIPH_DES
	 * GCI_CIPH_INVALID=0xFF
	 */
	GciCipherAlgo_t algo;

	/**
	 * GCI_BLOCK_MODE_NONE
	 * GCI_BLOCK_MODE_CBC
 	 * GCI_BLOCK_MODE_ECB
	 * GCI_BLOCK_MODE_CFB
	 * GCI_BLOCK_MODE_OFB
	 * GCI_BLOCK_MODE_GCM
	 * GCI_BLOCK_MODE_INVALID=0xFF
 	 */
	GciBlockMode_t blockMode;

	/**
	 * GCI_PADDING_NONE
	 * GCI_PADDING_ISO9797_METHOD2
	 * GCI_PADDING_PKCS5
	 * GCI_PADDING_PKCS7
	 * GCI_PADDING_INVALID=0xFF
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
 * \struct 					GciGFpDhDomainParam_t
 * \brief					Structure for the Diffie-Hellman domain parameters
 */
typedef struct
{
	/**Prime*/
	GciBigInt_t p;
	/**Generator*/
	GciBigInt_t g;
} GciGFpDhDomainParam_t;



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
 */
typedef enum
{
	/**Invalid Elliptic Curve*/
	GCI_EC_INVALID,
	/**SECP112R1 Elliptic Curve*/
	GCI_EC_SECP112R1,
	/**SECP112R2 Elliptic Curve*/
	GCI_EC_SECP112R2,
	/**SECP128R1 Elliptic Curve*/
	GCI_EC_SECP128R1,
	/**SECP128R2 Elliptic Curve*/
	GCI_EC_SECP128R2,
	/**SECP160R1 Elliptic Curve*/
	GCI_EC_SECP160R1,
	/**SECP160R2 Elliptic Curve*/
	GCI_EC_SECP160R2,
	/**SECP160K1 Elliptic Curve*/
	GCI_EC_SECP160K1,
	/**BRAINPOOLP160R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP160R1,
	/**SECP192R1 Elliptic Curve*/
	GCI_EC_SECP192R1,
	/**PRIME192V2 Elliptic Curve*/
	GCI_EC_PRIME192V2,
	/**PRIME192V3 Elliptic Curve*/
	GCI_EC_PRIME192V3,
	/**SECP192K1 Elliptic Curve*/
	GCI_EC_SECP192K1,
	/**BRAINPOOLP192R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP192R1,
	/**SECP224R1 Elliptic Curve*/
	GCI_EC_SECP224R1,
	/**SECP224K1 Elliptic Curve*/
	GCI_EC_SECP224K1,
	/**BRAINPOOLP224R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP224R1,
	/**PRIME239V1 Elliptic Curve*/
	GCI_EC_PRIME239V1,
	/**PRIME239V2 Elliptic Curve*/
	GCI_EC_PRIME239V2,
	/**PRIME239V3 Elliptic Curve*/
	GCI_EC_PRIME239V3,
	/**SECP256R1 Elliptic Curve*/
	GCI_EC_SECP256R1,
	/**SECP256K1 Elliptic Curve*/
	GCI_EC_SECP256K1,
	/**BRAINPOOLP256R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP256R1,
	/**BRAINPOOLP320R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP320R1,
	/**SECP384R1 Elliptic Curve*/
	GCI_EC_SECP384R1,
	/**BRAINPOOLP384R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP384R1,
	/**BRAINPOOLP512R1 Elliptic Curve*/
	GCI_EC_BRAINPOOLP512R1,
	/**SECP521R1 Elliptic Curve*/
	GCI_EC_SECP521R1,
	/**EC_PRIME256V1 Elliptic Curve*/
	GCI_EC_PRIME256V1
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
	/**No algorithm*/
	GCI_SIGN_NONE,
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
	/**Invalid signature*/
	GCI_SIGN_INVALID = 0xFF
} GciSignAlgo_t;



/*!
 * \struct 					GciSignCmacConfig_t
 * \brief					Structure for the configuration of a CMAC signature
 */
typedef struct
{

	/**
	 * GCI_BLOCK_MODE_NONE
	 * GCI_BLOCK_MODE_CBC
	 * GCI_BLOCK_MODE_ECB
	 * GCI_BLOCK_MODE_CFB
	 * GCI_BLOCK_MODE_OFB
	 * GCI_BLOCK_MODE_GCM
	 * GCI_BLOCK_MODE_INVALID=0xFF
	 */
	GciBlockMode_t block;

	/**
	 * GCI_PADDING_NONE
	 * GCI_PADDING_ISO9797_METHOD2
	 * GCI_PADDING_PKCS5
	 * GCI_PADDING_PKCS7
	 * GCI_PADDING_INVALID=0xFF
	 */
	GciPadding_t padding;

	/**Initialization vector (IV) */
	GciBuffer_t iv;
} GciSignCmacConfig_t;



/*!
 * \struct 					GciSignDsaConfig_t
 * \brief					Structure for the configuration of a DSA signature
 */
typedef struct
{
	/**ECDSA domain parameters*/
	GciDsaDomainParam_t param;
} GciSignDsaConfig_t;



/*!
 * \struct 					GciSignEcdsaConfig_t
 * \brief					Structure for the configuration of an ECDSA signature
 */
typedef struct
{
	/*!
	 * GCI_EC_INVALID
	 * GCI_EC_SECP112R1
	 * GCI_EC_SECP112R2
	 * GCI_EC_SECP128R1
	 * GCI_EC_SECP128R2
	 * GCI_EC_SECP160R1
	 * GCI_EC_SECP160R2
	 * GCI_EC_SECP160K1
	 * GCI_EC_BRAINPOOLP160R1
	 * GCI_EC_SECP192R1
	 * GCI_EC_PRIME192V2
	 * GCI_EC_PRIME192V3
	 * GCI_EC_SECP192K1
	 * GCI_EC_BRAINPOOLP192R1
	 * GCI_EC_SECP224R1
	 * GCI_EC_SECP224K1
	 * GCI_EC_BRAINPOOLP224R1
	 * GCI_EC_PRIME239V1
	 * GCI_EC_PRIME239V2
	 * GCI_EC_PRIME239V3
	 * GCI_EC_SECP256R1
	 * GCI_EC_SECP256K1
	 * GCI_EC_BRAINPOOLP256R1
	 * GCI_EC_BRAINPOOLP320R1
	 * GCI_EC_SECP384R1
	 * GCI_EC_BRAINPOOLP384R1
	 * GCI_EC_BRAINPOOLP512R1
	 * GCI_EC_SECP521R1
	 * GCI_EC_PRIME256V1
	 */
	GciNamedCurve_t name;
} GciSignEcdsaConfig_t;



/*!
 * \struct 					GciSignConfig_t
 * \brief					Structure for the configuration of a signature
 */
typedef struct
{
	/**
	 * GCI_SIGN_NONE
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
	 * GCI_SIGN_DSA
	 * GCI_SIGN_ECDSA_GFP
	 * GCI_SIGN_ECDSA_GF2M
	 * GCI_SIGN_INVALID
	 */
	GciSignAlgo_t algo;


	/**
	 * GCI_HASH_NONE
	 * GCI_HASH_MD5
	 * GCI_HASH_SHA1
	 * GCI_HASH_SHA224
	 * GCI_HASH_SHA256
	 * GCI_HASH_SHA384
	 * GCI_HASH_SHA512
	 * GCI_HASH_INVALID = 0xFF,
	 */

	GciHashAlgo_t hash;

	/**
	 * \union 				signConfig
	 * \brief				Union for the configuration of each signature
	 */
	union signConfig
	{
		/** CMAC Configuration */
		GciSignCmacConfig_t cmac;

		/** DSA Configuration */
		GciSignDsaConfig_t dsa;

		/** EC DSA Configuration */
		GciSignEcdsaConfig_t ecdsa;
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
	/**No key pair */
	GCI_KEY_PAIR_NONE,
	/**RSA key pair*/
	GCI_KEY_PAIR_RSA,
	/**DHE RSA key pair */
	GCI_KEY_PAIR_DHE_RSA,
	/**DHE DSS key pair */
	GCI_KEY_PAIR_DHE_DSS,
	/**ECDHE RSA */
	GCI_KEY_PAIR_ECDHE_RSA,
	/**ECDHE ECDSA */
	GCI_KEY_PAIR_ECDHE_ECDSA,
	/**DSA key pair*/
	GCI_KEY_PAIR_DSA,
	/**EC DSA key pair*/
	GCI_KEY_PAIR_ECDSA,
	/**Invalid key pair*/
	GCI_KEY_PAIR_INVALID=0xFF
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



/*!
 * \struct 					GciKeyGenConfig_t
 * \brief					Structure for the configuration to generate the key pair
 */
typedef struct
{
	/**
	 * GCI_KEY_PAIR_NONE
	 * GCI_KEY_RSA
	 * GCI_KEY_PAIR_DHE_RSA
	 * GCI_KEY_PAIR_DHE_DSS
	 * GCI_KEY_PAIR_ECDHE_RSA
	 * GCI_KEY_PAIR_ECDHE_ECDSA
	 * GCI_KEY_DSA
	 * GCI_KEY_ECDSA
	 * GCI_KEY_INVALID=0xFF
	 */
	GciKeyPairType_t algo;

	/**
	 * union 				keyConfig
	 * \brief				Union for all key pair configuration
	 */
	union keyConfig
	{
        /** RSA key generation parameters */
        GciRsaKeyGenConfig_t rsa;

		/**Digital Signature Algorithm domain parameters configuration*/
		GciDsaDomainParam_t dsa;

		/*!
		 * GCI_EC_INVALID
		 * GCI_EC_SECP112R1
		 * GCI_EC_SECP112R2
		 * GCI_EC_SECP128R1
		 * GCI_EC_SECP128R2
		 * GCI_EC_SECP160R1
		 * GCI_EC_SECP160R2
		 * GCI_EC_SECP160K1
		 * GCI_EC_BRAINPOOLP160R1
		 * GCI_EC_SECP192R1
		 * GCI_EC_PRIME192V2
		 * GCI_EC_PRIME192V3
		 * GCI_EC_SECP192K1
		 * GCI_EC_BRAINPOOLP192R1
		 * GCI_EC_SECP224R1
		 * GCI_EC_SECP224K1
		 * GCI_EC_BRAINPOOLP224R1
		 * GCI_EC_PRIME239V1
		 * GCI_EC_PRIME239V2
		 * GCI_EC_PRIME239V3
		 * GCI_EC_SECP256R1
		 * GCI_EC_SECP256K1
		 * GCI_EC_BRAINPOOLP256R1
		 * GCI_EC_BRAINPOOLP320R1
		 * GCI_EC_SECP384R1
		 * GCI_EC_BRAINPOOLP384R1
		 * GCI_EC_BRAINPOOLP512R1
		 * GCI_EC_SECP521R1
		 * GCI_EC_PRIME256V1
		 */
		GciNamedCurve_t ecdsaCurveName;

	} config;
} GciKeyGenConfig_t;



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



/*!
 * \struct 					GciDhConfig_t
 * \brief					Structure for the configuration of all Diffie-Hellman key pair type
 */
typedef struct
{
	/**
	 * GCI_DH_INVALID
	 * GCI_DH
	 * GCI_ECDH
	 */
	GciDhType_t type;

	/*!
	 * union 				DhConfig
	 * \brief				Union for all type of Diffie-Hellman configuration
	 */
	union DhConfig
	{
		/**Diffie-Hellman domain parameters configuration*/
		GciGFpDhDomainParam_t dhDomain;

		/*!
		 * GCI_EC_INVALID
		 * GCI_EC_SECP112R1
		 * GCI_EC_SECP112R2
		 * GCI_EC_SECP128R1
		 * GCI_EC_SECP128R2
		 * GCI_EC_SECP160R1
		 * GCI_EC_SECP160R2
		 * GCI_EC_SECP160K1
		 * GCI_EC_BRAINPOOLP160R1
		 * GCI_EC_SECP192R1
		 * GCI_EC_PRIME192V2
		 * GCI_EC_PRIME192V3
		 * GCI_EC_SECP192K1
		 * GCI_EC_BRAINPOOLP192R1
		 * GCI_EC_SECP224R1
		 * GCI_EC_SECP224K1
		 * GCI_EC_BRAINPOOLP224R1
		 * GCI_EC_PRIME239V1
		 * GCI_EC_PRIME239V2
		 * GCI_EC_PRIME239V3
		 * GCI_EC_SECP256R1
		 * GCI_EC_SECP256K1
		 * GCI_EC_BRAINPOOLP256R1
		 * GCI_EC_BRAINPOOLP320R1
		 * GCI_EC_SECP384R1
		 * GCI_EC_BRAINPOOLP384R1
		 * GCI_EC_BRAINPOOLP512R1
		 * GCI_EC_SECP521R1
		 * GCI_EC_PRIME256V1
		 */
		GciNamedCurve_t ecdhCurveName;
	} config;
} GciDhConfig_t;


/**********************************************************************************************************************/
/*		      										KEYS						      							  	  */
/**********************************************************************************************************************/


/*!
 * \struct 					GciRsaPubKey_t
 * \brief					Structure representing an RSA public key
 */
typedef struct
{
	/**Prime number*/
	GciBigInt_t n;
	/**Public exponent*/
	GciBigInt_t e;
} GciRsaPubKey_t;



/*!
 * \struct 					GciRsaPrivKey_t
 * \brief					Structure representing an RSA private key
 */
typedef struct
{
	/**Prime number*/
	GciBigInt_t n;
	/**Private exponent*/
	GciBigInt_t d;
} GciRsaPrivKey_t;



/*!
 * \enum 					GciKeyType_t
 * \brief					Enumeration for all type of key
 */
typedef enum
{
	/**No key*/
	GCI_KEY_NONE,
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
	/**RSA public key*/
	GCI_KEY_RSA_PUB,
	/**RSA private key*/
	GCI_KEY_RSA_PRIV,
	/**Invalid key*/
	GCI_KEY_INVALID=0xFF
} GciKeyType_t;



/*!
 * \struct 					GciKey_t
 * \brief					Structure for the parameters to each key object
 */
typedef struct
{
	/**
	 * GCI_KEY_NONE
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
	 * GCI_KEY_INVALID=0xFF
	 */
	GciKeyType_t type;

   /*!
	* union 					keyData
	* \brief					Union for the key/key-pair data of each key
	*/
	union keyData
	{
		/**Symmetric key*/
		GciBuffer_t symKey;
		/**Diffie-Hellman Public Key Object*/
		GciBigInt_t dhPub;
		/**Diffie-Hellman Private Key Object*/
		GciBigInt_t dhPriv;
		/**Diffie-Hellman Secret Key Object*/
		GciBuffer_t dhSecret;
		/**Elliptic Curve Diffie-Hellman Public Key Object*/
		GciEcPoint_t ecdhPub;
		/**Elliptic Curve Diffie-Hellman Private Key Object*/
		GciBigInt_t ecdhPriv;
		/**Elliptic Curve Diffie-Hellman Secret Key Object*/
		GciBuffer_t ecdhSecret;
		/**DSA Public Key Object*/
		GciBigInt_t dsaPub;
		/**DSA Private Key Object*/
		GciBigInt_t dsaPriv;
		/**Elliptic Curve DSA Public Key Object*/
		GciEcPoint_t ecdsaPub;
		/**Elliptic Curve DSA Private Key Object*/
		GciBigInt_t ecdsaPriv;
		/**RSA Public Key Object*/
		GciRsaPubKey_t rsaPub;
		/**RSA Private Key Object*/
		GciRsaPrivKey_t rsaPriv;
	} key;
} GciKey_t;


#endif
