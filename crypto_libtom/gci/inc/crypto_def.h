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
	GCI_NO_ERR,
	/**Overflow of IDs*/
	GCI_ID_OVERFLOW,
	/**Error of hash algorithm*/
	GCI_HASH_ALGO_ERR,
	/**Error in hash initialization*/
	GCI_HASH_INIT_ERR,
	/**Global error*/
	GCI_ERR
} GciResult_t;

//TODO new[16/11/2015]

/*!
 * \enum 					GciInfo_t
 * \brief					Enumeration for informations that should be needed to become during the process
 */
typedef enum
{
	/**Invalid information*/
	INFO_INVALID,
	/**Information of Elliptic Curve Name*/
	INFO_ECNAME
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

//TODO new[24/11/2015]
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
	HASH_ALGO_NONE,
	/** MD5 */
	HASH_ALGO_MD5,
	/** SHA 1 */
	HASH_ALGO_SHA1,
	/** SHA 224 */
	HASH_ALGO_SHA224,
	/** SHA 256 */
	HASH_ALGO_SHA256,
	/** SHA 384 */
	HASH_ALGO_SHA384,
	/** SHA 512 */
	HASH_ALGO_SHA512,
	/** Invalid Hash */
	HASH_ALGO_INVALID = 0xFF,
} GciHashAlgo_t;



/**********************************************************************************************************************/
/*		      										SYMMETRIC CIPHER			      							  	  */
/**********************************************************************************************************************/

//TODO new[16/11/2015]

/*!
 * \enum 					GciBlockMode_t
 * \brief					Enumeration for all block mode
 */
typedef enum
{
	/** Invalid block mode*/
	BLOCK_MODE_INVALID,
	/** No block mode used*/
	BLOCK_MODE_NONE,
	/** ECB mode*/
	BLOCK_MODE_ECB,
	/** CFB mode*/
	BLOCK_MODE_CFB,
	/** OFB mode*/
	BLOCK_MODE_OFB,
	/** CBC mode */
	BLOCK_MODE_CBC,
	/** GCM mode */
	BLOCK_MODE_GCM
} GciBlockMode_t;

//TODO new[16/11/2015]

/*!
 * \enum 					GciPadding_t
 * \brief					Enumeration for all padding
 */
typedef enum
{
	/**Invalid padding*/
	PADDING_INVALID,
	/** None padding */
	PADDING_NONE,
	/** ISO9797 padding */
	PADDING_ISO9797_METHOD2,
	/** PKCS5 padding */
	PADDING_PKCS5,
	/** PKCS7 padding */
	PADDING_PKCS7
} GciPadding_t;

//TODO new[16/11/2015]

/*!
 * \enum 					GciCipherAlgo_t
 * \brief					Enumeration for all symmetric cipher algorithm
 */
typedef enum
{
	/** Cipher type invalid*/
	CIPH_TYPE_INVALID,
	/**No cipher*/
	CIPH_TYPE_NONE,
	/** Stream cipher RC4 */
	CIPH_TYPE_RC4,
	/** Block cipher AES */
	CIPH_TYPE_AES,
	/** Block cipher DES*/
	CIPH_TYPE_DES,
	/** Block cipher Triple DES */
	CIPH_TYPE_TDES
} GciCipherAlgo_t;



/*!
 * \struct 					GciCipherConfig_t
 * \brief					Structure for all symmetric cipher data
 */
typedef struct
{
	/**
	 * CIPH_TYPE_INVALID
	 * CIPH_TYPE_NONE
	 * CIPH_TYPE_RC4
	 * CIPH_TYPE_AES
	 * CIPH_TYPE_DES
	 * CIPH_TYPE_TDES
	 */
	GciCipherAlgo_t algo;

	/**
	 * BLOCK_MODE_INVALID
	 * BLOCK_MODE_NONE
 	 * BLOCK_MODE_ECB
	 * BLOCK_MODE_CFB
	 * BLOCK_MODE_OFB
	 * BLOCK_MODE_CBC
	 * BLOCK_MODE_GCM
 	 */
	GciBlockMode_t blockMode;

	/**
	 * PADDING_INVALID
	 * PADDING_NONE
	 * PADDING_ISO9797_METHOD2
	 * PADDING_PKCS5
	 * PADDING_PKCS7
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

//TODO new[16/11/2015]

/*!
 * \enum 					GciNamedCurve_t
 * \brief					Enumeration of the Elliptic Curve
 */
typedef enum
{
	/**Invalid Elliptic Curve*/
	EC_INVALID,
	/**SECP112R1 Elliptic Curve*/
	EC_SECP112R1,
	/**SECP112R2 Elliptic Curve*/
	EC_SECP112R2,
	/**SECP128R1 Elliptic Curve*/
	EC_SECP128R1,
	/**SECP128R2 Elliptic Curve*/
	EC_SECP128R2,
	/**SECP160R1 Elliptic Curve*/
	EC_SECP160R1,
	/**SECP160R2 Elliptic Curve*/
	EC_SECP160R2,
	/**SECP160K1 Elliptic Curve*/
	EC_SECP160K1,
	/**BRAINPOOLP160R1 Elliptic Curve*/
	EC_BRAINPOOLP160R1,
	/**SECP192R1 Elliptic Curve*/
	EC_SECP192R1,
	/**PRIME192V2 Elliptic Curve*/
	EC_PRIME192V2,
	/**PRIME192V3 Elliptic Curve*/
	EC_PRIME192V3,
	/**SECP192K1 Elliptic Curve*/
	EC_SECP192K1,
	/**BRAINPOOLP192R1 Elliptic Curve*/
	EC_BRAINPOOLP192R1,
	/**SECP224R1 Elliptic Curve*/
	EC_SECP224R1,
	/**SECP224K1 Elliptic Curve*/
	EC_SECP224K1,
	/**BRAINPOOLP224R1 Elliptic Curve*/
	EC_BRAINPOOLP224R1,
	/**PRIME239V1 Elliptic Curve*/
	EC_PRIME239V1,
	/**PRIME239V2 Elliptic Curve*/
	EC_PRIME239V2,
	/**PRIME239V3 Elliptic Curve*/
	EC_PRIME239V3,
	/**SECP256R1 Elliptic Curve*/
	EC_SECP256R1,
	/**SECP256K1 Elliptic Curve*/
	EC_SECP256K1,
	/**BRAINPOOLP256R1 Elliptic Curve*/
	EC_BRAINPOOLP256R1,
	/**BRAINPOOLP320R1 Elliptic Curve*/
	EC_BRAINPOOLP320R1,
	/**SECP384R1 Elliptic Curve*/
	EC_SECP384R1,
	/**BRAINPOOLP384R1 Elliptic Curve*/
	EC_BRAINPOOLP384R1,
	/**BRAINPOOLP512R1 Elliptic Curve*/
	EC_BRAINPOOLP512R1,
	/**SECP521R1 Elliptic Curve*/
	EC_SECP521R1
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

//TODO new[16/11/2015]

/*!
 * \enum 					GciSignAlgo_t
 * \brief					Enumeration for Signature algorithms
 */
typedef enum
{
	/**No algorithm*/
	SIGN_ALGO_NONE,
	/** RSA */
	SIGN_ALGO_RSA,
	/** DSA */
	SIGN_ALGO_DSA,
	/** ECDSA */
	SIGN_ALGO_ECDSA,
	/** ISO9797 ALG1 */
	SIGN_ALGO_MAC_ISO9797_ALG1,
	/** ISO9797 ALG3 */
	SIGN_ALGO_MAC_ISO9797_ALG3,
	/** CMAC AES */
	SIGN_ALGO_CMAC_AES,
	/** HMAC */
	SIGN_ALGO_HMAC,
	/** RSA SSA PSS */
	SIGN_ALGO_RSASSA_PSS,
	/** RSA SSA PKCS */
	SIGN_ALGO_RSASSA_PKCS,
	/** RSA SSA X509 */
	SIGN_ALGO_RSASSA_X509,
	/** ECDSA GFP */
	SIGN_ALGO_ECDSA_GFP,
	/** ECDSA GF2M */
	SIGN_ALGO_ECDSA_GF2M,
	/**Invalid signature*/
	SIGN_ALGO_INVALID = 0xFF
} GciSignAlgo_t;



/*!
 * \struct 					GciSignCmacConfig_t
 * \brief					Structure for the configuration of a CMAC signature
 */
typedef struct
{

	/**
	 * BLOCK_MODE_INVALID
	 * BLOCK_MODE_NONE
	 * BLOCK_MODE_ECB
	 * BLOCK_MODE_CFB
	 * BLOCK_MODE_OFB
	 * BLOCK_MODE_CBC
	 * BLOCK_MODE_GCM
	 */
	GciBlockMode_t block;

	/**
	 * PADDING_INVALID
	 * PADDING_NONE
	 * PADDING_ISO9797_METHOD2
	 * PADDING_PKCS5
	 * PADDING_PKCS7
	 */
	GciPadding_t padding;

	/**Initialization vector (IV) */
	GciBuffer_t iv;
} GciSignCmacConfig_t;


/*!
 * \struct 					GciSignHmacConfig_t
 * \brief					Structure for the configuration of a HMAC signature
 */
typedef struct
{
	/**
	 * HASH_ALGO_NONE
	 * HASH_ALGO_MD5
	 * HASH_ALGO_SHA1
	 * HASH_ALGO_SHA224
	 * HASH_ALGO_SHA256
	 * HASH_ALGO_SHA384
	 * HASH_ALGO_SHA512
	 * HASH_INVALID
	 */
	GciHashAlgo_t hash;

} GciSignHmacConfig_t;



/*!
 * \struct 					GciSignRsassaConfig_t
 * \brief					Structure for the configuration of a RSASSA signature
 */
typedef struct
{
	/**
	 * HASH_ALGO_NONE
	 * HASH_ALGO_MD5
	 * HASH_ALGO_SHA1
	 * HASH_ALGO_SHA224
	 * HASH_ALGO_SHA256
	 * HASH_ALGO_SHA384
	 * HASH_ALGO_SHA512
	 * HASH_INVALID
	 */
	GciHashAlgo_t hash;
} GciSignRsassaConfig_t;



/*!
 * \struct 					GciSignDsaConfig_t
 * \brief					Structure for the configuration of a DSA signature
 */
typedef struct
{
	/**
	 * HASH_ALGO_NONE
	 * HASH_ALGO_MD5
	 * HASH_ALGO_SHA1
	 * HASH_ALGO_SHA224
	 * HASH_ALGO_SHA256
	 * HASH_ALGO_SHA384
	 * HASH_ALGO_SHA512
	 * HASH_INVALID
	 */
	GciHashAlgo_t hash;

	/**ECDSA domain parameters*/
	GciDsaDomainParam_t param;
} GciSignDsaConfig_t;



/*!
 * \struct 					GciSignEcdsaConfig_t
 * \brief					Structure for the configuration of an ECDSA signature
 */
typedef struct
{
	/**
	 * HASH_ALGO_NONE
	 * HASH_ALGO_MD5
	 * HASH_ALGO_SHA1
	 * HASH_ALGO_SHA224
	 * HASH_ALGO_SHA256
	 * HASH_ALGO_SHA384
	 * HASH_ALGO_SHA512
	 * HASH_INVALID
	 */
	GciHashAlgo_t hash;


	/*!
	 * EC_INVALID
	 * EC_SECP112R1
	 * EC_SECP112R2
	 * EC_SECP128R1
	 * EC_SECP128R2
	 * EC_SECP160R1
	 * EC_SECP160R2
	 * EC_SECP160K1
	 * EC_BRAINPOOLP160R1
	 * EC_SECP192R1
	 * EC_PRIME192V2
	 * EC_PRIME192V3
	 * EC_SECP192K1
	 * EC_BRAINPOOLP192R1
	 * EC_SECP224R1
	 * EC_SECP224K1
	 * EC_BRAINPOOLP224R1
	 * EC_PRIME239V1
	 * EC_PRIME239V2
	 * EC_PRIME239V3
	 * EC_SECP256R1
	 * EC_SECP256K1
	 * EC_BRAINPOOLP256R1
	 * EC_BRAINPOOLP320R1
	 * EC_SECP384R1
	 * EC_BRAINPOOLP384R1
	 * EC_BRAINPOOLP512R1
	 * EC_SECP521R1
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
	 * SIGN_ALGO_NONE
	 * SIGN_ALGO_RSA
	 * SIGN_ALGO_DSA
	 * SIGN_ALGO_ECDSA
	 * SIGN_ALGO_MAC_ISO9797_ALG1
	 * SIGN_ALGO_MAC_ISO9797_ALG3
	 * SIGN_ALGO_CMAC_AES
	 * SIGN_ALGO_HMAC
	 * SIGN_ALGO_RSASSA_PKCS
	 * SIGN_ALGO_RSASSA_PSS
	 * SIGN_ALGO_RSASSA_X509
	 * SIGN_ALGO_DSA
	 * SIGN_ALGO_ECDSA_GFP
	 * SIGN_ALGO_ECDSA_GF2M
	 * SIGN_ALGO_INVALID
	 */
	GciSignAlgo_t algo;

	/**
	 * \union 				signConfig
	 * \brief				Union for the configuration of each signature
	 */
	union signConfig
	{
		/** CMAC Configuration */
		GciSignCmacConfig_t cmac;

		/** HMAC Configuration */
		GciSignHmacConfig_t hmac;

		/** RSA Configuration */
		GciSignRsassaConfig_t rsa;

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
	/**Invalid key pair*/
	KEY_PAIR_INVALID,
	/**RSA key pair*/
	KEY_PAIR_RSA,
	/**DSA key pair*/
	KEY_PAIR_DSA,
	/**EC DSA key pair*/
	KEY_PAIR_ECDSA
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



//TODO new[11/11/2015] - Change of the configuration of each key
/*!
 * \struct 					GciKeyGenConfig_t
 * \brief					Structure for the configuration to generate the key pair
 */
typedef struct
{
	/**
	 * KEY_INVALID
	 * KEY_RSA
	 * KEY_DSA
	 * KEY_ECDSA
	 * KEY_ECDSA
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
		 * EC_INVALID
		 * EC_SECP112R1
		 * EC_SECP112R2
		 * EC_SECP128R1
		 * EC_SECP128R2
		 * EC_SECP160R1
		 * EC_SECP160R2
		 * EC_SECP160K1
		 * EC_BRAINPOOLP160R1
		 * EC_SECP192R1
		 * EC_PRIME192V2
		 * EC_PRIME192V3
		 * EC_SECP192K1
		 * EC_BRAINPOOLP192R1
		 * EC_SECP224R1
		 * EC_SECP224K1
		 * EC_BRAINPOOLP224R1
		 * EC_PRIME239V1
		 * EC_PRIME239V2
		 * EC_PRIME239V3
		 * EC_SECP256R1
		 * EC_SECP256K1
		 * EC_BRAINPOOLP256R1
		 * EC_BRAINPOOLP320R1
		 * EC_SECP384R1
		 * EC_BRAINPOOLP384R1
		 * EC_BRAINPOOLP512R1
		 * EC_SECP521R1
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
	DIFFIE_HELLMAN_INVALID,
	/**Diffie Hellman*/
	DIFFIE_HELLMAN,
	/**Elliptic curve Diffie-Helmann*/
	DIFFIE_HELLMAN_ELLIPTIC_CURVE
} GciDhType_t;



//TODO new[11/11/2015] - Update of the configuration

/*!
 * \struct 					GciDhConfig_t
 * \brief					Structure for the configuration of all Diffie-Hellman key pair type
 */
typedef struct
{
	/**
	 * DIFFIE_HELLMAN_INVALID
	 * DIFFIE_HELLMAN
	 * DIFFIE_HELLMAN_ELLIPTIC_CURVE
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
		 * EC_INVALID
		 * EC_SECP112R1
		 * EC_SECP112R2
		 * EC_SECP128R1
		 * EC_SECP128R2
		 * EC_SECP160R1
		 * EC_SECP160R2
		 * EC_SECP160K1
		 * EC_BRAINPOOLP160R1
		 * EC_SECP192R1
		 * EC_PRIME192V2
		 * EC_PRIME192V3
		 * EC_SECP192K1
		 * EC_BRAINPOOLP192R1
		 * EC_SECP224R1
		 * EC_SECP224K1
		 * EC_BRAINPOOLP224R1
		 * EC_PRIME239V1
		 * EC_PRIME239V2
		 * EC_PRIME239V3
		 * EC_SECP256R1
		 * EC_SECP256K1
		 * EC_BRAINPOOLP256R1
		 * EC_BRAINPOOLP320R1
		 * EC_SECP384R1
		 * EC_BRAINPOOLP384R1
		 * EC_BRAINPOOLP512R1
		 * EC_SECP521R1
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

//TODO new[16/11/2015]

/*!
 * \enum 					GciKeyType_t
 * \brief					Enumeration for all type of key
 */
typedef enum
{
	/**Invalid key*/
	KEY_INVALID,
	/**No key*/
	KEY_NONE,
	/**Symmetric key*/
	KEY_SYM,
	/**Diffie-Hellman public key*/
	KEY_DH_PUB,
	/**Diffie-Hellman private key*/
	KEY_DH_PRIV,
	/**Diffie-Hellman shared secret key*/
	KEY_DH_SECRET,
	/**Elliptic Curve Diffie-Hellman public key*/
	KEY_ECDH_PUB,
	/**Elliptic Curve Diffie-Hellman private key*/
	KEY_ECDH_PRIV,
	/**Elliptic Curve Diffie-Hellman shared secret key*/
	KEY_ECDH_SECRET,
	/**DSA public key*/
	KEY_DSA_PUB,
	/**DSA private key*/
	KEY_DSA_PRIV,
	/**ECDSA public key*/
	KEY_ECDSA_PUB,
	/**ECDSA private key*/
	KEY_ECDSA_PRIV,
	/**RSA public key*/
	KEY_RSA_PUB,
	/**RSA private key*/
	KEY_RSA_PRIV
} GciKeyType_t;


//TODO new[16/11/2015]

/*!
 * \struct 					GciKey_t
 * \brief					Structure for the parameters to each key object
 */
typedef struct
{
	/**
	 * KEY_INVALID
	 * KEY_NONE
	 * KEY_SYM
	 * KEY_DH_PUB
	 * KEY_DH_PRIV
	 * KEY_DH_SECRET
	 * KEY_ECDH_PUB
	 * KEY_ECDH_PRIV
	 * KEY_ECDH_SECRET
	 * KEY_DSA_PUB
	 * KEY_DSA_PRIV
	 * KEY_ECDSA_PUB
	 * KEY_ECDSA_PRIV
	 * KEY_RSA_PUB
	 * KEY_RSA_PRIV
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
