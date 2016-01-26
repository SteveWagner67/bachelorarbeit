/**
 * \file 				crypto_tomcrypt.h
 * \brief 				principals functions of the development of the new interface with tomcrypt library(Generic Crypto Interface)
 * \author				Steve Wagner
 * \date 				02/11/2015
 */

#ifndef CRYPTO_DEV_H_
#define CRYPTO_DEV_H_

/*--------------------------------------------------Include--------------------------------------------------------------*/
#define DESC_DEF_ONLY
#define AES_AND_3DES_ENABLED
#include "netGlobal.h"
#include "crypto_iface.h"

#include "tomcrypt.h"
#include "tommath.h"





/*-------------------------------------------------Definitions-----------------------------------------------------------*/
/** Debug */
#define TC_DBG

/** Maximal size in bits of symmetric key */
#define TC_SYM_KEY_SIZE_MAX_BITS            512

/** Maximal size in bytes of a symmetric key */
#define TC_SYM_KEY_SIZE_MAX_BYTES           (TC_SYM_KEY_SIZE_MAX_BITS / 8)

/** Size in bits of a Diffie-Hellmann key */
#define TC_DH_KEY_SIZE_MAX_BITS             1024

/** Size in bytes of a Diffie-Hellmann key */
#define TC_DH_KEY_SIZE_MAX_BYTES        192

/** Size in bits of the RSA key */
#define TC_RSA_KEY_SIZE_MAX_BITS            1024

/** Size in bytes of the RSA key */
#define TC_RSA_KEY_SIZE_MAX_BYTES           (TC_RSA_KEY_SIZE_MAX_BITS / 8)

/** Size in bits of the DSA key */
#define TC_DSA_KEY_SIZE_MAX_BITS            1024

/** Size in bytes of the DSA key */
#define TC_DSA_KEY_SIZE_MAX_BYTES           (TC_DSA_KEY_SIZE_MAX_BITS / 8)

/** Size in bytes of the ECDH key */
#define TC_ECDH_KEY_SIZE_MAX_BYTES          66

/** Size in bits of the ECDSA key */
#define TC_ECDSA_KEY_SIZE_MAX_BITS          512

/** Size in bytes of the ECDSA key */
#define TC_ECDSA_KEY_SIZE_MAX_BYTES         (TC_ECDSA_KEY_SIZE_MAX_BITS / 8)



/*----------------------------------------------Type Definitions--------------------------------------------------------*/

/**********************************************************************************************************************/
/*		      										CONTEXT			 				      							  */
/**********************************************************************************************************************/

/*!
 * \enum 					en_tcCtxType
 * \brief					Enumeration for all type of data that could be store in the context's array
 */
typedef enum en_tcCtxType
{
	/** Invalid context type */
	en_tcCtxType_Invalid,
	/** Hash context type*/
	en_tcCtxType_Hash,
	/** Signature Generation context type */
	en_tcCtxType_SignGen,
	/** Signature Verification context Type */
	en_tcCtxType_SignVfy,
	/**Cipher context type*/
	en_tcCtxType_Cipher,
	/**Diffie-Hellman context type*/
	en_tcCtxType_Dh
}en_tcCtxType_t;



/*!
 * \struct 					st_tcCtxConfig
 *  \brief					Structure for the configuration of each context
 */
typedef struct st_tcCtxConfig
{
	/**
	 * en_tcCtxType_Invalid
	 * en_tcCtxType_Hash
	 * en_tcCtxType_SignGen
	 * en_tcCtxType_SignVfY
	 * en_tcCtxType_Cipher
	 * en_tcCtxType_Dh
	 */
	en_tcCtxType_t type;

	/*!
	 * union				un_ctxConfig
	 * \brief				Union of the configuration of each context
	 */
	union un_ctxConfig
	{
		/** Configuration of the Hash context */
		en_gciHashAlgo_t ctxConfigHash;
		/** Configuration of the Signature (Generation and Verification) context */
		st_gciSignConfig_t ctxConfigSign;
		/** Configuration of Cipher context */
		st_gciCipherConfig_t ctxConfigCipher;
		/** Configuration of the Diffie-Hellman context */
		st_gciDhConfig_t ctxConfigDh;
	}un_ctxConfig;

	/* The ID of the key uses for the cipher or signature */
	GciKeyId_t keyID;

	/* The second key ID uses for the RSA in cipher (public and private are needed to decrypt) */
	GciKeyId_t secKeyID;

} st_tcCtxConfig_t;

/* TODO sw - This is in dh_static.c but impossible to include the header ... */
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

/*---------------------------------------------Prototype of functions----------------------------------------------*/

/**
 * \fn                          en_gciResult_t tcGetBigNum(const uint8_t* p_data, size_t dataLen, st_gciBigInt_t* p_bigNum)
 * \brief                       Get the big number of a data
 * \param [in]  p_data          Pointer to the data which will be convert the a big number
 * \param [in]  dataLen         Length of the data above
 * \param [out] p_bigNum        Pointer to the big number
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t tcGetBigNum(const uint8_t* p_data, size_t dataLen, st_gciBigInt_t* p_bigNum);


/**
 * \fn                          en_gciResult_t tcImportRsaPrivKey(uint8_t* p_buffer, size_t bufLen, GciKeyId_t* p_rsaPrivKeyID, GciKeyId_t* p_rsaPubKeyID)
 * \brief                       Get the RSA private key from a buffer (certificate)
 * \param [in]  p_data          Pointer to the buffer (certificate)
 * \param [in]  dataLen         Length of the buffer
 * \param [out] p_rsaPrivKeyID  Pointer to ID of the RSA private key
 * \param [out] p_rsaPubKeyID   Pointer to ID of the RSA public key
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t tcImportRsaPrivKey(uint8_t* p_buffer, size_t bufLen, GciKeyId_t* p_rsaPrivKeyID, GciKeyId_t* p_rsaPubKeyID);


#endif /* CRYPTO_DEV_H_ */
