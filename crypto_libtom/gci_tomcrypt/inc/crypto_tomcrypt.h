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
#include "crypto_iface.h"
#include "tommath.h"
#include "tomcrypt.h"





/*-------------------------------------------------Definitions-----------------------------------------------------------*/
/** Debug */
#define TC_DBG

/** Default size for a Diffie-Hellmann Ephemeral key */
#define TC_DEFAULT_DHE_KEYSIZE     192



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



#endif /* CRYPTO_DEV_H_ */
