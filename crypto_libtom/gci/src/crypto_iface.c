/**
 * \file 				crypto_iface.c
 * \brief 				see crypto_iface.h
 * \author				Steve Wagner
 * \date 				13/10/2015
 */

/**********************************************************************************************************************/
/*		      										LIBRARIES	 				      							  	  */
/**********************************************************************************************************************/
/** LIB_TOMCRYPT */
/** ... OTHER LIBRARIES*/
#define OTHER LIBRARIES

#ifdef LIB_TOMCRYPT
#include "tomcrypt.h"
#endif

//... OTHER LIBRARIES



/**********************************************************************************************************************/
/*		      										INCLUDE			 				      							  */
/**********************************************************************************************************************/
#include "crypto_iface.h"

/**********************************************************************************************************************/
/*		      										GLOBAL			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_init					*/
/********************************/
GciResult_t gci_init(const uint8_t* user, size_t userLen, const uint8_t* password, size_t passLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_deinit					*/
/********************************/
GciResult_t gci_deinit(void)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_get_info				*/
//********************************/
GciResult_t gci_get_info(GciInfo_t infoType, uint16_t* info, size_t* infoLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/**********************************************************************************************************************/
/*		      										CONTEXT			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_ctx_release				*/
/********************************/
GciResult_t gci_ctx_release(GciCtxId_t ctxID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/**********************************************************************************************************************/
/*		      										HASH			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_hash_new_ctx			*/
/********************************/
GciResult_t gci_hash_new_ctx(GciHashAlgo_t hashAlgo, GciCtxId_t* ctxID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_hash_ctx_clone			*/
/********************************/
GciResult_t gci_hash_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_hash_update				*/
/********************************/
GciResult_t gci_hash_update(GciCtxId_t ctxID, const uint8_t* blockMsg, size_t blockLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_hash_finish				*/
/********************************/
GciResult_t gci_hash_finish(GciCtxId_t ctxID, uint8_t* digest, size_t* digestLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/**********************************************************************************************************************/
/*		      										SIGNATURE		 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_sign_gen_new_ctx		*/
/********************************/
GciResult_t gci_sign_gen_new_ctx(const GciSignConfig_t* signConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_sign_verify_new_ctx		*/
/********************************/
GciResult_t gci_sign_verify_new_ctx(const GciSignConfig_t* signConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_sign_ctx_clone			*/
/********************************/
GciResult_t gci_sign_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_sign_update				*/
/********************************/
GciResult_t gci_sign_update(GciCtxId_t ctxID,const uint8_t* blockMsg, size_t blockLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_sign_gen_finish			*/
/********************************/
GciResult_t gci_sign_gen_finish(GciCtxId_t ctxID, uint8_t* sign, size_t* signLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_sign_verify_finish		*/
/********************************/
GciResult_t gci_sign_verify_finish(GciCtxId_t ctxID, const uint8_t* sign, size_t signLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/**********************************************************************************************************************/
/*		      											KEY GENERATOR			      							  	  */
/**********************************************************************************************************************/

/********************************/
/*	gci_key_pair_gen			*/
/********************************/
GciResult_t gci_key_pair_gen(const GciKeyPairType_t* keyType, GciKeyId_t* pubKeyID, GciKeyId_t* privKeyID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/**********************************************************************************************************************/
/*		      											CIPHERS                     							  	  */
/**********************************************************************************************************************/

/********************************/
/*	 gci_cipher_new_ctx			*/
/********************************/
GciResult_t gci_cipher_new_ctx(const GciCipherConfig_t* ciphConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_cipher_encrypt			*/
/********************************/
GciResult_t gci_cipher_encrypt(GciCtxId_t ctxId, const uint8_t* plaintxt, size_t pltxtLen, uint8_t* ciphtxt, size_t* cptxtLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}


/********************************/
/*	gci_cipher_decrypt			*/
/********************************/
GciResult_t gci_cipher_decrypt(GciCtxId_t ctxId, const uint8_t* ciphtxt, size_t cptxtLen, uint8_t* plaintxt, size_t* pltxtLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/**********************************************************************************************************************/
/*		    										 RANDOM NUMBER                 				    			      */
/**********************************************************************************************************************/

/********************************/
/*	gci_rng_gen					*/
/********************************/
GciResult_t gci_rng_gen(int rdmNb, uint8_t* rdmBuf)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_rng_seed				*/
/********************************/
GciResult_t gci_rng_seed(const uint8_t* sdBuf, size_t sdLen)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/**********************************************************************************************************************/
/*		    										 Diffie-Hellmann                 				    			  */
/**********************************************************************************************************************/

/********************************/
/*	gci_dh_new_ctx				*/
/********************************/
GciResult_t gci_dh_new_ctx(const GciDhType_t* dhType, GciCtxId_t* ctxID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_dh_gen_key				*/
/********************************/
GciResult_t gci_dh_gen_key(GciCtxId_t ctxID, GciKeyId_t* pubKeyID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_dh_calc_sharedSecret	*/
/********************************/
GciResult_t gci_dh_calc_sharedSecret(GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* secretKeyID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/**********************************************************************************************************************/
/*		      										KEY				 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_key_put					*/
/********************************/
GciResult_t gci_key_put(const GciKey_t* key, GciKeyId_t* keyID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_key_get					*/
/********************************/
GciResult_t gci_key_get(GciKeyId_t keyID, GciKey_t* key)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}



/********************************/
/*	gci_key_delete				*/
/********************************/
GciResult_t gci_key_delete(GciKeyId_t keyID)
{
	GciResult_t err = GCI_OK;
#ifdef LIB_TOMCRYPT

#endif
	return err;
}


