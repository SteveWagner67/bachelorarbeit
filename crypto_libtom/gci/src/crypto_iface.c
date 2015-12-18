/**
 * \file 				crypto_iface.c
 * \brief 				see crypto_iface.h
 * \author				Steve Wagner
 * \date 				13/10/2015
 */


/*--------------------------------------------------Include--------------------------------------------------------------*/
#include "crypto_iface.h"
#include "tomcrypt.h"



/*-------------------------------------------------Variables-------------------------------------------------------------*/



/*-------------------------------------------------Functions-------------------------------------------------------------*/

/**********************************************************************************************************************/
/*		      										GLOBAL			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_init					*/
/********************************/
en_gciResult_t gciInit(const uint8_t* user, size_t userLen, const uint8_t* password, size_t passLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Init");

	return err;
}



/********************************/
/*	gci_deinit					*/
/********************************/
en_gciResult_t gciDeinit(void)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: DeInit");

	return err;
}



/********************************/
/*	gci_get_info				*/
//********************************/
en_gciResult_t gciGetInfo(en_gciInfo_t infoType, uint16_t* info, size_t* infoLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Get Info");

	return err;
}



/**********************************************************************************************************************/
/*		      										CONTEXT			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_ctx_release				*/
/********************************/
en_gciResult_t gciCtxRelease(GciCtxId_t ctxID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Ctx Release");

	return err;
}



/**********************************************************************************************************************/
/*		      										HASH			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_hash_new_ctx			*/
/********************************/
en_gciResult_t gciHashNewCtx(en_gciHashAlgo_t hashAlgo, GciCtxId_t* ctxID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Hash New Ctx");

	return err;
}



/********************************/
/*	gci_hash_ctx_clone			*/
/********************************/
en_gciResult_t gciHashCtxClone(GciCtxId_t idSrc, GciCtxId_t* idDest)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Hash Ctx Clone");

	return err;
}



/********************************/
/*	gci_hash_update				*/
/********************************/
en_gciResult_t gciHashUpdate(GciCtxId_t ctxID, const uint8_t* blockMsg, size_t blockLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Hash Update");

	return err;
}



/********************************/
/*	gci_hash_finish				*/
/********************************/
en_gciResult_t gciHashFinish(GciCtxId_t ctxID, uint8_t* digest, size_t* digestLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Hash Finish");

	return err;
}



/**********************************************************************************************************************/
/*		      										SIGNATURE		 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_sign_gen_new_ctx		*/
/********************************/
en_gciResult_t gciSignGenNewCtx(const st_gciSignConfig_t* signConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Sign Gen New Ctx");

	return err;
}



/********************************/
/*	gci_sign_verify_new_ctx		*/
/********************************/
en_gciResult_t gciSignVerifyNewCtx(const st_gciSignConfig_t* signConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Sign Verify New Ctx");

	return err;
}



/********************************/
/*	gci_sign_ctx_clone			*/
/********************************/
en_gciResult_t gciSignCtxClone(GciCtxId_t idSrc, GciCtxId_t* idDest)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Sign Ctx Clone");

	return err;
}



/********************************/
/*	gci_sign_update				*/
/********************************/
en_gciResult_t gciSignUpdate(GciCtxId_t ctxID,const uint8_t* blockMsg, size_t blockLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Sign Update");

	return err;
}



/********************************/
/*	gci_sign_gen_finish			*/
/********************************/
en_gciResult_t gciSignGenFinish(GciCtxId_t ctxID, uint8_t* sign, size_t* signLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Sign Gen Finish");

	return err;
}



/********************************/
/*	gci_sign_verify_finish		*/
/********************************/
en_gciResult_t gciSignVerifyFinish(GciCtxId_t ctxID, const uint8_t* sign, size_t signLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Sign Verify Finish");

	return err;
}



/**********************************************************************************************************************/
/*		      											KEY GENERATOR			      							  	  */
/**********************************************************************************************************************/

/********************************/
/*	gci_key_pair_gen			*/
/********************************/
en_gciResult_t gciKeyPairGen(const st_gciKeyPairConfig_t* keyConf, GciKeyId_t* pubKeyID, GciKeyId_t* privKeyID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Key Pair Gen");

	return err;
}



/**********************************************************************************************************************/
/*		      											CIPHERS                     							  	  */
/**********************************************************************************************************************/

/********************************/
/*	 gci_cipher_new_ctx			*/
/********************************/
en_gciResult_t gciCipherNewCtx(const st_gciCipherConfig_t* ciphConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Cipher New Ctx");

	return err;
}



/********************************/
/*	gci_cipher_encrypt			*/
/********************************/
en_gciResult_t gciCipherEncrypt(GciCtxId_t ctxId, const uint8_t* plaintxt, size_t pltxtLen, uint8_t* ciphtxt, size_t* cptxtLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Cipher Encrypt");

	return err;
}


/********************************/
/*	gci_cipher_decrypt			*/
/********************************/
en_gciResult_t gciCipherDecrypt(GciCtxId_t ctxId, const uint8_t* ciphtxt, size_t cptxtLen, uint8_t* plaintxt, size_t* pltxtLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Cipher Decrypt");

	return err;
}



/**********************************************************************************************************************/
/*		    										 RANDOM NUMBER                 				    			      */
/**********************************************************************************************************************/

/********************************/
/*	gci_rng_gen					*/
/********************************/
en_gciResult_t gciRngGen(int rdmNb, uint8_t* rdmBuf)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Rng Gen");

	return err;
}



/********************************/
/*	gci_rng_seed				*/
/********************************/
en_gciResult_t gciRngSeed(const uint8_t* sdBuf, size_t sdLen)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Rng Seed");

	return err;
}



/**********************************************************************************************************************/
/*		    										 Diffie-Hellmann                 				    			  */
/**********************************************************************************************************************/

/********************************/
/*	gci_dh_new_ctx				*/
/********************************/
en_gciResult_t gciDhNewCtx(const st_gciDhConfig_t* dhConfig, GciCtxId_t* ctxID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: DH New Ctx");

	return err;
}



/********************************/
/*	gci_dh_gen_key				*/
/********************************/
en_gciResult_t gciDhGenKey(GciCtxId_t ctxID, GciKeyId_t* pubKeyID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: DH Gen Key");

	return err;
}



/********************************/
/*	gci_dh_calc_sharedSecret	*/
/********************************/
en_gciResult_t gciDhCalcSharedSecret(GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* secretKeyID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: DH Calc Shared Secret");

	return err;
}



/**********************************************************************************************************************/
/*		      										KEY				 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gci_key_put					*/
/********************************/
en_gciResult_t gciKeyPut(const st_gciKey_t* key, GciKeyId_t* keyID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Key Put");

	return err;
}



/********************************/
/*	gci_key_get					*/
/********************************/
en_gciResult_t gciKeyGet(GciKeyId_t keyID, st_gciKey_t* key)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Key Get");

	return err;
}



/********************************/
/*	gci_key_delete				*/
/********************************/
en_gciResult_t gciKeyDelete(GciKeyId_t keyID)
{
	en_gciResult_t err = en_gciResult_Ok;

	printf("GCI: Key Delete");

	return err;
}


