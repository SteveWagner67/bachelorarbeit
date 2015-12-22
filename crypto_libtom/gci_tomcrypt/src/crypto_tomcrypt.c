/**
 * \file 				crypto_tomcrypt.c
 * \brief 				See crypto_tomcrypt.h
 * \author				Steve Wagner
 * \date 		1		02/11/2015
 */

/**********************************************************************************************************************/
/*		      										INCLUDE			 				      							  */
/**********************************************************************************************************************/
#ifndef CRYPTO_TOM
#define CRYPTO_TOM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_tomcrypt.h"

#endif
/**********************************************************************************************************************/
/*		      										GLOBAL			 				      							  */
/**********************************************************************************************************************/

/*static GciCtxConfig_t ctxArray[GCI_NB_CTX_MAX];
static GciKeyConfig_t keyArray[GCI_NB_KEY_MAX];



GciResult_t gci_init(uint8_t* user, size_t userLen, uint8_t* password, size_t passLen)
{
	GciResult_t aErr=GCI_NO_ERR;
	int i=0;
	//Initialization of the context array
	for(i=0;i<GCI_NB_CTX_MAX;i++)
	{
		ctxArray[i].type = TYPE_NONE;
	}
//TODO Something with user and password
	return aErr;
}



GciResult_t gci_deinit(uint8_t* user, size_t userLen, uint8_t* password, size_t passLen)
{
	GciResult_t aErr=GCI_NO_ERR;
//TODO
	return aErr;
}



GciResult_t gci_get_info(GciInfo_t infoType, uint8_t* info, size_t infoLen)
{
	GciResult_t aErr=GCI_NO_ERR;
//TODO
	return aErr;
}

*/

/**********************************************************************************************************************/
/*		      										CONTEXT			 				      							  */
/**********************************************************************************************************************/

/*GciResult_t gci_ctx_release(GciCtxId_t ctxID)
{
	GciResult_t aErr=GCI_NO_ERR;
	int i, tabLen;
	switch(ctxArray[ctxID].type)
	{
		case TYPE_NONE:
			//ID already release
			aErr=GCI_ERR;
		break;

		case TYPE_HASH:
			ctxArray[ctxID].data.hash = HASH_ALGO_NONE;

			//Free the memory used
			free(ctxArray[ctxID].tcData.hash);

		break;

		case TYPE_SIGN:
			switch(ctxArray[ctxID].data.sign.algo)
			{
				case SIGN_ALGO_NONE:
				break;

				case SIGN_ALGO_MAC_ISO9797_ALG1:
				case SIGN_ALGO_MAC_ISO9797_ALG3:
				case SIGN_ALGO_CMAC_AES:
					ctxArray[ctxID].data.sign.config.cmac.block = BLOCK_MODE_NONE;
					ctxArray[ctxID].data.sign.config.cmac.padding = PADDING_NONE;
					ctxArray[ctxID].data.sign.config.cmac.iv.len = -1;

					//Free the memory space used by iv
					free(ctxArray[ctxID].data.sign.config.cmac.iv.data);

				break;

				case SIGN_ALGO_HMAC:
					ctxArray[ctxID].data.sign.config.hmac.hash = HASH_ALGO_NONE;
				break;

				case SIGN_ALGO_RSASSA_PSS:
				case SIGN_ALGO_RSASSA_PKCS:
				case SIGN_ALGO_RSASSA_X509:
					//TODO
				break;

				case SIGN_ALGO_DSA:
					//TODO
				break;

				case SIGN_ALGO_ECDSA_GF2M:
				case SIGN_ALGO_ECDSA_GFP:
					//TODO
				break;

				default:
					//Signature doesn't exist
					aErr=GCI_ERR;
				break;

			}
		break;

		case TYPE_CIPHER:
			ctxArray[ctxID].data.ciph.algo=CIPH_TYPE_NONE;
			ctxArray[ctxID].data.ciph.blockMode=BLOCK_MODE_NONE;
			ctxArray[ctxID].data.ciph.padding=PADDING_NONE;
		break;

		case TYPE_DH:
			switch(ctxArray[ctxID].data.dh.type)
			{
				case DIFFIE_HELLMAN:
					//TODO
				break;

				case DIFFIE_HELLMANELLIPTIC_CURVE:
					//TODO
				break;

				default:
					//Type doesn't exist
					aErr = GCI_ERR;
				break;
			}
		break;
	}

	//Put the type of the context to NONE
	ctxArray[ctxID].type = TYPE_NONE;

	return aErr;
}


*/
/**********************************************************************************************************************/
/*		      										HASH			 				      							  */
/**********************************************************************************************************************/

/*
GciResult_t gci_hash_new_ctx(GciHashAlgo_t hashAlgo, GciCtxId_t* ctxID)
{
	//**GCI VARAIBLE**
	GciResult_t aErr=GCI_NO_ERR;
	int id_index=0;
	int free_id=0;

	//**TOMCRYPT VARIABLE**
	int TCErr;


	//Search for a free ID
	while(0==free_id)
	{
		//Check that there is no type to the context -> free context
		if(TYPE_NONE == ctxArray[id_index].type)
		{
			switch(hashAlgo)
			{
				case HASH_ALGO_NONE:
					//No algorithm chosen
					aErr = GCI_HASH_ALGO_ERR;
				break;

				case HASH_ALGO_MD5:
					ctxArray[id_index].data.hash = hashAlgo;

					//Initialization of the hash
					ctxArray[id_index].tcData.hash = (hash_state*)malloc(sizeof(hash_state));
					TCErr = md5_init(ctxArray[id_index].tcData.hash);

					if(TCErr != CRYPT_OK)
					{
						aErr = GCI_HASH_INIT_ERR;
					}

				break;
				case HASH_ALGO_SHA1:
					ctxArray[id_index].data.hash = hashAlgo;

					//Initialization of the hash
					ctxArray[id_index].tcData.hash = (hash_state*)malloc(sizeof(hash_state));
					TCErr = sha1_init(ctxArray[id_index].tcData.hash);

					if(TCErr != CRYPT_OK)
					{
						aErr = GCI_HASH_INIT_ERR;
					}
				break;
				case HASH_ALGO_SHA224:
					//TODO
				break;
				case HASH_ALGO_SHA256:
					ctxArray[id_index].data.hash = hashAlgo;

					//Initialization of the hash
					ctxArray[id_index].tcData.hash = (hash_state*)malloc(sizeof(hash_state));
					TCErr = sha256_init(ctxArray[id_index].tcData.hash);

					if(TCErr != CRYPT_OK)
					{
						aErr = GCI_HASH_INIT_ERR;
					}
				break;
				case HASH_ALGO_SHA384:
					ctxArray[id_index].data.hash = hashAlgo;

					//Initialization of the hash
					ctxArray[id_index].tcData.hash = (hash_state*)malloc(sizeof(hash_state));
					TCErr = sha384_init(ctxArray[id_index].tcData.hash);

					if(TCErr != CRYPT_OK)
					{
						aErr = GCI_HASH_INIT_ERR;
					}
				break;
				case HASH_ALGO_SHA512:
					ctxArray[id_index].data.hash = hashAlgo;

					//Initialization of the hash
					ctxArray[id_index].tcData.hash = (hash_state*)malloc(sizeof(hash_state));
					TCErr = sha512_init(ctxArray[id_index].tcData.hash);

					if(TCErr != CRYPT_OK)
					{
						aErr = GCI_HASH_INIT_ERR;
					}
				break;

				default:
					//Algorithm doesn't exist
					aErr = GCI_HASH_ALGO_ERR;
				break;
			}
			*ctxID = id_index;
			//Go out of the loop
			free_id=1;
		}

		else
		{
			id_index++;
			if(GCI_NB_CTX_MAX <= id_index)
			{
				//No ID free
				aErr=GCI_ID_OVERFLOW;

				//Go out of the loop
				free_id=1;

			}
		}
	}

	if(GCI_NO_ERR == aErr)
	{
		*ctxID = id_index;
		ctxArray[id_index].type = TYPE_HASH;
	}

	return aErr;
}


GciResult_t gci_hash_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest)
{
	GciResult_t aErr=GCI_NO_ERR;
	GciHashAlgo_t hashAlgo;

	hashAlgo = ctxArray[idSrc].data.hash;
	aErr = gci_hash_new_ctx(hashAlgo, idDest);

	return aErr;
}



GciResult_t gci_hash_update(GciCtxId_t ctxID, uint8_t* blockMsg, size_t blockLen)
{
	GciResult_t aErr=GCI_NO_ERR;

	//**TOMCRYPT VARIABLE**
	int TCErr;

	switch(ctxArray[ctxID].data.hash)
	{
		case HASH_ALGO_NONE:
			//No algorithm initialized
			aErr = GCI_HASH_ALGO_ERR;
		break;

		case HASH_ALGO_MD5:
			TCErr = md5_process(ctxArray[ctxID].tcData.hash, blockMsg, blockLen);
			if(TCErr != CRYPT_OK)
			{
				aErr = GCI_HASH_UPDATE_ERR;
			}
		break;

		case HASH_ALGO_SHA1:
			TCErr = sha1_process(ctxArray[ctxID].tcData.hash, blockMsg, blockLen);
			if(TCErr != CRYPT_OK)
			{
				aErr = GCI_HASH_UPDATE_ERR;
			}
		break;

		case HASH_ALGO_SHA256:
			TCErr = sha256_process(ctxArray[ctxID].tcData.hash, blockMsg, blockLen);
			if(TCErr != CRYPT_OK)
			{
				aErr = GCI_HASH_UPDATE_ERR;
			}
		break;

		case HASH_ALGO_SHA384:
			TCErr = sha384_process(ctxArray[ctxID].tcData.hash, blockMsg, blockLen);
			if(TCErr != CRYPT_OK)
			{
				aErr = GCI_HASH_UPDATE_ERR;
			}
		break;

		case HASH_ALGO_SHA512:
			TCErr = sha512_process(ctxArray[ctxID].tcData.hash, blockMsg, blockLen);
			if(TCErr != CRYPT_OK)
			{
				aErr = GCI_HASH_UPDATE_ERR;
			}
		break;
	}

	return aErr;
}



GciResult_t gci_hash_finish(GciCtxId_t ctxID, uint8_t* digest, size_t* digestLen)
{
	GciResult_t aErr=GCI_NO_ERR;
	int TCErr;

	switch(ctxArray[ctxID].data.hash)
	{
		case HASH_ALGO_NONE:
			//No algorithm initialized
			aErr = GCI_HASH_ALGO_ERR;
		break;

		case HASH_ALGO_MD5:
			TCErr = md5_done(ctxArray[ctxID].tcData.hash, digest);

			if(CRYPT_OK != TCErr)
			{
				aErr = GCI_ERR;
			}

			else
			{
				//128 bits -> 32 characters -> 16 bytes
				*digestLen = 16;
			}

		break;

		case HASH_ALGO_SHA1:
			TCErr = sha1_done(ctxArray[ctxID].tcData.hash, digest);
			if(CRYPT_OK != TCErr)
			{
				aErr = GCI_ERR;
			}

			else
			{
				//160 bits -> 40 characters -> 20 bytes
				*digestLen = 20;
			}

		break;

		case HASH_ALGO_SHA256:
			TCErr = sha256_done(ctxArray[ctxID].tcData.hash, digest);
			if(CRYPT_OK != TCErr)
			{
				aErr = GCI_ERR;
			}

			else
			{
				//256 bits -> 64 characters -> 32 bytes
				*digestLen = 32;
			}

		break;

		case HASH_ALGO_SHA384:
			TCErr = sha384_done(ctxArray[ctxID].tcData.hash, digest);
			if(CRYPT_OK != TCErr)
			{
				aErr = GCI_ERR;
			}

			else
			{
				//384 bits -> 96 characters -> 48 bytes
				*digestLen = 48;
			}
		break;

		case HASH_ALGO_SHA512:
			TCErr = sha512_done(ctxArray[ctxID].tcData.hash, digest);
			if(CRYPT_OK != TCErr)
			{
				aErr = GCI_ERR;
			}

			else
			{
				//512 bits -> 128 characters -> 64 bytes
				*digestLen = 64;
			}
		break;
	}

	return aErr;
}

*/

/**********************************************************************************************************************/
/*		      										SIGNATURE		 				      							  */
/**********************************************************************************************************************/
/*
GciResult_t gci_sign_new_ctx(GciSignConfig_t signConfig, GciCtxId_t* ctxID)
{
	GciResult_t aErr=GCI_NO_ERR;
	int id_index=0, i=0, tabLen=0;
	int free_id=0;

	//Search for a free ID
	while(!free_id)
	{
		//Check that there is no type to the context -> free context
		if(TYPE_NONE == ctxArray[id_index].type)
		{
			switch(signConfig.algo)
			{
				case SIGN_ALGO_NONE:
				break;

				case SIGN_ALGO_MAC_ISO9797_ALG1:
				case SIGN_ALGO_MAC_ISO9797_ALG3:
				case SIGN_ALGO_CMAC_AES:
					ctxArray[id_index].data.sign.config.cmac.block = signConfig.config.cmac.block;
					ctxArray[id_index].data.sign.config.cmac.padding = signConfig.config.cmac.padding;
					ctxArray[id_index].data.sign.config.cmac.iv.len = signConfig.config.cmac.iv.len;

					//Reserve memory
					ctxArray[id_index].data.sign.config.cmac.iv.data = (uint8_t*)malloc(sizeof(uint8_t) * ctxArray[id_index].data.sign.config.cmac.iv.len);

					//Copy the content of the iv buffer of signConfig to the context array
					memcpy(ctxArray[id_index].data.sign.config.cmac.iv.data, signConfig.config.cmac.iv.data, signConfig.config.cmac.iv.len);
				break;

				case SIGN_ALGO_HMAC:
					ctxArray[id_index].data.sign.config.hmac.hash = signConfig.config.hmac.hash;
				break;

				case SIGN_ALGO_RSASSA_PSS:
				case SIGN_ALGO_RSASSA_PKCS:
				case SIGN_ALGO_RSASSA_X509:
					//TODO
				break;

				case SIGN_ALGO_DSA:
					//TODO
				break;

				case SIGN_ALGO_ECDSA_GF2M:
				case SIGN_ALGO_ECDSA_GFP:
					//TODO
				break;
				default:
					//Signature doesn't exist
					aErr=GCI_ERR;
				break;

			}

			//Go out of the loop
			free_id=1;
		}

		else
		{
			id_index++;
			if(GCI_NB_CTX_MAX <= id_index)
			{
				//No ID free
				aErr=GCI_ERR;

				//Go out of the loop
				free_id=1;

			}
		}
	}

	//Return the ID + change the type and signature algorithm only if no error occurred
	if(GCI_NO_ERR == aErr)
	{
		*ctxID = id_index;
		ctxArray[id_index].type = TYPE_SIGN;
		ctxArray[id_index].data.sign.algo = signConfig.algo;
	}

	return aErr;
}



GciResult_t gci_sign_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest)
{
	GciResult_t aErr=GCI_NO_ERR;
	GciSignConfig_t signConfig;

	signConfig = ctxArray[idSrc].data.sign;

	gci_sign_new_ctx(signConfig, idDest);

	return aErr;
}



GciResult_t gci_sign_update(GciCtxId_t ctxID, uint8_t* blockMsg, size_t blockLen)
{
	GciResult_t aErr=GCI_NO_ERR;

	//TODO

	return aErr;
}



GciResult_t gci_sign_gen_finish(GciCtxId_t ctxID, uint8_t* sign, size_t* signLen)
{
	GciResult_t aErr = GCI_NO_ERR;

	//TODO

	return aErr;
}



GciResult_t gci_sign_verify_finish(GciCtxId_t ctxID, uint8_t* sign, size_t signLen)
{
	GciResult_t aErr = GCI_NO_ERR;

	//TODO

	return aErr;
}

*/

/**********************************************************************************************************************/
/*		      											SYMMETRIC CIPHER			      							  */
/**********************************************************************************************************************/
/*
GciResult_t gci_cipher_sym_new_ctx(GciCiphSymConfig_t ciphConfig, GciCtxId_t* ctxID, GciKeyId_t* keyID)
{
	GciResult_t aErr = GCI_NO_ERR;
	int id_index=0;
	int free_id=0;

	//Search for a free ID
	while(!free_id)
	{
		//Check that there is no type to the context -> free context
		if(TYPE_NONE == ctxArray[id_index].type)
		{
			switch(ciphConfig.algo)
			{
				case CIPH_TYPE_NONE:
				break;

				case CIPH_TYPE_AES:
				case CIPH_TYPE_TDES:
					ctxArray[id_index].data.ciph.blockMode = ciphConfig.blockMode;
					ctxArray[id_index].data.ciph.padding = ciphConfig.padding;
					//Todo initil vector
				break;

				case CIPH_TYPE_RC4:
				break;

				default:
					//Cipher doesn't exist
					aErr = GCI_ERR;
				break;
			}

			//Go out of the loop
			free_id=1;
		}

		else
		{
			id_index++;
			if(GCI_NB_CTX_MAX <= id_index)
			{
				//No ID free
				aErr=GCI_ERR;

				//Go out of the loop
				free_id=1;
			}
		}
	}

	//Return the ID + change the algorithm and keyID only if no error occurred
	if(GCI_NO_ERR == aErr)
	{
		*ctxID = id_index;
		ctxArray[id_index].type = TYPE_CIPHER;
		ctxArray[id_index].data.ciph.algo = ciphConfig.algo;
	}

	return aErr;
}

*/

/**********************************************************************************************************************/
/*		      											KEY GENERATOR			      							  	  */
/**********************************************************************************************************************/
/*
GciResult_t gci_key_pair_gen(GciKeyGenConfig_t keyConfig, size_t keyLen, GciKeyId_t* pubKeyID, GciKeyId_t* privKeyID)
{
	GciResult_t aErr = GCI_NO_ERR;

	//TODO

	return aErr;
}

*/

/**********************************************************************************************************************/
/*		      											ENCRYPT/DECRYPT			      							  	  */
/**********************************************************************************************************************/
/*
GciResult_t gci_encrypt(GciCtxId_t ctxId, uint8_t* plaintxt, size_t pltxtLen, uint8_t* ciphtxt, size_t* cptxtLen)
{
	GciResult_t aErr = GCI_NO_ERR;

	//TODO

	return aErr;
}



GciResult_t gci_decrypt(GciCtxId_t ctxId, uint8_t* ciphtxt, int cptxtLen, uint8_t* plaintxt, size_t* pltxtLen)
{
	GciResult_t aErr = GCI_NO_ERR;

	//TODO

	return aErr;
}

*/

/**********************************************************************************************************************/
/*		    										 RANDOM NUMBER                 				    			      */
/**********************************************************************************************************************/
/*
GciResult_t gci_rng_gen(int rdmNb, uint8_t* rdmBuf)
{
	GciResult_t aErr = GCI_NO_ERR;

	//TODO

	return aErr;
}



GciResult_t gci_rng_seed(uint8_t* sdBuf, size_t* sdLen)
{
	GciResult_t aErr = GCI_NO_ERR;

	//TODO

	return aErr;
}

*/

/**********************************************************************************************************************/
/*		    										 Diffie-Hellmann                 				    			  */
/**********************************************************************************************************************/
/*
GciResult_t gci_dh_new_ctx(GciDhConfig_t dhConfig, GciCtxId_t* ctxID)
{
	GciResult_t aErr = GCI_NO_ERR;
	int id_index=0, tabLen=0, i=0;
	int free_id=0;

	//Search for a free ID
	while(!free_id)
	{
		//Check that there is no type to the context -> free context
		if(TYPE_NONE == ctxArray[id_index].type)
		{
			switch(dhConfig.type)
			{
				case DIFFIE_HELLMAN:
					//TODO
				break;

				case ELLIPTIC_CURVE_DIFFIE_HELLMAN:
					//TODO
				break;

				default:
					//Type doesn't exist
					aErr = GCI_ERR;
				break;
			}

			if(GCI_NO_ERR == aErr)
			{
				*ctxID = id_index;
			}

			//Go out of the loop
			free_id=1;
		}

		else
		{
			id_index++;
			if(GCI_NB_CTX_MAX <= id_index)
			{
				//No ID free
				aErr=GCI_ERR;

				//Go out of the loop
				free_id=1;
			}
		}
	}

	if(GCI_NO_ERR == aErr)
	{
		*ctxID = id_index;
		ctxArray[id_index].type = TYPE_DH;
		ctxArray[id_index].data.dh.type = dhConfig.type;
	}

	return aErr;
}



GciResult_t gci_dh_gen_key(GciCtxId_t ctxID, GciKeyId_t* pubKey)
{
	GciResult_t aErr = GCI_NO_ERR;

	//TODO

	return aErr;
}


GciResult_t gci_dh_calc_sharedSecret(GciCtxId_t ctxID, GciKeyId_t pubKey, GciKeyId_t* secretKey)
{
	GciResult_t aErr = GCI_NO_ERR;

	//TODO

	return aErr;
}

*/

/**********************************************************************************************************************/
/*		      										KEY				 				      							  */
/**********************************************************************************************************************/

/*GciResult_t gci_key_put(uint8_t* key, len_t keyLen, GciKeyId_t* keyID)
{
	GciResult_t aErr = GCI_NO_ERR;
	int id_index=0, tabLen=0, i=0;
	bool_t free_id=FALSE;


	/*Automatic research of an ID*/
/*	if(-1 == *keyID)
	{
		/*Search for a free ID*/
/*		while(!free_id)
		{
			//Check that there is no type to the context -> free context
			if(KEY_NONE == keyArray[id_index].type)
			{
				keyArray[id_index].keyLen = keyLen;

				tabLen = keyArray[id_index].keyLen;

				for(i=0; i<tabLen;i++)
				{
					keyArray[id_index].key[i] = key[i];
				}

				*keyID = id_index;
			}

			else
			{
				id_index++;

				if(NB_KEY_MAX <= id_index)
				{
					/*No ID free*/
/*					aErr=GCI_ERR;

					//Go out of the loop
					free_id=TRUE;
				}
			}
		}
	}

	/*Manual research*/
/*	else
	{
		/*Check if the ID is free*/
/*		if(KEY_NONE == keyArray[*keyID].type)
		{
			keyArray[*keyID].keyLen = keyLen;

			tabLen = keyArray[*keyID].keyLen;

			for(i=0; i<tabLen;i++)
			{
				keyArray[*keyID].key[i] = key[i];
			}
		}

		else
		{
			/*No ID free*/
/*			aErr=GCI_ERR;
		}
	}

	return aErr;
}



GciResult_t gci_key_get(GciKeyId_t keyID, uint8_t* key, len_t* keyLen)
{
	GciResult_t aErr=GCI_NO_ERR;
	int i=0;

	*keyLen = keyArray[keyID].keyLen;

	for(i=0; i< *keyLen; i++)
	{
		keyArray[keyID].key[i] = key[i];
	}

	return aErr;
}



GciResult_t gci_key_delete(GciKeyId_t keyID)
{
	GciResult_t aErr=GCI_NO_ERR;
	int i=0;

	keyArray[keyID].type = KEY_NONE;

	for(i=0; i< keyArray[keyID].keyLen; i++)
	{
		keyArray[keyID].key[i] = 0;
	}

	keyArray[keyID].keyLen = -1;

	return aErr;
}

*/
