/**
 * \file 				crypto_iface.h
 * \brief 				principals functions of the new interface (Generic Crypto Interface)
 * \author				Steve Wagner
 * \date 				13/10/2015
 */
 


/**********************************************************************************************************************/
/*		      										INCLUDE			 				      							  */
/**********************************************************************************************************************/
#ifndef CRYPTO_IFACE
#define CRYPTO_IFACE
#include "crypto_def.h"
#endif

/**********************************************************************************************************************/
/*		      										GLOBAL			 				      							  */
/**********************************************************************************************************************/

/*!
 * \fn						GciResult_t gci_init(const uint8_t* user, size_t userLen, const uint8_t* password, size_t passLen)
 * \brief					Initialization of the interface
 * \param [in]  user		Buffer of the user name
 * \param [in]  userLen		Length of the buffer for the user name
 * \param [in]	password	Buffer of the password
 * \param [in]	passLen		Length of the buffer for the password
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_init(const uint8_t* user, size_t userLen, const uint8_t* password, size_t passLen);



/*!
 * \fn						GciResult_t gci_deinit();
 * \brief					Delete the initialization of the interface
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_deinit();



/**
 * \fn						GciResult_t gci_get_info(GciInfo_t infoType, uint8_t* info, size_t* infoLen)
 * \brief					Get some information
 * \param [in]	infoType	Which information
 * \param [out]	info		Buffer with the information
 * \param [out] infoLen		Length of the buffer with the information
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_get_info(GciInfo_t infoType, uint8_t* info, size_t* infoLen);



/**********************************************************************************************************************/
/*		      										CONTEXT			 				      							  */
/**********************************************************************************************************************/

/*!
 * \fn 					GciResult_t gci_ctx_release(GciCtxId_t ctxID)
 * \brief				Release a context
 * \param [in] ctxID	Context's ID
 * @return				GCI_NO_ERR on success
 * @return				GCI_ERR on error
 */
GciResult_t gci_ctx_release(GciCtxId_t ctxID);



/**********************************************************************************************************************/
/*		      										HASH			 				      							  */
/**********************************************************************************************************************/

/**
 * \fn						GciResult_t gci_hash_new_ctx(GciHashAlgo_t hashAlgo, GciCtxId_t* ctxID)
 * \brief					Create a new hash context and become an ID of it
 * \param [in]  hashAlgo 	Algorithm of the hash context
 * \param [out] ctxID		Context's ID
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_hash_new_ctx(GciHashAlgo_t hashAlgo, GciCtxId_t* ctxID);



/*!
 * \fn 					GciResult_t gci_hash_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest)
 * \brief				Clone a context
 * \param [in]  idSrc	The context which will be cloned
 * \param [out] idDest	The context ID where the source context is cloned
 * @return				GCI_NO_ERR on success
 * @return				GCI_ERR on error
 */
GciResult_t gci_hash_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest);



/**
 * \fn						GciResult_t gci_hash_update(GciCtxId_t ctxID, const uint8_t* blockMsg, size_t blockLen)
 * \brief					Add block of the message
 * \param [in]  ctxID	 	Context's ID
 * \param [in]  blockMsg	Block of the message
 * \param [in]  blockLen	Block message's length
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_hash_update(GciCtxId_t ctxID, const uint8_t* blockMsg, size_t blockLen);



/**
 * \fn						GciResult_t gci_hash_finish(GciCtxId_t ctxID, uint8_t* digest, size_t* digestLen)
 * \brief					Get the digest of the message after adding all the block of the message
 * \param [in]  ctxID	 	Context's ID
 * \param [out] digest		Digest of the complete message added
 * \param [out] digestLen	Length of the digest in bytes
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_hash_finish(GciCtxId_t ctxID, uint8_t* digest, size_t* digestLen);



/**********************************************************************************************************************/
/*		      										SIGNATURE		 				      							  */
/**********************************************************************************************************************/

/**
 * \fn						GciResult_t gci_sign_new_ctx(const GciSignConfig_t* signConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)
 * \brief					Create a new signature context and become an ID of it
 * \param [in]  signConfig	Configuration of the signature
 * \param [in]  keyID		Private Key's ID
 * \param [out] ctxID		Context's ID
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_sign_new_ctx(const GciSignConfig_t* signConfig, GciKeyId_t keyID, GciCtxId_t* ctxID);



/*!
 * \fn 					GciResult_t gci_sign_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest)
 * \brief				Clone a context
 * \param [in]  idSrc	The context which will be cloned
 * \param [out] idDest	The context ID where the source context is cloned
 * @return				GCI_NO_ERR on success
 * @return				GCI_ERR on error
 */
GciResult_t gci_sign_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest);



/**
 * \fn						GciResult_t gci_sign_update(GciCtxId_t ctxID,const uint8_t* blockMsg, size_t blockLen)
 * \brief					Add block of the message to generate a signature (use for generate part and verify part)
 * \param [in]  ctxID	 	Context's ID
 * \param [in]  blockMsg	Block of the message
 * \param [in]  blockLen	Block message's length in bytes
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_sign_update(GciCtxId_t ctxID,const uint8_t* blockMsg, size_t blockLen);



/**
 * \fn						GciResult_t gci_sign_gen_finish(GciCtxId_t ctxID, uint8_t* sign, size_t* signLen)
 * \brief					Get the signature of the message after adding all the block of the message
 * \param [in]  ctxID	 	Context's ID
 * \param [out] sign		Signature of the complete message added
 * \param [out] signLen		Length of the signature in bytes
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_sign_gen_finish(GciCtxId_t ctxID, uint8_t* sign, size_t* signLen);



/**
 * \fn						GciResult_t gci_sign_verify_finish(GciCtxId_t ctxID, const uint8_t* sign, size_t signLen)
 * \brief					Compare the generated signature with the signature added to the function
 * 							after adding all the block of the message
 * \param [in]  ctxID 		Context's ID
 * \param [in]  sign		Signature of the message which will be compare with this generate in the function
 * \param [in]  signLen		Length of the signature described above in bytes
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_sign_verify_finish(GciCtxId_t ctxID, const uint8_t* sign, size_t signLen);


/**********************************************************************************************************************/
/*		      											KEY GENERATOR			      							  	  */
/**********************************************************************************************************************/

/**
 * \fn						GciResult_t gci_key_pair_gen(const GciKeyGenConfig_t* keyConfig, size_t keyLen, GciKeyId_t* pubKeyID, GciKeyId_t* privKeyID)
 * \brief					Generate a pair of key and get the ID of the public key
 * \param [in]  keyConfig	Configuration of the key
 * \param [in] 	keyLen		Length of the keys in bytes
 * \param [out] pubKeyID	ID of the public key
 * \param [out] privKeyID	ID of the private key
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_key_pair_gen(const GciKeyGenConfig_t* keyConfig, size_t keyLen, GciKeyId_t* pubKeyID, GciKeyId_t* privKeyID);



/**********************************************************************************************************************/
/*		      											CIPHERS                     							  	  */
/**********************************************************************************************************************/

/**
 * \fn						GciResult_t gci_cipher_new_ctx(const GciCipherConfig_t* ciphConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)

 * \brief					Create a new symmetric cipher context
 * \param [in]	ciphConfig	Configuration of the symmetric cipher
 * \param [in]  keyID		Key's ID
 * \param [out] ctxID		Context's ID
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_cipher_new_ctx(const GciCipherConfig_t* ciphConfig, GciKeyId_t keyID, GciCtxId_t* ctxID);



/**
 * \fn						GciResult_t gci_cipher_encrypt(GciCtxId_t ctxId, const uint8_t* plaintxt, size_t pltxtLen, uint8_t* ciphtxt, size_t* cptxtLen)
 * \brief					Encrypt a plaintext and get the ciphertext
 * \param [in]  ctxId		Context's ID
 * \param [in]  plaintxt	data to be encrypted
 * \param [in]  pltxtLen	length of the data to be encrypted in bytes
 * \param [out] ciphtxt 	encrypted data
 * \param [out] cptxtLen 	length of the encrypted data in bytes
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_cipher_encrypt(GciCtxId_t ctxId, const uint8_t* plaintxt, size_t pltxtLen, uint8_t* ciphtxt, size_t* cptxtLen);



/**
 * \fn						GciResult_t gci_cipher_decrypt(GciCtxId_t ctxId, const uint8_t* ciphtxt, int cptxtLen, uint8_t* plaintxt, size_t* pltxtLen)
 * \brief					Decrypt a ciphertext and get the plaintext
 * \param [in]	ctxId		Context's ID
 * \param [in]  ciphtxt		data to be decrypted
 * \param [in]  cptxtLen	length of the data to be decrypted in bytes
 * \param [out] plaintxt 	decrypted data
 * \param [out] pltxtLen 	length of the decrypted data in bytes
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_cipher_decrypt(GciCtxId_t ctxId, const uint8_t* ciphtxt, int cptxtLen, uint8_t* plaintxt, size_t* pltxtLen);



/**********************************************************************************************************************/
/*		    										 RANDOM NUMBER                 				    			      */
/**********************************************************************************************************************/

/**
 * \fn						GciResult_t gci_rng_gen(int rdmNb, uint8_t* rdmBuf)
 * \brief 					Generates random bytes
 * \param [in]  rdmNb		Number of random characters to generate
 * \param [out] rdmBuf		Buffer to receive the random characters
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_rng_gen(int rdmNb, uint8_t* rdmBuf);



/**
 * \fn						GciResult_t gci_rng_seed(const uint8_t* sdBuf, size_t sdLen)
 * \brief 					Seed the random number generator
 * \param [in]	sdBuf		Buffer of the seed
 * \param [in]  sdLen		Length of the seed in bytes
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_rng_seed(const uint8_t* sdBuf, size_t sdLen);



/**********************************************************************************************************************/
/*		    										 Diffie-Hellmann                 				    			  */
/**********************************************************************************************************************/

/**
 * \fn						GciResult_t gci_dh_new_ctx(const GciDhConfig_t* dhConfig, GciCtxId_t* ctxID)
 * \brief					Create a new Diffie-Hellman context
 * \param [in]  dhConfig	Configuration of the Diffie-Hellman
 * \param [out] ctxID		Context's ID
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_dh_new_ctx(const GciDhConfig_t* dhConfig, GciCtxId_t* ctxID);



/**
 * \fn						GciResult_t gci_dh_gen_key(GciCtxId_t ctxID, GciKeyId_t* pubKeyID)
 * \brief					Generate a pair of key and get the ID of the public key (private key stay intern)
 * \param [in]  ctxID		Context's ID
 * \param [out] pubKeyID	Public key
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_dh_gen_key(GciCtxId_t ctxID, GciKeyId_t* pubKeyID);



/**
 * \fn						GciResult_t gci_dh_calc_sharedSecret(GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* secretKeyID)
 * \brief					Calculate the shared DH secret with the public key receives (not internally generated)
 * \brief					The private key is stored internally with the context when generating key pair
 * \param [in]  ctxID		Context's ID
 * \param [in]  pubKeyID	Public key receives for a pair
 * \param [out] secretKeyID	Premaster secret key
 * @return					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_dh_calc_sharedSecret(GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* secretKeyID);



/**********************************************************************************************************************/
/*		      										KEY				 				      							  */
/**********************************************************************************************************************/

/*!
 * \fn						GciResult_t gci_key_put(const GciKey_t* key, GciKeyId_t* keyID)
 * \brief					Store a key and get an ID of the key
 * \param [in]	key			Structure with the key and its length
 * \param [in, out] keyID	Key ID - -1 to generate an automatic key ID or and other (>= 0) that will be the key ID
 * @return 					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_key_put(const GciKey_t* key, GciKeyId_t* keyID);



/*!
 * \fn						GciResult_t gci_key_get(GciKeyId_t keyID, GciKey_t* key)
 * \brief					Get a stored key
 * \param [in]  keyID		Key's ID
 * \param [out] key			Buffer of the key and its length
 * @return 					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_key_get(GciKeyId_t keyID, GciKey_t* key);



/*!
 * \fn						GciResult_t gci_key_delete(GciKeyId_t keyID)
 * \brief					Delete a stored key
 * \param [in]  keyID		Key's ID
 * @return 					GCI_NO_ERR on success
 * @return					GCI_ERR on error
 */
GciResult_t gci_key_delete(GciKeyId_t keyID);



