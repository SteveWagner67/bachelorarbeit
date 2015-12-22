/**
 * \file 				crypto_iface.h
 * \author				Steve Wagner
 * \date 				13/10/2015
 * \version				1.0
 *
 * \brief 				principals functions of the new cryptographic interface ( Generic Crypto Interface  )
 */
 


/*--------------------------------------------------Include--------------------------------------------------------------*/
#ifndef CRYPTO_IFACE
#define CRYPTO_IFACE
#include "crypto_def.h"
#endif


/*-------------------------------------------------Variables-------------------------------------------------------------*/


/*----------------------------------------------Macro Definitions--------------------------------------------------------*/


/*----------------------------------------------Type Definitions--------------------------------------------------------*/


/**********************************************************************************************************************/
/*		      										GLOBAL			 				      							  */
/**********************************************************************************************************************/

/*!
 * \fn							en_gciResult_t gciInit( const uint8_t* p_user, size_t userLen, const uint8_t* p_password, size_t passLen )
 * \brief						Initialization of the interface
 * \param [in]  p_user			Pointer to the buffer of the user name
 * \param [in]  userLen			Length of the buffer for the user name
 * \param [in]	p_password		Pointer to the buffer of the password
 * \param [in]	passLen			Length of the buffer for the password
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciInit( const uint8_t* p_user, size_t userLen, const uint8_t* p_password, size_t passLen );



/*!
 * \fn							en_gciResult_t gciDeinit( void  )
 * \brief						Delete the initialization of the interface
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciDeinit( void );



/**
 * \fn							en_gciResult_t gciGetInfo( en_gciInfo_t infoType, uint16_t* p_info, size_t* p_infoLen )
 * \brief						Get some information
 * \param [in]	infoType		Which information
 * \param [out]	p_info			Pointer to the buffer with the information
 * \param [out] p_infoLen		Pointer to the length of the buffer with the information
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciGetInfo( en_gciInfo_t infoType, uint16_t* p_info, size_t* p_infoLen );



/**********************************************************************************************************************/
/*		      										CONTEXT			 				      							  */
/**********************************************************************************************************************/

/*!
 * \fn 							en_gciResult_t gciCtxRelease( GciCtxId_t ctxID )
 * \brief						Release a context
 * \param [in] ctxID			Context's ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciCtxRelease( GciCtxId_t ctxID );



/**********************************************************************************************************************/
/*		      										HASH			 				      							  */
/**********************************************************************************************************************/

/**
 * \fn							en_gciResult_t gciHashNewCtx( en_gciHashAlgo_t hashAlgo, GciCtxId_t* p_ctxID )
 * \brief						Create a new hash context and become an ID of it
 * \param [in]  hashAlgo 		Algorithm of the hash context
 * \param [out] p_ctxID			Pointer to the context's ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciHashNewCtx( en_gciHashAlgo_t hashAlgo, GciCtxId_t* p_ctxID );



/*!
 * \fn 							en_gciResult_t gciHashCtxClone( GciCtxId_t idSrc, GciCtxId_t* p_idDest )
 * \brief						Clone a context
 * \param [in]  idSrc			The context which will be cloned
 * \param [out] p_idDest		Pointer to the context ID where the source context is cloned
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciHashCtxClone( GciCtxId_t idSrc, GciCtxId_t* p_idDest );



/**
 * \fn							en_gciResult_t gciHashUpdate( GciCtxId_t ctxID, const uint8_t* p_blockMsg, size_t blockLen )
 * \brief						Add block of the message
 * \param [in]  ctxID	 		Context's ID
 * \param [in]  p_blockMsg		Pointer to the block of the message
 * \param [in]  blockLen		Block message's length
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciHashUpdate( GciCtxId_t ctxID, const uint8_t* p_blockMsg, size_t blockLen );



/**
 * \fn							en_gciResult_t gciHashFinish( GciCtxId_t ctxID, uint8_t* p_digest, size_t* p_digestLen )
 * \brief						Get the digest of the message after adding all the block of the message
 * \param [in]  ctxID	 		Context's ID
 * \param [out] p_digest		Pointer to the digest of the complete message added
 * \param [out] p_digestLen		Pointer to the length of the digest in bytes
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciHashFinish( GciCtxId_t ctxID, uint8_t* p_digest, size_t* p_digestLen );



/**********************************************************************************************************************/
/*		      										SIGNATURE		 				      							  */
/**********************************************************************************************************************/

/**
 * \fn							en_gciResult_t gciSignGenNewCtx( const st_gciSignConfig_t* p_signConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID )
 * \brief						Create a new signature context and become an ID of it
 * \param [in]  p_signConfig	Pointer to the configuration of the signature
 * \param [in]  keyID			Key's ID
 * \param [out] p_ctxID			Pointer to the context's ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciSignGenNewCtx( const st_gciSignConfig_t* p_signConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID );



/**
 * \fn							en_gciResult_t gciSignVerifyNewCtx( const st_gciSignConfig_t* p_signConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID )
 * \brief						Create a new signature context and become an ID of it
 * \param [in]  p_signConfig	Pointer to the configuration of the signature
 * \param [in]  keyID			Key's ID
 * \param [out] p_ctxID			Pointer to the context's ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciSignVerifyNewCtx( const st_gciSignConfig_t* p_signConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID );



/*!
 * \fn 							en_gciResult_t gciSignCtxClone( GciCtxId_t idSrc, GciCtxId_t* p_idDest )
 * \brief						Clone a context
 * \param [in]  idSrc			The context which will be cloned
 * \param [out] p_idDest		Pointer to the context ID where the source context is cloned
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciSignCtxClone( GciCtxId_t idSrc, GciCtxId_t* p_idDest );



/**
 * \fn							en_gciResult_t gciSignUpdate( GciCtxId_t ctxID,const uint8_t* p_blockMsg, size_t blockLen )
 * \brief						Add block of the message to generate a signature ( use for generate part and verify part )
 * \param [in]  ctxID	 		Context's ID
 * \param [in]  p_blockMsg		Pointer to the block of the message
 * \param [in]  blockLen		Block message's length in bytes
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciSignUpdate( GciCtxId_t ctxID,const uint8_t* p_blockMsg, size_t blockLen );



/**
 * \fn							en_gciResult_t gciSignGenFinish( GciCtxId_t ctxID, uint8_t* p_sign, size_t* p_signLen )
 * \brief						Get the signature of the message after adding all the block of the message
 * \param [in]  ctxID	 		Context's ID
 * \param [out] p_sign			Pointer to the signature of the complete message added
 * \param [out] p_signLen		Pointer to the length of the signature (in bytes)
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciSignGenFinish( GciCtxId_t ctxID, uint8_t* p_sign, size_t* p_signLen );



/**
 * \fn							en_gciResult_t gciSignVerifyFinish( GciCtxId_t ctxID, const uint8_t* p_sign, size_t signLen )
 * \brief						Compare the generated signature with the signature added to the function
 * 								after adding all the block of the message
 * \param [in]  ctxID 			Context's ID
 * \param [in]  p_sign			Pointer to the signature of the message which will be compare with this generate in the function
 * \param [in]  signLen			Length of the signature described above in bytes
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciSignVerifyFinish( GciCtxId_t ctxID, const uint8_t* p_sign, size_t signLen );



/**********************************************************************************************************************/
/*		      											KEY GENERATOR			      							  	  */
/**********************************************************************************************************************/

/**
 * \fn							en_gciResult_t gciKeyPairGen( const st_gciKeyPairConfig_t* p_keyConf, GciKeyId_t* p_pubKeyID, GciKeyId_t* p_privKeyID )
 * \brief						Generate a pair of key and get the ID of the public key
 * \param [in]  p_keyConf		Pointer to the configuration of the key pair
 * \param [out] p_pubKeyID		Pointer to the ID of the public key
 * \param [out] p_privKeyID		Pointer to the ID of the private key
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciKeyPairGen( const st_gciKeyPairConfig_t* p_keyConf, GciKeyId_t* p_pubKeyID, GciKeyId_t* p_privKeyID );



/**********************************************************************************************************************/
/*		      											CIPHERS                     							  	  */
/**********************************************************************************************************************/

/**
 * \fn							en_gciResult_t gciCipherNewCtx( const st_gciCipherConfig_t* p_ciphConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID )
 * \brief						Create a new symmetric cipher context
 * \param [in]	p_ciphConfig	Pointer to the configuration of the symmetric cipher
 * \param [in]  keyID			Key's ID
 * \param [out] p_ctxID			Pointer to the context's ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciCipherNewCtx( const st_gciCipherConfig_t* p_ciphConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID );



/**
 * \fn							en_gciResult_t gciCipherEncrypt( GciCtxId_t ctxId, const uint8_t* p_plaintxt, size_t pltxtLen, uint8_t* p_ciphtxt, size_t* p_cptxtLen )
 * \brief						Encrypt a plaintext and get the ciphertext
 * \param [in]  ctxId			Context's ID
 * \param [in]  p_plaintxt		Pointer to the data to be encrypted
 * \param [in]  pltxtLen		length of the data to be encrypted (in bytes)
 * \param [out] p_ciphtxt 		Pointer to the encrypted data
 * \param [out] p_cptxtLen 		Pointer to the length of the encrypted data (in bytes)
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciCipherEncrypt( GciCtxId_t ctxId, const uint8_t* p_plaintxt, size_t pltxtLen, uint8_t* p_ciphtxt, size_t* p_cptxtLen );



/**
 * \fn							en_gciResult_t gciCipherDecrypt( GciCtxId_t ctxId, const uint8_t* p_ciphtxt, size_t cptxtLen, uint8_t* p_plaintxt, size_t* p_pltxtLen )
 * \brief						Decrypt a ciphertext and get the plaintext
 * \param [in]	ctxId			Context's ID
 * \param [in]  p_ciphtxt		Pointer to the data to be decrypted
 * \param [in]  cptxtLen		length of the data to be decrypted (in bytes)
 * \param [out] p_plaintxt 		Pointer to the decrypted data
 * \param [out] p_pltxtLen 		Pointer to the length of the decrypted data (in bytes)
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciCipherDecrypt( GciCtxId_t ctxId, const uint8_t* p_ciphtxt, size_t cptxtLen, uint8_t* p_plaintxt, size_t* p_pltxtLen );



/**********************************************************************************************************************/
/*		    										 RANDOM NUMBER                 				    			      */
/**********************************************************************************************************************/

/**
 * \fn							en_gciResult_t gciRngGen( int rdmNb, uint8_t* p_rdmBuf )
 * \brief 						Generates random bytes
 * \param [in]  rdmNb			Number of random characters to generate
 * \param [out] p_rdmBuf		Pointer to the buffer to receive the random characters
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciRngGen( int rdmNb, uint8_t* p_rdmBuf );



/**
 * \fn							en_gciResult_t gciRngSeed( const uint8_t* p_sdBuf, size_t sdLen )
 * \brief 						Seed the random number generator
 * \param [in]	p_sdBuf			Pointer to the buffer of the seed
 * \param [in]  sdLen			Length of the seed in bytes
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciRngSeed( const uint8_t* p_sdBuf, size_t sdLen );



/**********************************************************************************************************************/
/*		    										 Diffie-Hellmann                 				    			  */
/**********************************************************************************************************************/

/**
 * \fn							en_gciResult_t gciDhNewCtx( const st_gciDhConfig_t* p_dhConfig, GciCtxId_t* p_ctxID )
 * \brief						Create a new Diffie-Hellman context
 * \param [in]  p_dhConfig		Pointer to the configuration of the Diffie-Hellman
 * \param [out] p_ctxID			Pointer to the context's ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciDhNewCtx( const st_gciDhConfig_t* p_dhConfig, GciCtxId_t* p_ctxID );



/**
 * \fn							en_gciResult_t gciDhGenKey( GciCtxId_t ctxID, GciKeyId_t* p_pubKeyID )
 * \brief						Generate a pair of key and get the ID of the public key ( private key stay intern )
 * \param [in]  ctxID			Context's ID
 * \param [out] p_pubKeyID		Pointer to the Public key ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciDhGenKey( GciCtxId_t ctxID, GciKeyId_t* p_pubKeyID );



/**
 * \fn							en_gciResult_t gciDhCalcSharedSecret( GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* p_secretKeyID )
 * \brief						Calculate the shared DH secret with the public key receives ( not internally generated )
 * \brief						The private key is stored internally with the context when generating key pair
 * \param [in]  ctxID			Context's ID
 * \param [in]  pubKeyID		Public key receives for a pair
 * \param [out] p_secretKeyID	Pointer to the shared secret key
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciDhCalcSharedSecret( GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* p_secretKeyID );



/**********************************************************************************************************************/
/*		      										KEY				 				      							  */
/**********************************************************************************************************************/

/*!
 * \fn							en_gciResult_t gciKeyPut( const st_gciKey_t* p_key, GciKeyId_t* p_keyID )
 * \brief						Store a key and get an ID of the key
 * \param [in]		p_key		Pointer to a structure with the key and its length
 * \param [in, out] p_keyID		Pointer to the key ID: -1 to generate an automatic key ID or
 * 														>= 0 that will be the key ID (return an error if it's not possible)
 * @return 						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciKeyPut( const st_gciKey_t* p_key, GciKeyId_t* p_keyID );



/*!
 * \fn							en_gciResult_t gciKeyGet( GciKeyId_t keyID, st_gciKey_t* p_key )
 * \brief						Get a stored key
 * \param [in]  keyID			Key's ID
 * \param [out] p_key			Pointer to a structure with the key and its length
 * @return 						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciKeyGet( GciKeyId_t keyID, st_gciKey_t* p_key );



/*!
 * \fn							en_gciResult_t gciKeyDelete( GciKeyId_t keyID  )
 * \brief						Delete a stored key
 * \param [in]  keyID			Key's ID
 * @return 						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t gciKeyDelete( GciKeyId_t keyID  );



