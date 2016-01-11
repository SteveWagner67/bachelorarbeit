/**
 * \file 				crypto_iface.c
 * \brief 				see crypto_iface.h
 * \author				Steve Wagner
 * \date 				13/10/2015
 */


/*--------------------------------------------------Include--------------------------------------------------------------*/

#include <stdlib.h>
#include "crypto_tomcrypt.h"

#include "ssl_certHandler.h"
#include "ssl.h"
#include "ssl_diag.h"
#include "ssl_oid.h"
#include "netGlobal.h"
#include "ssl_target.h"
#include "ssl_certHelper.h"
#include "ssl_record.h"
#include "tomcrypt.h"

/* Display the GCI Info of each function uses in the project */
#define GCI_DBG_INFO 0




/*-------------------------------------------------Global variables-------------------------------------------------------------*/

/* Array for the context ID */
static st_tcCtxConfig_t ga_ctxID[GCI_NB_CTX_MAX];

/* Array for the Key ID */
static st_gciKey_t ga_keyID[GCI_NB_KEY_MAX];

/* Pseudo random numbers fortuna */
static prng_state g_fortuna_prng;
static int g_fortunaID;

/* Diffie-Hellmann domain parameters length buffer */
static size_t ga_allocDhDomainParam[GCI_BUFFER_MAX_SIZE];
/* Diffie-Hellmann domain parameter p buffer */
static uint8_t ga_allocDhDomainP[GCI_BUFFER_MAX_SIZE/2];
/* Diffie-Hellmann domain parameter g buffer */
static uint8_t ga_allocDhDomainG[GCI_BUFFER_MAX_SIZE/2];


/* Hash MD5 */
static hash_state ga_hashMd5[GCI_NB_CTX_MAX][sizeof(hash_state)];
/* Hash SHA1 */
static hash_state ga_hashSha1[GCI_NB_CTX_MAX][sizeof(hash_state)];
/* Hash SHA224 */
static hash_state ga_hashSha224[GCI_NB_CTX_MAX][sizeof(hash_state)];
/* Hash SHA256 */
static hash_state ga_hashSha256[GCI_NB_CTX_MAX][1024];
/* Hash SHA384 */
static hash_state ga_hashSha384[GCI_NB_CTX_MAX][sizeof(hash_state)];
/* Hash SHA512 */
static hash_state ga_hashSha512[GCI_NB_CTX_MAX][sizeof(hash_state)];

/* HMAC */
static hmac_state ga_hmac[GCI_NB_CTX_MAX];
//hmac_state ga_hmac;

/* Cipher RC4 */
static prng_state ga_cipherRc4[GCI_NB_CTX_MAX];

/* Initialization vector */
static uint8_t ga_allocIV[GCI_NB_CTX_MAX][GCI_BUFFER_MAX_SIZE];

/* Block mode CBC */
static symmetric_CBC ga_blockModeCBC[GCI_NB_CTX_MAX];
/* Block mode CFB */
static symmetric_CFB ga_blockModeCFB[GCI_NB_CTX_MAX];
/* Block mode ECB */
static symmetric_ECB ga_blockModeECB[GCI_NB_CTX_MAX];
/* Block mode OFB */
static symmetric_OFB ga_blockModeOFB[GCI_NB_CTX_MAX];
/* Block mode GCM */
static gcm_state ga_blockModeGCM[GCI_NB_CTX_MAX];

/* Symmetric key */
static uint8_t ga_allocSymKey[GCI_NB_KEY_MAX][TC_SYM_KEY_SIZE_MAX_BYTES];

/* Diffie-Hellmann private key */
//static uint8_t ga_allocDhPrivKey[GCI_NB_KEY_MAX][TC_DH_KEY_SIZE_MAX_BYTES];

/* Private key corresponds to g_dhPrivKey.x */
dh_key g_dhPrivKey;

/* Private key corresponds to eccKey.k */
ecc_key g_ecdhPrivKey;

/* Diffie-Hellmann public key */
static uint8_t ga_allocDhPubKey[GCI_NB_KEY_MAX][TC_DH_KEY_SIZE_MAX_BYTES];

/* Diffie-Hellmann secret key */
static uint8_t ga_allocDhSecretKey[GCI_NB_KEY_MAX][TC_DH_KEY_SIZE_MAX_BYTES];

/* DSA private key */
static uint8_t ga_allocDsaPrivKey[GCI_NB_KEY_MAX][TC_DSA_KEY_SIZE_MAX_BYTES];

/* DSA public key */
static uint8_t ga_allocDsaPubKey[GCI_NB_KEY_MAX][TC_DSA_KEY_SIZE_MAX_BYTES];

/* ECDH private key */
static uint8_t ga_allocEcdhPrivKey[GCI_NB_KEY_MAX][TC_ECDH_KEY_SIZE_MAX_BYTES];

/* ECDH public coordinate x */
static uint8_t ga_allocEcdhPubCoordX[GCI_NB_KEY_MAX][TC_ECDH_KEY_SIZE_MAX_BYTES];

/* ECDH public coordinate y */
static uint8_t ga_allocEcdhPubCoordY[GCI_NB_KEY_MAX][TC_ECDH_KEY_SIZE_MAX_BYTES];

/* ECDH secret key */
static uint8_t ga_allocEcdhSecretKey[GCI_NB_KEY_MAX][TC_ECDH_KEY_SIZE_MAX_BYTES];

/* ECDSA private key */
static uint8_t ga_allocEcdsaPrivKey[GCI_NB_KEY_MAX][TC_ECDSA_KEY_SIZE_MAX_BYTES];

/* ECDSA public coordinate x */
static uint8_t ga_allocEcdsaPubCoordX[GCI_NB_KEY_MAX][TC_ECDSA_KEY_SIZE_MAX_BYTES];

/* ECDSA public coordinate y */
static uint8_t ga_allocEcdsaPubCoordY[GCI_NB_KEY_MAX][TC_ECDSA_KEY_SIZE_MAX_BYTES];

/* RSA public/private modulus (n) */
static uint8_t ga_allocRsaN[GCI_NB_KEY_MAX][TC_RSA_KEY_SIZE_MAX_BYTES];

/* RSA private exponent (d) */
static uint8_t ga_allocRsaPrivD[GCI_NB_KEY_MAX][TC_RSA_KEY_SIZE_MAX_BYTES];

/* RSA public exponent (e) */
static uint8_t ga_allocRsaPubE[GCI_NB_KEY_MAX][TC_RSA_KEY_SIZE_MAX_BYTES];


/*---------------------------------------------Prototype of local functions----------------------------------------------*/

/**
 * \fn							en_gciResult_t _searchFreeCtxID(GciCtxId_t* p_ctxID)
 * \brief						Search a free ID in a_ctxID[GCI_NB_CTX_MAX]
 * \param [out] p_ctxID			Pointer to the context's ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t _searchFreeCtxID( GciCtxId_t* p_ctxID );

/**
 * \fn							en_gciResult_t _searchFreeKeyID( GciKeyId_t* p_keyID )
 * \brief						Search a free ID in a_keyID[GCI_NB_CTX_MAX]
 * \param [out] p_keyID			Pointer to the key's ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t _searchFreeKeyID( GciKeyId_t* p_keyID );

/**
 * \fn							en_gciResult_t _registerAndTest( void )
 * \brief						Register and test functions used (hash, prng, cipher)
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t _registerAndTest( void );


/**
 * \fn                          en_gciResult_t _initPrng(uint8_t* randBuf, size_t randLen)
 * \brief                       Initialization of the Pseudo-Random Number Generator
 * \param [in]  p_randBuf       Pointer of the buffer with random number
 * \param [in]  randLen         Length of the buffer with random number
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t _initPrng(const uint8_t* p_randBuf, size_t randLen);

/**
 * \fn							en_gciResult_t _genDhDomainParam( st_gciDhDomainParam_t* dhParam )
 * \brief						Generate Diffie-Hellmann domain parameters
 * \param [out] dhParam			Pointer to the structure for the domain parameter
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t _genDhDomainParam(uint8_t* p_g, size_t* p_gLen, uint8_t* p_p, size_t* p_pLen);

/**
 * \fn                          en_gciResult_t _genDhKeyPair( GciKeyId_t* p_pubKeyID )
 * \brief                       Generate a Diffie-Hellmann key pair
 * \param [in]  ctxID           Context ID
 * \param [out] p_pubKeyID      Pointer to the ID of the public key
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t _genDhKeyPair( GciCtxId_t ctxID, GciKeyId_t* p_pubKeyID );


/**
 * \fn                          en_gciResult_t _calcDhSecret( GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* p_secretKeyID)
 * \brief                       Generate a Diffie-Hellmann shared secret
 * \param [in]  ctxID           Context ID
 * \param [in]  pubKeyID        The ID of the public key
 * \param [out] p_secretKeyID   Pointer to the ID of the shared secret
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t _calcDhSecret( GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* p_secretKeyID);

/**
 * \fn                          en_gciResult_t _getEccCurve( uint16_t* p_curve, size_t* p_nbCurve)
 * \brief                       Get the curve available + the number of curve available
 * \param [in]  p_curve         Pointer to the buffer to save the curve
 * \param [out] p_nbCurve       Pointer to the number of curve available
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t _getEccCurve( uint8_t* p_curve, size_t* p_nbCurve);

/**
 * \fn                          en_gciResult_t _getCurveSize(en_gciNamedCurve_t curve,  size_t* p_curveSize)
 * \brief                       Get the size of the curve
 * \param [in]  curve           The curve to get the size
 * \param [out] p_curveSize     Pointer to the size of the curve
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t _getCurveSize(en_gciNamedCurve_t curve,  size_t* p_curveSize);

/**
 * \fn                          en_gciResult_t _genEchKeyPair( GciKeyId_t* p_pubKeyID )
 * \brief                       Generate an Ellipti Curve Diffie-Hellmann key pair
 * \param [in]  ctxID           Context ID
 * \param [out] p_pubKeyID      Pointer to the ID of the public key
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t _genEchKeyPair( GciCtxId_t ctxID, GciKeyId_t* p_pubKeyID );

/**
 * \fn                          en_gciResult_t _calcEcdhSecret( GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* p_secretKeyID)
 * \brief                       Generate Elliptic Curve Diffie-Hellmann shared secret
 * \param [in]  ctxID           Context ID
 * \param [in]  pubKeyID        The ID of the public key
 * \param [out] p_secretKeyID   Pointer to the ID of the shared secret
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t _calcEcdhSecret( GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* p_secretKeyID);

/**
 * \fn                          en_gciResult_t _ctxRelease( st_tcCtxConfig_t ctx)
 * \brief                       Release a context
 * \param [in] ctx              The context to release
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t _ctxRelease( st_tcCtxConfig_t* ctx);

/**
 * \fn                          en_gciResult_t _keyRelease( st_gciKey_t key)
 * \brief                       Release a key
 * \param [in] key              The key to release
 * @return                      en_gciResult_Ok on success
 * @return                      en_gciResult_Err on error
 */
en_gciResult_t _keyRelease( st_gciKey_t* key);


/*---------------------------------------------Functions from crypto_iface.h---------------------------------------------*/

/**********************************************************************************************************************/
/*		      										GLOBAL			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gciInit					    */
/********************************/
en_gciResult_t gciInit( const uint8_t* p_user, size_t userLen, const uint8_t* p_password, size_t passLen )
{
	en_gciResult_t err = en_gciResult_Ok;
	int i = 0;
	int tmpErr = CRYPT_OK;

	/* !! This is very important to use functions from the ltm_desc library */
	ltc_mp = ltm_desc;

	/* Use some "random" bytes to init the PRNG fortuna */
	uint8_t c_rand[] = { 0x42, 0x72, 0x75, 0x63, 0x65, 0x20, 0x53, 0x63, 0x68,
						 0x6E, 0x65, 0x69, 0x65, 0x72, 0x21, 0x0D, 0x0A, 0x00 };

    #if GCI_DBG_INFO
	printf("GCI Info: Init\r\n");
    #endif

	/* Initialization of the context array */
	for( i = 0; i < GCI_NB_CTX_MAX; i++ )
	{
		err = _ctxRelease(&ga_ctxID[i]);

		if(err != en_gciResult_Ok)
		{
		    printf("GCI Error in gciInit: Release context\r\n");
		}

	}

	/* Initialization of the key array */
	for( i = 0; i < GCI_NB_KEY_MAX; i++ )
	{
		err = _keyRelease(&ga_keyID[i]);

		if(err != en_gciResult_Ok)
		{
		    printf("GCI Error in gciInit: Release key\r\n");
		}

	}

	/* Register and test */
	err = _registerAndTest();

	if(err != en_gciResult_Ok)
	{
		printf("GCI Error in gciInit: Register and test\r\n");
	}


	/* Init pseudo random number generator */
	err = _initPrng(c_rand, sizeof(c_rand));
    if(err != en_gciResult_Ok)
    {
        printf("GCI Error in gciInit: Init PRNG\r\n");
    }


	return err;
}



/********************************/
/*	gciDeinit					*/
/********************************/
en_gciResult_t gciDeinit(void)
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: DeInit\r\n");
#endif

	return err;
}



/********************************/
/*	gciGetInfo				*/
//********************************/
en_gciResult_t gciGetInfo( en_gciInfo_t infoType, uint8_t* p_info, size_t* p_infoLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: Get Info\r\n");
#endif

	switch(infoType)
	{
	    case en_gciInfo_CurveName:
	        _getEccCurve(p_info, p_infoLen);

#if GCI_DBG_INFO
	        printf("GCI Info: %d curve(s) available\r\n", *p_infoLen);
#endif

	    break;

	    case en_gciInfo_Invalid:
	    default:
	        printf("GCI Error in gciGetInfo: Invalid information\r\n");
	    break;
	}

	return err;
}



/**********************************************************************************************************************/
/*		      										CONTEXT			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gciCtxRelease				*/
/********************************/
en_gciResult_t gciCtxRelease(GciCtxId_t ctxID)
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: Ctx Release ID: %d\r\n", ctxID);
#endif

	err = _ctxRelease(&ga_ctxID[ctxID]);

	if(err != en_gciResult_Ok)
	{
	    printf("GCI Error in gciCtxRealease: Context release\r\n");
	}

	else
	{
#if GCI_DBG_INFO
	    printf("GCI Info: Context release done\r\n");
#endif
	}

	return err;
}



/**********************************************************************************************************************/
/*		      										HASH			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gciHashNewCtx			*/
/********************************/
en_gciResult_t gciHashNewCtx( en_gciHashAlgo_t hashAlgo, GciCtxId_t* p_ctxID )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;

#if GCI_DBG_INFO
	printf("GCI Info: Hash New Ctx\r\n");
#endif

	/* Search free context ID
	 *
	 * return:  en_gciResult_Ok                 on success
	 *          en_gciResult_ErrBufferIdFull    on error (Buffer of the context ID is full)
	 */
	err = _searchFreeCtxID(p_ctxID);

	if(err != en_gciResult_Ok)
	{
	    printf("GCI Error in gciHashNewCtx: No context ID free\r\n");

	    return err;
	}

	/* Indicate the type of the context */
	ga_ctxID[*p_ctxID].type = en_tcCtxType_Hash;

	/* Save the configuration */
	ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigHash = hashAlgo;

	/* Init the hash */
	switch(hashAlgo)
	{
	    case en_gciHashAlgo_MD5:
#if GCI_DBG_INFO
	        printf("GCI Info: Hash MD5 context ID = %d\r\n", *p_ctxID);
#endif

	        tmpErr = md5_init(&ga_hashMd5[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashNewCtx: init Md5\r\n");
	        }

	    break;

	    case en_gciHashAlgo_SHA1:

#if GCI_DBG_INFO
	        printf("GCI Info: Hash SHA1 context ID = %d\r\n", *p_ctxID);
#endif

	        tmpErr = sha1_init(&ga_hashSha1[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashNewCtx: init Sha1\r\n");
	        }

	    break;

	    case en_gciHashAlgo_SHA224:

#if GCI_DBG_INFO
	        printf("GCI Info: Hash SHA224 context ID = %d\r\n", *p_ctxID);
#endif

	        tmpErr = sha224_init(&ga_hashSha224[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashNewCtx: init Sha224\r\n");
	        }
	    break;

	    case en_gciHashAlgo_SHA256:

#if GCI_DBG_INFO
	        printf("GCI Info: Hash SHA256 context ID = %d\r\n", *p_ctxID);
#endif

	        tmpErr = sha256_init(&ga_hashSha256[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashNewCtx: init Sha256\r\n");
	        }
	    break;

	    case en_gciHashAlgo_SHA384:

#if GCI_DBG_INFO
	        printf("GCI Info: Hash SHA384 context ID = %d\r\n", *p_ctxID);
#endif

	        tmpErr = sha384_init(&ga_hashSha384[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashNewCtx: init Sha384\r\n");
	        }
	    break;

	    case en_gciHashAlgo_SHA512:

#if GCI_DBG_INFO
	        printf("GCI Info: Hash SHA512 context ID = %d\r\n", *p_ctxID);
#endif

	        tmpErr = sha512_init(&ga_hashSha512[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashNewCtx: init Sha512\r\n");
	        }
	    break;
	}

	return err;
}



/********************************/
/*	gciHashCtxClone			    */
/********************************/
en_gciResult_t gciHashCtxClone( GciCtxId_t idSrc, GciCtxId_t* p_idDest )
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: Hash Ctx Clone\r\n");
#endif

	/* Search a free context ID */
	err = _searchFreeCtxID(p_idDest);

    if(err != en_gciResult_Ok)
    {
        printf("GCI Error in gciHashCtxClone: No context ID free\r\n");
        return err;
    }

    else
    {
#if GCI_DBG_INFO
        printf("GCI Info: Hash clone context ID  %d to new context ID %d\r\n", idSrc, *p_idDest);
#endif

    }

    ga_ctxID[*p_idDest].keyID = ga_ctxID[idSrc].keyID;
    ga_ctxID[*p_idDest].type = ga_ctxID[idSrc].type;
    ga_ctxID[*p_idDest].un_ctxConfig.ctxConfigHash = ga_ctxID[idSrc].un_ctxConfig.ctxConfigHash;

    switch(ga_ctxID[*p_idDest].un_ctxConfig.ctxConfigHash)
    {
        case en_gciHashAlgo_MD5:

            memcpy(&ga_hashMd5[*p_idDest], &ga_hashMd5[idSrc], sizeof(hash_state));


        break;

        case en_gciHashAlgo_SHA1:

            memcpy(&ga_hashSha1[*p_idDest], &ga_hashSha1[idSrc], sizeof(hash_state));

        break;

        case en_gciHashAlgo_SHA224:

            memcpy(&ga_hashSha224[*p_idDest], &ga_hashSha224[idSrc], sizeof(hash_state));

        break;

        case en_gciHashAlgo_SHA256:

            memcpy(&ga_hashSha256[*p_idDest], &ga_hashSha256[idSrc], sizeof(hash_state));

        break;

        case en_gciHashAlgo_SHA384:

            memcpy(&ga_hashSha384[*p_idDest], &ga_hashSha384[idSrc], sizeof(hash_state));

        break;

        case en_gciHashAlgo_SHA512:

            memcpy(&ga_hashSha512[*p_idDest], &ga_hashSha512[idSrc], sizeof(hash_state));

        break;
    }

	return err;
}



/********************************/
/*	gciHashUpdate				*/
/********************************/
en_gciResult_t gciHashUpdate( GciCtxId_t ctxID, const uint8_t* p_blockMsg, size_t blockLen )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;
	hash_state hash;

#if GCI_DBG_INFO
	printf("GCI Info: Hash Update ID %d\r\n", ctxID);
#endif

	/* Compare the type of the context */
	if(ga_ctxID[ctxID].type != en_tcCtxType_Hash)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in gciHashUpdate: Context type not Hash\r\n");

	    return err;
	}

	/* Hash the block message */
	switch(ga_ctxID[ctxID].un_ctxConfig.ctxConfigHash)
	{
	    case en_gciHashAlgo_MD5:

	        tmpErr = md5_process(&ga_hashMd5[ctxID], p_blockMsg, blockLen);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashUpdate: update Md5\r\n");
	        }

	        else
	        {
#if GCI_DBG_INFO
	            printf("GCI Info: Update MD5 done\r\n");
#endif
	        }

	    break;

	    case en_gciHashAlgo_SHA1:

	        tmpErr = sha1_process(&ga_hashSha1[ctxID], p_blockMsg, blockLen);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashUpdate: Update Sha1\r\n");
	        }

	        else
	        {
#if GCI_DBG_INFO
	            printf("GCI Info: Update SHA1 done\r\n");
#endif
	        }

	    break;

	    case en_gciHashAlgo_SHA224:

	        tmpErr = sha224_process(&ga_hashSha224[ctxID], p_blockMsg, blockLen);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashUpdate: Update Sha224\r\n");
	        }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: Update SHA224 done\r\n");
#endif
            }

	    break;

	    case en_gciHashAlgo_SHA256:

	        tmpErr = sha256_process(&ga_hashSha256[ctxID], p_blockMsg, blockLen);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashUpdate: Update Sha256\r\n");
	        }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: Update SHA256 done\r\n");
#endif
            }

	    break;

	    case en_gciHashAlgo_SHA384:

	        tmpErr = sha384_process(&ga_hashSha384[ctxID], p_blockMsg, blockLen);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashUpdate: Update Sha384\r\n");
	        }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: Update SHA384 done\r\n");
#endif
            }

	    break;

	    case en_gciHashAlgo_SHA512:

	        tmpErr = sha512_process(&ga_hashSha512[ctxID], p_blockMsg, blockLen);

	        if(tmpErr != CRYPT_OK)
	        {
	            err = en_gciResult_Err;
	            printf("GCI Error in gciHashUpdate: Update Sha512\r\n");
	        }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: Update SHA512 done\r\n");
#endif
            }

	    break;
	}

	return err;
}



/********************************/
/*	gciHashFinish				*/
/********************************/
en_gciResult_t gciHashFinish( GciCtxId_t ctxID, uint8_t* p_digest, size_t* p_digestLen )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;

#if GCI_DBG_INFO
	printf("GCI Info: Hash Finish\r\n");
#endif

	/* Compare the type of the context */
	    if(ga_ctxID[ctxID].type != en_tcCtxType_Hash)
	    {
	        err = en_gciResult_Err;
	        printf("GCI Error in gciHashFinish: Context type not Hash\r\n");

	        return err;
	    }

	    /* Hash the block message */
	    switch(ga_ctxID[ctxID].un_ctxConfig.ctxConfigHash)
	    {
	        case en_gciHashAlgo_MD5:

#if GCI_DBG_INFO
                printf("GCI Info: Finish MD5\r\n");
#endif

	            tmpErr = md5_done(&ga_hashMd5[ctxID], p_digest);

	            if(tmpErr != CRYPT_OK)
	            {
	                err = en_gciResult_Err;
	                printf("GCI Error in gciHashFinish: Finish Md5\r\n");
	            }

	            else
	            {
#if GCI_DBG_INFO
	                printf("GCI Info: Finish MD5 done\r\n");
#endif
	            }

	            p_digestLen = (size_t)strlen(p_digest);

	        break;

	        case en_gciHashAlgo_SHA1:

#if GCI_DBG_INFO
                printf("GCI Info: Finish SHA1\r\n");
#endif

	            tmpErr = sha1_done(&ga_hashSha1[ctxID], p_digest);

	            if(tmpErr != CRYPT_OK)
	            {
	                err = en_gciResult_Err;
	                printf("GCI Error in gciHashFinish: Finish Sha1\r\n");
	            }

	            else
	            {
#if GCI_DBG_INFO
	                printf("GCI Info: Finish SHA1 done\r\n");
#endif
	            }

	            p_digestLen = strlen(p_digest);

	        break;

	        case en_gciHashAlgo_SHA224:

#if GCI_DBG_INFO
                printf("GCI Info: Finish SHA224\r\n");
#endif

	            tmpErr = sha224_done(&ga_hashSha224[ctxID], p_digest);

	            if(tmpErr != CRYPT_OK)
	            {
	                err = en_gciResult_Err;
	                printf("GCI Error in gciHashFinish: Finish Sha224\r\n");
	            }

	            else
	            {
#if GCI_DBG_INFO
	                printf("GCI Info: Finish SHA224 done\r\n");
#endif
	            }

	            p_digestLen = (size_t)strlen(p_digest);

	        break;

	        case en_gciHashAlgo_SHA256:

#if GCI_DBG_INFO
	            printf("GCI Info: Finish SHA256\r\n");
#endif

	            tmpErr = sha256_done(&ga_hashSha256[ctxID], p_digest);

	            if(tmpErr != CRYPT_OK)
	            {
	                err = en_gciResult_Err;
	                printf("GCI Error in gciHashFinish: finish Sha256\r\n");
	            }

	            else
	            {
#if GCI_DBG_INFO
	                printf("GCI Info: Finish SHA256 done\r\n");
#endif
	            }

	            p_digestLen = (size_t)strlen(p_digest);

	        break;

	        case en_gciHashAlgo_SHA384:

#if GCI_DBG_INFO
                printf("GCI Info: Finish SHA384\r\n");
#endif

	            tmpErr = sha384_done(&ga_hashSha384[ctxID], p_digest);

	            if(tmpErr != CRYPT_OK)
	            {
	                err = en_gciResult_Err;
	                printf("GCI Error in gciHashFinish: Finish Sha384\r\n");
	            }

                else
                {
#if GCI_DBG_INFO
                    printf("GCI Info: Finish SHA384 done\r\n");
#endif
                }

	            p_digestLen = (size_t)strlen(p_digest);

	        break;

	        case en_gciHashAlgo_SHA512:

#if GCI_DBG_INFO
                printf("GCI Info: Finish SHA512\r\n");
#endif

	            tmpErr = sha512_done(&ga_hashSha512[ctxID], p_digest);

	            if(tmpErr != CRYPT_OK)
	            {
	                err = en_gciResult_Err;
	                printf("GCI Error in gciHashFinish: finish Sha512\r\n");
	            }

                else
                {
#if GCI_DBG_INFO
                    printf("GCI Info: Finish SHA512 done\r\n");
#endif
                }

	            p_digestLen = (size_t)strlen(p_digest);

	        break;
	    }

	return err;
}



/**********************************************************************************************************************/
/*		      										SIGNATURE		 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gciSignGenNewCtx		*/
/********************************/
en_gciResult_t gciSignGenNewCtx( const st_gciSignConfig_t* p_signConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;
	st_gciKey_t key;
	int hashID;

	uint8_t a_allocKey[GCI_BUFFER_MAX_SIZE];

#if GCI_DBG_INFO
	printf("GCI Info: Sign Gen New Ctx");
#endif

	/* Search free context ID */
	err = _searchFreeCtxID(p_ctxID);

	if(err != en_gciResult_Ok)
	{
	    printf("GCI Error in gciSignGenNewCtx: No context ID free\r\n");

	    return err;
	}

#if GCI_DBG_INFO
    printf(" with context ID %d\r\n", *p_ctxID);
#endif

	/* Indicate the type of the context */
	ga_ctxID[*p_ctxID].type = en_tcCtxType_SignGen;

	/* Save the configuration */
	ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigSign.algo = p_signConfig->algo;
	ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigSign.hash = p_signConfig->hash;

	switch(p_signConfig->algo)
	{
	    case en_gciSignAlgo_CMAC_AES:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code CMAC\r\n");
#endif

	    break;

	    case en_gciSignAlgo_DSA:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm DSA\r\n");
#endif

	    break;

	    case en_gciSignAlgo_ECDSA:
	    case en_gciSignAlgo_ECDSA_GF2M:
	    case en_gciSignAlgo_ECDSA_GFP:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm ECDSA\r\n");
#endif

	    break;


	    case en_gciSignAlgo_HMAC:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code HMAC\r\n");
#endif

            /* Get the hmac/symmetric key with the ID in input */
            key.type = en_gciKeyType_Hmac;
            key.un_key.keySym.data = a_allocKey;
            err = gciKeyGet(keyID, &key);

            if( err != en_gciResult_Ok)
            {
                printf("GCI Error in gciSignGenNewCtx: Getting the HMAC/symmetric key\r\n");
                return err;
            }

            /* Hash */
            switch(p_signConfig->hash)
            {
                case en_gciHashAlgo_MD5:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash MD5\r\n");
#endif

                    /* Get the ID of the hash MD5 */
                    hashID = find_hash("md5");

                break;

                case en_gciHashAlgo_SHA1:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA1\r\n");
#endif

                    /* Get the ID of the hash SHA1 */
                    hashID = find_hash("sha1");

                break;

                case en_gciHashAlgo_SHA224:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA224\r\n");
#endif

                    /* Get the ID of the hash SHA224 */
                    hashID = find_hash("sha224");

                break;

                case en_gciHashAlgo_SHA256:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA256\r\n");
#endif

                    /* Get the ID of the hash SHA256 */
                    hashID = find_hash("sha256");

                break;

                case en_gciHashAlgo_SHA384:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA384\r\n");
#endif

                    /* Get the ID of the hash SHA384 */
                    hashID = find_hash("sha384");

                break;


                case en_gciHashAlgo_SHA512:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA512\r\n");
#endif

                    /* Get the ID of the hash SHA512 */
                    hashID = find_hash("sha512");

                break;

                case en_gciHashAlgo_None:
                case en_gciHashAlgo_Invalid:
                default:

                    printf("GCI Error in gciSignGenNewCtx: Invalid Hash\r\n");
                    err = en_gciResult_Err;
                    return err;
                break;

            }

            /* Check the validity of the hash */
            tmpErr = hash_is_valid(hashID);
            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error in gciSignNewGenCtx: Hash not valid\r\n");
                err = en_gciResult_Err;
                return err;
            }

            /* Initialize the HMAC */
            tmpErr = hmac_init(&ga_hmac[*p_ctxID], hashID, key.un_key.keySym.data, key.un_key.keySym.len);
            //tmpErr = hmac_init(&ga_hmac, hashID, key.un_key.keySym.data, key.un_key.keySym.len);

            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error: HMAC init\r\n");
                err = en_gciResult_Err;
            }

	    break;

	    case en_gciSignAlgo_MAC_ISO9797_ALG1:
	    case en_gciSignAlgo_MAC_ISO9797_ALG3:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code MAC\r\n");
#endif

	    break;


	    case en_gciSignAlgo_RSA:
	    case en_gciSignAlgo_RSASSA_PKCS:
	    case en_gciSignAlgo_RSASSA_PSS:
	    case en_gciSignAlgo_RSASSA_X509:

#if GCI_DBG_INFO
	        printf("GCI Info: Signature algorithm RSA\r\n");
#endif

	    break;


	    case en_gciSignAlgo_None:
	    case en_gciSignAlgo_Invalid:
	    default:

	        printf("GCI Error in gciSignGenNewCtx: Invalid signature algorithm\r\n");
	        err = en_gciResult_Err;

	    break;

	}


	return err;
}



/********************************/
/*	gciSignVerifyNewCtx		*/
/********************************/
en_gciResult_t gciSignVerifyNewCtx( const st_gciSignConfig_t* p_signConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID )
{
	en_gciResult_t err = en_gciResult_Ok;
    int tmpErr = CRYPT_OK;
    st_gciKey_t key;
    int hashID;

    uint8_t a_allocKey[GCI_BUFFER_MAX_SIZE];

#if GCI_DBG_INFO
    printf("GCI Info: Sign Verify New Ctx\r\n");
#endif

    /* Search free context ID */
    err = _searchFreeCtxID(p_ctxID);

    if(err != en_gciResult_Ok)
    {
        printf("GCI Error in gciSignVerifyNewCtx: No context ID free\r\n");

        return err;
    }

#if GCI_DBG_INFO
    printf(" with context ID %d\r\n", *p_ctxID);
#endif

    /* Indicate the type of the context */
    ga_ctxID[*p_ctxID].type = en_tcCtxType_SignVfy;

    /* Save the configuration */
    ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigSign.algo = p_signConfig->algo;
    ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigSign.hash = p_signConfig->hash;

    /* Save the key ID */
    ga_ctxID[*p_ctxID].keyID = keyID;

    switch(p_signConfig->algo)
    {
        case en_gciSignAlgo_CMAC_AES:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code CMAC\r\n");
#endif

        break;

        case en_gciSignAlgo_DSA:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm DSA\r\n");
#endif

        break;

        case en_gciSignAlgo_ECDSA:
        case en_gciSignAlgo_ECDSA_GF2M:
        case en_gciSignAlgo_ECDSA_GFP:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm ECDSA\r\n");
#endif

        break;


        case en_gciSignAlgo_HMAC:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code HMAC\r\n");
#endif

            /* Get the hmac/symmetric key with the ID in input */
            key.type = en_gciKeyType_Hmac;
            key.un_key.keySym.data = a_allocKey;
            err = gciKeyGet(keyID, &key);

            if( err != en_gciResult_Ok)
            {
                printf("GCI Error in gciSignVerifyNewCtx: Getting the HMAC/symmetric key\r\n");
                return err;
            }

            /* Hash */
            switch(p_signConfig->hash)
            {
                case en_gciHashAlgo_MD5:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash MD5\r\n");
#endif

                    /* Get the ID of the hash MD5 */
                    hashID = find_hash("md5");

                break;

                case en_gciHashAlgo_SHA1:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA1\r\n");
#endif

                    /* Get the ID of the hash SHA1 */
                    hashID = find_hash("sha1");

                break;

                case en_gciHashAlgo_SHA224:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA224\r\n");
#endif

                    /* Get the ID of the hash SHA224 */
                    hashID = find_hash("sha224");

                break;

                case en_gciHashAlgo_SHA256:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA256\r\n");
#endif

                    /* Get the ID of the hash SHA256 */
                    hashID = find_hash("sha256");

                break;

                case en_gciHashAlgo_SHA384:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA384\r\n");
#endif

                    /* Get the ID of the hash SHA384 */
                    hashID = find_hash("sha384");

                break;


                case en_gciHashAlgo_SHA512:

#if GCI_DBG_INFO
                    printf("GCI Info: Hash SHA512\r\n");
#endif

                    /* Get the ID of the hash SHA512 */
                    hashID = find_hash("sha512");

                break;

                case en_gciHashAlgo_None:
                case en_gciHashAlgo_Invalid:
                default:

                    printf("GCI Error in gciSignVerifyNewCtx: Invalid Hash\r\n");
                    err = en_gciResult_Err;
                    return err;
                break;

            }

            /* Initialize the HMAC */
            tmpErr = hmac_init(&ga_hmac[*p_ctxID], hashID, key.un_key.keySym.data, key.un_key.keySym.len);
            //tmpErr = hmac_init(&ga_hmac, hashID, key.un_key.keySym.data, key.un_key.keySym.len);

            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error in gciSignVerifyNewCtx: HMAC init\r\n");
                err = en_gciResult_Err;
            }

        break;

        case en_gciSignAlgo_MAC_ISO9797_ALG1:
        case en_gciSignAlgo_MAC_ISO9797_ALG3:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code MAC\r\n");
#endif

        break;


        case en_gciSignAlgo_RSA:
        case en_gciSignAlgo_RSASSA_PKCS:
        case en_gciSignAlgo_RSASSA_PSS:
        case en_gciSignAlgo_RSASSA_X509:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm RSA\r\n");
#endif

        break;


        case en_gciSignAlgo_None:
        case en_gciSignAlgo_Invalid:
        default:

            printf("GCI Error in gciSignVerifyNewCtx: Invalid signature algorithm\r\n");
            err = en_gciResult_Err;

        break;

    }


    return err;
}



/********************************/
/*	gciSignCtxClone			    */
/********************************/
en_gciResult_t gciSignCtxClone( GciCtxId_t idSrc, GciCtxId_t* p_idDest )
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: Sign Ctx Clone\r\n");
#endif

	return err;
}



/********************************/
/*	gciSignUpdate				*/
/********************************/
en_gciResult_t gciSignUpdate( GciCtxId_t ctxID, const uint8_t* p_blockMsg, size_t blockLen )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;

#if GCI_DBG_INFO
	printf("GCI Info: Signature Update\r\n");
#endif

	/* Verify the type of the context */
	if(ga_ctxID[ctxID].type != en_tcCtxType_SignGen)
	{
	    printf("GCI Error in gciSignUpdate: Type of the context not signature gen\r\n");
	    err = en_gciResult_Err;
	    return err;
	}

	switch(ga_ctxID[ctxID].un_ctxConfig.ctxConfigSign.algo)
	{

	    case en_gciSignAlgo_CMAC_AES:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code CMAC\r\n");
#endif

        break;

        case en_gciSignAlgo_DSA:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm DSA\r\n");
#endif

        break;

        case en_gciSignAlgo_ECDSA:
        case en_gciSignAlgo_ECDSA_GF2M:
        case en_gciSignAlgo_ECDSA_GFP:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm ECDSA\r\n");
#endif

        break;


        case en_gciSignAlgo_HMAC:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code HMAC\r\n");
#endif

            tmpErr = hmac_process(&ga_hmac[ctxID], p_blockMsg, blockLen);
            //tmpErr = hmac_process(&ga_hmac, p_blockMsg, blockLen);

            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error in gciSignUpdate: HMAC process\r\n");
                err = en_gciResult_Err;
            }

        break;

        case en_gciSignAlgo_MAC_ISO9797_ALG1:
        case en_gciSignAlgo_MAC_ISO9797_ALG3:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code MAC\r\n");
#endif

        break;


        case en_gciSignAlgo_RSA:
        case en_gciSignAlgo_RSASSA_PKCS:
        case en_gciSignAlgo_RSASSA_PSS:
        case en_gciSignAlgo_RSASSA_X509:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm RSA\r\n");
#endif

        break;


        case en_gciSignAlgo_None:
        case en_gciSignAlgo_Invalid:
        default:

            printf("GCI Error in gciSignUpdate: Invalid signature algorithm\r\n");

        break;
	}

	return err;
}



/********************************/
/*	gciSignGenFinish			*/
/********************************/
en_gciResult_t gciSignGenFinish( GciCtxId_t ctxID, uint8_t* p_sign, size_t* p_signLen )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;

#if GCI_DBG_INFO
	printf("GCI Info: Sign Gen Finish\r\n");
#endif

    /* Verify the type of the context */
    if(ga_ctxID[ctxID].type != en_tcCtxType_SignGen)
    {
        printf("GCI Error in gciSignGenFinish: Type of the context not signature gen\r\n");
        err = en_gciResult_Err;
        return err;
    }

    switch(ga_ctxID[ctxID].un_ctxConfig.ctxConfigSign.algo)
    {

        case en_gciSignAlgo_CMAC_AES:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code CMAC\r\n");
#endif

        break;

        case en_gciSignAlgo_DSA:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm DSA\r\n");
#endif

        break;

        case en_gciSignAlgo_ECDSA:
        case en_gciSignAlgo_ECDSA_GF2M:
        case en_gciSignAlgo_ECDSA_GFP:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm ECDSA\r\n");
#endif

        break;


        case en_gciSignAlgo_HMAC:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code HMAC\r\n");
#endif



            tmpErr = hmac_done(&ga_hmac[ctxID], p_sign, p_signLen);

            //tmpErr = hmac_done(&ga_hmac, p_sign, p_signLen);

            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error: HMAC done\r\n");
                err = en_gciResult_Err;
            }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: HMAC done\r\n");
#endif
            }

        break;

        case en_gciSignAlgo_MAC_ISO9797_ALG1:
        case en_gciSignAlgo_MAC_ISO9797_ALG3:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code MAC\r\n");
#endif

        break;


        case en_gciSignAlgo_RSA:
        case en_gciSignAlgo_RSASSA_PKCS:
        case en_gciSignAlgo_RSASSA_PSS:
        case en_gciSignAlgo_RSASSA_X509:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm RSA\r\n");
#endif

        break;


        case en_gciSignAlgo_None:
        case en_gciSignAlgo_Invalid:
        default:

            printf("GCI Error in gciSignGenFinish: Invalid signature algorithm\r\n");

        break;
    }

	return err;
}



/********************************/
/*	gciSignVerifyFinish		*/
/********************************/
en_gciResult_t gciSignVerifyFinish( GciCtxId_t ctxID, const uint8_t* p_sign, size_t signLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: Sign Verify Finish\r\n");
#endif

    /* Verify the type of the context */
    if(ga_ctxID[ctxID].type != en_tcCtxType_SignVfy)
    {
        printf("GCI Error in gciSignVerifyFinish: Type of the context not signature verify\r\n");
        err = en_gciResult_Err;
        return err;
    }

    switch(ga_ctxID[ctxID].un_ctxConfig.ctxConfigSign.algo)
    {
        case en_gciSignAlgo_CMAC_AES:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code CMAC\r\n");
#endif

        break;

        case en_gciSignAlgo_DSA:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm DSA\r\n");
#endif

        break;

        case en_gciSignAlgo_ECDSA:
        case en_gciSignAlgo_ECDSA_GF2M:
        case en_gciSignAlgo_ECDSA_GFP:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm ECDSA\r\n");
#endif

        break;


        case en_gciSignAlgo_HMAC:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code HMAC\r\n");
#endif

        break;

        case en_gciSignAlgo_MAC_ISO9797_ALG1:
        case en_gciSignAlgo_MAC_ISO9797_ALG3:

#if GCI_DBG_INFO
            printf("GCI Info: Message Authentication code MAC\r\n");
#endif

        break;


        case en_gciSignAlgo_RSA:
        case en_gciSignAlgo_RSASSA_PKCS:
        case en_gciSignAlgo_RSASSA_PSS:
        case en_gciSignAlgo_RSASSA_X509:

#if GCI_DBG_INFO
            printf("GCI Info: Signature algorithm RSA\r\n");
#endif

        break;


        case en_gciSignAlgo_None:
        case en_gciSignAlgo_Invalid:
        default:

            printf("GCI Error in gciSignVerifyFinish: Invalid signature algorithm\r\n");

        break;
    }



	return err;
}



/**********************************************************************************************************************/
/*		      											KEY GENERATOR			      							  	  */
/**********************************************************************************************************************/

/********************************/
/*	gciKeyPairGen			*/
/********************************/
en_gciResult_t gciKeyPairGen( const st_gciKeyPairConfig_t* p_keyConf, GciKeyId_t* p_pubKeyID, GciKeyId_t* p_privKeyID )
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: Key Pair Gen\r\n");
#endif

	return err;
}



/**********************************************************************************************************************/
/*		      											CIPHERS                     							  	  */
/**********************************************************************************************************************/

/********************************/
/*	 gciCipherNewCtx			*/
/********************************/
en_gciResult_t gciCipherNewCtx( const st_gciCipherConfig_t* p_ciphConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;

	int cipherName;
	int addConfig = 0;

    uint8_t a_allocSymKey[TC_SYM_KEY_SIZE_MAX_BYTES];
    st_gciKey_t symKey = {.type = en_gciKeyType_Sym };

    symKey.un_key.keySym.data = a_allocSymKey;

#if GCI_DBG_INFO
	printf("GCI Info: Cipher New Ctx\r\n");
#endif

	/* Means that we do not have an ID */
	if(*p_ctxID < 0)
	{
	    /* Research a free context ID */
	    err = _searchFreeCtxID(p_ctxID);

	    if(err != en_gciResult_Ok)
	    {
	        printf("GCI Error in gciCipherNewCtx: No context ID free\r\n");

	        return err;
	    }


	    /* Indicate the type of the context */
	    ga_ctxID[*p_ctxID].type = en_tcCtxType_Cipher;

	    /* Save the data */
	    ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigCipher.algo = p_ciphConfig->algo;
	    ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigCipher.blockMode = p_ciphConfig->blockMode;
	    ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigCipher.padding = p_ciphConfig->padding;

	    /* Get the symmetric key with the ID in input */
	    if(p_ciphConfig->algo != en_gciCipherAlgo_RSA)
	    {
	        err = gciKeyGet(keyID, &symKey);

	        if(err != en_gciResult_Ok)
	        {
	            printf("GCI Error in gciCipherNewCtx: Getting the symmetric key\r\n");

	            return err;
	        }

	    }

	    ga_ctxID[*p_ctxID].keyID = keyID;
	}

	else
	{
	    addConfig = 1;
	}


	if(p_ciphConfig->iv.data != NULL)
	{
	    memcpy(&ga_allocIV[*p_ctxID], &p_ciphConfig->iv.data, p_ciphConfig->iv.len);
	    ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigCipher.iv.len = p_ciphConfig->iv.len;

	}



	switch(ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigCipher.algo)
	{
	    /* Symmetric Stream Cipher */
	    case en_gciCipherAlgo_RC4:

#if GCI_DBG_INFO
	        printf("GCI Info: New symmetric cipher context ID %d, with algorithm RC4\r\n", *p_ctxID);
#endif

	        /* Terminate the prng if it's not already done */
	        tmpErr = rc4_done(&ga_cipherRc4[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error: RC4 done\r\n");
	            err = en_gciResult_Err;
	        }

	        /* Start the RC4 prng */
	        tmpErr = rc4_start(&ga_cipherRc4[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherNewCtx: RC4 start\r\n");
	            err = en_gciResult_Err;

	            return err;
	        }

	        /* Add the key */
	        tmpErr = rc4_add_entropy(symKey.un_key.keySym.data, symKey.un_key.keySym.len, &ga_cipherRc4[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherNewCtx: RC4 add key\r\n");
	            err = en_gciResult_Err;

	            return err;
	        }

	        /* Cipher ready */
	        tmpErr = rc4_ready(&ga_cipherRc4[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherNewCtx: RC4 ready\r\n");
	            err = en_gciResult_Err;

	            return err;
	        }

	    break;

	    /* Symmetric Block Cipher */
	    case en_gciCipherAlgo_AES:

#if GCI_DBG_INFO
	        printf("GCI Info: New symmetric cipher ID %d with algorithm AES\r\n", *p_ctxID);
#endif

	        /* Find the cipher */
	        cipherName = find_cipher("aes");

	    break;

	    /* Symmetric Block Cipher */
	    case en_gciCipherAlgo_DES:

#if GCI_DBG_INFO
	        printf("GCI Info: New symmetric cipher ID %d with algorithm DES\r\n", *p_ctxID);
#endif

	        /* Find the cipher */
	        cipherName = find_cipher("des");
	    break;

	    /* Symmetric Block Cipher */
	    case en_gciCipherAlgo_3DES:

#if GCI_DBG_INFO
	        printf("GCI Info: New symmetric cipher ID %d with algorithm 3DES\r\n", *p_ctxID);
#endif

	        /* Find the cipher */
	        cipherName = find_cipher("3des");
	    break;

	    /* Asymmetric cipher */
	    case en_gciCipherAlgo_RSA:

#if GCI_DBG_INFO
            printf("GCI Info: New asymmetric cipher ID %d with algorithm RSA\r\n", *p_ctxID);
#endif

	    break;

	    case en_gciCipherAlgo_Invalid:
	    case en_gciCipherAlgo_None:
	    default:

	        printf("GCI Error in gciCipherNewCtx: Invalid cipher algorithm\r\n");
	        gciCtxRelease(*p_ctxID);

	        err = en_gciResult_Err;

	        return err;
	    break;


	}

	switch(ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigCipher.blockMode)
	{
	    printf("GCI Info: Block mode\r\n");

	    case en_gciBlockMode_CBC:

#if GCI_DBG_INFO
	        printf("GCI Info: Block mode CBC\r\n");
#endif

	        /* Case the context ID was already initialize (>0) before coming in this function */
	        if(addConfig == 1)
	        {
	            tmpErr = cbc_setiv(p_ciphConfig->iv.data, p_ciphConfig->iv.len, &ga_blockModeCBC[*p_ctxID]);

	            if(tmpErr != CRYPT_OK)
                {
                    printf("GCI Error in gciCipherNewCtx: CBC start\r\n");
                    err = en_gciResult_Err;
                }
	        }

	        /* Context ID has been initialized in this function */
	        else
	        {
	            /* Initialize the CBC block mode */
	            tmpErr = cbc_start(cipherName, p_ciphConfig->iv.data, symKey.un_key.keySym.data, symKey.un_key.keySym.len, 0, &ga_blockModeCBC[*p_ctxID]);

	            if(tmpErr != CRYPT_OK)
	            {
	                printf("GCI Error in gciCipherNewCtx: CBC start\r\n");
	                err = en_gciResult_Err;
	            }
	        }



	    break;

	    case en_gciBlockMode_CFB:

#if GCI_DBG_INFO
	        printf("GCI Info: Block mode CFB\r\n");
#endif

	        /* Initialize the CFB block mode */
	        tmpErr = cfb_start(cipherName, p_ciphConfig->iv.data, symKey.un_key.keySym.data, symKey.un_key.keySym.len, 0, &ga_blockModeCFB[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherNewCtx: CFB start\r\n");
	        }

	    break;

	    case en_gciBlockMode_ECB:

#if GCI_DBG_INFO
	        printf("GCI Info: Block mode ECB\r\n");
#endif

	        /* Initialize the ECB block mode */
	        tmpErr = ecb_start(cipherName, symKey.un_key.keySym.data, symKey.un_key.keySym.len, 0, &ga_blockModeECB[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherNewCtx: ECB start\r\n");
	        }

	    break;

	    case en_gciBlockMode_GCM:

#if GCI_DBG_INFO
	        printf("GCI Info: Block mode GCM\r\n");
#endif

	        /* Initialize the GCM block mode */
	        tmpErr = gcm_init(&ga_blockModeGCM[*p_ctxID], cipherName, symKey.un_key.keySym.data, symKey.un_key.keySym.len);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherNewCtx: GCM start\r\n");
	        }

	    break;

	    case en_gciBlockMode_OFB:

#if GCI_DBG_INFO
	        printf("GCI Info: Block mode OFB\r\n");
#endif

	        /* Initialize the OFB block mode */
	        tmpErr = ofb_start(cipherName, p_ciphConfig->iv.data, symKey.un_key.keySym.data, symKey.un_key.keySym.len, 0, &ga_blockModeOFB[*p_ctxID]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherNewCtx: OFB start\r\n");
	        }

	    break;

	    case en_gciBlockMode_None:

#if GCI_DBG_INFO
            printf("GCI Info: No block mode\r\n");
#endif

	    break;

	    case en_gciBlockMode_Invalid:
	    default:

	        printf("GCI Error in gciCipherNewCtx: Invalid block mode\r\n");

	        err = en_gciResult_Err;

	        return err;

	    break;

	}

	return err;
}



/********************************/
/*	gciCipherEncrypt			*/
/********************************/
en_gciResult_t gciCipherEncrypt( GciCtxId_t ctxId, const uint8_t* p_plaintxt, size_t pltxtLen, uint8_t* p_ciphtxt, size_t* p_cptxtLen )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr;
	int bytesRead;

	st_gciKey_t rsaPubKey = {.type = en_gciKeyType_RsaPub };

	uint8_t a_allocRsaPubN[TC_RSA_KEY_SIZE_MAX_BYTES];
	uint8_t a_allocRsaPubE[TC_RSA_KEY_SIZE_MAX_BYTES];

	rsa_key libRsaPubKey = {.type =  PK_PUBLIC};
	mp_int bigNumN, bigNumE;

#if GCI_DBG_INFO
	printf("GCI Info: Cipher Encrypt from context ID %d\r\n", ctxId);
#endif

	/* Verify the type of the context is correct */
	if(ga_ctxID[ctxId].type != en_tcCtxType_Cipher)
	{
	    printf("GCI Error in gciCipherEncrypt: The type of the context is not cipher\r\n");
	    err = en_gciResult_Err;

	    return err;
	}


	switch(ga_ctxID[ctxId].un_ctxConfig.ctxConfigCipher.algo)
	{
	    /* Symmetric Stream cipher */
	    case en_gciCipherAlgo_RC4:

#if GCI_DBG_INFO
	        printf("GCI Info: Symmetric encryption with algorithm RC4\r\n");
#endif

	        /* Copy the input- to the output-buffer */
	        memcpy(p_ciphtxt, p_plaintxt, pltxtLen);

	        p_cptxtLen = &pltxtLen;

	        /* Encrypt */
	        bytesRead = rc4_read(p_ciphtxt, *p_cptxtLen, &ga_cipherRc4[ctxId]);

	        if(bytesRead != *p_cptxtLen)
	        {
	            printf("GCI Error in gciCipherEncrypt: RC4 encrypt\r\n");
	            err = en_gciResult_Err;
	        }

	        else
	        {
#if GCI_DBG_INFO
	            printf("GCI Info: RC4 encrypt %d bytes\r\n", bytesRead);
#endif
	        }

	    break;

	    /* Symmetric Block Cipher */
	    case en_gciCipherAlgo_AES:

#if GCI_DBG_INFO
	        printf("GCI Info: Symmetric encryption with algorithm AES\r\n");
#endif

	    break;

	    /* Symmetric Block Cipher */
	    case en_gciCipherAlgo_DES:

#if GCI_DBG_INFO
	        printf("GCI Info: Symmetric encryption with algorithm DES\r\n");
#endif

	    break;

	    /* Symmetric Block Cipher */
	    case en_gciCipherAlgo_3DES:

#if GCI_DBG_INFO
	        printf("GCI Info: Symmetric encryption with algorithm 3DES\r\n");
#endif

	    break;

	    /* Asymmetric cipher */
	    case en_gciCipherAlgo_RSA:

#if GCI_DBG_INFO
	        printf("GCI Info: Asymmetric encryption with algorithm RSA\r\n");
#endif

	        /* Allocate memory */
	        rsaPubKey.un_key.keyRsaPub.n.data = a_allocRsaPubN;
	        rsaPubKey.un_key.keyRsaPub.e.data = a_allocRsaPubE;
	        mp_init(&bigNumN);
	        mp_init(&bigNumE);

	        /* Get the RSA public key with the saved ID */
	        err = gciKeyGet(ga_ctxID[ctxId].keyID, &rsaPubKey);

	        if(err != en_gciResult_Ok)
	        {
	            printf("GCI Error in gciCipherEncrypt: Cannot get the RSA public key\r\n");
	            return err;
	        }

	        /* Convert the gciKeyType_t to a big number for the rsa_key (from LibTomCrypt) */
	        mp_read_unsigned_bin(&bigNumN, a_allocRsaPubN, rsaPubKey.un_key.keyRsaPub.n.len);
	        mp_read_unsigned_bin(&bigNumE, a_allocRsaPubE, rsaPubKey.un_key.keyRsaPub.e.len);


	        libRsaPubKey.N = &bigNumN;
	        libRsaPubKey.e = &bigNumE;

	        /* Padding */
	        switch(ga_ctxID[ctxId].un_ctxConfig.ctxConfigCipher.padding)
	        {
	            case en_gciPadding_PKCS1_V1_5:

#if GCI_DBG_INFO
	                printf("GCI Info: Padding PKCS1\r\n");
#endif

	                /* Encrypt */
	                tmpErr = rsa_encrypt_key_ex(p_plaintxt, pltxtLen, p_ciphtxt, p_cptxtLen, NULL, 0, &g_fortuna_prng, g_fortunaID, 0, LTC_PKCS_1_V1_5, &libRsaPubKey);

	                if (tmpErr != CRYPT_OK)
	                {
	                    printf("GCI Error in gciCipherEncrypt: PKCS1_V1_5 Encryption\r\n");
	                    err = en_gciResult_Err;
	                }

	                else
	                {
#if GCI_DBG_INFO
	                    printf("GCI Info: Encryption done\r\n");
#endif
	                }

	            break;
	        }

	        /* Free the memory allocated */
	        mp_clear(&bigNumN);
	        mp_clear(&bigNumE);


	    break;


	    case en_gciCipherAlgo_None:
	    case en_gciCipherAlgo_Invalid:
	    default:

	        printf("GCI Error in gciCipherEncrypt: Invalid algorithm\r\n");

	        err = en_gciResult_Err;

	    break;
	}


	/* Block mode for symmetric block cipher */
	switch(ga_ctxID[ctxId].un_ctxConfig.ctxConfigCipher.blockMode)
	{
	    case en_gciBlockMode_CBC:

#if GCI_DBG_INFO
	        printf("GCI Info: CBC block mode encryption\r\n");
#endif

	        /* Encrypt with CBC block mode */
	        tmpErr = cbc_encrypt(p_plaintxt, p_ciphtxt, pltxtLen, &ga_blockModeCBC[ctxId]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherEncrypt: CBC encrypt\r\n");
	            err = en_gciResult_Err;
	        }

	        else
	        {
#if GCI_DBG_INFO
	            printf("GCI Info: CBC encrypt done\r\n");
#endif
	            p_cptxtLen = strlen(p_ciphtxt);
	        }

	    break;

	    case en_gciBlockMode_CFB:

#if GCI_DBG_INFO
	        printf("GCI Info: CFB block mode encryption\r\n");
#endif

	        /* Encrypt with CFB block mode */
	        tmpErr = cfb_encrypt(p_plaintxt, p_ciphtxt, pltxtLen, &ga_blockModeCFB[ctxId]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherEncrypt: CFB encrypt\r\n");
	            err = en_gciResult_Err;
	        }

	        else
	        {
#if GCI_DBG_INFO
	            printf("GCI Info: CFB encrypt done\r\n");
#endif
	            *p_cptxtLen = strlen(p_ciphtxt);
	        }

	    break;

	    case en_gciBlockMode_ECB:

#if GCI_DBG_INFO
	        printf("GCI Info: ECB block mode encryption\r\n");
#endif

	        /* Encrypt with ECB block mode */
	        tmpErr = ecb_encrypt(p_plaintxt, p_ciphtxt, pltxtLen, &ga_blockModeECB[ctxId]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherEncrypt: ECB encrypt\r\n");
	            err = en_gciResult_Err;
	        }

	        else
	        {
#if GCI_DBG_INFO
	            printf("GCI Info: ECB encrypt done\r\n");
#endif
	            *p_cptxtLen = strlen(p_ciphtxt);
	        }

	    break;

	    case en_gciBlockMode_GCM:

#if GCI_DBG_INFO
	        printf("GCI Info: GCM block mode encryption\r\n");
#endif

	        /* Encrypt with GCM block mode */
	        tmpErr = gcm_process(&ga_blockModeGCM[ctxId], p_plaintxt, pltxtLen, p_ciphtxt, GCM_ENCRYPT);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherEncrypt: GCM encrypt\r\n");
	            err = en_gciResult_Err;
	            *p_cptxtLen = -1;
	        }

	        else
	        {
#if GCI_DBG_INFO
	            printf("GCI Info: GCM encrypt done\r\n");
#endif
	            *p_cptxtLen = strlen(p_ciphtxt);
	        }

	    break;

	    case en_gciBlockMode_OFB:

#if GCI_DBG_INFO
	        printf("GCI Info: OFB block mode encryption\r\n");
#endif

	        /* Encrypt with OFB block mode */
	        tmpErr = ofb_encrypt(p_plaintxt, p_ciphtxt, pltxtLen, &ga_blockModeOFB[ctxId]);

	        if(tmpErr != CRYPT_OK)
	        {
	            printf("GCI Error in gciCipherEncrypt: OFB encrypt\r\n");
	            err = en_gciResult_Err;
	            *p_cptxtLen = -1;
	        }

	        else
	        {
#if GCI_DBG_INFO
	            printf("GCI Info: OFB encrypt done\r\n");
#endif
	            *p_cptxtLen = strlen(p_ciphtxt);
	        }


	    break;

	    case en_gciBlockMode_None:

#if GCI_DBG_INFO
            printf("GCI Info: No block mode\r\n");
#endif

        break;

	    case en_gciBlockMode_Invalid:
	    default:

	        printf("GCI Error in gciCipherEncrypt: Invalid block mode\r\n");

	        err = en_gciResult_Err;

	        return err;
	    break;

	}

	return err;
}


/********************************/
/*	gciCipherDecrypt			*/
/********************************/
en_gciResult_t gciCipherDecrypt( GciCtxId_t ctxId, const uint8_t* p_ciphtxt, size_t cptxtLen, uint8_t* p_plaintxt, size_t* p_pltxtLen )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;
	int bytesRead;
    int modulusBitLen;
    int isValid = 0;

	uint8_t a_allocRsaN[TC_RSA_KEY_SIZE_MAX_BYTES];
	uint8_t a_allocRsaPrivD[TC_RSA_KEY_SIZE_MAX_BYTES];
	uint8_t a_allocRsaPubE[TC_RSA_KEY_SIZE_MAX_BYTES];

	st_gciKey_t rsaKey;
	rsa_key libRsaKey;

	mp_int bigNumN, bigNumD, bigNumE;

#if GCI_DBG_INFO
	printf("GCI Info: Cipher Decrypt with context ID %d \r\n", ctxId);
#endif

    /* Verify the type of the context is correct */
    if(ga_ctxID[ctxId].type != en_tcCtxType_Cipher)
    {
        printf("GCI Error in gciCipherDecrypt: The type of the context is not cipher\r\n");
 //       err = en_gciResult_Err;

 //       return err;
    }

    switch(ga_ctxID[ctxId].un_ctxConfig.ctxConfigCipher.algo)
    {
        case en_gciCipherAlgo_RC4:

#if GCI_DBG_INFO
            printf("GCI Info: Symmetric decryption with algorithm RC4\r\n");
#endif


            /* Copy the input- to the output-buffer */
            memcpy(p_plaintxt, p_ciphtxt, cptxtLen);


            /* Decrypt */
            bytesRead = rc4_read(p_plaintxt, cptxtLen, &ga_cipherRc4[ctxId]);

            if(bytesRead != cptxtLen)
            {
                printf("GCI Error in gciCipherDecrypt: RC4 decrypt\r\n");
                err = en_gciResult_Err;
            }

            err = memcmp(p_ciphtxt, p_plaintxt, cptxtLen);

            if(err != 0)
            {
                printf("GCI Error in gciCipherDecrypt: RC4 decrypt -> plaintext = ciphertext\r\n");
            }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: RC4 encrypt %d bytes\r\n", bytesRead);
#endif
            }

        break;

        case en_gciCipherAlgo_AES:

#if GCI_DBG_INFO
            printf("GCI Info: Symmetric decryption with algorithm AES\r\n");
#endif

        break;

        case en_gciCipherAlgo_DES:

#if GCI_DBG_INFO
            printf("GCI Info: Symmetric decryption with algorithm DES\r\n");
#endif

        break;

        case en_gciCipherAlgo_3DES:

#if GCI_DBG_INFO
            printf("GCI Info: Symmetric decryption with algorithm 3DES\r\n");
#endif

        break;

        case en_gciCipherAlgo_RSA:

#if GCI_DBG_INFO
            printf("GCI Info: Asymmetric decryption with algorithm RSA\r\n");
#endif

            /* Allocate memory */
            rsaKey.un_key.keyRsaPriv.n.data = a_allocRsaN;
            rsaKey.un_key.keyRsaPriv.d.data = a_allocRsaPrivD;
            rsaKey.un_key.keyRsaPub.n.data = a_allocRsaN;
            rsaKey.un_key.keyRsaPub.e.data = a_allocRsaPubE;

            mp_init(&bigNumN);
            mp_init(&bigNumD);
            mp_init(&bigNumE);

            /* Padding */
            switch(ga_ctxID[ctxId].un_ctxConfig.ctxConfigCipher.padding)
            {
                case en_gciPadding_PKCS1_V1_5:

#if GCI_DBG_INFO
                    printf("GCI Info: Padding PKCS1 V1_5\r\n");
#endif

                    /* Allocate memory */
                    rsaKey.un_key.keyRsaPriv.n.data = a_allocRsaN;
                    rsaKey.un_key.keyRsaPriv.d.data = a_allocRsaPrivD;

                    mp_init(&bigNumN);
                    mp_init(&bigNumD);

                    rsaKey.type = en_gciKeyType_RsaPriv;
                    libRsaKey.type = PK_PRIVATE;

                    /* Get the RSA private key with the saved ID */
                    err = gciKeyGet(ga_ctxID[ctxId].keyID, &rsaKey);

                    if(err != en_gciResult_Ok)
                    {
                        printf("GCI Error in gciCipherDecrypt: Cannot get the RSA private key\r\n");
                        return err;
                    }

                    /* Convert the gciKeyType_t to a big number for the rsa_key (from LibTomCrypt) */
                    mp_read_unsigned_bin(&bigNumD, a_allocRsaPrivD, rsaKey.un_key.keyRsaPriv.d.len);
                    mp_read_unsigned_bin(&bigNumN, a_allocRsaN, rsaKey.un_key.keyRsaPriv.n.len);

                    libRsaKey.N = &bigNumN;
                    libRsaKey.d = &bigNumD;

                    /* Decrypt with RSA private key */
                    tmpErr = rsa_decrypt_key_ex(p_ciphtxt, cptxtLen, p_plaintxt, p_pltxtLen, 0, &g_fortuna_prng, g_fortunaID, 0, LTC_PKCS_1_V1_5, &libRsaKey);

                    if (tmpErr != CRYPT_OK)
                    {
                        printf("GCI Error in gciCipherDecrypt: PKCS1_V1_5 Decryption\r\n");
                        err = en_gciResult_Err;
                    }

                    else
                    {
#if GCI_DBG_INFO
                        printf("GCI Info: Decryption done\r\n");
#endif
                    }


                break;

                case en_gciPadding_PKCS1_EMSA:

#if GCI_DBG_INFO
                    printf("GCI Info: Padding PKCS1 EMSA\r\n");
#endif

                    /* Decrypt a signature with the RSA public key */

                    /* Allocate memory */
                    rsaKey.un_key.keyRsaPub.n.data = a_allocRsaN;
                    rsaKey.un_key.keyRsaPub.e.data = a_allocRsaPubE;

                    mp_init(&bigNumN);
                    mp_init(&bigNumE);

                    rsaKey.type = en_gciKeyType_RsaPub;
                    libRsaKey.type = PK_PUBLIC;

                    /* Get the RSA public key with the saved ID */
                    err = gciKeyGet(ga_ctxID[ctxId].keyID, &rsaKey);

                    if(err != en_gciResult_Ok)
                    {
                        printf("GCI Error: Cannot get the RSA public key\r\n");
                        return err;
                    }

                    /* Convert the gciKeyType_t to a big number for the rsa_key (from LibTomCrypt) */
                    mp_read_unsigned_bin(&bigNumE, a_allocRsaPubE, rsaKey.un_key.keyRsaPub.e.len);
                    mp_read_unsigned_bin(&bigNumN, a_allocRsaN, rsaKey.un_key.keyRsaPub.n.len);

                    libRsaKey.N = &bigNumN;
                    libRsaKey.e = &bigNumE;

                    modulusBitLen = mp_count_bits(libRsaKey.N);

                    tmpErr = rsa_exptmod(p_ciphtxt, cptxtLen, p_ciphtxt, &cptxtLen, PK_PUBLIC, &libRsaKey);

                    if (tmpErr != CRYPT_OK)
                    {
                        printf("GCI Error in gciCipherDecrypt: Failed to decrypt signature");
                        err = en_gciResult_Err;
                        return err;
                    }

                    else
                    {
#if GCI_DBG_INFO
                        printf("GCI Info: Decrypt signature done\r\n");
#endif
                    }

                    err = pkcs_1_v1_5_decode(p_ciphtxt, cptxtLen, LTC_PKCS_1_EMSA, modulusBitLen, p_plaintxt, p_pltxtLen, &isValid);

                    if (tmpErr != CRYPT_OK)
                    {
                        printf("GCI Error in gciCipherDecrypt: Failed to decode signature");
                        err = en_gciResult_Err;
                        return err;
                    }

                    else
                    {
#if GCI_DBG_INFO
                        printf("GCI Info: Decode signature done\r\n");
#endif
                    }

                break;

                case en_gciPadding_None:
                case en_gciPadding_Invalid:
                default:
                    printf("GCI Error in gciCipherDecrypt: Invalid Padding for RSA\r\n");
                    err = en_gciResult_Err;

                break;

            }

            /* Free the memory allocated */
            mp_clear(&bigNumD);
            mp_clear(&bigNumN);
            mp_clear(&bigNumE);

        break;

        case en_gciCipherAlgo_None:
        case en_gciCipherAlgo_Invalid:
        default:

            printf("GCI Error in gciCipherDecrypt: Invalid algorithm\r\n");

            err = en_gciResult_Err;

        break;

    }

    /* Symmetric cipher block mode */
    switch(ga_ctxID[ctxId].un_ctxConfig.ctxConfigCipher.blockMode)
    {
        case en_gciBlockMode_CBC:

#if GCI_DBG_INFO
            printf("GCI Info: CBC block mode decryption\r\n");
#endif

            /* Decrypt with CBC block mode */
            tmpErr = cbc_decrypt(p_ciphtxt, p_plaintxt, cptxtLen, &ga_blockModeCBC[ctxId]);

            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error in gciCipherDecrypt: CBC decrypt\r\n");
                err = en_gciResult_Err;
                p_pltxtLen = -1;
            }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: CBC decrypt done\r\n");
#endif
                p_pltxtLen = strlen(p_ciphtxt);
            }

        break;


        case en_gciBlockMode_CFB:

#if GCI_DBG_INFO
            printf("GCI Info: CFB block mode decryption\r\n");
#endif

            /* Decrypt with CFB block mode */
            tmpErr = cfb_decrypt(p_ciphtxt, p_plaintxt, cptxtLen, &ga_blockModeCFB[ctxId]);

            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error in gciCipherDecrypt: CFB decrypt\r\n");
                err = en_gciResult_Err;
                p_pltxtLen = -1;
            }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: CFB decrypt done\r\n");
#endif
                p_pltxtLen = strlen(p_ciphtxt);
            }


        break;


        case en_gciBlockMode_ECB:

#if GCI_DBG_INFO
            printf("GCI Info: ECB block mode decryption\r\n");
#endif

            /* Decrypt with ECB block mode */
            tmpErr = ecb_decrypt(p_ciphtxt, p_plaintxt, cptxtLen, &ga_blockModeECB[ctxId]);

            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error in gciCipherDecrypt: ECB decrypt\r\n");
                err = en_gciResult_Err;
                p_pltxtLen = -1;
            }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: ECB decrypt done\r\n");
#endif
                p_pltxtLen = strlen(p_ciphtxt);
            }

        break;


        case en_gciBlockMode_GCM:

#if GCI_DBG_INFO
            printf("GCI Info: GCM block mode decryption\r\n");
#endif

            /* Decrypt with GCM block mode */
            tmpErr = gcm_process(&ga_blockModeGCM[ctxId], p_ciphtxt, cptxtLen, p_plaintxt, GCM_DECRYPT);

            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error in gciCipherDecrypt: GCM decrypt\r\n");
                err = en_gciResult_Err;
                p_pltxtLen = -1;
            }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: GCM decrypt done\r\n");
#endif
                p_pltxtLen = strlen(p_ciphtxt);
            }

        break;


        case en_gciBlockMode_OFB:

#if GCI_DBG_INFO
            printf("GCI Info: OFB block mode decryption\r\n");
#endif

            /* Decrypt with OFB block mode */
            tmpErr = ofb_decrypt(p_ciphtxt, p_plaintxt, cptxtLen, &ga_blockModeECB[ctxId]);

            if(tmpErr != CRYPT_OK)
            {
                printf("GCI Error in gciCipherDecrypt: OFB decrypt\r\n");
                err = en_gciResult_Err;
                p_pltxtLen = -1;
            }

            else
            {
#if GCI_DBG_INFO
                printf("GCI Info: OFB decrypt done\r\n");
#endif
                p_pltxtLen = strlen(p_ciphtxt);
            }

        break;


        case en_gciBlockMode_None:

#if GCI_DBG_INFO
            printf("GCI Info: No block mode\r\n");
#endif

        break;


        case en_gciBlockMode_Invalid:
        default:

            printf("GCI Error in gciCipherDecrypt: Invalid block mode\r\n");

            err = en_gciResult_Err;

        break;

    }


	return err;
}



/**********************************************************************************************************************/
/*		    										 RANDOM NUMBER                 				    			      */
/**********************************************************************************************************************/

/********************************/
/*	gciRngGen					*/
/********************************/
en_gciResult_t gciRngGen( int rdmNb, uint8_t* p_rdmBuf )
{
	en_gciResult_t err = en_gciResult_Ok;
	int len;

#if GCI_DBG_INFO
	printf("GCI Info: Rng Gen\r\n");
#endif

	/* Read the prng initialize in gciInit() */
	len = fortuna_read(p_rdmBuf, rdmNb, &g_fortuna_prng);

	if(len != rdmNb)
	{
	    printf("GCI Error in gciRngGen: Rng Gen\r\n");
	    err = en_gciResult_Err;
	}

	else
	{
#if GCI_DBG_INFO
	    printf("GCI Info: Rng Gen done\r\n");
#endif
	}

	return err;
}



/********************************/
/*	gciRngSeed				    */
/********************************/
en_gciResult_t gciRngSeed( const uint8_t* p_sdBuf, size_t sdLen )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;

#if GCI_DBG_INFO
	printf("GCI Info: Rng Seed\r\n");
#endif

    while (sdLen > 0)
    {
        tmpErr = fortuna_add_entropy(p_sdBuf, ((sdLen > 32) ? 32 : sdLen), &g_fortuna_prng);
        if( tmpErr != CRYPT_OK)
        {
            printf("GCI Error in gciRngSeed: Rng seed\r\n");
            err = en_gciResult_Err;
            return err;
        }
        sdLen -= 32;
    }

#if GCI_DBG_INFO
    printf("GCI Info: Rng seed done\r\n");
#endif

	return err;
}



/**********************************************************************************************************************/
/*		    										 Diffie-Hellmann                 				    			  */
/**********************************************************************************************************************/

/********************************/
/*	gciDhNewCtx				    */
/********************************/
en_gciResult_t gciDhNewCtx( const st_gciDhConfig_t* p_dhConfig, GciCtxId_t* p_ctxID )
{
    en_gciResult_t err = en_gciResult_Ok;

	uint8_t a_allocDhKey[GCI_BUFFER_MAX_SIZE];

	/* Variable to a better visibility */
	uint8_t* p_p;
	uint8_t* p_g;
	size_t pLen;
	size_t gLen;


	err = _searchFreeCtxID(p_ctxID);

	if(err != en_gciResult_Ok)
	{
		printf("GCI Error in gciDhNewCtx: No context ID free\r\n");

		return err;
	}

	/* Indicate the type of the context */
	ga_ctxID[*p_ctxID].type = en_tcCtxType_Dh;


	/* Save the configuration */
	ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.type = p_dhConfig->type;

	switch((*p_dhConfig).type)
	{
		case en_gciDhType_Dh:

#if GCI_DBG_INFO
			printf("GCI Info: DH context ID = %d\r\n", *p_ctxID);
#endif

			/* Allocate memory */

			/* Diffie-Hellmann domain parameters length */
			ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain = ga_allocDhDomainParam;
			/* Diffie-Hellmann domain parameter g */
			ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.data = ga_allocDhDomainG;
			/* Diffie-Hellmann domain parameter p */
			ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.data = ga_allocDhDomainP;

			p_p = ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.data;
			p_g = ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.data;


			/* Init the buffer */
			memset(p_p, 0 , GCI_BUFFER_MAX_SIZE/2);
			memset(p_g, 0 , GCI_BUFFER_MAX_SIZE/2);


			/* Save the parameters if different to NULL*/
			if(p_dhConfig->un_dhParam.dhParamDomain != NULL)
			{
			    memcpy(ga_allocDhDomainG, p_dhConfig->un_dhParam.dhParamDomain->g.data, p_dhConfig->un_dhParam.dhParamDomain->g.len);
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.len = p_dhConfig->un_dhParam.dhParamDomain->g.len;

				memcpy(p_p, p_dhConfig->un_dhParam.dhParamDomain->p.data, p_dhConfig->un_dhParam.dhParamDomain->p.len);
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.len = p_dhConfig->un_dhParam.dhParamDomain->p.len;

#if GCI_DBG_INFO
				printf("GCI Info: copy DH domain parameters done\r\n");
#endif
			}

			/* Create the domain parameters */
			else
			{
			    /* Generate Diffie-Hellmann domain parameters */
				err = _genDhDomainParam(p_g, &gLen, p_p, &pLen);

				/*Save the length */
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.len = pLen;;
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.len = gLen;;

				if(err != en_gciResult_Ok)
				{
					printf("GCI Error in gciDhNewCtx: DH gen domain parameters\r\n");
				}

				else
				{
#if GCI_DBG_INFO
					printf("GCI Info: DH gen domain parameters done\r\n");
#endif
				}
			}

		break;

		case en_gciDhType_Ecdh:

#if GCI_DBG_INFO
			printf("GCI Info: ECDH context ID = %d\r\n", *p_ctxID);
#endif

			/* Allocate memory */
			//ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = &ga_allocEcdhCurveName[*p_ctxID];

			/* Save the parameters if different to NULL*/
			if(p_dhConfig->un_dhParam.dhParamDomain != NULL)
			{
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = p_dhConfig->un_dhParam.dhParamCurveName;
			}

			/* Create the domain parameters */
			else
			{
				/* Choose a default elliptic curve */
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = en_gciNamedCurve_SECP384R1;
			}

		break;

		case en_gciDhType_Invalid:
		default:

			printf("GCI Error in gciDhNewCtx: Invalid or unknown configuration\r\n");

			err = gciCtxRelease(*p_ctxID);

			if (err == en_gciResult_Ok)
			{
#if GCI_DBG_INFO
				printf("GCI Info: Context releases\r\n");
#endif
			}

			else
			{
				printf("GCI Error in gciDhNewCtx: Context releases\r\n");

			}

			err = en_gciResult_Err;

		break;

	}

	return err;
}



/********************************/
/*	gciDhGenKey				    */
/********************************/
en_gciResult_t gciDhGenKey( GciCtxId_t ctxID, GciKeyId_t* p_pubKeyID )
{
	en_gciResult_t err = en_gciResult_Ok;

	/* Compare the type of the context */
	if(ga_ctxID[ctxID].type != en_tcCtxType_Dh)
	{
		err = en_gciResult_Err;
		printf("GCI Error in gciDhGenKey: Context Type not DH\r\n");

		return err;
	}

	switch(ga_ctxID[ctxID].un_ctxConfig.ctxConfigDh.type)
	{
		case en_gciDhType_Dh:

#if GCI_DBG_INFO
			printf("GCI Info: DH Gen Key with context ID %d\r\n", ctxID);
#endif

			err = _genDhKeyPair(ctxID, p_pubKeyID);

			if(err == en_gciResult_Ok)
			{
#if GCI_DBG_INFO
			    printf("GCI Info: DH generate key pair done\r\n");
#endif
			}

			else
			{
			    printf("GCI Error in gciDhGenKey: DH generate key pair\r\n");
			}

		break;


		case en_gciDhType_Ecdh:

#if GCI_DBG_INFO
			printf("GCI Info: ECDH Gen Key\r\n");
#endif

			err = _genEchKeyPair(ctxID, p_pubKeyID);

            if(err == en_gciResult_Ok)
            {
#if GCI_DBG_INFO
                printf("GCI Info: ECDH generate key pair done\r\n");
#endif
            }

            else
            {
                printf("GCI Error in gciDhGenKey: ECDH generate key pair\r\n");
            }




		break;


		case en_gciDhType_Invalid:
		default:

		    printf("GCI Error in gciDhGenKey: Invalid DH type\r\n");

		break;

	}

	return err;
}



/********************************/
/*	gciDhCalcSharedSecret	*/
/********************************/
en_gciResult_t gciDhCalcSharedSecret( GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* p_secretKeyID )
{
	en_gciResult_t err = en_gciResult_Ok;

    /* Compare the type of the context */
    if(ga_ctxID[ctxID].type != en_tcCtxType_Dh)
    {
        err = en_gciResult_Err;
        printf("GCI Error in gciDhCalcSharedSecret: Context Type not DH\r\n");

        return err;
    }

    switch(ga_ctxID[ctxID].un_ctxConfig.ctxConfigDh.type)
    {
        case en_gciDhType_Dh:

#if GCI_DBG_INFO
            printf("GCI Info: Calculation of DH secret key\r\n");
#endif

            err = _calcDhSecret(ctxID, pubKeyID, p_secretKeyID);

            if(err == en_gciResult_Ok)
            {
#if GCI_DBG_INFO
                printf("GCI Info: DH secret key calculated\r\n");
#endif
            }

            else
            {
                printf("GCI Error in gciDhCalcSharedSecret: Calculate DH secret key\r\n");
            }

        break;


        case en_gciDhType_Ecdh:

            err = _calcEcdhSecret(ctxID, pubKeyID, p_secretKeyID);

            if(err == en_gciResult_Ok)
            {
#if GCI_DBG_INFO
                printf("GCI Info: ECDH secret key calculated\r\n");
#endif
            }

            else
            {
                printf("GCI Error in gciDhCalcSharedSecret: Calculate ECDH secret key\r\n");
            }

        break;


        case en_gciDhType_Invalid:
        default:

            printf("GCI Error in gciDhCalcSharedSecret: Invalid DH type\r\n");
            err = en_gciResult_Err;

        break;
    }


	return err;
}



/**********************************************************************************************************************/
/*		      										KEY				 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gciKeyPut					*/
/********************************/
en_gciResult_t gciKeyPut( const st_gciKey_t* p_key, GciKeyId_t* p_keyID )
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: Key Put\r\n");
#endif

	/* Search a free key ID */
	err = _searchFreeKeyID( p_keyID );

	if(err != en_gciResult_Ok)
	{
		printf("GCI Error in gciKeyPut: No key ID free\r\n");
		return err;
	}

	/* Save the type of the key */
	ga_keyID[*p_keyID].type = p_key->type;

	/* Store the key as big number in the key array */
	switch(p_key->type)
	{
		case en_gciKeyType_Sym:

#if GCI_DBG_INFO
			printf("GCI Info: sym key ID = %d\r\n", *p_keyID);
#endif

			/* Save the data */

			ga_keyID[*p_keyID].type = p_key->type;

			memcpy(&ga_allocSymKey[*p_keyID], p_key->un_key.keySym.data, p_key->un_key.keySym.len);
			ga_keyID[*p_keyID].un_key.keySym.len = p_key->un_key.keySym.len;

		break;


		case en_gciKeyType_DhPriv:

#if GCI_DBG_INFO
			printf("GCI Info: DH priv key not implemented\r\n", *p_keyID);
#endif

		break;


		case en_gciKeyType_DhPub:

#if GCI_DBG_INFO
			printf("GCI Info: DH pub key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */

            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocDhPubKey[*p_keyID], p_key->un_key.keyDhPub.key.data, p_key->un_key.keyDhPub.key.len);

            ga_keyID[*p_keyID].un_key.keyDhPub.key.len = p_key->un_key.keyDhPub.key.len;


		break;


		case en_gciKeyType_DhSecret:

#if GCI_DBG_INFO
			printf("GCI Info: DH secret key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */

            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocDhSecretKey[*p_keyID], p_key->un_key.keyDhSecret.data, p_key->un_key.keyDhSecret.len);

            ga_keyID[*p_keyID].un_key.keyDhSecret.len = p_key->un_key.keyDhSecret.len;

		break;


		case en_gciKeyType_DsaPriv:

#if GCI_DBG_INFO
			printf("GCI Info: DSA priv key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */

            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocDsaPrivKey[*p_keyID], p_key->un_key.keyDsaPriv.key.data, p_key->un_key.keyDsaPriv.key.len);

            ga_keyID[*p_keyID].un_key.keyDsaPriv.key.len = p_key->un_key.keyDsaPriv.key.len;

		break;


		case en_gciKeyType_DsaPub:

#if GCI_DBG_INFO
			printf("GCI Info: DSA pub key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */

            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocDsaPubKey[*p_keyID], p_key->un_key.keyDsaPub.key.data, p_key->un_key.keyDsaPub.key.len);

            ga_keyID[*p_keyID].un_key.keyDsaPub.key.len = p_key->un_key.keyDsaPub.key.len;

		break;


		case en_gciKeyType_EcdhPriv:

#if GCI_DBG_INFO
			printf("GCI Info: ECDH priv key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */
            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocEcdhPrivKey[*p_keyID], p_key->un_key.keyEcdhPriv.key.data, p_key->un_key.keyEcdhPriv.key.len);

            ga_keyID[*p_keyID].un_key.keyEcdhPriv.key.len = p_key->un_key.keyEcdhPriv.key.len;

		break;


		case en_gciKeyType_EcdhPub:

#if GCI_DBG_INFO
			printf("GCI Info: ECDH pub key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */
            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocEcdhPubCoordX[*p_keyID], p_key->un_key.keyEcdhPub.coord.x.data, p_key->un_key.keyEcdhPub.coord.x.len);
            ga_keyID[*p_keyID].un_key.keyEcdhPub.coord.x.len = p_key->un_key.keyEcdhPub.coord.x.len;

            memcpy(&ga_allocEcdhPubCoordY[*p_keyID], p_key->un_key.keyEcdhPub.coord.y.data, p_key->un_key.keyEcdhPub.coord.y.len);
            ga_keyID[*p_keyID].un_key.keyEcdhPub.coord.y.len = p_key->un_key.keyEcdhPub.coord.y.len;


		break;


		case en_gciKeyType_EcdhSecret:

#if GCI_DBG_INFO
			printf("GCI Info: ECDH secret key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */
            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocEcdhSecretKey[*p_keyID], p_key->un_key.keyEcdhSecret.data, p_key->un_key.keyEcdhSecret.len);

            ga_keyID[*p_keyID].un_key.keyEcdhSecret.len = p_key->un_key.keyEcdhSecret.len;

		break;


		case en_gciKeyType_EcdsaPriv:

#if GCI_DBG_INFO
			printf("GCI Info: ECDSA priv key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */
            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocEcdsaPrivKey[*p_keyID],  p_key->un_key.keyEcdsaPriv.key.data,  p_key->un_key.keyEcdsaPriv.key.len);

            ga_keyID[*p_keyID].un_key.keyEcdsaPriv.key.len =  p_key->un_key.keyEcdsaPriv.key.len;

		break;


		case en_gciKeyType_EcdsaPub:

#if GCI_DBG_INFO
			printf("GCI Info: ECDSA pub key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */
            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocEcdsaPubCoordX[*p_keyID], p_key->un_key.keyEcdsaPub.coord.x.data, p_key->un_key.keyEcdsaPub.coord.x.len);
            ga_keyID[*p_keyID].un_key.keyEcdsaPub.coord.x.len = p_key->un_key.keyEcdsaPub.coord.x.len;

            memcpy(&ga_allocEcdsaPubCoordY[*p_keyID], p_key->un_key.keyEcdsaPub.coord.y.data, p_key->un_key.keyEcdsaPub.coord.y.len);
            ga_keyID[*p_keyID].un_key.keyEcdsaPub.coord.y.len = p_key->un_key.keyEcdsaPub.coord.y.len;

		break;


		case en_gciKeyType_Hmac:

#if GCI_DBG_INFO
			printf("GCI Info: HMAC key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */
            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocSymKey[*p_keyID], p_key->un_key.keySym.data, p_key->un_key.keySym.len);
            ga_keyID[*p_keyID].un_key.keySym.len = p_key->un_key.keySym.len;

		break;


		case en_gciKeyType_RsaPriv:
		case en_gciKeyType_RsaPrivEs:
		case en_gciKeyType_RsaPrivSsa:

#if GCI_DBG_INFO
			printf("GCI Info: RSA priv key ID = %d\r\n", *p_keyID);
#endif

            /* Save the data */
            ga_keyID[*p_keyID].type = p_key->type;

            memcpy(&ga_allocRsaPrivD[*p_keyID], p_key->un_key.keyRsaPriv.d.data, p_key->un_key.keyRsaPriv.d.len);
            ga_keyID[*p_keyID].un_key.keyRsaPriv.d.len = p_key->un_key.keyRsaPriv.d.len;

            memcpy(&ga_allocRsaN[*p_keyID], p_key->un_key.keyRsaPriv.n.data, p_key->un_key.keyRsaPriv.n.len);
            ga_keyID[*p_keyID].un_key.keyRsaPriv.n.len = p_key->un_key.keyRsaPriv.n.len;

		break;


		case en_gciKeyType_RsaPub:
		case en_gciKeyType_RsaPubEs:
		case en_gciKeyType_RsaPubSsa:
#if GCI_DBG_INFO
			printf("GCI Info: RSA pub key ID = %d\r\n", *p_keyID);
#endif

			/* Save the data */

			ga_keyID[*p_keyID].type = p_key->type;

			memcpy(&ga_allocRsaPubE[*p_keyID], p_key->un_key.keyRsaPub.e.data, p_key->un_key.keyRsaPub.e.len);
			ga_keyID[*p_keyID].un_key.keyRsaPub.e.len = p_key->un_key.keyRsaPub.e.len;

			memcpy(&ga_allocRsaN[*p_keyID], p_key->un_key.keyRsaPub.n.data, p_key->un_key.keyRsaPub.n.len);
			ga_keyID[*p_keyID].un_key.keyRsaPub.n.len = p_key->un_key.keyRsaPub.n.len;

		break;



		case en_gciKeyType_Invalid:
		case en_gciKeyType_None:

			printf("GCI Error in gciKeyPut: No key type initialized\r\n");

		break;
		default:

			printf("GCI Error in gciKeyPut: key type not exist\r\n");

		break;
	}


	return err;
}



/********************************/
/*	gciKeyGet					*/
/********************************/
en_gciResult_t gciKeyGet( GciKeyId_t keyID, st_gciKey_t* p_key )
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: Key Get from ID %d\r\n", keyID);
#endif


	/* Store the key as big number in the key array */
	switch(ga_keyID[keyID].type)
	{
	    case en_gciKeyType_Sym:

#if GCI_DBG_INFO
	        printf("GCI Info: Symmetric key\r\n");
#endif

	        /* Copy the type of the key */
	        p_key->type = ga_keyID[keyID].type;

	        /* Copy of the key */
	        if(p_key->un_key.keySym.data == NULL)
	        {
	            printf("GCI Error in gciKeyGet: pointer of the data for the key is NULL\r\n");
	            p_key->un_key.keySym.len = -1;
	            err = en_gciResult_Err;
	        }

	        else
	        {
	            memcpy(p_key->un_key.keySym.data, &ga_allocSymKey[keyID], ga_keyID[keyID].un_key.keySym.len);
	            p_key->un_key.keySym.len = ga_keyID[keyID].un_key.keySym.len;

#if GCI_DBG_INFO
	            printf("GCI Info: Symmetric key copied\r\n");
#endif
	        }

	    break;


	    case en_gciKeyType_DhPriv:

            printf("GCI Error in gciKeyGet: DH private key copy not possible\r\n");

	    break;


	    case en_gciKeyType_DhPub:

#if GCI_DBG_INFO
            printf("GCI Info: DH public key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            /* Copy of the key */
            if(p_key->un_key.keyDhPub.key.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the key is NULL\r\n");
                p_key->un_key.keyDhPub.key.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyDhPub.key.data, &ga_allocDhPubKey[keyID], ga_keyID[keyID].un_key.keyDhPub.key.len);
                p_key->un_key.keyDhPub.key.len = ga_keyID[keyID].un_key.keyDhPub.key.len;

#if GCI_DBG_INFO
                printf("GCI Info: DH public key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_DhSecret:

#if GCI_DBG_INFO
            printf("GCI Info: DH secret key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            /* Copy of the key */
            if(p_key->un_key.keyDhSecret.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data is NULL\r\n");
                p_key->un_key.keyDhSecret.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyDhSecret.data, &ga_allocDhSecretKey[keyID], ga_keyID[keyID].un_key.keyDhSecret.len);
                p_key->un_key.keyDhSecret.len = ga_keyID[keyID].un_key.keyDhSecret.len;

#if GCI_DBG_INFO
                printf("GCI Info: DH secret key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_DsaPriv:

#if GCI_DBG_INFO
            printf("GCI Info: DSA private key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            /* Copy of the key */
            if(p_key->un_key.keyDsaPriv.key.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the key is NULL\r\n");
                p_key->un_key.keyDsaPriv.key.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyDsaPriv.key.data, &ga_allocDsaPrivKey[keyID], ga_keyID[keyID].un_key.keyDsaPriv.key.len);
                p_key->un_key.keyDsaPriv.key.len = ga_keyID[keyID].un_key.keyDsaPriv.key.len;

#if GCI_DBG_INFO
                printf("GCI Info: DSA private key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_DsaPub:

#if GCI_DBG_INFO
            printf("GCI Info: DSA public key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            /* Copy of the key */
            if(p_key->un_key.keyDsaPub.key.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the key is NULL\r\n");
                p_key->un_key.keyDsaPub.key.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyDsaPub.key.data, &ga_allocDsaPubKey[keyID], ga_keyID[keyID].un_key.keyDsaPub.key.len);
                p_key->un_key.keyDsaPub.key.len = ga_keyID[keyID].un_key.keyDsaPub.key.len;

#if GCI_DBG_INFO
                printf("GCI Info: DSA private key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_EcdhPriv:

#if GCI_DBG_INFO
            printf("GCI Info: ECDH private key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            /* Copy of the key */
            if(p_key->un_key.keyEcdhPriv.key.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the key is NULL\r\n");
                p_key->un_key.keyEcdhPriv.key.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyEcdhPriv.key.data, &ga_allocEcdhPrivKey[keyID], ga_keyID[keyID].un_key.keyEcdhPriv.key.len);
                p_key->un_key.keyEcdhPriv.key.len = ga_keyID[keyID].un_key.keyEcdhPriv.key.len;

#if GCI_DBG_INFO
                printf("GCI Info: ECDH private key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_EcdhPub:

#if GCI_DBG_INFO
            printf("GCI Info: ECDH public key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            /* Copy of the key */
            if(p_key->un_key.keyEcdhPub.coord.x.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the x-coordinate is NULL\r\n");
                p_key->un_key.keyEcdhPub.coord.x.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyEcdhPub.coord.x.data, &ga_allocEcdhPubCoordX[keyID], ga_keyID[keyID].un_key.keyEcdhPub.coord.x.len);
                p_key->un_key.keyEcdhPub.coord.x.len = ga_keyID[keyID].un_key.keyEcdhPub.coord.x.len;
            }

            if(p_key->un_key.keyEcdhPub.coord.y.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the y-coordinate is NULL\r\n");
                p_key->un_key.keyEcdhPub.coord.y.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyEcdhPub.coord.y.data, &ga_allocEcdhPubCoordY[keyID], ga_keyID[keyID].un_key.keyEcdhPub.coord.y.len);
                p_key->un_key.keyEcdhPub.coord.y.len = ga_keyID[keyID].un_key.keyEcdhPub.coord.y.len;
            }

            if((p_key->un_key.keyEcdhPub.coord.x.data != NULL) && (p_key->un_key.keyEcdhPub.coord.y.data != NULL))
            {
#if GCI_DBG_INFO
                printf("GCI Info: ECDH public key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_EcdhSecret:

#if GCI_DBG_INFO
            printf("GCI Info: ECDH secret key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            /* Copy of the key */
            if(p_key->un_key.keyEcdhSecret.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data is NULL\r\n");
                p_key->un_key.keyEcdhSecret.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyEcdhSecret.data, &ga_allocEcdhSecretKey[keyID], ga_keyID[keyID].un_key.keyEcdhSecret.len);
                p_key->un_key.keyEcdhSecret.len = ga_keyID[keyID].un_key.keyEcdhSecret.len;

#if GCI_DBG_INFO
                printf("GCI Info: ECDH secret key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_EcdsaPriv:

#if GCI_DBG_INFO
            printf("GCI Info: ECDSA public key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            if(p_key->un_key.keyEcdsaPriv.key.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the key is NULL\r\n");
                p_key->un_key.keyEcdsaPriv.key.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyEcdsaPriv.key.data, &ga_allocEcdsaPrivKey[keyID], ga_keyID[keyID].un_key.keyEcdsaPriv.key.len);
                p_key->un_key.keyEcdsaPriv.key.len = ga_keyID[keyID].un_key.keyEcdsaPriv.key.len;

#if GCI_DBG_INFO
                printf("GCI Info: ECDSA private key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_EcdsaPub:

#if GCI_DBG_INFO
            printf("GCI Info: ECDSA public key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            if(p_key->un_key.keyEcdsaPub.coord.x.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the x-coordinate is NULL\r\n");
                p_key->un_key.keyEcdsaPub.coord.x.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyEcdsaPub.coord.x.data, &ga_allocEcdsaPubCoordX[keyID], ga_keyID[keyID].un_key.keyEcdsaPub.coord.x.len);
                p_key->un_key.keyEcdsaPub.coord.x.len = ga_keyID[keyID].un_key.keyEcdsaPub.coord.x.len;
            }

            if(p_key->un_key.keyEcdsaPub.coord.y.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the y-coordinate is NULL\r\n");
                p_key->un_key.keyEcdsaPub.coord.y.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyEcdsaPub.coord.y.data, &ga_allocEcdsaPubCoordY[keyID], ga_keyID[keyID].un_key.keyEcdsaPub.coord.y.len);
                p_key->un_key.keyEcdsaPub.coord.y.len = ga_keyID[keyID].un_key.keyEcdsaPub.coord.y.len;
            }

            if((p_key->un_key.keyEcdsaPub.coord.x.data != NULL) && (p_key->un_key.keyEcdsaPub.coord.y.data != NULL))
            {
#if GCI_DBG_INFO
                printf("GCI Info: ECDSA public key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_Hmac:

#if GCI_DBG_INFO
            printf("GCI Info: HMAC key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            /* Copy of the key */
            if(p_key->un_key.keySym.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the key is NULL\r\n");
                p_key->un_key.keySym.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keySym.data, &ga_allocSymKey[keyID], ga_keyID[keyID].un_key.keySym.len);
                p_key->un_key.keySym.len = ga_keyID[keyID].un_key.keySym.len;

#if GCI_DBG_INFO
                printf("GCI Info: HMAC key copied\r\n");
#endif
            }

	    break;


	    case en_gciKeyType_RsaPriv:
	    case en_gciKeyType_RsaPrivEs:
	    case en_gciKeyType_RsaPrivSsa:

#if GCI_DBG_INFO
            printf("GCI Info: RSA private key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

            /* Copy of the key */
            if(p_key->un_key.keyRsaPriv.d.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the exponent (d) is NULL\r\n");
                p_key->un_key.keyRsaPriv.d.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyRsaPriv.d.data, &ga_allocRsaPrivD[keyID], ga_keyID[keyID].un_key.keyRsaPriv.d.len);
                p_key->un_key.keyRsaPriv.d.len = ga_keyID[keyID].un_key.keyRsaPriv.d.len;
            }

            /* Copy modulus (n) */
            if(p_key->un_key.keyRsaPriv.n.data == NULL)
            {
                printf("GCI Error in gciKeyGet: pointer of the data for the modulus (n) is NULL\r\n");
                p_key->un_key.keyRsaPriv.n.len = -1;
                err = en_gciResult_Err;
            }

            else
            {
                memcpy(p_key->un_key.keyRsaPriv.n.data, &ga_allocRsaN[keyID], ga_keyID[keyID].un_key.keyRsaPriv.n.len);
                p_key->un_key.keyRsaPriv.n.len = ga_keyID[keyID].un_key.keyRsaPriv.n.len;
            }

            /* All is copied */
            if((p_key->un_key.keyRsaPriv.d.data != NULL) && (p_key->un_key.keyRsaPriv.n.data != NULL))
            {
#if GCI_DBG_INFO
                printf("GCI Info: Private key copied\r\n");
#endif

            }

	    break;


	    case en_gciKeyType_RsaPub:
	    case en_gciKeyType_RsaPubEs:
	    case en_gciKeyType_RsaPubSsa:

#if GCI_DBG_INFO
	        printf("GCI Info: RSA public key\r\n");
#endif

            /* Copy the type of the key */
            p_key->type = ga_keyID[keyID].type;

	        /* Copy exponent (e) */
	        if(p_key->un_key.keyRsaPub.e.data == NULL)
	        {
	            printf("GCI Error in gciKeyGet: pointer of the data for the exponent (e) is NULL\r\n");
	            p_key->un_key.keyRsaPub.e.len = -1;
	            err = en_gciResult_Err;
	        }

	        else
	        {
	            memcpy(p_key->un_key.keyRsaPub.e.data, &ga_allocRsaPubE[keyID], ga_keyID[keyID].un_key.keyRsaPub.e.len);
	            p_key->un_key.keyRsaPub.e.len = ga_keyID[keyID].un_key.keyRsaPub.e.len;
	        }

	        /* Copy modulus (n) */
	        if(p_key->un_key.keyRsaPub.n.data == NULL)
	        {
	            printf("GCI Error in gciKeyGet: pointer of the data for the modulus (n) is NULL\r\n");
	            p_key->un_key.keyRsaPub.n.len = -1;
	            err = en_gciResult_Err;
	        }

	        else
	        {
	            memcpy(p_key->un_key.keyRsaPub.n.data, &ga_allocRsaN[keyID], ga_keyID[keyID].un_key.keyRsaPub.n.len);
	            p_key->un_key.keyRsaPub.n.len = ga_keyID[keyID].un_key.keyRsaPub.n.len;
	        }

	        /* All is copied */
	        if((p_key->un_key.keyRsaPub.e.data != NULL) && (p_key->un_key.keyRsaPub.n.data != NULL))
	        {
#if GCI_DBG_INFO
	            printf("GCI Info: Public key copied\r\n");
#endif
	        }

	    break;



	    case en_gciKeyType_Invalid:
	    case en_gciKeyType_None:

	        printf("GCI Error in gciKeyGet: No key initialized\r\n");

	    break;
	    default:

	        printf("GCI Error in gciKeyGet: key does not exist\r\n");

	    break;
	}

	return err;
}



/********************************/
/*	gciKeyDelete				*/
/********************************/
en_gciResult_t gciKeyDelete( GciKeyId_t keyID  )
{
	en_gciResult_t err = en_gciResult_Ok;

#if GCI_DBG_INFO
	printf("GCI Info: Key Delete from ID: %d\r\n", keyID);
#endif


	err = _keyRelease(&ga_keyID[keyID]);

	if(err != en_gciResult_Ok)
	{
	    printf("GCI Error in gciKeyDelete: Key delete\r\n");
	}

	else
	{
#if GCI_DBG_INFO
	    printf("GCI Info: Key delete done\r\n");
#endif
	}

	return err;
}


/*---------------------------------------------local functions----------------------------------------------------------*/

/********************************/
/*	_searchFreeCtxID			*/
/********************************/
en_gciResult_t _searchFreeCtxID( GciCtxId_t* p_ctxID )
{
	en_gciResult_t err = en_gciResult_Ok;

	/* Initialize the context ID */
	*p_ctxID = -1;

	int i = 0;

	for( i = 0 ; i < GCI_NB_CTX_MAX ; i++ )
	{
		/* Free ctx ID when type is invalid */
		if( ga_ctxID[i].type == en_tcCtxType_Invalid )
		{
			*p_ctxID = i;

			return err;
		}
	}

	/* No free ID */
	if(*p_ctxID == -1)
	{
		err = en_gciResult_Err;
	}


	return err;
}


/********************************/
/*  _ctxRelease                 */
/********************************/
en_gciResult_t _ctxRelease( st_tcCtxConfig_t* ctx)
{
    en_gciResult_t err = en_gciResult_Ok;

    ctx->type = en_tcCtxType_Invalid;

    /* TODO sw - memset of 0 for each pointer (if possible) and write NULL */
    /* TODO sw - initialize all global array with 0 */

    /* Hash */
    ctx->un_ctxConfig.ctxConfigHash = en_gciHashAlgo_Invalid;

    /* Signature */
    ctx->un_ctxConfig.ctxConfigSign.algo = en_gciSignAlgo_Invalid;
    ctx->un_ctxConfig.ctxConfigSign.hash = en_gciHashAlgo_Invalid;
    ctx->un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.block = en_gciBlockMode_Invalid;
    ctx->un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.iv.len = -1;
    ctx->un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.iv.data = NULL;
    ctx->un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.padding = en_gciPadding_Invalid;
    ctx->un_ctxConfig.ctxConfigSign.un_signConfig.signConfigRsa.padding = en_gciPadding_Invalid;

    /* Cipher */
    ctx->un_ctxConfig.ctxConfigCipher.algo = en_gciCipherAlgo_Invalid;
    ctx->un_ctxConfig.ctxConfigCipher.blockMode = en_gciBlockMode_Invalid;
    ctx->un_ctxConfig.ctxConfigCipher.iv.data = NULL;
    ctx->un_ctxConfig.ctxConfigCipher.iv.len = -1;
    ctx->un_ctxConfig.ctxConfigCipher.padding = en_gciPadding_Invalid;

    /* Diffie-Hellman */
    ctx->un_ctxConfig.ctxConfigDh.type = en_gciDhType_Invalid;
    ctx->un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = en_gciNamedCurve_Invalid;
    ctx->un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain = NULL;

    /* TODO sw - ECDH */

    return err;
}


/********************************/
/*	_searchFreeKeyID			*/
/********************************/
en_gciResult_t _searchFreeKeyID( GciKeyId_t* p_keyID )
{
	en_gciResult_t err = en_gciResult_Ok;

	int i = 0;

	/* Random search for a free key ID */
	if(*p_keyID == -1)
	{
#if GCI_DBG_INFO
	    printf("GCI Info: Random research\r\n");
#endif

	    for( i = 0 ; i < GCI_NB_CTX_MAX ; i++ )
	    {
	        /* Free key ID when type is invalid */
	        if( ga_keyID[i].type == en_gciKeyType_Invalid )
	        {
	            *p_keyID = i;

	            /* To stop the loop */
	            return err;
	        }

	    }

        /* If it goes out of the loop mean no key ID are free */
        err = en_gciResult_Err;

	}

	/* Search for a key ID with the value in input */
	else if(*p_keyID >= 0)
	{
	    /* Free key ID when type is invalid */
	    if( ga_keyID[*p_keyID].type == en_gciKeyType_Invalid )
	    {
#if GCI_DBG_INFO
	        printf("GCI Info: Key ID %d free\r\n", *p_keyID);
#endif
	    }

	    else
	    {
	        printf("GCI Error in _searchFreeKeyID: Key ID %d not free\r\n", *p_keyID);
	        err = en_gciResult_Err;
	    }
	}

	/* Key ID not initialize in input */
	else
	{
	    printf("GCI Error in _searchFreeKeyID: Key ID not initialize in input\r\n", *p_keyID);
	    err = en_gciResult_Err;
	}

	return err;
}

/********************************/
/*  _keyRelease                 */
/********************************/
en_gciResult_t _keyRelease( st_gciKey_t* key)
{
    en_gciResult_t err = en_gciResult_Ok;

    key->type = en_gciKeyType_Invalid;

    /* Diffie-Hellmann private key */
    key->un_key.keyDhPriv.key.data = NULL;
    key->un_key.keyDhPriv.key.len = -1;
    key->un_key.keyDhPriv.param = NULL;

    /* Diffie-Hellmann public key */
    key->un_key.keyDhPub.key.data = NULL;
    key->un_key.keyDhPub.key.len = -1;
    key->un_key.keyDhPub.param = NULL;

    /* Diffie-Hellmann shared secret key */
    key->un_key.keyDhSecret.data = NULL;
    key->un_key.keyDhSecret.len = -1;

    /* DSA private key */
    key->un_key.keyDsaPriv.param = NULL;
    key->un_key.keyDsaPriv.key.data = NULL;
    key->un_key.keyDsaPriv.key.len = -1;

    /* DSA public key */
    key->un_key.keyDsaPub.key.data = NULL;
    key->un_key.keyDsaPub.key.len = -1;
    key->un_key.keyDsaPub.param = NULL;

    /* ECDH private key */
    key->un_key.keyEcdhPriv.curve = en_gciNamedCurve_Invalid;
    key->un_key.keyEcdhPriv.key.data = NULL;
    key->un_key.keyEcdhPriv.key.len = -1;

    /* ECDH public key */
    key->un_key.keyEcdhPub.coord.x.data = NULL;
    key->un_key.keyEcdhPub.coord.x.len = -1;
    key->un_key.keyEcdhPub.coord.y.data = NULL;
    key->un_key.keyEcdhPub.coord.y.len = -1;
    key->un_key.keyEcdhPub.curve = en_gciNamedCurve_Invalid;

    /* ECDH shared secret key */
    key->un_key.keyEcdhSecret.data = NULL;
    key->un_key.keyEcdhSecret.len = -1;

    /* ECDSA private key */
    key->un_key.keyEcdsaPriv.curve = en_gciNamedCurve_Invalid;
    key->un_key.keyEcdsaPriv.key.data = NULL;
    key->un_key.keyEcdsaPriv.key.len = -1;

    /* ECDSA public key */
    key->un_key.keyEcdsaPub.coord.x.data = NULL;
    key->un_key.keyEcdsaPub.coord.x.len = -1;
    key->un_key.keyEcdsaPub.coord.y.data = NULL;
    key->un_key.keyEcdsaPub.coord.y.len = -1;
    key->un_key.keyEcdsaPub.curve = en_gciNamedCurve_Invalid;

    /* RSA private key */
    key->un_key.keyRsaPriv.crt = NULL;
    key->un_key.keyRsaPriv.d.data = NULL;
    key->un_key.keyRsaPriv.d.len = -1;
    key->un_key.keyRsaPriv.n.data = NULL;
    key->un_key.keyRsaPriv.n.len = -1;

    /* RSA public key */
    key->un_key.keyRsaPub.e.data = NULL;
    key->un_key.keyRsaPub.e.len = -1;
    key->un_key.keyRsaPub.n.data = NULL;
    key->un_key.keyRsaPub.n.len = -1;

    /* Symmetric key */
    key->un_key.keySym.data = NULL;
    key->un_key.keySym.len = -1;

    return err;
}


/********************************/
/*	_registerAndTest			*/
/********************************/
en_gciResult_t _registerAndTest( void )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = 0;

	/* HASH */

	/* Register hash MD5 */
	tmpErr = register_hash(&md5_desc);

	if(tmpErr == -1)
	{
		err = en_gciResult_Err;
		printf("GCI Error in _registerAndTest: register hash MD5\r\n");
	}

	/* Test hash MD5 */
	tmpErr = md5_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
		err = en_gciResult_Err;
		printf("GCI Error in _registerAndTest: test hash MD5\r\n");
	}

	/* Register hash SHA1 */
	tmpErr = register_hash(&sha1_desc);

	if(tmpErr == -1)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: register hash SHA1\r\n");
	}

	/* Test hash sha1 */
	tmpErr = sha1_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: test hash SHA1\r\n");
	}

	/* Register hash SHA224 */
	tmpErr = register_hash(&sha224_desc);

	if(tmpErr == -1)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: register hash SHA224\r\n");
	}

	/* Test hash sha224 */
	tmpErr = sha224_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: test hash SHA224\r\n");
	}

	/* Register hash SHA256 */
	tmpErr = register_hash(&sha256_desc);

	if(tmpErr == -1)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: register hash SHA256\r\n");
	}

	/* Test hash sha256 */
	tmpErr = sha256_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: test hash SHA256\r\n");
	}


	/* Register hash SHA384 */
	tmpErr = register_hash(&sha384_desc);

	if(tmpErr == -1)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: register hash SHA384\r\n");
	}

	/* Test hash sha384 */
	tmpErr = sha384_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: test hash SHA384\r\n");
	}


	/* Register hash SHA512 */
	tmpErr = register_hash(&sha512_desc);

	if(tmpErr == -1)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: register hash SHA512\r\n");
	}

	/* Test hash sha512 */
	tmpErr = sha512_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: test hash SHA512\r\n");
	}

	/* PRNG */

	/* Register prng fortuna */
	tmpErr = register_prng(&fortuna_desc);

	if(tmpErr == -1)
	{
		err = en_gciResult_Err;
		printf("GCI Error in _registerAndTest: register prng fortuna\r\n");
	}

	/* Test prng fortuna */
	tmpErr = fortuna_test();

	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
		err = en_gciResult_Err;
		printf("GCI Error in _registerAndTest: test prng fortuna\r\n");
	}

	/* CIPHER */

	/* Register stream cipher RC4 */
	tmpErr = register_cipher(&rc4_desc);

	if(tmpErr == -1)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: register stream cipher RC4\r\n");
	}

	/* Test stream cipher RC4 */
	tmpErr = rc4_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: test stream cipher RC4\r\n");
	}

	/* Register block cipher AES */
	tmpErr = register_cipher(&aes_desc);

	if(tmpErr == -1)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: register block cipher AES\r\n");
	}

	/* Test block cipher AES */
	tmpErr = aes_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: test block cipher AES\r\n");
	}

	/* Register block cipher DES */
	tmpErr = register_cipher(&des_desc);

	if(tmpErr == -1)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: register block cipher DES\r\n");
	}

	/* Test block cipher DES */
	tmpErr = des_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: test block cipher DES\r\n");
	}

	/* Register block cipher 3DES */
	tmpErr = register_cipher(&des3_desc);

	if(tmpErr == -1)
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: register block cipher 3DES\r\n");
	}

	/* Test block cipher 3DES */
	tmpErr = des3_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
	    err = en_gciResult_Err;
	    printf("GCI Error in _registerAndTest: test block cipher 3DES\r\n");
	}



	return err;

}


/********************************/
/*  _initPrng                   */
/********************************/
en_gciResult_t _initPrng(const uint8_t* p_randBuf, size_t randLen)
{
    en_gciResult_t err = en_gciResult_Ok;
    int tmpErr = CRYPT_OK;

    /* Start it */
    tmpErr = fortuna_start(&g_fortuna_prng);
    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _initPrng: start prng");

    }

    /* Add entropy */
    tmpErr = fortuna_add_entropy(p_randBuf, randLen, &g_fortuna_prng);
    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _initPrng: start prng");

    }
    /* Ready and read */
    tmpErr = fortuna_ready(&g_fortuna_prng);
    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _initPrng: ready prng");

    }

    /* Get the ID of the prng */
    g_fortunaID = find_prng("fortuna");

    if(err == en_gciResult_Ok)
    {
#if GCI_DBG_INFO
        printf("GCI Info: Init done\r\n");
#endif
    }

    return err;
}


/********************************/
/*	_genDhDomainParam			*/
/********************************/
en_gciResult_t _genDhDomainParam(uint8_t* p_g, size_t* p_gLen, uint8_t* p_p, size_t* p_pLen)
{
	en_gciResult_t err = en_gciResult_Ok;
	size_t keysize = TC_DH_KEY_SIZE_MAX_BITS;
	uint8_t x;
	mp_err tmpErr;

	/* Temporary domain parameters */
	mp_int g;
	mp_int p;

#if GCI_DBG_INFO
	printf("GCI Info: Generate DH domain parameters\r\n");
#endif

	/* Initialize the temporary domain parameters */
	tmpErr = mp_init_multi(&g, &p, NULL);

	if(tmpErr != CRYPT_OK)
	{
		err = en_gciResult_Err;
		printf("GCI DH Error in _genDhDomainParam: Init domain parameters error\r\n");
	}

	/* find key size */
	for (x = 0; (keysize > (size_t)sets[x].size) && (sets[x].size != 0); x++);

	if( sets[x].size == 0 )
	{
		err = en_gciResult_Err;
		printf("GCI Error in _genDhDomainParam: No key size found\r\n");
		return err;
	}

	/* Generate g */
	mp_read_radix(&g, (char *)sets[x].base, 64);
	if(tmpErr != CRYPT_OK)
	{
		err = en_gciResult_Err;
		printf("GCI Error in _genDhDomainParam: generation domain parameters\r\n");
	}

	/* Generate p */
	mp_read_radix(&p, (char *)sets[x].prime, 64);

	if(tmpErr != CRYPT_OK)
	{
		err = en_gciResult_Err;
	}

	/* Save the temporary domain parameters */

	mp_to_unsigned_bin(&p, p_p);
	mp_to_unsigned_bin(&g, p_g);

	*p_gLen = mp_unsigned_bin_size(&g);
	*p_pLen = mp_unsigned_bin_size(&p);

	/* Clear the temporary domain parameters */
	mp_clear_multi(&p, &g, NULL);

	return err;
}

en_gciResult_t _genDhKeyPair( GciCtxId_t ctxID, GciKeyId_t* p_pubKeyID )
{
    en_gciResult_t err = en_gciResult_Ok;

    int tmpErr = CRYPT_OK;

    st_gciKey_t dhPubKey  = {.type = en_gciKeyType_DhPub};

    uint8_t a_prngBuf[TC_DH_KEY_SIZE_MAX_BITS];
    size_t prngSize = TC_DH_KEY_SIZE_MAX_BITS;

    uint8_t* dhParamG;
    uint8_t* dhParamP;

    mp_int p, g;

    /* Search a free key ID */
    err = _searchFreeKeyID( p_pubKeyID );


    if(err != en_gciResult_Ok)
    {
        printf("GCI Error in _genDhKeyPair: No key ID free\r\n");
        return err;
    }


    /* Allocate memory */
    dhPubKey.un_key.keyDhPub.key.data = ga_allocDhPubKey;
    dhParamG = ga_allocDhDomainG;
    dhParamP = ga_allocDhDomainP;

    /* Init the big numbers */
    mp_init_multi(&p, &g, NULL);

    /* Init the keys */
    ltc_init_multi(&g_dhPrivKey.x, &g_dhPrivKey.y, NULL);


    /* Check the validity of the prng */
    tmpErr = prng_is_valid(g_fortunaID);

    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _genDhKeyPair: Invalid pnrg\r\n");
    }

    /* Create prng */
    tmpErr = rng_make_prng(128, g_fortunaID, &g_fortuna_prng, NULL);
    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _genDhKeyPair: Make prng\r\n");

    }

    /* Store the prng in a buf */
    if ( prng_descriptor[g_fortunaID].read( a_prngBuf, prngSize, &g_fortuna_prng ) != prngSize )
    {
        err = en_gciResult_Err;
        printf("GCI Error in _genDhKeyPair: Store prng\r\n");

    }

    /* Read private key from prngBuf */
    tmpErr = mp_read_unsigned_bin(g_dhPrivKey.x, a_prngBuf, prngSize);
    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _genDhKeyPair: Read private key as big number\r\n");
    }

    /* Read domain parameter g */
    tmpErr = mp_read_unsigned_bin(&g, dhParamG, ga_ctxID[ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.len);
    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _genDhKeyPair: Read generator (g)\r\n");
    }

    /* Read domain parameter p */
    tmpErr = mp_read_unsigned_bin(&p, dhParamP, ga_ctxID[ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.len);
    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _genDhKeyPair: Read prime (p)\r\n");
    }

    /* Generate DH key pair */
    tmpErr = mp_exptmod(&g, g_dhPrivKey.x, &p, g_dhPrivKey.y);

    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _genDhKeyPair: DH generate keys\r\n");
    }

    /* Convert the public key in a bytes buffer */
    dhPubKey.un_key.keyDhPub.key.len = mp_unsigned_bin_size(g_dhPrivKey.y);
    tmpErr = mp_to_unsigned_bin(g_dhPrivKey.y, dhPubKey.un_key.keyDhPub.key.data);

    if (tmpErr != CRYPT_OK)
    {
        err = en_gciResult_Err;
        printf("GCI Error in _genDhKeyPair: Convert big number to bytes buffer\r\n");
    }



    /* Get an ID for the public key */
    gciKeyPut(&dhPubKey, p_pubKeyID);

    return err;
}



en_gciResult_t _getEccCurve( uint8_t* p_curve, size_t* p_nbCurve)
{
    en_gciResult_t err = en_gciResult_Ok;

    *p_nbCurve = 0;

    int index = 0;

    /* BRAINPOOL512R1 */
    *(p_curve+index) = 28;
    index++;

    /* BRAINPOOL384R1 */
    *(p_curve+index) = 27;
    index++;

    /* BRAINPOOL256R1 */
    *(p_curve+index) = 26;
    index++;

    /* SECP521R1 */
    *(p_curve+index) = 25;
    index++;

    /* SECP384R1 */
    *(p_curve+index) = 24;
    index++;

    /* SECP256R1 / PRIME256V1 */
    *(p_curve+index) = 23;
    index++;

    /* SECP256K1 */
    *(p_curve+index) = 22;
    index++;

    /* SECP224R1 */
    *(p_curve+index) = 21;
    index++;

    /* SECP224K1 */
    *(p_curve+index) = 20;
    index++;

    /* SECP192R1 / PRIME912V1 */
    *(p_curve+index) = 19;
    index++;

    /* SECP192K1 */
    *(p_curve+index) = 18;
    index++;

    /* SECP160R2 */
    *(p_curve+index) = 17;
    index++;

    /* SECP160R1 */
    *(p_curve+index) = 16;
    index++;

    /* SECP160K1 */
    *(p_curve+index) = 15;
    index++;

    *p_nbCurve = (size_t)index;

    return err;
}

en_gciResult_t _getCurveSize(en_gciNamedCurve_t curve,  size_t* p_curveSize)
{
   en_gciResult_t err = en_gciResult_Ok;

   switch(curve)
   {
       case en_gciNamedCurve_SECP521R1:

           *p_curveSize = 66;

       break;


       case en_gciNamedCurve_BRAINPOOLP512R1:

           *p_curveSize = 64;

       break;


       case en_gciNamedCurve_SECP384R1:
       case en_gciNamedCurve_BRAINPOOLP384R1:

           *p_curveSize = 48;

       break;


       case en_gciNamedCurve_SECP256R1:
       case en_gciNamedCurve_BRAINPOOLP256R1:
       case en_gciNamedCurve_SECP256K1:

           *p_curveSize = 32;

       break;


       case en_gciNamedCurve_SECP224R1:
       case en_gciNamedCurve_SECP224K1:

           *p_curveSize = 28;

       break;


       case en_gciNamedCurve_SECP192R1:
       case en_gciNamedCurve_SECP192K1:

           *p_curveSize = 24;

       break;


       case en_gciNamedCurve_SECP160K1:
       case en_gciNamedCurve_SECP160R1:
       case en_gciNamedCurve_SECP160R2:

           *p_curveSize = 20;

       break;


       case en_gciNamedCurve_SECT163K1:
       case en_gciNamedCurve_SECT163R1:
       case en_gciNamedCurve_SECT163R2:
       case en_gciNamedCurve_SECT193R1:
       case en_gciNamedCurve_SECT193R2:
       case en_gciNamedCurve_SECT233K1:
       case en_gciNamedCurve_SECT233R1:
       case en_gciNamedCurve_SECT239K1:
       case en_gciNamedCurve_SECT283K1:
       case en_gciNamedCurve_SECT283R1:
       case en_gciNamedCurve_SECT409K1:
       case en_gciNamedCurve_SECT409R1:
       case en_gciNamedCurve_SECT571K1:
       case en_gciNamedCurve_SECT571R1:

           printf("GCI Error: ECC not implemented in LibTomCrypt\r\n");
           err = en_gciResult_Err;
           *p_curveSize = 0;

       break;


       default:
           printf("GCI Error: Invalid curve\r\n");
           err = en_gciResult_Err;
           *p_curveSize = 0;
       break;
   }

   return err;
}


en_gciResult_t _calcDhSecret( GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* p_secretKeyID)
{
    en_gciResult_t err = en_gciResult_Ok;

    int tmpErr = MP_OKAY;

    uint8_t a_allocDhPubKey[TC_DH_KEY_SIZE_MAX_BYTES];
    uint8_t a_allocDhSecretKey[TC_DH_KEY_SIZE_MAX_BYTES];

    st_gciKey_t pubKey = {.type = en_gciKeyType_DhPub};
    st_gciKey_t secretKey = {.type = en_gciKeyType_DhSecret};

    mp_int bnPubKey, bnParamP, bnSecretKey;

    /* Allocate memory */
    mp_init(&bnPubKey);
    mp_init(&bnParamP);
    mp_init(&bnSecretKey);
    pubKey.un_key.keyDhPub.key.data = a_allocDhPubKey;
    secretKey.un_key.keyDhSecret.data = a_allocDhSecretKey;

#if GCI_DBG_INFO
    printf("GCI Info: DH Calc Shared Secret with context ID %d\r\n", ctxID);
#endif

    /* Get the public key as a buffer with the ID */
    err = gciKeyGet(pubKeyID, &pubKey);
    if(err != en_gciResult_Ok)
    {
        printf("GCI Error in _calcDhSecret: get the public key\r\n");
        return err;
    }

    /* Convert the public key as a buffer of bytes to a big number */
    tmpErr = mp_read_unsigned_bin(&bnPubKey, pubKey.un_key.keyDhPub.key.data, pubKey.un_key.keyDhPub.key.len);

    if(tmpErr != MP_OKAY)
    {
        printf("GCI Error in _calcDhSecret: Get public key (as a big number)\r\n");
        err = en_gciResult_Err;
        return err;
    }

    /* Convert the prime (p) as a buffer of bytes to a big number */
    tmpErr = mp_read_unsigned_bin(&bnParamP, ga_ctxID[ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.data, ga_ctxID[ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.len);

    if(tmpErr != MP_OKAY)
    {
        printf("GCI Error in _calcDhSecret: Get prime (as a big number)\r\n");
        err = en_gciResult_Err;
        return err;
    }

    /* Create the secret key */
    tmpErr = mp_exptmod(&bnPubKey, g_dhPrivKey.x, &bnParamP, &bnSecretKey);

    if(tmpErr != MP_OKAY)
    {
        printf("GCI Error in _calcDhSecret: Create secret key (as a big number)\r\n");
        err = en_gciResult_Err;
        return err;
    }

    /* Get the size of the secret key */
    secretKey.un_key.keyDhSecret.len = (size_t)mp_unsigned_bin_size(&bnSecretKey);

    /* Get the secret key as a buffer of bytes */
    tmpErr = mp_to_unsigned_bin(&bnSecretKey, secretKey.un_key.keyDhSecret.data);

    if(tmpErr != MP_OKAY)
    {
        printf("GCI Error in _calcDhSecret: Convert big number to unsigned\r\n");
        err = en_gciResult_Err;
        return err;
    }

    /* Get an ID of the secret key */
    err = gciKeyPut(&secretKey, p_secretKeyID);


    return err;
}


en_gciResult_t _calcEcdhSecret( GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* p_secretKeyID)
{
    en_gciResult_t err = en_gciResult_Ok;
    int tmpErr = CRYPT_OK;
    int x;

    st_gciKey_t ecdhPubKey;

    st_gciKey_t secretKey = {.type = en_gciKeyType_EcdhSecret};

    ecc_key bnEcdhPubKey;

    uint8_t a_allocEcdhPubCoordX[TC_ECDH_KEY_SIZE_MAX_BYTES/2];
    uint8_t a_allocEcdhPubCoordY[TC_ECDH_KEY_SIZE_MAX_BYTES/2];
    uint8_t a_allocEcdhSecret[TC_ECDH_KEY_SIZE_MAX_BYTES/2];


    /* Allocate memory */
    ecdhPubKey.un_key.keyEcdhPub.coord.x.data = a_allocEcdhPubCoordX;
    ecdhPubKey.un_key.keyEcdhPub.coord.y.data = a_allocEcdhPubCoordY;
    secretKey.un_key.keyEcdhSecret.data = a_allocEcdhSecret;

    ltc_init_multi(&bnEcdhPubKey.pubkey.x, &bnEcdhPubKey.pubkey.y, &bnEcdhPubKey.pubkey.z, NULL);

    /* Get the public key from the ID */
    err = gciKeyGet(pubKeyID, &ecdhPubKey);

    /* Convert the key as bytes buffer to a big number */
    tmpErr = mp_read_unsigned_bin(bnEcdhPubKey.pubkey.x, ecdhPubKey.un_key.keyEcdhPub.coord.x.data, ecdhPubKey.un_key.keyEcdhPub.coord.x.len);

    if(tmpErr != CRYPT_OK)
    {
        printf("GCI Error in _calcEcdhSecret: Convert x-coordinate of the public key to a big number\r\n");
        err = en_gciResult_Err;
        return err;
    }

    tmpErr = mp_read_unsigned_bin(bnEcdhPubKey.pubkey.y, ecdhPubKey.un_key.keyEcdhPub.coord.y.data, ecdhPubKey.un_key.keyEcdhPub.coord.y.len);

    if(tmpErr != CRYPT_OK)
    {
        printf("GCI Error in _calcEcdhSecret: Convert y-coordinate of the public key to a big number\r\n");
        err = en_gciResult_Err;
        return err;
    }

    mp_set(bnEcdhPubKey.pubkey.z, 1);


    /* determine the idx for the public key */
    for (x = 0; ltc_ecc_sets[x].size != 0; x++)
    {
        /* Not important if it's x or y length because it's the same length */
        if ((unsigned)ltc_ecc_sets[x].size >= ecdhPubKey.un_key.keyEcdhPub.coord.x.len)
        {
            break;
        }
    }


    if (ltc_ecc_sets[x].size == 0)
    {
        printf("GCI Error in  _calcEcdhSecret: Invalid public key\r\n");
        err = en_gciResult_Err;
        return err;
    }
    /* set the idx */
    bnEcdhPubKey.idx  = x;
    bnEcdhPubKey.dp = &ltc_ecc_sets[x];
    bnEcdhPubKey.type = PK_PUBLIC;

    /* Length of the secret is the same length as one of the coordinate of the public key */
    secretKey.un_key.keyEcdhSecret.len = ecdhPubKey.un_key.keyEcdhPub.coord.x.len;

    ecc_shared_secret(&g_ecdhPrivKey, &bnEcdhPubKey, secretKey.un_key.keyEcdhSecret.data, (long unsigned int*)&secretKey.un_key.keyEcdhSecret.len);

    /* Get an ID of the secret key */
    err = gciKeyPut(&secretKey, p_secretKeyID);

    return err;
}

en_gciResult_t _genEchKeyPair( GciCtxId_t ctxID, GciKeyId_t* p_pubKeyID )
{
    en_gciResult_t err = en_gciResult_Ok;

    int numLen;
    size_t curveSize;
    uint8_t buf[TC_ECDH_KEY_SIZE_MAX_BYTES];
    uint8_t a_allocEcdhCoordX[TC_ECDH_KEY_SIZE_MAX_BYTES/2];
    uint8_t a_allocEcdhCoordY[TC_ECDH_KEY_SIZE_MAX_BYTES/2];
    st_gciKey_t ecdhPubKey = {.type = en_gciKeyType_EcdhPub};

    ecdhPubKey.un_key.keyEcdhPub.coord.x.data = a_allocEcdhCoordX;
    ecdhPubKey.un_key.keyEcdhPub.coord.y.data = a_allocEcdhCoordY;

    memset(ecdhPubKey.un_key.keyEcdhPub.coord.x.data, 0, TC_ECDH_KEY_SIZE_MAX_BYTES/2);
    memset(ecdhPubKey.un_key.keyEcdhPub.coord.y.data, 0, TC_ECDH_KEY_SIZE_MAX_BYTES/2);

    /* Search a free key ID */
    err = _searchFreeKeyID( p_pubKeyID );


    if(err != en_gciResult_Ok)
    {
        printf("GCI Error in _genEchKeyPair: No key ID free\r\n");
        return err;
    }

    /* Init the big numbers */
    ltc_init_multi(g_ecdhPrivKey.pubkey.x, g_ecdhPrivKey.pubkey.y, NULL);

    /* Get the curve size */
    _getCurveSize(*ga_ctxID[ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName, &curveSize);

    /* Generate the key pair */
    ecc_make_key(&g_fortuna_prng, g_fortunaID, curveSize, &g_ecdhPrivKey);


    numLen = g_ecdhPrivKey.dp->size;
    zeromem(buf, sizeof(buf));

    /* Convert the big number to a bytes buffer */
    mp_to_unsigned_bin(g_ecdhPrivKey.pubkey.x, buf + (numLen - mp_unsigned_bin_size(g_ecdhPrivKey.pubkey.x)));
    memcpy(ecdhPubKey.un_key.keyEcdhPub.coord.x.data, buf, numLen);

    ecdhPubKey.un_key.keyEcdhPub.coord.x.len = mp_unsigned_bin_size(g_ecdhPrivKey.pubkey.x);


    zeromem(buf, sizeof(buf));
    mp_to_unsigned_bin(g_ecdhPrivKey.pubkey.y, buf + (numLen - mp_unsigned_bin_size(g_ecdhPrivKey.pubkey.y)));

    memcpy(ecdhPubKey.un_key.keyEcdhPub.coord.y.data, buf, numLen);
    ecdhPubKey.un_key.keyEcdhPub.coord.y.len = mp_unsigned_bin_size(g_ecdhPrivKey.pubkey.y);

    /* Get a random ID of the key */
    err = gciKeyPut(&ecdhPubKey, p_pubKeyID);

    return err;
}

/*---------------------------------------------EOF-----------------------------------------------------------------------*/
