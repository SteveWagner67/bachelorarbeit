/**
 * \file 				crypto_iface.c
 * \brief 				see crypto_iface.h
 * \author				Steve Wagner
 * \date 				13/10/2015
 */


/*--------------------------------------------------Include--------------------------------------------------------------*/

#include "crypto_tomcrypt.h"


/*-------------------------------------------------Global variables-------------------------------------------------------------*/

/* Array for the context ID */
static st_tcCtxConfig_t ga_ctxID[GCI_NB_CTX_MAX];


/* Array for the Key ID */
static st_gciKey_t ga_keyID[GCI_NB_KEY_MAX];

/* Pseudo random numbers fortuna */
static prng_state g_fortuna_prng;
static int g_fortunaID;

/* Diffie-Hellmann private key ID */
static GciKeyId_t dhPrivKeyID;

/* Diffie-Hellmann domain parameters length buffer */
static size_t ga_allocDhDomainParam[GCI_BUFFER_MAX_SIZE];
/* Diffie-Hellmann domain parameter p buffer */
static uint8_t ga_allocDhDomainP[GCI_BUFFER_MAX_SIZE/2];
/* Diffie-Hellmann domain parameter g buffer */
static uint8_t ga_allocDhDomainG[GCI_BUFFER_MAX_SIZE/2];



/* Diffie-Hellmann private key buffer */
static uint8_t ga_allocDhPrivKey[TC_DEFAULT_DHE_KEYSIZE];

/* Diffie-Hellmann public key buffer */
static uint8_t ga_allocDhPubKey[TC_DEFAULT_DHE_KEYSIZE];

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
 * \fn							en_gciResult_t _genDhDomainParam( st_gciDhDomainParam_t* dhParam )
 * \brief						Generate Diffie-Hellmann domain parameters
 * \param [out] dhParam			Pointer to the structure for the domain parameter
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t _genDhDomainParam(uint8_t* p_g, size_t* gLen, uint8_t* p_p, size_t* pLen);


en_gciResult_t _genDhKeyPair( dh_key* p_dhKey );


/*---------------------------------------------Functions from crypto_iface.h---------------------------------------------*/

/**********************************************************************************************************************/
/*		      										GLOBAL			 				      							  */
/**********************************************************************************************************************/

/********************************/
/*	gciInit					*/
/********************************/
en_gciResult_t gciInit( const uint8_t* p_user, size_t userLen, const uint8_t* p_password, size_t passLen )
{
	en_gciResult_t err = en_gciResult_Ok;
	int i = 0;
	int tmpErr = CRYPT_OK;

	/* Use some "random" bytes to init the PRNG fortuna */
	uint8_t c_rand[] = { 0x42, 0x72, 0x75, 0x63, 0x65, 0x20, 0x53, 0x63, 0x68,
						 0x6E, 0x65, 0x69, 0x65, 0x72, 0x21, 0x0D, 0x0A, 0x00 };

	printf("GCI Info: Init\r\n");

	/* Initialization of the context array */
	for( i = 0; i < GCI_NB_CTX_MAX; i++ )
	{
		ga_ctxID[i].type = en_tcCtxType_Invalid;

		/* Hash */
		ga_ctxID[i].un_ctxConfig.ctxConfigHash = en_gciHashAlgo_Invalid;

		/* Signature */
		ga_ctxID[i].un_ctxConfig.ctxConfigSign.algo = en_gciSignAlgo_Invalid;
		ga_ctxID[i].un_ctxConfig.ctxConfigSign.hash = en_gciHashAlgo_Invalid;
		ga_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.block = en_gciBlockMode_Invalid;
		ga_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.iv.len = -1;
		ga_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.iv.data = NULL;
		ga_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.padding = en_gciPadding_Invalid;
		ga_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigRsa.padding = en_gciPadding_Invalid;

		/* Cipher */
		ga_ctxID[i].un_ctxConfig.ctxConfigCipher.algo = en_gciCipherAlgo_Invalid;
		ga_ctxID[i].un_ctxConfig.ctxConfigCipher.blockMode = en_gciBlockMode_Invalid;
		ga_ctxID[i].un_ctxConfig.ctxConfigCipher.iv.data = NULL;
		ga_ctxID[i].un_ctxConfig.ctxConfigCipher.iv.len = -1;
		ga_ctxID[i].un_ctxConfig.ctxConfigCipher.padding = en_gciPadding_Invalid;

		/* Diffie-Hellman */
		ga_ctxID[i].un_ctxConfig.ctxConfigDh.type = en_gciDhType_Invalid;
		ga_ctxID[i].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = en_gciNamedCurve_Invalid;
		ga_ctxID[i].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain = NULL;

	}

	/* Initialization of the key array */
	for( i = 0; i < GCI_NB_KEY_MAX; i++ )
	{
		ga_keyID[i].type = en_gciKeyType_Invalid;

		/* Diffie-Hellmann private key */
		ga_keyID[i].un_key.keyDhPriv.key.data = NULL;
		ga_keyID[i].un_key.keyDhPriv.key.len = -1;
		ga_keyID[i].un_key.keyDhPriv.param = NULL;

		/* Diffie-Hellmann public key */
		ga_keyID[i].un_key.keyDhPub.key.data = NULL;
		ga_keyID[i].un_key.keyDhPub.key.len = -1;
		ga_keyID[i].un_key.keyDhPub.param = NULL;

		/* Diffie-Hellmann shared secret key */
		ga_keyID[i].un_key.keyDhSecret.data = NULL;
		ga_keyID[i].un_key.keyDhSecret.len = -1;

		/* DSA private key */
		ga_keyID[i].un_key.keyDsaPriv.param = NULL;
		ga_keyID[i].un_key.keyDsaPriv.key.data = NULL;
		ga_keyID[i].un_key.keyDsaPriv.key.len = -1;

		/* DSA public key */
		ga_keyID[i].un_key.keyDsaPub.key.data = NULL;
		ga_keyID[i].un_key.keyDsaPub.key.len = -1;
		ga_keyID[i].un_key.keyDsaPub.param = NULL;

		/* ECDH private key */
		ga_keyID[i].un_key.keyEcdhPriv.curve = en_gciNamedCurve_Invalid;
		ga_keyID[i].un_key.keyEcdhPriv.key.data = NULL;
		ga_keyID[i].un_key.keyEcdhPriv.key.len = -1;

		/* ECDH public key */
		ga_keyID[i].un_key.keyEcdhPub.coord.x.data = NULL;
		ga_keyID[i].un_key.keyEcdhPub.coord.x.len = -1;
		ga_keyID[i].un_key.keyEcdhPub.coord.y.data = NULL;
		ga_keyID[i].un_key.keyEcdhPub.coord.y.len = -1;
		ga_keyID[i].un_key.keyEcdhPub.curve = en_gciNamedCurve_Invalid;

		/* ECDH shared secret key */
		ga_keyID[i].un_key.keyEcdhSecret.data = NULL;
		ga_keyID[i].un_key.keyEcdhSecret.len = -1;

		/* ECDSA private key */
		ga_keyID[i].un_key.keyEcdsaPriv.curve = en_gciNamedCurve_Invalid;
		ga_keyID[i].un_key.keyEcdsaPriv.un_key.data = NULL;
		ga_keyID[i].un_key.keyEcdsaPriv.un_key.len = -1;

		/* ECDSA public key */
		ga_keyID[i].un_key.keyEcdsaPub.coord.x.data = NULL;
		ga_keyID[i].un_key.keyEcdsaPub.coord.x.len = -1;
		ga_keyID[i].un_key.keyEcdsaPub.coord.y.data = NULL;
		ga_keyID[i].un_key.keyEcdsaPub.coord.y.len = -1;
		ga_keyID[i].un_key.keyEcdsaPub.curve = en_gciNamedCurve_Invalid;

		/* RSA private key */
		ga_keyID[i].un_key.keyRsaPriv.crt = NULL;
		ga_keyID[i].un_key.keyRsaPriv.d.data = NULL;
		ga_keyID[i].un_key.keyRsaPriv.d.len = -1;
		ga_keyID[i].un_key.keyRsaPriv.n.data = NULL;
		ga_keyID[i].un_key.keyRsaPriv.n.len = -1;

		/* RSA public key */
		ga_keyID[i].un_key.keyRsaPub.e.data = NULL;
		ga_keyID[i].un_key.keyRsaPub.e.len = -1;
		ga_keyID[i].un_key.keyRsaPub.n.data = NULL;
		ga_keyID[i].un_key.keyRsaPub.n.len = -1;

		/* Symmetric key */
		ga_keyID[i].un_key.keysym.data = NULL;
		ga_keyID[i].un_key.keysym.len = -1;

	}

	/* Register and test */
	err = _registerAndTest();

	if(err != en_gciResult_Ok)
	{
		printf("GCI Error: register and test");
	}


	/* Init pseudo random number generator */

    /* Start it */
	tmpErr = fortuna_start(&g_fortuna_prng);
    if (tmpErr != CRYPT_OK)
    {
    	err = en_gciResult_Err;
    	printf("GCI Error: start prng");

    }



    /* Add entropy */
    tmpErr = fortuna_add_entropy(c_rand, sizeof(c_rand), &g_fortuna_prng);
    if (tmpErr != CRYPT_OK)
    {
    	err = en_gciResult_Err;
    	printf("GCI Error: start prng");

    }
    /* Ready and read */
    tmpErr = fortuna_ready(&g_fortuna_prng);
    if (tmpErr != CRYPT_OK)
    {
    	err = en_gciResult_Err;
    	printf("GCI Error: ready prng");

    }

    /* Get the ID of the prng */
    g_fortunaID = find_prng("fortuna");

    if(err == en_gciResult_Ok)
    {
    	printf("GCI Info: Init done\r\n");
    }


	return err;
}



/********************************/
/*	gciDeinit					*/
/********************************/
en_gciResult_t gciDeinit(void)
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: DeInit\r\n");
#endif

	return err;
}



/********************************/
/*	gciGetInfo				*/
//********************************/
en_gciResult_t gciGetInfo( en_gciInfo_t InfoType, uint16_t* p_Info, size_t* p_InfoLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Get Info\r\n");
#endif

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

#ifdef TC_DBG
	printf("GCI Info: Ctx Release\r\n");
#endif

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

#ifdef TC_DBG
	printf("GCI Info: Hash New Ctx\r\n");
#endif

	return err;
}



/********************************/
/*	gciHashCtxClone			*/
/********************************/
en_gciResult_t gciHashCtxClone( GciCtxId_t idSrc, GciCtxId_t* p_idDest )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Hash Ctx Clone\r\n");
#endif

	return err;
}



/********************************/
/*	gciHashUpdate				*/
/********************************/
en_gciResult_t gciHashUpdate( GciCtxId_t ctxID, const uint8_t* p_blockMsg, size_t blockLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Hash Update\r\n");
#endif

	return err;
}



/********************************/
/*	gciHashFinish				*/
/********************************/
en_gciResult_t gciHashFinish( GciCtxId_t ctxID, uint8_t* p_digest, size_t* p_digestLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Hash Finish\r\n");
#endif

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

#ifdef TC_DBG
	printf("GCI Info: Sign Gen New Ctx\r\n");
#endif

	return err;
}



/********************************/
/*	gciSignVerifyNewCtx		*/
/********************************/
en_gciResult_t gciSignVerifyNewCtx( const st_gciSignConfig_t* p_signConfig, GciKeyId_t keyID, GciCtxId_t* p_ctxID )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Sign Verify New Ctx\r\n");
#endif

	return err;
}



/********************************/
/*	gciSignCtxClone			*/
/********************************/
en_gciResult_t gciSignCtxClone( GciCtxId_t idSrc, GciCtxId_t* p_idDest )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Sign Ctx Clone\r\n");
#endif

	return err;
}



/********************************/
/*	gciSignUpdate				*/
/********************************/
en_gciResult_t gciSignUpdate( GciCtxId_t ctxID,const uint8_t* p_blockMsg, size_t blockLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Sign Update\r\n");
#endif

	return err;
}



/********************************/
/*	gciSignGenFinish			*/
/********************************/
en_gciResult_t gciSignGenFinish( GciCtxId_t ctxID, uint8_t* p_sign, size_t* p_signLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Sign Gen Finish\r\n");
#endif

	return err;
}



/********************************/
/*	gciSignVerifyFinish		*/
/********************************/
en_gciResult_t gciSignVerifyFinish( GciCtxId_t ctxID, const uint8_t* p_sign, size_t signLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Sign Verify Finish\r\n");
#endif

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

#ifdef TC_DBG
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

#ifdef TC_DBG
	printf("GCI Info: Cipher New Ctx\r\n");
#endif

	return err;
}



/********************************/
/*	gciCipherEncrypt			*/
/********************************/
en_gciResult_t gciCipherEncrypt( GciCtxId_t ctxId, const uint8_t* p_plaintxt, size_t pltxtLen, uint8_t* p_ciphtxt, size_t* p_cptxtLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Cipher Encrypt\r\n");
#endif

	return err;
}


/********************************/
/*	gciCipherDecrypt			*/
/********************************/
en_gciResult_t gciCipherDecrypt( GciCtxId_t ctxId, const uint8_t* p_ciphtxt, size_t cptxtLen, uint8_t* p_plaintxt, size_t* p_pltxtLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Cipher Decrypt\r\n");
#endif

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

#ifdef TC_DBG
	printf("GCI Info: Rng Gen\r\n");
#endif

	return err;
}



/********************************/
/*	gciRngSeed				*/
/********************************/
en_gciResult_t gciRngSeed( const uint8_t* p_sdBuf, size_t sdLen )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Rng Seed\r\n");
#endif

	return err;
}



/**********************************************************************************************************************/
/*		    										 Diffie-Hellmann                 				    			  */
/**********************************************************************************************************************/

/********************************/
/*	gciDhNewCtx				*/
/********************************/
en_gciResult_t gciDhNewCtx( const st_gciDhConfig_t* p_dhConfig, GciCtxId_t* p_ctxID )
{
    en_gciResult_t err = en_gciResult_Ok;

    //int a_allocDhDomainParam[GCI_BUFFER_MAX_SIZE];


	uint8_t a_allocDhKey[GCI_BUFFER_MAX_SIZE];

	mp_digit con[255];


	/* 2 bytes for the curve name */
	uint8_t a_allocEcdhCurveName[2];

	/* Search free context ID
	 *
	 * return: 	en_gciResult_Ok 				on success
	 * 			en_gciResult_ErrBufferIdFull	on error (Buffer of the context ID is full)
	 */
	err = _searchFreeCtxID(p_ctxID);

	if(err != en_gciResult_Ok)
	{
		printf("GCI Error: No context ID free\r\n");

		return err;
	}

	/* Indicate the type of the context */
	ga_ctxID[*p_ctxID].type = en_tcCtxType_Dh;


	/* Save the configuration */
	ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.type = p_dhConfig->type;

	switch((*p_dhConfig).type)
	{
		case en_gciDhType_Dh:

			printf("GCI Info: DH context ID = %d\r\n", *p_ctxID);

			/* Allocate memory */

			/* Diffie-Hellmann domain parameters length */
			ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain = ga_allocDhDomainParam;
			/* Diffie-Hellmann domain parameter g */
			ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.data = ga_allocDhDomainG;
			/* Diffie-Hellmann domain parameter p */
			ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.data = ga_allocDhDomainP;

			/* Init the buffer */
			memset(ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.data, 0 , GCI_BUFFER_MAX_SIZE/2);
			memset(ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.data, 0 , GCI_BUFFER_MAX_SIZE/2);


			/* Save the parameters if different to NULL*/
			if(p_dhConfig->un_dhParam.dhParamDomain != NULL)
			{
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.data = p_dhConfig->un_dhParam.dhParamDomain->g.data;
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.len = p_dhConfig->un_dhParam.dhParamDomain->g.len;

				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.data = p_dhConfig->un_dhParam.dhParamDomain->p.data;
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.len = p_dhConfig->un_dhParam.dhParamDomain->p.len;

				printf("GCI Info: copy DH domain parameters done\r\n");
			}

			/* Create the domain parameters */
			else
			{

			    /* Variable to a better visibility */
			    uint8_t* p_p;
			    uint8_t* p_g;
			    size_t pLen;
			    size_t gLen;

			    /* Allocate memory */
			    p_p = ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.data;
			    p_g = ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.data;

			    /* Generate Diffie-Hellmann domain parameters */
				err = _genDhDomainParam(p_g, &gLen, p_p, &pLen);

				/*Save the length */
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.len = pLen;;
				ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.len = gLen;;

				if(err != en_gciResult_Ok)
				{
					printf("GCI Error: DH gen domain parameters\r\n");
				}

				else
				{
					printf("GCI Info: DH gen domain parameters done\r\n");
				}


			}

		break;

		case en_gciDhType_Ecdh:

			printf("GCI Info: ECDH context ID = %d\r\n", *p_ctxID);

			/* Allocate memory */
			ga_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = a_allocEcdhCurveName;

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

			printf("GCI Error: Invalid or unknown configuration\r\n");

			err = gciCtxRelease(*p_ctxID);

			if (err == en_gciResult_Ok)
			{
				printf("GCI Info: Context releases\r\n");
			}

			else
			{
				printf("GCI Error: Context releases\r\n");

			}

			err = en_gciResult_Err;

		break;

	}

	return err;
}



/********************************/
/*	gciDhGenKey				*/
/********************************/
en_gciResult_t gciDhGenKey( GciCtxId_t ctxID, GciKeyId_t* p_pubKeyID )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = CRYPT_OK;
	uint8_t a_prngBuf[TC_DEFAULT_DHE_KEYSIZE];
	size_t prngSize = TC_DEFAULT_DHE_KEYSIZE;

	uint8_t* dhParamG;
	uint8_t* dhParamP;
	dh_key dhKey = {0};

	mp_int p, g;

	/* Init the big numbers */
	mp_init_multi(&p, &g, NULL);

	/* Compare the type of the context */
	if(ga_ctxID[ctxID].type != en_tcCtxType_Dh)
	{
		err = en_gciResult_Err;
		printf("GCI Error: Context Type not DH\r\n");

		return err;
	}

	switch(ga_ctxID[ctxID].un_ctxConfig.ctxConfigDh.type)
	{
		case en_gciDhType_Dh:

		    /* TODO sw - the part in _genDhKeyPair doesn't work
		     * Problem: should initialize the keys with ltc_multi_init
		     *          but in this function is called mp_init which return 0x0 (in step to step mode)
		     *          BUT in valentin's project is instead of mp_init, init from ltc_desc.c used (in step to step mode)
		     *
		     * To resolve the problem, find where is written that init is called instead of mp_init in valentin's projet
		     */

			printf("GCI Info: DH Gen Key\r\n");

			dh_free(p_pubKeyID);


			/* Allocate memory */
			dhParamG = ga_allocDhDomainG;
			dhParamP = ga_allocDhDomainP;


			/* Init the keys */
			//err = _genDhKeyPair(&dhKey);

			/* Copy the the domain parameters set in gciDhNewCtx */
			memcpy(dhParamG, ga_allocDhDomainG, GCI_BUFFER_MAX_SIZE/2);
			memcpy(dhParamP, ga_allocDhDomainP, GCI_BUFFER_MAX_SIZE/2);

			/* Check the validity of the prng */
			tmpErr = prng_is_valid(g_fortunaID);

			if (tmpErr != CRYPT_OK)
			{
				err = en_gciResult_Err;
				printf("GCI Error: Invalid pnrg\r\n");
			}

			/* Create prng */
			tmpErr = rng_make_prng(128, g_fortunaID, &g_fortuna_prng, NULL);
			if (tmpErr != CRYPT_OK)
			{
				err = en_gciResult_Err;
				printf("GCI Error: Make prng\r\n");

			}

			/* Store the prng in a buf */
			 if ( prng_descriptor[g_fortunaID].read( a_prngBuf, prngSize, &g_fortuna_prng ) != prngSize )
			 {
				 err = en_gciResult_Err;
				 printf("GCI Error: Store prng\r\n");

			 }


			 /* TODO sw - the part below doesn't work without the initialization of the keys with ltc_multi init (see above for more details) */

			 /* Read private key from prngBuf */
//			 tmpErr = mp_read_unsigned_bin(dhKey->x, a_prngBuf, prngSize);
//			 if (tmpErr != CRYPT_OK)
//			 {
//				 err = en_gciResult_Err;
//				 printf("GCI Error: Read private key as big number\r\n");
//			 }
//
//			 /* Read domain parameter g */
//			 tmpErr = mp_read_unsigned_bin(&g, dhParamG, a_ctxID[ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.len);
//
//			 /* Read domain parameter p */
//			 tmpErr = mp_read_unsigned_bin(&p, dhParamP, a_ctxID[ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.len);
//
//			 /* Generate DH public key */
//			 tmpErr = mp_exptmod(&g, dhKey->x, &p, dhKey->y);
//
//			 if (tmpErr != CRYPT_OK)
//			 {
//				 err = en_gciResult_Err;
//				 printf("GCI Error: DH generate keys");
//			 }


		 	 /*TODO sw - Get an ID for the public key */

			 /*TODO sw - Get an ID for the private key (use the global ID) */

			 /* TODO sw - put the whole case in a local function to have more visibility */




		break;



		case en_gciDhType_Ecdh:

			printf("GCI Info: ECDH Gen Key\r\n");

		break;



		case en_gciDhType_Invalid:

			printf("GCI Error: Invalid DH type\r\n");

		break;



		default:

			printf("GCI Error: Unknown DH type\r\n");

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

#ifdef TC_DBG
	printf("GCI Info: DH Calc Shared Secret\r\n");
#endif

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

	printf("GCI Info: Key Put\r\n");

	/* Search a free key ID */
	err = _searchFreeKeyID( p_keyID );

	if(err != en_gciResult_Ok)
	{
		err = en_gciResult_Err;
		printf("GCI Error: No key ID free\r\n");
		return err;
	}


	/* Store the key as big number in the key array */
	switch(ga_keyID[*p_keyID].type)
	{
		case en_gciKeyType_Sym:
			printf("GCI Info: sym key ID = %d\r\n", *p_keyID);

		break;


		case en_gciKeyType_DhPriv:
			printf("GCI Info: DH priv key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_DhPub:
			printf("GCI Info: DH pub key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_DhSecret:
			printf("GCI Info: DH secret key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_DsaPriv:
			printf("GCI Info: DSA priv key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_DsaPub:
			printf("GCI Info: DSA pub key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_EcdhPriv:
			printf("GCI Info: ECDH priv key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_EcdhPub:
			printf("GCI Info: ECDH pub key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_EcdhSecret:
			printf("GCI Info: ECDH secret key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_EcdsaPriv:
			printf("GCI Info: ECDSA priv key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_EcdsaPub:
			printf("GCI Info: ECDSA pub key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_Hmac:
			printf("GCI Info: HMAC key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_RsaPriv:
		case en_gciKeyType_RsaPrivEs:
		case en_gciKeyType_RsaPrivSsa:
			printf("GCI Info: RSA priv key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_RsaPub:
		case en_gciKeyType_RsaPubEs:
		case en_gciKeyType_RsaPubSsa:
			printf("GCI Info: RSA pub key ID = %d\r\n", *p_keyID);
		break;


		case en_gciKeyType_Invalid:
		case en_gciKeyType_None:

			printf("GCI Error: No key type initialized");

		break;
		default:

			printf("GCI Error: No key type initialized");

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

#ifdef TC_DBG
	printf("GCI Info: Key Get\r\n");
#endif

	return err;
}



/********************************/
/*	gciKeyDelete				*/
/********************************/
en_gciResult_t gciKeyDelete( GciKeyId_t keyID  )
{
	en_gciResult_t err = en_gciResult_Ok;

#ifdef TC_DBG
	printf("GCI Info: Key Delete\r\n");
#endif

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
/*	_searchFreeKeyID			*/
/********************************/
en_gciResult_t _searchFreeKeyID( GciKeyId_t* p_keyID )
{
	en_gciResult_t err = en_gciResult_Ok;

	/* Initialize the key ID */
	*p_keyID = -1;

	int i = 0;

	for( i = 0 ; i < GCI_NB_CTX_MAX ; i++ )
	{
		/* Free key ID when type is invalid */
		if( ga_keyID[i].type == en_gciKeyType_Invalid )
		{
			*p_keyID = i;

			return err;
		}
	}

	/* No free ID */
	if(*p_keyID == -1)
	{
		err = en_gciResult_Err;
	}

	return err;
}


/********************************/
/*	_registerAndTest			*/
/********************************/
en_gciResult_t _registerAndTest( void )
{
	en_gciResult_t err = en_gciResult_Ok;
	int tmpErr = 0;

	/* Register hash MD5 */
	tmpErr = register_hash(&md5_desc);

	if(tmpErr == -1)
	{
		err = en_gciResult_Err;
		printf("GCI Error: register hash MD5\r\n");
	}

	/* Test hash MD5 */
	tmpErr = md5_test();
	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
		err = en_gciResult_Err;
		printf("GCI Error: test hash MD5\r\n");
	}

	/* ... */

	/* Register prng fortuna */
	tmpErr = register_prng(&fortuna_desc);

	if(tmpErr == -1)
	{
		err = en_gciResult_Err;
		printf("GCI Error: register prng fortuna");
	}

	/* Test prng fortuna */
	tmpErr = fortuna_test();

	if((tmpErr != CRYPT_OK) && (tmpErr != CRYPT_NOP))
	{
		err = en_gciResult_Err;
		printf("GCI Error: test prng fortuna");
	}

	return err;

}


/********************************/
/*	_genDhDomainParam			*/
/********************************/
en_gciResult_t _genDhDomainParam(uint8_t* p_g, size_t* gLen, uint8_t* p_p, size_t* pLen)
{
	en_gciResult_t err = en_gciResult_Ok;
	size_t keysize = TC_DEFAULT_DHE_KEYSIZE;
	uint8_t x;
	mp_err tmpErr;

	/* Temporary domain parameters */
	mp_int g;
	mp_int p;

	/* Initialize the temporary domain parameters */
	tmpErr = mp_init_multi(&g, &p, NULL);

	if(tmpErr != CRYPT_OK)
	{
		err = en_gciResult_Err;
		printf("GCI DH Error: Init domain parameters error");
	}

	/* find key size */
	for (x = 0; (keysize > (size_t)sets[x].size) && (sets[x].size != 0); x++);

	if( sets[x].size == 0 )
	{
		err = en_gciResult_Err;
		printf("GCI Error: No key size found");
		return err;
	}

	/* Generate g */
	mp_read_radix(&g, (char *)sets[x].base, 64);
	if(tmpErr != CRYPT_OK)
	{
		err = en_gciResult_Err;
		printf("GCI DH Error: generation domain parameters");
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

	*gLen = mp_unsigned_bin_size(&g);
	*pLen = mp_unsigned_bin_size(&p);

	/* Clear the temporary domain parameters */
	mp_clear_multi(&p, &g, NULL);

	return err;
}

en_gciResult_t _genDhKeyPair( dh_key* p_dhKey )
{
    en_gciResult_t err = en_gciResult_Ok;
    ltc_init_multi(&p_dhKey->x, &p_dhKey->y, NULL);

    return err;
}

/*---------------------------------------------EOF-----------------------------------------------------------------------*/
