/**
 * \file 				crypto_iface.c
 * \brief 				see crypto_iface.h
 * \author				Steve Wagner
 * \date 				13/10/2015
 */


/*--------------------------------------------------Include--------------------------------------------------------------*/
#include "crypto_tomcrypt.h"


/*-------------------------------------------------Variables-------------------------------------------------------------*/

/** Array for the context ID */
static st_tcCtxConfig_t a_ctxID[GCI_NB_CTX_MAX];

/** Array for the Key ID */
static st_gciKey_t a_keyID[GCI_NB_KEY_MAX];


/*---------------------------------------------Prototype of local functions----------------------------------------------*/

/**
 * \fn							en_gciResult_t _searchFreeCtxID(GciCtxId_t* p_ctxID)
 * \brief						Search a free ID in a_ctxID[GCI_NB_CTX_MAX]
 * \param [out] p_ctxID			Pointer to the context's ID
 * @return						en_gciResult_Ok on success
 * @return						en_gciResult_Err on error
 */
en_gciResult_t _searchFreeCtxID( GciCtxId_t* p_ctxID );


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

	/* Initialization of the context array */
	for( i = 0; i < GCI_NB_CTX_MAX; i++ )
	{
		a_ctxID[i].type = en_tcCtxType_Invalid;

		/* Hash */
		a_ctxID[i].un_ctxConfig.ctxConfigHash = en_gciHashAlgo_Invalid;

		/* Signature */
		a_ctxID[i].un_ctxConfig.ctxConfigSign.algo = en_gciSignAlgo_Invalid;
		a_ctxID[i].un_ctxConfig.ctxConfigSign.hash = en_gciHashAlgo_Invalid;
		a_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.block = en_gciBlockMode_Invalid;
		a_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.iv.len = -1;
		a_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.iv.data = NULL;
		a_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigCmac.padding = en_gciPadding_Invalid;
		a_ctxID[i].un_ctxConfig.ctxConfigSign.un_signConfig.signConfigRsa.padding = en_gciPadding_Invalid;

		/* Cipher */
		a_ctxID[i].un_ctxConfig.ctxConfigCipher.algo = en_gciCipherAlgo_Invalid;
		a_ctxID[i].un_ctxConfig.ctxConfigCipher.blockMode = en_gciBlockMode_Invalid;
		a_ctxID[i].un_ctxConfig.ctxConfigCipher.iv.data = NULL;
		a_ctxID[i].un_ctxConfig.ctxConfigCipher.iv.len = -1;
		a_ctxID[i].un_ctxConfig.ctxConfigCipher.padding = en_gciPadding_Invalid;

		/* Diffie-Hellman */
		a_ctxID[i].un_ctxConfig.ctxConfigDh.type = en_gciDhType_Invalid;
		a_ctxID[i].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = en_gciNamedCurve_Invalid;
		a_ctxID[i].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain = NULL;

	}

	/* Initialization of the key array */
	for( i = 0; i < GCI_NB_KEY_MAX; i++ )
	{
		a_keyID[i].type = en_gciKeyType_Invalid;

		/* Diffie-Hellmann private key */
		a_keyID[i].un_key.keyDhPriv.key.data = NULL;
		a_keyID[i].un_key.keyDhPriv.key.len = -1;
		a_keyID[i].un_key.keyDhPriv.param = NULL;

		/* Diffie-Hellmann public key */
		a_keyID[i].un_key.keyDhPub.key.data = NULL;
		a_keyID[i].un_key.keyDhPub.key.len = -1;
		a_keyID[i].un_key.keyDhPub.param = NULL;

		/* Diffie-Hellmann shared secret key */
		a_keyID[i].un_key.keyDhSecret.data = NULL;
		a_keyID[i].un_key.keyDhSecret.len = -1;

		/* DSA private key */
		a_keyID[i].un_key.keyDsaPriv.param = NULL;
		a_keyID[i].un_key.keyDsaPriv.key.data = NULL;
		a_keyID[i].un_key.keyDsaPriv.key.len = -1;

		/* DSA public key */
		a_keyID[i].un_key.keyDsaPub.key.data = NULL;
		a_keyID[i].un_key.keyDsaPub.key.len = -1;
		a_keyID[i].un_key.keyDsaPub.param = NULL;

		/* ECDH private key */
		a_keyID[i].un_key.keyEcdhPriv.curve = en_gciNamedCurve_Invalid;
		a_keyID[i].un_key.keyEcdhPriv.key.data = NULL;
		a_keyID[i].un_key.keyEcdhPriv.key.len = -1;

		/* ECDH public key */
		a_keyID[i].un_key.keyEcdhPub.coord.x.data = NULL;
		a_keyID[i].un_key.keyEcdhPub.coord.x.len = -1;
		a_keyID[i].un_key.keyEcdhPub.coord.y.data = NULL;
		a_keyID[i].un_key.keyEcdhPub.coord.y.len = -1;
		a_keyID[i].un_key.keyEcdhPub.curve = en_gciNamedCurve_Invalid;

		/* ECDH shared secret key */
		a_keyID[i].un_key.keyEcdhSecret.data = NULL;
		a_keyID[i].un_key.keyEcdhSecret.len = -1;

		/* ECDSA private key */
		a_keyID[i].un_key.keyEcdsaPriv.curve = en_gciNamedCurve_Invalid;
		a_keyID[i].un_key.keyEcdsaPriv.un_key.data = NULL;
		a_keyID[i].un_key.keyEcdsaPriv.un_key.len = -1;

		/* ECDSA public key */
		a_keyID[i].un_key.keyEcdsaPub.coord.x.data = NULL;
		a_keyID[i].un_key.keyEcdsaPub.coord.x.len = -1;
		a_keyID[i].un_key.keyEcdsaPub.coord.y.data = NULL;
		a_keyID[i].un_key.keyEcdsaPub.coord.y.len = -1;
		a_keyID[i].un_key.keyEcdsaPub.curve = en_gciNamedCurve_Invalid;

		/* RSA private key */
		a_keyID[i].un_key.keyRsaPriv.crt = NULL;
		a_keyID[i].un_key.keyRsaPriv.d.data = NULL;
		a_keyID[i].un_key.keyRsaPriv.d.len = -1;
		a_keyID[i].un_key.keyRsaPriv.n.data = NULL;
		a_keyID[i].un_key.keyRsaPriv.n.len = -1;

		/* RSA public key */
		a_keyID[i].un_key.keyRsaPub.e.data = NULL;
		a_keyID[i].un_key.keyRsaPub.e.len = -1;
		a_keyID[i].un_key.keyRsaPub.n.data = NULL;
		a_keyID[i].un_key.keyRsaPub.n.len = -1;

		/* Symmetric key */
		a_keyID[i].un_key.keysym.data = NULL;
		a_keyID[i].un_key.keysym.len = -1;

	}

#ifdef TC_DBG
	printf("GCI Info: Init\r\n");
#endif

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
	uint8_t a_allocDhDomainParam[GCI_BUFFER_MAX_SIZE];
	/* 2 bytes for the curve name */
	uint8_t a_allocEcdhCurveName[2];

	size_t keysize = TC_DEFAULT_DHE_KEYSIZE;
	int x;
	int tmpErr;

	/* Temporary domain parameters */
	void *p, *g;


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

	else
	{

	}

	/* Save the configuration */
	a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.type = p_dhConfig->type;

	switch((*p_dhConfig).type)
	{
		case en_gciDhType_Dh:

			printf("GCI Info: DH context ID = %d\r\n", *p_ctxID);

			/* Allocate memory */
			a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain = &a_allocDhDomainParam;

			/* Save the parameters if different to NULL*/
			if(p_dhConfig->un_dhParam.dhParamDomain != NULL)
			{
				//TODO sw - memcpy better ? */
				a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.data = p_dhConfig->un_dhParam.dhParamDomain->g.data;
				a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.len = p_dhConfig->un_dhParam.dhParamDomain->g.len;

				//TODO sw - memcpy better ? */
				a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.data = p_dhConfig->un_dhParam.dhParamDomain->p.data;
				a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.len = p_dhConfig->un_dhParam.dhParamDomain->p.len;
			}

			/* Create the domain parameters */
			else
			{
				/* Initialize the temporary domain parameters */
				tmpErr = mp_init_multi(&g, &p, NULL);

				if(tmpErr != 0)
				{
					err = en_gciResult_ErrInitDomainParam;
					printf("GCI DH Error: Init domain parameters error");
				}

				/* find key size */
				for (x = 0; (keysize > (int)sets[x].size) && (sets[x].size != 0); x++);

				/* Generate g */
				mp_read_radix(g, sets[x].base, 64);
				if(tmpErr != 0)
				{
					err = en_gciResult_ErrGenDomainParam;
					printf("GCI DH Error: generation domain parameters");
				}

				/* Generate p */
				mp_read_radix(g, sets[x].base, 64);
				if(tmpErr != 0)
				{
					err = en_gciResult_ErrGenDomainParam;
				}

				/* Save the temporary domain parameters */
				memcpy(a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.data, g, sizeof(g));
				a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->g.len = sizeof(g);

				memcpy(a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.data, p, sizeof(p));
				a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamDomain->p.len = sizeof(p);


				/* Clear the temporary domain parameters */
				 mp_clear_multi(p, g, NULL);

				 printf("GCI Info: DH New Ctx\r\n");

			}

				//TODO sw - generate domain parameters in gciDhGenKey with dhe_make_key and get public and private key from it


		break;

		case en_gciDhType_Ecdh:

			printf("GCI Info: ECDH context ID = %d\r\n", *p_ctxID);

			/* Allocate memory */
			a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = &a_allocEcdhCurveName;

			/* Save the parameters if different to NULL*/
			if(p_dhConfig->un_dhParam.dhParamDomain != NULL)
			{
				a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = p_dhConfig->un_dhParam.dhParamCurveName;
			}

			/* Create the domain parameters */
			else
			{
				/* Choose a default elliptic curve */
				a_ctxID[*p_ctxID].un_ctxConfig.ctxConfigDh.un_dhParam.dhParamCurveName = en_gciNamedCurve_SECP384R1;
			}

			printf("GCI Info: ECDH New Ctx\r\n");

		break;

		case en_gciDhType_Invalid:
		default:

			err = gciCtxRelease(*p_ctxID);

			printf("GCI Error: Invalid Configuration\r\n");

			if (err == en_gciResult_Ok)
			{
				printf("GCI Info: Context releases\r\n");
			}

			else
			{
				printf("GCI Error: Context releases\r\n");

			}

			err = en_gciResult_ErrInvalidConfig;


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

#ifdef TC_DBG
	printf("GCI Info: DH Gen Key\r\n");
#endif

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

#ifdef TC_DBG
	printf("GCI Info: Key Put\r\n");
#endif

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
en_gciResult_t _searchFreeCtxID( GciCtxId_t* p_ctxID )
{
	en_gciResult_t err = en_gciResult_Ok;

	/* Initialize the context ID */
	*p_ctxID = -1;

	int i = 0;

	for( i = 0 ; i < GCI_NB_CTX_MAX ; i++ )
	{
		/* Free ctx ID when type is invalid */
		if( a_ctxID[i].type == en_tcCtxType_Invalid )
		{
			*p_ctxID = i;

			return err;
		}
	}

	/* No free ID */
	if(*p_ctxID == -1)
	{
		err = en_gciResult_ErrBufferIdFull;
	}


	return err;
}



/*---------------------------------------------EOF-----------------------------------------------------------------------*/
