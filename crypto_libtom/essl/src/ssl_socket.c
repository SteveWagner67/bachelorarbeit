/*============================================================================*/
/*!                                                                               
 \file   ssl_socket.c

 \author ??? by Thomas Gillen & STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  SSL API functions

 These are the SSL API functions needed to establish, run and shutdown
 a SSL connection

 \version  $Version$

 */
/*==============================================================================
 INCLUDE FILES
 ==============================================================================*/
#include <stdarg.h>
/* General includes for SSL */
#include "ssl_socket.h"
#include "ssl_record.h"
#include "ssl_target.h"
#include "ssl_oid.h"
#include "ssl_diag.h"
#include "key_management.h"
#include "ssl_sessCache.h"

/*==============================================================================
 MACROS
 ==============================================================================*/
#define	LOGGER_ENABLE		DBG_SSL_SOCKET
#include "logger.h"

#define _min(a,b)          ({ __typeof__ (a) _a = (a); \
		__typeof__ (b) _b = (b);    \
		_a < _b ? _a : _b; })

/*==============================================================================
 GLOBAL VARIABLES
 ==============================================================================*/
/*! Reserve memory for the connection contexts */
static s_sslCtx_t as_sslConnCtx[SSL_MAX_SSL_CTX];

/*! Storage for the session resumption cache */
static s_sslSessCache_t as_sessCache[SSL_SESSION_CACHE_SIZE];

/*! Buffer holding the elements of the handshake phase */
static s_sslHsElem_t as_hsElemBuf[SSL_MAX_SSL_CTX];

/*==============================================================================
 LOCAL FUNCTION PROTOTYPES
 ==============================================================================*/
static int _sslSoc_sett_import_RSAprivKey(s_cdbCert_t* pcdt_privKey,
		gci_rsaPrivKey_t* pcwt_privKey);
static int _sslSoc_sett_import_ECCprivKey(s_cdbCert_t* pcdt_privKey,
		ecc_key* pcwt_privKey, ltc_ecc_set_type* dp);


/*==============================================================================
 LOCAL FUNCTIONS
 ==============================================================================*/

/*============================================================================*/
/*! 
 \brief  Import a private key

 A wrapping function to import a private key that has previously been
 imported to cert_db format. This method imports this key to a mpi
 accessible privatekey

 \param pcdt_privKey pointer to the private key in cdb format
 \param pcwt_privKey pointer to the private key in mpi accessible format

 \return E_SSL_OK on success
 \return E_SSL_ERROR on fail

 */
/*============================================================================*/
static int _sslSoc_sett_import_RSAprivKey(s_cdbCert_t* pcdt_privKey,
		gci_rsaPrivKey_t* pcwt_privKey)
{
	int err = E_SSL_ERROR;
	size_t cwt_len;
	unsigned char* p_buffer;
	/*
	 * Read the cert into the cert_db buffer
	 */
	p_buffer = cdb_read2buf(pcdt_privKey, &cwt_len);
	if (p_buffer != NULL)
	{
		int iRet;
		/*
		 * Import the privatekey
		 */
		//TODO sw gci_key_pair_gen RSA
		iRet = cw_rsa_privatekey_init(p_buffer, (uint32_t) cwt_len,
				pcwt_privKey);
		if (iRet == CRYPT_OK)
		{
			//TODO sw ?? private key shrink
			cw_rsa_privatekey_shrink(pcwt_privKey);
			err = E_SSL_OK;
		} /* if */
		else
		{
			LOG_ERR(
					"Import of the private key was't successful! Cryptolib says: %s",
					cw_error2string(iRet));
		} /* else */

		cdb_free();
	} /* if */
	else
	{
		LOG_ERR("Reading the private key from cert_db was not successful");
	} /* else */

	return err;
} /* _sslSoc_sett_import_privKey() */


//begin vpy
/*============================================================================*/
/*!
 \brief  Import a private key

 A wrapping function to import a private key that has previously been
 imported to cert_db format. This method imports this key to a mpi
 accessible privatekey

 \param pcdt_privKey pointer to the private key in cdb format
 \param pcwt_privKey pointer to the private key in mpi accessible format
 \param	dp			 Pointer to a struct that will be filled by curves' parameters


 \return E_SSL_OK on success
 \return E_SSL_ERROR on fail

 */
/*============================================================================*/
static int _sslSoc_sett_import_ECCprivKey(s_cdbCert_t* pcdt_privKey,
		ecc_key* pcwt_privKey, ltc_ecc_set_type* dp)
{
	int err = E_SSL_ERROR;

	size_t cwt_len;
	unsigned char* p_buffer;

	/*
	 * Read the cert into the cert_db buffer
	 */
	p_buffer = cdb_read2buf(pcdt_privKey, &cwt_len);
	if (p_buffer != NULL)
	{
		int iRet;
		/*
		 * Import the privatekey
		 */

		//TODO sw gci_key_pair_gen for ECDSA or gci_dh_gen_key for ECDH
		iRet = cw_ecc_privatekey_init(p_buffer, (uint32_t) cwt_len, pcwt_privKey, dp);
		if (iRet == CRYPT_OK)
		{
			//printf()
			err = E_SSL_OK;
		} /* if */
		else
		{
			LOG_ERR(
					"Import of the private key was't successful! Cryptolib says: %s",
					cw_error2string(iRet));
		} /* else */

		cdb_free();
	} /* if */
	else
	{
		LOG_ERR("Reading the private key from cert_db was not successful");
	} /* else */

	return err;
} /* _sslSoc_sett_import_privKey() */
//end vpy
/*==============================================================================
 GLOBAL FUNCTIONS
 ==============================================================================*/

/*==============================================================================
 SSL_init()
 ==============================================================================*/
void SSL_init(void)
{
	int i;

	/*
	 * Reset the whole module
	 */
	sslSoc_killall();

	/*
	 * Set every context explicit to E_SSL_SOCKET_UNUSED, so it can be picked by sslSoc_new()
	 */
	for (i = 0; i < SSL_MAX_SSL_CTX; i++)
	{
		as_sslConnCtx[i].e_socState = E_SSL_SOCKET_UNUSED;
	}

	return;
} /* SSL_init() */

/*==============================================================================
 sslSoc_initSett()
 ==============================================================================*/
void sslSoc_initSett(s_sslSett_t* ps_sslSett, e_sslKeyType_t keyType)
{
	assert(ps_sslSett != NULL);

	CW_MEMSET(ps_sslSett, 0x00, sizeof(s_sslSett_t));

	sslSoc_setVer(ps_sslSett, SSL_MIN_SSL_TLS_VERSION, SSL_MAX_SSL_TLS_VERSION);

	sslSoc_setAuthLvl(ps_sslSett, SSL_DEFAULT_CLIENTAUTH_LEVEL);

	sslSoc_setSessTimeout(ps_sslSett, SSL_DEFAULT_SESSION_TIMEOUT);

	sslSoc_setReneg(ps_sslSett, SSL_DEFAULT_RENEGOTIATION_BEHAVIOR);

	/* TODO move this hardcoded selection later, on cert parsing step */
	//TODO vpy EDSA: move in cert parsing
	if(keyType == E_SSL_KEY_EC)
	{
		ps_sslSett->s_certSignHashAlg.c_hash = E_SSL_HASH_SHA256;
		ps_sslSett->s_certSignHashAlg.c_sign = E_SSL_SIGN_RSA;
	}
	else
	{
		ps_sslSett->s_certSignHashAlg.c_hash = E_SSL_HASH_SHA256;
		ps_sslSett->s_certSignHashAlg.c_sign = E_SSL_SIGN_ECDSA;
	}


	return;
} /* sslSoc_initSett() */

/*==============================================================================
 sslSoc_freeSett()
 ==============================================================================*/
void sslSoc_freeSett(s_sslSett_t* ps_sslSett)
{
	assert(ps_sslSett != NULL);

	if (ps_sslSett->pgci_rsaMyPrivKey)
	{
		cw_rsa_privatekey_free(ps_sslSett->pgci_rsaMyPrivKey);
		free(ps_sslSett->pgci_rsaMyPrivKey);
	} /* if */

	return;
} /* sslSoc_freeSett() */

/*==============================================================================
 sslSoc_setReadWrite()
 ==============================================================================*/
void sslSoc_setReadWrite(s_sslSett_t* ps_sslSett, fp_ssl_readHandler read,
		fp_ssl_writeHandler write)
{
	assert(ps_sslSett != NULL);

	ps_sslSett->fp_stdRead = read;
	ps_sslSett->fp_stdWrite = write;

	return;
} /* sslSoc_setReadWrite()  */

/*==============================================================================
 sslSoc_setTimeFunc()
 ==============================================================================*/
void sslSoc_setTimeFunc(s_sslSett_t* ps_sslSett, fp_ssl_getCurrentTime getTime)
{
	assert(ps_sslSett != NULL);

	ps_sslSett->fp_getCurTime = getTime;

	if (getTime == NULL)
		ps_sslSett->c_allowInsecure = 1;
	else
		ps_sslSett->c_allowInsecure = 0;

	return;
} /* sslSoc_setTimeFunc()  */

/*==============================================================================
 sslSoc_setAuthLvl()
 ==============================================================================*/
void sslSoc_setAuthLvl(s_sslSett_t* ps_sslSett, e_sslAuthLevel_t e_level)
{
	assert(ps_sslSett != NULL);

	ps_sslSett->e_authLvl = e_level;

	return;
} /* sslSoc_setAuthLvl()  */

/*==============================================================================
 sslSoc_setVer()
 ==============================================================================*/
void sslSoc_setVer(s_sslSett_t* ps_sslSett, e_sslVer_t min, e_sslVer_t max)
{
	assert(ps_sslSett != NULL);
	if (min <= max)
	{
		ps_sslSett->e_minVer = min;
		ps_sslSett->e_maxVer = max;
	}
	else
	{
		ps_sslSett->e_minVer = max;
		ps_sslSett->e_maxVer = min;
	}
	return;
} /* sslSoc_setVer()  */

/*==============================================================================
 sslSoc_setReneg()
 =============================================================================*/
uint8_t sslSoc_setReneg(s_sslSett_t* ps_sslSett, uint8_t enable)
{
	uint8_t ret;
	assert(ps_sslSett != NULL);
	ret = ps_sslSett->c_isRenegOn;
	ps_sslSett->c_isRenegOn = enable;
	return ret;
} /* sslSoc_setReneg() */

/*==============================================================================
 sslSoc_setSessTimeout()
 ==============================================================================*/
void sslSoc_setSessTimeout(s_sslSett_t* ps_sslSett, uint32_t ui_timeoutInSeconds)
{
	assert(ps_sslSett != NULL);

	ps_sslSett->l_sessTimespan = (uint32_t) (ui_timeoutInSeconds * 1000);

	return;
} /* sslSoc_setSessTimeout() */

/*==============================================================================
 sslSoc_setCaCertList()
 ==============================================================================*/
void sslSoc_setCaCertList(s_sslSett_t* ps_sslSett,s_sslCertList_t * p_list_head)
{
	assert(ps_sslSett != NULL);

	ps_sslSett->ps_caCertsListHead = p_list_head;
} /* sslSoc_setCaCertList() */

/*==============================================================================
 sslSoc_getCaCertList()
 ==============================================================================*/
s_sslCertList_t * sslSoc_getCaCertList(s_sslSett_t* ps_sslSett)
{
	assert(ps_sslSett != NULL);

	return ps_sslSett->ps_caCertsListHead;
} /* sslSoc_getCaCertList() */

/*==============================================================================
 sslSoc_setCertChainList()
 ==============================================================================*/
void sslSoc_setCertChainList(s_sslSett_t* ps_sslSett,s_sslCertList_t * p_list_head)
{
	assert(ps_sslSett != NULL);

	ps_sslSett->ps_certChainListHead = p_list_head;
} /* sslSoc_setCertChainList() */

/*==============================================================================
 sslSoc_getCertChainList()
 ==============================================================================*/
s_sslCertList_t * sslSoc_getCertChainList(s_sslSett_t* ps_sslSett)
{
	assert(ps_sslSett != NULL);

	return ps_sslSett->ps_certChainListHead;
} /* sslSoc_getCertChainList() */

/*==============================================================================
 sslSoc_setRsaPrivKey()
 ==============================================================================*/
int sslSoc_setRsaPrivKey(s_sslSett_t* ps_sslSett, s_cdbCert_t* pcdt_privKey)
{
	int iRet;

	assert(ps_sslSett != NULL);
	assert(pcdt_privKey != NULL);

	/* Memory for my RSA Private Key */
	ps_sslSett->pgci_rsaMyPrivKey = malloc(sizeof(gci_rsaPrivKey_t));

	iRet = _sslSoc_sett_import_RSAprivKey(pcdt_privKey, ps_sslSett->pgci_rsaMyPrivKey);
	if (iRet != E_SSL_OK)
	{
		ps_sslSett->pgci_rsaMyPrivKey = NULL;
	}

	return iRet;
} /* sslSoc_setRsaPrivKey() */

//begin vpy
/*==============================================================================
 sslSoc_setRsaPrivKey()
 ==============================================================================*/
int sslSoc_setECCPrivKey(s_sslSett_t* ps_sslSett, s_cdbCert_t* pcdt_privKey)
{
	//TODO prototype + implement + content of switch
	int iRet;

	assert(ps_sslSett != NULL);
	assert(pcdt_privKey != NULL);

	/* Memory for my ECC Private Key */
	ps_sslSett->p_ECCMyPrivKey = malloc(sizeof(ecc_key));

	iRet = _sslSoc_sett_import_ECCprivKey(pcdt_privKey, ps_sslSett->p_ECCMyPrivKey, &(ps_sslSett->ltc_ECC_curvesParameters));
	if (iRet != E_SSL_OK)
	{
		ps_sslSett->p_ECCMyPrivKey = NULL;
	}

	return iRet;
} /*sslSoc_setECCPrivKey()*/

//end vpy

/*==============================================================================
 sslSoc_getCtxAuthLvl()
 ==============================================================================*/
uint32_t sslSoc_getCtxAuthLvl(s_sslCtx_t* ps_sslCtx)
{
	assert(ps_sslCtx != NULL);

	return ps_sslCtx->ps_hsElem->s_sessElem.l_authId;
} /* sslSoc_getCtxAuthLvl() */

/*==============================================================================
 sslSoc_setCtxCipSpecs()
 ==============================================================================*/
void sslSoc_setCtxCipSpecs(s_sslCtx_t* ps_sslCtx, e_sslCipSpec_t wt_ciph, ...)
{
	assert(ps_sslCtx != NULL);
	int i = 0;
	va_list args;

	CW_MEMSET(ps_sslCtx->s_sslGut.ae_cipSpecs, 0,
			sizeof(ps_sslCtx->s_sslGut.ae_cipSpecs));
	va_start(args, wt_ciph);

	while ((wt_ciph != 0) && (i < SSL_CIPSPEC_COUNT))
	{
		ps_sslCtx->s_sslGut.ae_cipSpecs[i] = wt_ciph;
		wt_ciph = (e_sslCipSpec_t) va_arg(args, int);
		i++;
	}
	va_end(args);
	return;
} /* sslSoc_setCtxCipSpecs() */

/*==============================================================================
 sslSoc_setCtxCipList()
 ==============================================================================*/
int sslSoc_setCtxCipList(s_sslCtx_t *ps_sslCtx, const char *str)
{
	assert(ps_sslCtx != NULL);
	assert(str != NULL);
	int i;
	char *p_str = str;

	char strCipher[64];

	i = 0;
	CW_MEMSET(ps_sslCtx->s_sslGut.ae_cipSpecs, 0,
			sizeof(ps_sslCtx->s_sslGut.ae_cipSpecs));

	while ((str != NULL) && (i < SSL_CIPSPEC_COUNT) && (p_str < (str+strlen(str))))
	{
		char *ps_endSubStr;
		ps_endSubStr = strstr(p_str, ":");
		if(ps_endSubStr==NULL)
		{
			ps_endSubStr = p_str + strlen(p_str);
		}
		char lenSubStr = ps_endSubStr - p_str;

		if (lenSubStr ==0) //If size is 0, do not compare string. Should not happen
		{
			return i;
		}

		if (lenSubStr > sizeof(strCipher) - 1) {
			p_str+=(lenSubStr+1);
			continue;
		} else {
			memset(strCipher, 0, sizeof(strCipher));
			strncpy(strCipher, p_str, lenSubStr);
			p_str+=(lenSubStr+1);
		}

#ifdef AES_AND_3DES_ENABLED
		if (strcmp(strCipher, TLS_DHE_RSA_WITH_AES_128_CBC_SHA256_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
			i++;
		}
		else if (strcmp(strCipher, TLS_DHE_RSA_WITH_AES_256_CBC_SHA256_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
			i++;
		}
		else if (strcmp(strCipher, TLS_RSA_WITH_AES_256_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_RSA_WITH_AES_256_CBC_SHA;
			i++;
		}
		else if (strcmp(strCipher, TLS_RSA_WITH_AES_256_CBC_SHA256_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_RSA_WITH_AES_256_CBC_SHA256;
			i++;
		}
		else if (strcmp(strCipher, TLS_RSA_WITH_AES_128_CBC_SHA256_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_RSA_WITH_AES_128_CBC_SHA256;
			i++;
		}
		else if (strcmp(strCipher, TLS_RSA_WITH_AES_128_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_RSA_WITH_AES_128_CBC_SHA;
			i++;
		}
		else if (strcmp(strCipher, TLS_RSA_WITH_3DES_EDE_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_RSA_WITH_3DES_EDE_CBC_SHA;
			i++;
		}
		else if (strcmp(strCipher, TLS_DHE_RSA_WITH_AES_256_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
			i++;
		}
		else if (strcmp(strCipher, TLS_DHE_RSA_WITH_AES_128_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
			i++;
		}
		else if (strcmp(strCipher, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA;
			i++;
		}
		//begin vpy
		else if (strcmp(strCipher, TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA;
			i++;
		}

		else if (strcmp(strCipher, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
			i++;
		}

		else if (strcmp(strCipher, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;
			i++;
		}

		else if (strcmp(strCipher, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
			i++;
		}

		else if (strcmp(strCipher, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
			i++;
		}

		else if (strcmp(strCipher, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] =
					TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
			i++;
		}
		//end vpy
		else
#endif
		if (strcmp(strCipher, TLS_RSA_WITH_RC4_128_SHA_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] = TLS_RSA_WITH_RC4_128_SHA;
			i++;
		}
		else if (strcmp(strCipher, TLS_RSA_WITH_RC4_128_MD5_NAME) == 0)
		{
			ps_sslCtx->s_sslGut.ae_cipSpecs[i] = TLS_RSA_WITH_RC4_128_MD5;
			i++;
		}
	}
	return i;
} /* sslSoc_setCtxCipList() */

/*==============================================================================
 sslSoc_setCtxMtu()
 ==============================================================================*/
void sslSoc_setCtxMtu(s_sslCtx_t* ps_sslCtx, uint32_t l_mtu)
{
	assert(ps_sslCtx != NULL);
	if (l_mtu <= SSL_TLS_MAX_PLAINTEXTLEN)
	{
		ps_sslCtx->l_mtu = l_mtu;
	}
	else
	{
		ps_sslCtx->l_mtu = SSL_TLS_MAX_PLAINTEXTLEN;
	}
	return;
} /* sslSoc_setCtxMtu() */

/*==============================================================================
 sslSoc_setCtxVerif()
 ==============================================================================*/
void sslSoc_setCtxVerif(s_sslCtx_t* ps_sslCtx, e_sslAuthLevel_t level)
{
	assert(ps_sslCtx != NULL);
	ps_sslCtx->e_authLvl = level;
	return;
} /* sslSoc_setCtxVerif() */

/*==============================================================================
 sslSoc_setCtxVer()
 ==============================================================================*/
void sslSoc_setCtxVer(s_sslCtx_t* ps_sslCtx, e_sslVer_t version)
{
	assert(ps_sslCtx != NULL);
	ps_sslCtx->e_ver = version;
	return;
} /* sslSoc_setCtxVer() */

/*==============================================================================
 sslSoc_setCtxReneg()
 ==============================================================================*/
uint8_t sslSoc_setCtxReneg(s_sslCtx_t* ps_sslCtx, uint8_t enable)
{
	uint8_t ret;
	assert(ps_sslCtx != NULL);
	ret = ps_sslCtx->c_isRenegOn;
	ps_sslCtx->c_isRenegOn = enable;
	return ret;
} /* sslSoc_setCtxReneg() */

/*==============================================================================
 sslSoc_setCtxSess()
 ==============================================================================*/
e_sslResult_t sslSoc_setCtxSess(s_sslCtx_t* ps_sslCtx, l_sslSess_t s_desc)
{
	int ret;
	assert(ps_sslCtx != NULL);
	/*
	 * The return value indicates if the given session identifier was found or not
	 */
	if ((s_desc != SSL_INVALID_SESSION )
			&& (sslSesCache_getById(ps_sslCtx->ps_sslSett->ps_sessCache, s_desc)
					== E_SSL_SESSCACHE_HIT))
	{
		ret = E_SSL_OK;
	} /* if */
	else
	{
		ret = E_SSL_ERROR;
	} /* else */

	/*
	 * The session identifier is set when it is a valid one
	 */
	if (s_desc != SSL_INVALID_SESSION)
		ps_sslCtx->ps_hsElem->s_sessElem.s_desc = s_desc;

	return ret;
} /* sslSoc_setCtxSess() */

/*==============================================================================
 sslSoc_getCtxSess()
 ==============================================================================*/
l_sslSess_t sslSoc_getCtxSess(s_sslCtx_t* ps_sslCtx)
{
	assert(ps_sslCtx != NULL);
	return ps_sslCtx->ps_hsElem->s_sessElem.s_desc;
} /* sslSoc_getCtxSess() */

/*==============================================================================
 sslSoc_killall()
 ==============================================================================*/
e_sslResult_t sslSoc_killall(void)
{
	int i;

	/* Clear the memory that holds the socket interface contexts */
	/* Clear the memory buffer containing the connection contexts */
	CW_MEMSET(&as_sslConnCtx, 0x00, sizeof(as_sslConnCtx));

	/* Clear the memory buffer storing the information used during the SSL    */
	/* handshake phase */
	CW_MEMSET(&as_hsElemBuf, 0x00, sizeof(as_hsElemBuf));

	/*
	 * Reset the timers
	 */
	for (i = 0; i < SSL_SESSION_CACHE_SIZE; ++i)
	{
		tot2_resetTmr(&as_sessCache[i].s_sessTimeout);
	}

	/* Clear the buffer containing the session resumption cache */
	CW_MEMSET(&as_sessCache, 0x00, sizeof(as_sessCache));

	return E_SSL_OK;
} /* sslSoc_killall() */

/*==============================================================================
 sslSoc_shutdown()
 ==============================================================================*/
int sslSoc_shutdown(s_sslCtx_t* ps_sslCtx)
{
	/* This function behaves different than usual.
	 * Return values are 0 for no success (yet),
	 * 1 for success; usually this function is called twice ...
	 */
	int i_retVal = E_SSL_ERROR;

	if (ps_sslCtx != NULL)
	{
		/* Check the actual shutdown state first */
		switch (ps_sslCtx->s_sslGut.e_smState)
		{
		case E_SSL_SM_SHUTDOWN_SENT:
#if SSL_WAIT_FOR_SHUTDOWN
			/* Shutdown message already sent, wait for response */
			if(sslSoc_read(ps_sslCtx, NULL, 0xFFFF) != E_SSL_ERROR)
			{
				i_retVal = E_SSL_AGAIN;
			}
#else
	/* Shutdown message already sent, we've finished */
			if (ps_sslCtx->e_socState == E_SSL_SOCKET_IDLE) {
				i_retVal = E_SSL_OK; /* Success */
			} else {
				if (sslSoc_flush(ps_sslCtx) != E_SSL_ERROR) {
					i_retVal = E_SSL_AGAIN;
				}
			}
#endif
			break;
		case E_SSL_SM_SEND_SHUTDOWN:
			ps_sslCtx->e_event = E_PENDACT_SRV_SCACHE;
			if (sslSoc_flush(ps_sslCtx) != E_SSL_ERROR)
			{
				i_retVal = E_SSL_AGAIN;
			}
			break;
		case E_SSL_SM_SHUTDOWN_COMPLETE:
			i_retVal = E_SSL_OK; /* Success */
			break;
		default: /* In all other states: send SHUTDOWN (close) alert */
			i_retVal = E_SSL_AGAIN;
			/* Todo check line below ((ps_sslCtx->c_isResumable == TRUE))*/
			if ((ps_sslCtx->e_socState == E_SSL_SOCKET_IDLE) /*&& (ps_sslCtx->c_isResumable == TRUE)*/)
			{
				/* prepare shutdown message */
				ps_sslCtx->s_sslGut.e_smState = E_SSL_SM_SEND_SHUTDOWN;
				ps_sslCtx->s_sslGut.e_alertType = E_SSL_ALERT_CLOSE_NOTIFY;
				ps_sslCtx->e_event = E_PENDACT_SRV_SCACHE;
			}
			else
			{
				if (sslSoc_io(ps_sslCtx) == E_SSL_ERROR)
				{
					i_retVal = E_SSL_ERROR;
				}
			}
			break;
		}
	}

	return i_retVal;
} /* sslSoc_shutdown() */

/*==============================================================================
 sslSoc_setCtxFd()
 ==============================================================================*/
int sslSoc_setCtxFd(s_sslCtx_t * ps_sslCtx, int fd)
{
	assert(ps_sslCtx != NULL);
	LOG1_INFO("SSL socket at %p gets socket %i assigned", ps_sslCtx, fd);
	ps_sslCtx->i_socNum = fd;
	return E_SSL_OK;
} /* sslSoc_setCtxFd() */

/*==============================================================================
 sslSoc_new()
 ==============================================================================*/
s_sslCtx_t* sslSoc_new(s_sslSett_t* ps_sslSett)
{
	assert(ps_sslSett != NULL);
	int i;

	s_sslCtx_t *pas_sslArray;
	s_sslCtx_t *ps_sslElem;

	pas_sslArray = (s_sslCtx_t*) as_sslConnCtx;

	/* Search for an unused SSL-Socket for the new connection */

	/* ATOMAR SECTION START */

	for (i = 0; i < SSL_MAX_SSL_CTX; i++)
	{
		if (pas_sslArray[i].e_socState == E_SSL_SOCKET_UNUSED)
		{
			break;
		}
	}

	/* ATOMAR SECTION ENDS */

	if (i == SSL_MAX_SSL_CTX)
	{
		/* All connections are in use, no free socket found */
		return NULL;
	}
	else
	{
		/*
		 * An unused connection space was found
		 * accept the new connection and start up negotiation
		 */
		ps_sslElem = &pas_sslArray[i];
		LOG1_INFO("sslSoc_new() returns socket %i", i);

		/*
		 * Check if there is the possibility to check the s_validity of the certificates
		 */
		if ((ps_sslSett->fp_getCurTime != NULL) || (ps_sslSett->c_allowInsecure == 1))
		{
			ps_sslSett->ps_sessCache = as_sessCache;

			ssl_initCtx(ps_sslElem, ps_sslSett, &as_hsElemBuf[i]);

			ps_sslElem->e_socState = E_SSL_SOCKET_IDLE;
			ps_sslElem->e_ver = E_VER_DCARE;
			ps_sslElem->l_hsCtx = i;
			ps_sslElem->i_socNum = SSL_INVALID_SOCKET;
			ps_sslElem->l_mtu = SSL_WRITE_BLOCK_LEN;
			/*
			 * Default the c_secureReneg to FALSE
			 */
			 ps_sslElem->c_secReneg = FALSE;
		}
		else
		{
			/*
			 * otherwise an error is triggered
			 */
			LOG_ERR("No possibility given to check s_validity of certificate and"
					"general context hasn't been set to allow insecure connections");
			ps_sslElem = NULL;
		}
		return ps_sslElem;
	}
} /* sslSoc_new() */

/*==============================================================================
 sslSoc_free()
 ==============================================================================*/
int sslSoc_free(s_sslCtx_t* ps_sslCtx)
{

	assert(ps_sslCtx != NULL);
	assert(ps_sslCtx->ps_hsElem != NULL);

	//TODO sw gci_key_delete
	cw_rsa_publickey_free(&ps_sslCtx->ps_hsElem->gci_peerPubKey);

	//TODO sw gci_key_delete
	cw_dh_free(&ps_sslCtx->ps_hsElem->gci_dheCliPrivKey);

	cw_dh_free(&ps_sslCtx->ps_hsElem->gci_dheSrvPubKey);

	if (ps_sslCtx->ps_hsElem->pgci_dheP != NULL)
	{
		//TODO sw ?? delete a BigNumber
		cw_bn_freefree(ps_sslCtx->ps_hsElem->pgci_dheP);
	}

	if (ps_sslCtx->s_secParams.c_useDheKey == TRUE)
		km_dhe_releaseKey();

	CW_MEMSET(ps_sslCtx->ps_hsElem, 0x00, sizeof(s_sslHsElem_t));
	CW_MEMSET(ps_sslCtx, 0x00, sizeof(s_sslCtx_t)); /* Destroy context data */

	ps_sslCtx->e_socState = E_SSL_SOCKET_UNUSED;

	return E_SSL_OK;
} /* sslSoc_free() */

/*==============================================================================
 sslSoc_pending()
 ==============================================================================*/
int sslSoc_pending(s_sslCtx_t* ps_sslCtx)
{
	int iRet = 0;
	assert(ps_sslCtx != NULL);
	if (ps_sslCtx->e_socState == E_SSL_SOCKET_READOUT)
	{
		iRet = ps_sslCtx->l_buffLen - ps_sslCtx->l_readOff;
	}
	return iRet;
} /* sslSoc_pending() */

/*==============================================================================
 sslSoc_read()
 ==============================================================================*/
int sslSoc_read(s_sslCtx_t* ps_sslCtx, char* pcReadBuffer, int iReadBufferLen)
{
	int iBytesToTransfer;

	assert(ps_sslCtx != NULL);

	switch (ps_sslCtx->e_socState)
	{
	/* Buffer access */
	case E_SSL_SOCKET_READOUT:
		iBytesToTransfer = _min(iReadBufferLen, ps_sslCtx->l_buffLen);

		if (pcReadBuffer)
			CW_MEMCOPY( pcReadBuffer, ps_sslCtx->ac_socBuf + ps_sslCtx->l_readOff, iBytesToTransfer );

		ps_sslCtx->l_readOff += iBytesToTransfer;
		ps_sslCtx->l_buffLen -= iBytesToTransfer;

		if (ps_sslCtx->l_buffLen <= 0)
		{
			ps_sslCtx->e_socState = E_SSL_SOCKET_IDLE;
			ps_sslCtx->l_buffLen = 0;
			ps_sslCtx->l_readOff = 0;
		}
		return (iBytesToTransfer);

		/* Network access */
	case E_SSL_SOCKET_TXBUFF:
		if (sslSoc_io(ps_sslCtx) < 0)
		{
			return E_SSL_ERROR;
		}
		return E_SSL_AGAIN;

	case E_SSL_SOCKET_IDLE:
		/*
		 * Fall through, when the user wants to read, let him do this if data is available
		 */
	case E_SSL_SOCKET_RXBUFF:
		/* perform an network action */
		switch (sslSoc_io(ps_sslCtx))
		{
		case E_SSL_AGAIN:
			break;
		case E_SSL_ERROR:
			return E_SSL_ERROR;
		default:
			break;
		}
		/* Check for an complete record received */
		if (ps_sslCtx->l_buffLen
				&& (sslRec_getLen(ps_sslCtx) == ps_sslCtx->l_buffLen))
		{
			/* Process the record, to be replaced by an sslSoc_procRec call */
			ps_sslCtx->e_event = E_PENDACT_SRV_RECORD;

			sslSoc_procRec(ps_sslCtx);
		}
		return E_SSL_AGAIN;

		case E_SSL_SOCKET_READIN:
			return E_SSL_WANT_WRITE;
		case E_SSL_SOCKET_CLOSE:
			if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_SHUTDOWN_COMPLETE)
			{
				ps_sslCtx->e_lastError = E_SSL_NO_ERROR_SHDOWN;
			}
			else
			{
				ps_sslCtx->e_lastError = E_SSL_ERROR_SOCSTATE;
			}
			return E_SSL_ERROR;
		default:
			ps_sslCtx->e_socState = E_SSL_SOCKET_UNUSED;
		case E_SSL_SOCKET_UNUSED:
			ps_sslCtx->l_buffLen = 0;
			ps_sslCtx->l_readOff = 0;
			return E_SSL_ERROR;
	}
} /* sslSoc_read() */

/*==============================================================================
 sslSoc_write()
 ==============================================================================*/
int sslSoc_write(s_sslCtx_t* ps_sslCtx, const char* pcWriteBuffer,
		int iWriteBufferLen)
{
	assert(ps_sslCtx != NULL);
	int iBytesToTransfer;

	unsigned char * pcBuffer;

	pcBuffer = ps_sslCtx->ac_socBuf;
	if (iWriteBufferLen)
	{
		switch (ps_sslCtx->e_socState)
		{
		/* Buffer operations */
		case E_SSL_SOCKET_IDLE:
			ps_sslCtx->l_buffLen = REC_HEADERLEN;

			/* Fall through, the rest of the handling is identical to E_SSL_SOCKET_READIN */
		case E_SSL_SOCKET_READIN:
			iBytesToTransfer = _min(iWriteBufferLen,
					(ps_sslCtx->l_mtu - ps_sslCtx->l_buffLen));

			CW_MEMCOPY(pcBuffer + ps_sslCtx->l_buffLen, pcWriteBuffer, iBytesToTransfer);

			ps_sslCtx->l_buffLen += iBytesToTransfer;

			if ((ps_sslCtx->l_buffLen < ps_sslCtx->l_mtu))
			{
				ps_sslCtx->e_socState = E_SSL_SOCKET_READIN;
				return (iBytesToTransfer);
			}

			/* Send trigger level reached */

			if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_APPDATA_EXCHANGE)
				ps_sslCtx->e_event = E_PENDACT_SRV_APPRESP;

			sslSoc_procRec(ps_sslCtx);

			/* Dont fall through because "sslSoc_io" call could block */
			return (iBytesToTransfer);

			/* Network operations */
		case E_SSL_SOCKET_TXBUFF:

			switch (ps_sslCtx->e_nextAction)
			{
			case E_PENDACT_COM_CIPHER_TXCLOSE:
			case E_PENDACT_COM_CIPHER_TX:
				if (sslSoc_io(ps_sslCtx) < 0)
				{
					return E_SSL_ERROR;
				}

				if (ps_sslCtx->l_buffLen > 0)
				{
					return E_SSL_AGAIN;
				}

				/* The buffer was sent entirely */
				ps_sslCtx->e_socState = E_SSL_SOCKET_IDLE;

				if (ps_sslCtx->e_nextAction == E_PENDACT_COM_CIPHER_TX)
					return E_SSL_AGAIN;
				/* action is COM_TXMIT_CLOSE: Fall through and close the connection */
			case E_PENDACT_COM_CIPHER_CLOSE:

				return E_SSL_ERROR;
			default:
				return E_SSL_AGAIN;
			}
			case E_SSL_SOCKET_RXBUFF:
			case E_SSL_SOCKET_READOUT:
				return E_SSL_WANT_AGAIN;
			case E_SSL_SOCKET_CLOSE:
				if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_SHUTDOWN_COMPLETE)
				{
					ps_sslCtx->e_lastError = E_SSL_NO_ERROR_SHDOWN;
				}
				else
				{
					ps_sslCtx->e_lastError = E_SSL_ERROR_SOCSTATE;
				}
				return E_SSL_ERROR;
			default:
				ps_sslCtx->e_socState = E_SSL_SOCKET_UNUSED;
			case E_SSL_SOCKET_UNUSED:
				ps_sslCtx->l_buffLen = 0;
				ps_sslCtx->l_readOff = 0;
				return E_SSL_ERROR;
		}
	}
	return E_SSL_AGAIN;
} /* sslSoc_write() */

/*==============================================================================
 sslSoc_flush()
 ==============================================================================*/
int sslSoc_flush(s_sslCtx_t* ps_sslCtx)
{
	assert(ps_sslCtx != NULL);

	switch (ps_sslCtx->e_socState)
	{
	/* Buffer operations */
	case E_SSL_SOCKET_IDLE:
		ps_sslCtx->l_buffLen = REC_HEADERLEN;
		/* Fall through, the rest of the handling is identical to E_SSL_SOCKET_READIN */

	case E_SSL_SOCKET_READIN:

		if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_APPDATA_EXCHANGE)
			ps_sslCtx->e_event = E_PENDACT_SRV_APPRESP;

		sslSoc_procRec(ps_sslCtx);

		/* Dont fall through because "sslSoc_io" call could block */
		return E_SSL_AGAIN;

		/* Network operations */
	case E_SSL_SOCKET_TXBUFF:

		switch (ps_sslCtx->e_nextAction)
		{
		case E_PENDACT_COM_CIPHER_TXCLOSE:
		case E_PENDACT_COM_CIPHER_TX:
			if (sslSoc_io(ps_sslCtx) < 0)
			{
				return E_SSL_ERROR;
			}

			if (ps_sslCtx->l_buffLen > 0)
			{
				return E_SSL_AGAIN;
			}

			/* The buffer was sent entirely */
			ps_sslCtx->e_socState = E_SSL_SOCKET_IDLE;
			ps_sslCtx->l_buffLen = 0;
			ps_sslCtx->l_readOff = 0;
			CW_MEMSET(ps_sslCtx->ac_socBuf, 0x00, 5);
			if (ps_sslCtx->e_nextAction == E_PENDACT_COM_CIPHER_TX)
				return E_SSL_OK;
			/* action is COM_TXMIT_CLOSE: Fall through and close the connection */
		case E_PENDACT_COM_CIPHER_CLOSE:

			return E_SSL_ERROR;
		default:
			return E_SSL_AGAIN;
		}
		case E_SSL_SOCKET_RXBUFF:
		case E_SSL_SOCKET_READOUT:
			return E_SSL_WANT_AGAIN;
		case E_SSL_SOCKET_CLOSE:
			if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_SHUTDOWN_COMPLETE)
			{
				ps_sslCtx->e_lastError = E_SSL_NO_ERROR_SHDOWN;
			}
			else
			{
				ps_sslCtx->e_lastError = E_SSL_ERROR_SOCSTATE;
			}
			return E_SSL_ERROR;
		default:
			ps_sslCtx->e_socState = E_SSL_SOCKET_UNUSED;
		case E_SSL_SOCKET_UNUSED:
			ps_sslCtx->l_buffLen = 0;
			ps_sslCtx->l_readOff = 0;
			return E_SSL_ERROR;
	}
} /* sslSoc_flush() */

/*==============================================================================
 sslSoc_accept()
 ==============================================================================*/
int sslSoc_accept(s_sslCtx_t * ps_sslCtx)
{
	assert(ps_sslCtx != NULL);

	/* the number of bytes to be read to retrieve a complete record */
	int bytes;

	/* TODO this condition shouldn't be here, what if connection is requiring */
	/* check if the private key has been initialized, otherwise return */
	/* Check for ECC key or RSA*/
	if ((ps_sslCtx->ps_sslSett->pgci_rsaMyPrivKey != NULL)|| (ps_sslCtx->ps_sslSett->p_ECCMyPrivKey !=NULL)) //vpy
	{
		switch (ps_sslCtx->s_sslGut.e_smState)
		{
		case E_SSL_SM_APPDATA_EXCHANGE:
			return E_SSL_OK;
		case E_SSL_SM_WAIT_INIT:
			ps_sslCtx->s_sslGut.e_smState = E_SSL_SM_WAIT_CLIENT_HELLO;
			ps_sslCtx->b_isCli = FALSE;
		default:
			break;
		}

		switch (sslSoc_io(ps_sslCtx))
		{
		case E_SSL_ERROR:
			return E_SSL_ERROR;
		case 0:
			return E_SSL_AGAIN;
		default:
			break;
		}

		bytes = sslRec_getBytesToRead(ps_sslCtx);

		if (bytes > 0) {
			/* more bytes to accumulate before record is complete */
			return E_SSL_AGAIN;
		} else if (bytes == 0) {
			/* record is complete: process it */
			ps_sslCtx->e_event = E_PENDACT_SRV_RECORD;
		} else {
			/* bytes < 0: an error occurred */
			if (bytes == -2) {
				/* send a fatal record_overflow alert */
				ps_sslCtx->e_event = E_PENDACT_SRV_FATAL_ERROR;
			} else {
				ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
			}
		}

		sslSoc_procRec(ps_sslCtx);

		return E_SSL_AGAIN;

	} /* if */
	else
	{
		LOG_ERR("Can't enter server mode without RSA or ECDSA private key");
		ps_sslCtx->e_lastError = E_SSL_ERROR_GENERAL;
		return E_SSL_ERROR;
	} /* else */
} /* sslSoc_accept() */

/*==============================================================================
 sslSoc_connect()
 ==============================================================================*/
int sslSoc_connect(s_sslCtx_t* ps_sslCtx)
{
	assert(ps_sslCtx != NULL);

	if (((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH) != E_SSL_MUST_AUTH)
			|| ((ps_sslCtx->ps_sslSett->ps_certChainListHead != NULL)
					&& (ps_sslCtx->ps_sslSett->pgci_rsaMyPrivKey != NULL)))
	{
		if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_APPDATA_EXCHANGE)
			return E_SSL_OK; /* Means success  */

			if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_WAIT_INIT)
			{
				ps_sslCtx->s_sslGut.e_smState = E_SSL_SM_SEND_CLIENT_HELLO;
				ps_sslCtx->b_isCli = TRUE;
				ps_sslCtx->e_event = E_PENDACT_SRV_SCACHE;
			} /* if */
			else
			{
				switch (sslSoc_io(ps_sslCtx))
				{
				case E_SSL_ERROR:
					return E_SSL_ERROR;
				case 0:
					return E_SSL_AGAIN;
				default:
					break;
				} /* switch */

				switch (sslRec_getBytesToRead(ps_sslCtx))
				{
				case E_SSL_ERROR:
					ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
					return E_SSL_ERROR;
				case 0:
					break;
				default:
					return E_SSL_AGAIN;
				} /* switch */

				ps_sslCtx->e_event = E_PENDACT_SRV_RECORD;
			} /* else */

			sslSoc_procRec(ps_sslCtx);

			return E_SSL_AGAIN;
	} /* if */
	else
	{
		LOG_ERR(
				"Can't enter client mode with client authentication " "without a RSA private key");
		return E_SSL_ERROR;
	} /* else */
} /* sslSoc_connect()  */

int sslSoc_procRec(s_sslCtx_t * ps_sslCtx/*, int socket, char * source */)
{
	int i;
	size_t iBufLen;
	int iRetValue;

	unsigned char * pcBuffer;

	pcBuffer = ps_sslCtx->ac_socBuf;

	while (ps_sslCtx->e_event != E_PENDACT_GEN_WAIT_EVENT)
	{
		ps_sslCtx->e_nextAction = ssl_serverFSM(ps_sslCtx,
				(uint8_t) ps_sslCtx->e_event, pcBuffer, ps_sslCtx->l_buffLen,
				pcBuffer, &iBufLen);

		switch (ps_sslCtx->e_nextAction)
		{
		case E_PENDACT_COM_CIPHER_TXCLOSE:

			/* TODO: close connection right after
			 * transmission (probably an alert) (#1368) */
			LOG_INFO("E_PENDACT_COM_CIPHER_TXCLOSE: Connection is supposed to "
					"be closed after pending transmission");

		case E_PENDACT_COM_CIPHER_TX:
			ps_sslCtx->e_socState = E_SSL_SOCKET_TXBUFF;
			ps_sslCtx->l_buffLen = iBufLen;
			ps_sslCtx->l_writeOff = 0;
			ps_sslCtx->e_event = E_PENDACT_GEN_WAIT_EVENT;
			break;

		case E_PENDACT_COM_CIPHER_CLOSE:
			ps_sslCtx->e_socState = E_SSL_SOCKET_CLOSE;
			ps_sslCtx->s_sslGut.e_smState = E_SSL_SM_SHUTDOWN_COMPLETE;
			ps_sslCtx->e_event = E_PENDACT_GEN_WAIT_EVENT;
			break;

		case E_PENDACT_APP_REQUEST:
			/* put message in buffer and thats it */
			ps_sslCtx->l_readOff = REC_HEADERLEN;
			ps_sslCtx->l_buffLen = iBufLen - ps_sslCtx->l_readOff;
			if ((ps_sslCtx->e_ver > E_TLS_1_0)
					&& (ps_sslCtx->s_secParams.b_isBlkCip == TRUE))
				ps_sslCtx->l_readOff += ps_sslCtx->s_secParams.c_blockLen;
			ps_sslCtx->e_socState = E_SSL_SOCKET_READOUT;
			ps_sslCtx->e_event = E_PENDACT_GEN_WAIT_EVENT;
			/* -------------- */
			CW_MEMSET(pcBuffer, 0x00, ps_sslCtx->l_readOff);
			break;

		case E_PENDACT_SCACHE_RM:
			sslSesCache_delEntry(ps_sslCtx->ps_sslSett->ps_sessCache,
					ps_sslCtx->ps_hsElem->s_sessElem.ac_id);
			ps_sslCtx->e_event = E_PENDACT_SRV_SCACHE;
			break;

		case E_PENDACT_SCACHE_INS:
			sslSesCache_addEntry(ps_sslCtx->ps_sslSett->ps_sessCache,
					&ps_sslCtx->ps_hsElem->s_sessElem,
					ps_sslCtx->ps_sslSett->l_sessTimespan);
			if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_APPDATA_EXCHANGE)
			{
				ps_sslCtx->e_socState = E_SSL_SOCKET_IDLE;
				ps_sslCtx->e_event = E_PENDACT_GEN_WAIT_EVENT;
			}
			else
				ps_sslCtx->e_event = E_PENDACT_SRV_SCACHE;
			break;

		case E_PENDACT_SCACHE_FIND:
			iRetValue = sslSesCache_findElem(ps_sslCtx->ps_sslSett->ps_sessCache,
					&ps_sslCtx->ps_hsElem->s_sessElem);
			if (iRetValue == E_SSL_SESSCACHE_HIT)
			{
				ps_sslCtx->c_isResumed = TRUE;
			}
			else
			{
				ps_sslCtx->c_isResumed = FALSE;
			}
			LOG1_INFO("Search session%s successful",
					(iRetValue == E_SSL_SESSCACHE_HIT) ? "" : " not");
			ps_sslCtx->e_event = E_PENDACT_SRV_SCACHE;
			break;
		case E_PENDACT_SCACHE_GET:
			iRetValue = sslSesCache_getElem(ps_sslCtx->ps_sslSett->ps_sessCache,
					&ps_sslCtx->ps_hsElem->s_sessElem);

			/* Check if the session is still in the cache */
			if (iRetValue == E_SSL_SESSCACHE_HIT)
			{
				ps_sslCtx->c_isResumed = TRUE;
				ps_sslCtx->s_sslGut.e_smState =
						E_SSL_SM_SEND_SERVER_HELLO_FINISH;
			}
			else if (iRetValue == E_SSL_SESSCACHE_MISS)
			{

				/* Generate new SessionID using the old one. The  */
						/* usage of the random generator is not needed as */
				/* the SessionID is not cryptographic sensitive   */

				for (i = 0; i < SESSID_SIZE; i++)
				{
					/* Mix actual SessionID, client and server     */
					/* random together */
					ps_sslCtx->ps_hsElem->s_sessElem.ac_id[i] ^=
							(ps_sslCtx->ps_hsElem->s_sessElem.ac_id[SESSID_SIZE
																	- i]
																	+ ps_sslCtx->ps_hsElem->ac_cliRand[i]);
				}
			}
			LOG1_INFO("Get session%s successful",
					(iRetValue == E_SSL_SESSCACHE_HIT) ? "" : " not");
			ps_sslCtx->e_event = E_PENDACT_SRV_SCACHE;
			break;

		case E_PENDACT_ASYM_CERTVERIFY:
		case E_PENDACT_ASYM_CLICERTCHAIN:
		case E_PENDACT_ASYM_PKCS1_DECRYPT:
		case E_PENDACT_ASYM_PKCS1_VERIFY:
		case E_PENDACT_ASYM_DHECALCSHARED:
		case E_PENDACT_ASYM_ECDHECALCSHARED: //vpy
		case E_PENDACT_ASYM_SRVCERTCHAIN:
			i = iBufLen;
			iBufLen = sizeof(ps_sslCtx->ac_socBuf);
			ps_sslCtx->e_event = sslConf_asymCryptoDisp(ps_sslCtx,
					(uint8_t) ps_sslCtx->e_nextAction, pcBuffer, i, pcBuffer,
					&iBufLen);
			if (ps_sslCtx->e_event == E_PENDACT_GEN_WAIT_EVENT)
			{
				ps_sslCtx->e_socState = E_SSL_SOCKET_IDLE;
			}
			break;

		default:
			ps_sslCtx->e_socState = E_SSL_SOCKET_IDLE;
			ps_sslCtx->e_event = E_PENDACT_GEN_WAIT_EVENT;
			break;
		} /* Switch */
	} /* while ( event == ...) */

	return (0); /* Means success  */
}

/*************************************************************************** */

int32_t sslSoc_io(s_sslCtx_t * ps_sslCtx)
{
	int32_t l_outBytes;
	int32_t l_inBytes;

	switch (ps_sslCtx->e_socState)
	{
	case E_SSL_SOCKET_IDLE:
		ps_sslCtx->l_buffLen = 0;
		ps_sslCtx->l_writeOff = 0;

		/* Fall through to the READ section! */
	case E_SSL_SOCKET_RXBUFF:
		/* Bytes to be read to aquire an entire SSL record or at least the header */
		l_inBytes = sslRec_getBytesToRead(ps_sslCtx);

		if (l_inBytes == -1)
		{
			ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
			return E_SSL_ERROR;
		}

		/* Prevent buffer overruns */
		l_outBytes = sizeof(ps_sslCtx->ac_socBuf)
                		- ps_sslCtx->l_buffLen;

		if (l_outBytes < 0)
		{
			/* Indicates an buffer overrun, return with error
			 * This case should be avoided. Better: Check it with an ASSERT
			 */
			ps_sslCtx->e_lastError = E_SSL_ERROR_BUFFEROFLOW;
			return E_SSL_ERROR;
		}

		l_outBytes = _min(l_outBytes, l_inBytes);

		if (ps_sslCtx->read)
			l_outBytes = ps_sslCtx->read(ps_sslCtx->i_socNum,
					ps_sslCtx->ac_socBuf + ps_sslCtx->l_buffLen,
					l_outBytes);

		switch (l_outBytes)
		{
		case E_SSL_SOCKET_AGAIN:
			return E_SSL_AGAIN;
		case E_SSL_SOCKET_ERROR:
			LOG_ERR("Severe Error on SLI occured!");
			ps_sslCtx->e_lastError = E_SSL_ERROR_SOCKET;
			return E_SSL_ERROR;
		case E_SSL_SOCKET_CLOSED:
		{
			if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_SHUTDOWN_COMPLETE)
			{
				LOG1_INFO("Connection has been shut down. Socket %d",
						ps_sslCtx->i_socNum);
				return E_SSL_AGAIN;
			}
			LOG_INFO("Connection has been reset. Socket %d",
					ps_sslCtx->i_socNum);
			ps_sslCtx->e_lastError = E_SSL_ERROR_SOCKET;
			return E_SSL_ERROR;
		}
		default:
			break;
		}

		ps_sslCtx->e_socState = E_SSL_SOCKET_RXBUFF;
		ps_sslCtx->l_buffLen += l_outBytes;
		return l_outBytes;

		case E_SSL_SOCKET_TXBUFF:
			l_outBytes = ps_sslCtx->l_buffLen;

			if (ps_sslCtx->write)
				l_outBytes = ps_sslCtx->write(ps_sslCtx->i_socNum,
						ps_sslCtx->ac_socBuf + ps_sslCtx->l_writeOff,
						l_outBytes);

			switch (l_outBytes)
			{
			case E_SSL_SOCKET_AGAIN:
				return E_SSL_AGAIN;
			case E_SSL_SOCKET_ERROR:
				LOG_ERR("Severe Error on SLI occured!");
				ps_sslCtx->e_lastError = E_SSL_ERROR_SOCKET;
				return E_SSL_ERROR;
			case E_SSL_SOCKET_CLOSED:
			{
				if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_SHUTDOWN_COMPLETE)
				{
					LOG1_OK("Connection has been shut down. Socket %d",
							ps_sslCtx->i_socNum);
					return E_SSL_AGAIN;
				}
				LOG_ERR("Connection has been reset. Socket %d",
						ps_sslCtx->i_socNum);
				ps_sslCtx->e_lastError = E_SSL_ERROR_SOCKET;
				return E_SSL_ERROR;
			}
			default:
				break;
			}

			ps_sslCtx->l_buffLen -= l_outBytes;
			ps_sslCtx->l_writeOff += l_outBytes;

			if (ps_sslCtx->l_buffLen > 0)
			{
				return l_outBytes;
			}

			/* Close connection right after
			 * transmission (probably an alert) (#1368) */
			/* TODO: Enable this code to close a connection after sending an alert!
        if (ps_sslCtx->e_nextAction == E_PENDACT_COM_CIPHER_TXCLOSE) {
            LOG_INFO("Closing socket now!");

            ps_sslCtx->e_lastError = E_SSL_ERROR_GENERAL;
            return E_SSL_ERROR;
        }
			 */

			/* At this point the Buffer len must be 0 */
			/* The buffer is sent entirely */
			ps_sslCtx->e_socState = E_SSL_SOCKET_IDLE;
			ps_sslCtx->l_writeOff = 0;

			return l_outBytes;
			case E_SSL_SOCKET_CLOSE:
				ps_sslCtx->e_lastError = E_SSL_NO_ERROR_SHDOWN;
				return E_SSL_ERROR;
			case E_SSL_SOCKET_UNUSED:
				ps_sslCtx->e_lastError = E_SSL_ERROR_SOCKET;
				return E_SSL_ERROR;

			default:

				return E_SSL_AGAIN;
	}

}

/***************************************************************************/

/*                                   EOF                                      */
