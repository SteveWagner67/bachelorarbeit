/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl.c                                                  */
/*                                                                           */
/*  FUNCTIONS:                                                               */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*   This module implements the SSL core.                                    */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  CAUTIONS:                                                                */
/*   None                                                                    */
/*                                                                           */
/*                                                                           */
/*  LANGUAGE:        ANSI C                 COMPILER:                        */
/*  TARGET SYSTEM:                                                           */
/*                                                                           */
/*****************************************************************************/
/*                                                                           */
/*  MODIFICATION HISTORY: (Optional for DSEE files)                          */
/*                                                                           */
/*  Date        Person        Change                                         */
/*  ====        ======        ======                                         */
/*  2002-2003    T. Gillen     Initial version                               */
/*  05.03.03     WAM           First version after splitting into several    */
/*                             files                                         */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*****************************************************************************/
#include "assert.h"
#include "ssl.h"
#include "ssl_diag.h"
#include "ssl_certHelper.h"
#include "ssl_sessCache.h"
#include "ssl_conf.h"
#include "ssl_record.h"
#include "key_management.h"
//#include "crypto_wrap.h"

/*** Defines ****************************************************************/
#define	LOGGER_ENABLE		DBG_SSL_PROTO_MODULE
#include "logger.h"

/*** Global Variables *******************************************************/

/*** Typedefs ****************************************************************/
typedef enum hashProcessingOperationTypes {
	E_HASHOP_INIT, E_HASHOP_UPDATE, E_HASHOP_FINISH
} e_hashOp_t;

/*** Local Variables ********************************************************/
#if DBG_SSL_BAD_RECORDS
static unsigned char ac_badRecBuf[17000];
#endif

/* Padding values used for the several hashes during connection setup */
/* These pads are constant and will not be changed (neither values nor length) .... */
static const uint8_t rac_macPad1[48] = { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };

static const uint8_t rac_macPad2[48] = { 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
		0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
		0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
		0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
		0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C };

static const uint8_t rac_TLSlabelCliFin[] = "client finished";
static const uint8_t rac_TLSlabelSrvFin[] = "server finished";
static const uint8_t rac_SSLlabelCliFin[] = "CLNT"; /* = 0x434C4E54 */
static const uint8_t rac_SSLlabelSrvFin[] = "SRVR"; /* = 0x53525652*/
static const uint8_t rac_TLSlabelMsSec[] = "master secret";
static const uint8_t rac_TLSlabelKeyExp[] = "key expansion";

/*! Supported Signature/Hash Algorithms */
static const uint16_t rai_tlsSHAlgs[] = { ((en_gciHashAlgo_SHA256 << 8)
		+ (en_gciSignAlgo_RSA & 0xFF)), ((en_gciHashAlgo_MD5 << 8) + (en_gciSignAlgo_RSA & 0xFF)),
		((en_gciHashAlgo_SHA1 << 8) + (en_gciSignAlgo_RSA & 0xFF)), };

/* Handles the generation of the server responses:
 * Server hello (divided in 3 or 4 messages)
 * Content must be ordered using one certificate handler request
 *  - server certificate chain
 *  - server certificate chain + client certificate CA list
 *
 *
 * Generates only the handshakes, the record headers are inserted later on
 *
 */

static const uint8_t rac_cliHello[] = { 0x01, 0x00, 0x00, 0x00 /* Client Hello indicator and len (3 bytes), var */
};

static const uint8_t rac_srvHello[] = { 0x02, 0x00, 0x00, 0x00 /* Server Hello indicator and len (3 bytes), var */
};

static const uint8_t rac_cert[] = { 0x0b, 0x00, 0x00, 0x00 /* Server Certificate indicator and len (3 bytes), var */
};

static const uint8_t rac_srvKeyExch[] = { 0x0c, 0x00, 0x00, 0x00 };

static const uint8_t rac_certReq[] = { 0x0d, 0x00, 0x00, 0x00, 0x01, 0x01 /* handshake Cert Request indicator and len (3 bytes), var */
};

static const uint8_t rac_srvHelloDone[] = { 0x0e, 0x00, 0x00, 0x00 /* server hello done, message length is 0 */
};

static const uint8_t rac_certVerify[] = { 0x0F, 0x00, 0x00, 0x00 };

static const uint8_t rac_cliKeyExch[] = { 0x10, 0x00, 0x00, 0x00 };

static const uint8_t rac_srvFinish[] = { 0x14, 0x00, 0x00 /* Server finished indicator, 1 byte length needs to be added */
};

/*** Forward declarations ***************************************************/
//OLD-CW: static uint8_t loc_getHashSize(e_sslHashAlg_t e_hashAlg);
static uint8_t loc_getHashSize(en_gciHashAlgo_t hashAlg);

static uint8_t loc_getHashSizeByPrf(e_sslPrf_t e_prfAlg);

//OLD-C: Wstatic e_sslHashAlg_t loc_getHashTypeByPrf(e_sslPrf_t e_prfAlg);
static en_gciHashAlgo_t loc_getHashTypeByPrf(e_sslPrf_t e_prfAlg);
/*===========================================================================*/
/*                      VERSION DEPENDANT FUNCTIONS                          */
/*===========================================================================*/
static e_sslError_t loc_verifySign(s_sslCtx_t* ps_sslCtx, uint8_t* pc_tbvParams,
		size_t sz_inLen, uint8_t* pc_encSign, size_t sz_ecnSignLen);

static e_sslError_t loc_signHash(s_sslCtx_t* ps_sslCtx, uint8_t* pc_in,
		size_t sz_inLen, uint8_t* pc_out, size_t* sz_outLen);

static const uint8_t* const loc_getFinLabel(s_sslCtx_t *ps_sslCtx,
		uint8_t isCli);

static void loc_setDefPrf(s_sslCtx_t *ps_sslCtx);

static void loc_hash(e_hashOp_t e_hashOp, s_sslCtx_t* ps_sslCtx, uint8_t* pc_in,
		size_t sz_inLen);

static void loc_compHash(s_sslCtx_t* ps_sslCtx, const uint8_t* pc_label,
		uint8_t* pc_res);

static void loc_compHashSSL(s_sslCtx_t *ps_sslCtx, const uint8_t *sender,
		uint8_t *result);

static void loc_compHashTLS(s_sslCtx_t *ps_sslCtx, const uint8_t *pc_expansion,
		uint8_t *pc_result);

//OLD-CW: static size_t   loc_compMac(s_sslCtx_t *ps_sslCtx,
//		uint8_t    *pc_result, size_t l_resultLen,
//		uint8_t    *pc_inData, uint16_t i_inDataLen,
//		uint8_t    c_msgType,  uint8_t c_dir,
//		e_sslHashAlg_t e_hashType);
static size_t loc_compMac(s_sslCtx_t *ps_sslCtx, uint8_t *pc_result,
		size_t l_resultLen, uint8_t *pc_inData, uint16_t i_inDataLen,
		uint8_t c_msgType, uint8_t c_dir, en_gciHashAlgo_t hashAlgo);

//OLD-CW: static size_t   loc_compMacSSL(s_sslCtx_t  *ps_sslCtx,  uint8_t    *result,
//		uint8_t     *pc_inData,  uint16_t   i_inDataLen,
//		uint8_t     c_msgType,   uint8_t    c_ioDir,
//		e_sslHashAlg_t  e_hashType);
static size_t loc_compMacSSL(s_sslCtx_t *ps_sslCtx, uint8_t *result,
		uint8_t *pc_inData, uint16_t i_inDataLen, uint8_t c_msgType,
		uint8_t c_ioDir, en_gciHashAlgo_t hashAlgo);

//static size_t   loc_compMacTLS(s_sslCtx_t  *ps_sslCtx,
//		uint8_t     *pc_result, size_t l_resultLen,
//		uint8_t     *pc_inData, uint16_t i_inDataLen,
//		uint8_t     c_msgType,  uint8_t c_dir,
//		e_sslHashAlg_t  e_hashType);
static size_t loc_compMacTLS(s_sslCtx_t *ps_sslCtx, uint8_t *pc_out,
		size_t l_outLen, uint8_t *pc_in, uint16_t i_inLen, uint8_t c_msgType,
		uint8_t c_iodir, en_gciHashAlgo_t hashAlgo);

//OLD-CW: static void loc_pHash(e_sslHashAlg_t e_hashType,
//		uint8_t*      pc_secret, size_t  sz_secLen,
//		const  uint8_t*      pc_label,  uint8_t c_labelLen,
//		uint8_t*      pc_seed,   uint8_t c_seedLen,
//		uint8_t*      pc_xSeed,  uint8_t c_xSeedLen,
//		uint8_t*      pc_out,    size_t  sz_outLen);
//{
static void loc_pHash(en_gciHashAlgo_t hashAlgo, uint8_t* pc_secret,
		size_t sz_secLen, const uint8_t* pc_label, uint8_t c_labelLen,
		uint8_t* pc_seed, uint8_t c_seedLen, uint8_t* pc_xSeed,
		uint8_t c_xSeedLen, uint8_t* pc_out, size_t sz_outLen);

static e_sslError_t loc_prf(s_sslCtx_t* ps_sslCtx, uint8_t* pc_secret,
		size_t sz_secLen, const uint8_t* pc_label, uint8_t c_lbLen,
		uint8_t* pc_par1, uint8_t c_par1Len, uint8_t* pc_par2,
		uint8_t c_par2Len, uint8_t* pc_result, size_t sz_outLen);

static void loc_prfSSL(uint8_t* pc_sec, size_t cwt_secLen, uint8_t* pc_par1,
		uint8_t cwt_par1Len, uint8_t* pc_par2, uint8_t cwt_par2Len,
		uint8_t* pc_out, size_t cwt_outLen);

/*! \brief Function to calculate given stream of psudo random bytes for TLS
 *
 * TLS’s PRF is created by applying P_hash to the secret as:
 * PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 *
 * \param e_prf             : Type of a prf function from @ref e_sslPrf_t type
 * \param pc_secret         : Secret information
 * \param c_secretLen       : Length of a secret
 * \param pc_label          : Label for a given secret
 * \param c_labelLen        : Length of a label
 * \param pc_seed           : Seed for a prf function
 * \param c_seedLen         : Seed length
 * \param pc_out            : Pointer where result data will be stored
 * \param sz_outLen         : Requested length of a data
 *
 */
static void loc_prfTLS(e_sslPrf_t e_prf, uint8_t* pc_secret, size_t c_secretLen,
		const uint8_t* pc_label, uint8_t c_labelLen, uint8_t* pc_seed1,
		uint8_t c_seed1Len, uint8_t* pc_seed2, uint8_t c_seed2Len,
		uint8_t* pc_out, size_t sz_outLen);

static uint32_t loc_addPadding(s_sslCtx_t* ps_sslCtx, uint8_t *pc_data,
		uint32_t l_actLen, uint32_t l_blkSize);

static uint32_t loc_rmPadding(s_sslCtx_t* ps_sslCtx, uint8_t *pc_data,
		uint32_t l_len, uint32_t l_blkSize);

static size_t loc_cpCompositeHs(s_sslCtx_t* ps_sslCtx, uint8_t* pc_to,
		uint8_t* pc_from, size_t cwt_len);
/*===========================================================================*/
/*                   END OF VERSION DEPENDANT FUNCTIONS                      */
/*===========================================================================*/

static void loc_compKey(s_sslCtx_t *ps_sslCtx, uint8_t b_srvKey);

static e_sslPendAct_t loc_selVer(s_sslCtx_t* ps_sslCtx, e_sslVer_t e_ver);

static void loc_setSecParams(s_sslCtx_t* ps_sslCtx, e_sslCipSpec_t e_cipSpec);

static void loc_incrSeqNum(uint8_t* pc_seqNum);

static void loc_selectSeqNum(s_sslCtx_t *ps_sslCtx, uint8_t c_dir,
		uint8_t **ppc_seqNum, uint8_t **ppc_macSecret);

static e_sslPendAct_t loc_smLenVerCheck(s_sslCtx_t *ps_sslCtx);

static e_sslPendAct_t loc_smDecryptMacCheck(s_sslCtx_t * ps_sslCtx,
		uint8_t *pc_rawTxt, size_t *pcwt_rawTxtLen, uint8_t *pc_rec,
		size_t cwt_recLen);

static e_sslPendAct_t loc_v2UpwardHandler(s_sslCtx_t * ps_sslCtx,
		uint8_t *pc_rec, size_t cwt_recLen);

static e_sslPendAct_t loc_protocolHand(s_sslCtx_t * ps_sslCtx, uint8_t c_event,
		uint8_t *pc_rec, size_t cwt_recLen, uint8_t *pc_wData,
		size_t *cwt_wDataLen);

static e_sslPendAct_t loc_protocolResp(s_sslCtx_t * ps_sslCtx, uint8_t *pc_rec,
		size_t *pcwt_recLen, uint8_t *pInputData, size_t uiInputDataLen);

static e_sslPendAct_t loc_smMacEncrypt(s_sslCtx_t * ps_sslCtx,
		uint8_t *pc_rawTxt, size_t cwt_rawTxtLen, uint8_t *pc_rec,
		size_t *pcwt_recLen, e_sslRecType_t e_recType);

static int loc_buildRecordHeader(s_sslCtx_t * ps_sslCtx, uint8_t *pc_rec,
		size_t cwt_recLen, uint8_t c_recType);

static uint8_t *loc_matchCipherSpec(s_sslCtx_t* ps_sslCtx,
		uint8_t *cipherSpecList, uint16_t cipherSpecListLen, uint16_t u_bufLen);

static int32_t loc_processExtens(s_sslCtx_t* ps_sslCtx, uint8_t* pc_extsStart,
		uint8_t* pc_hsEnd);

static uint8_t *loc_appendExtens(s_sslCtx_t* ps_sslCtx, uint8_t* pc_dataStart);

/*
 * Parse and process signature_algorithms extension
 */
static int32_t loc_procExtSignAlg(s_sslCtx_t* ps_sslCtx, uint8_t* pc_read,
		uint32_t lLen);

/*** Local Functions ********************************************************/

//OLD-CW:
//static uint8_t loc_getHashSize(e_sslHashAlg_t e_hashAlg)
//{
//	uint8_t c_hashSize;
//
//	switch (e_hashAlg)
//	{
//	case E_SSL_HASH_MD5:
//		c_hashSize = GCI_MD5_SIZE;
//		break;
//	case E_SSL_HASH_SHA1:
//		c_hashSize = GCI_SHA1_SIZE;
//		break;
//	case E_SSL_HASH_SHA256:
//		c_hashSize = GCI_SHA256_SIZE;
//		break;
//	default:
//	case E_SSL_HASH_NONE:
//	case E_SSL_HASH_INVALID:
//		c_hashSize = 0;
//		break;
//	}
//	return (c_hashSize);
//}
static uint8_t loc_getHashSize(en_gciHashAlgo_t hashAlg) {
	uint8_t hashSize;

	switch (hashAlg) {
	case en_gciHashAlgo_MD5:
		hashSize = GCI_MD5_SIZE_BYTES;
		break;
	case en_gciHashAlgo_SHA1:
		hashSize = GCI_SHA1_SIZE_BYTES;
		break;
	case en_gciHashAlgo_SHA256:
		hashSize = GCI_SHA256_SIZE_BYTES;
		break;
	default:
	case en_gciHashAlgo_None:
	case en_gciHashAlgo_Invalid:
		hashSize = 0;
		break;
	}
	return (hashSize);
}

static uint8_t loc_getHashSizeByPrf(e_sslPrf_t e_prfAlg) {
	uint8_t c_hashSize;

	switch (e_prfAlg) {
	case E_SSL_PRF_MD5_SHA1:
		c_hashSize = GCI_MD5_SIZE_BYTES + GCI_SHA1_SIZE_BYTES;
		break;
	case E_SSL_PRF_SHA256:
		c_hashSize = GCI_SHA256_SIZE_BYTES;
		break;
	default:
	case E_SSL_PRF_UNDEF:
		c_hashSize = 0;
		break;
	}

	return (c_hashSize);
}

//OLD-CW: static e_sslHashAlg_t loc_getHashTypeByPrf(e_sslPrf_t e_prfAlg)
static en_gciHashAlgo_t loc_getHashTypeByPrf(e_sslPrf_t e_prfAlg) {
	//OLD-CW: e_sslHashAlg_t c_hashType;
	en_gciHashAlgo_t hashAlgo;

	switch (e_prfAlg) {
	case E_SSL_PRF_MD5_SHA1:
		//OLD-CW: c_hashType = E_SSL_HASH_INVALID;
		hashAlgo = en_gciHashAlgo_Invalid;
		break;
	case E_SSL_PRF_SHA256:
		//OLD-CW: c_hashType = E_SSL_HASH_SHA256;
		hashAlgo = en_gciHashAlgo_SHA256;
		break;
	default:
	case E_SSL_PRF_UNDEF:
		//OLD-CW: c_hashType = E_SSL_HASH_NONE;
		hashAlgo = en_gciHashAlgo_None;
		break;
	}

	return (hashAlgo);
}

/*===========================================================================*/
/*===========================================================================*/
/*===========================================================================*/
/*                      VERSION DEPENDANT FUNCTIONS                          */
/*===========================================================================*/
/*===========================================================================*/
/*===========================================================================*/
/* \brief Calculate hash of a given data using selected hash algorithm
 * (from signature algorithm) and verify signature
 * \param ps_sslCtx         : Pointer to the ssl connection context
 * \param pc_tbv            : Pointer to the hash buffer to be hashed
 * \param sz_len            : length of a given data
 *
 * \return E_SSL_NO_ERROR
 * \return E_SSL_ERROR_GENERAL
 */
static e_sslError_t loc_verifySign(s_sslCtx_t* ps_sslCtx, uint8_t* pc_tbvParams,
		size_t sz_inLen, uint8_t* pc_encSign, size_t sz_ecnSignLen) {
	s_sslHsElem_t* ps_hsElem;
	s_sslSecParams_t* ps_secPar;
	uint16_t i_signLen;
	uint8_t hashLen;
	int8_t e_result = E_SSL_NO_ERROR;
	uint8_t ac_sign[GCI_MAX_HASHSIZE_BYTES];
	/* In case of TLS 1.2 we have prepended hash oid */
	size_t sz_decSignLen = GCI_MAX_HASHSIZE_BYTES
			+ SSL_DER_ASN1_OID_HASH_MAX_LEN;
	uint8_t ac_decSign[sz_decSignLen];

	//OLD-CW: gci_sha1Ctx_t  cwt_sha1Ctx;
	//OLD-CW: gci_md5Ctx_t  cwt_md5Ctx;

	GciCtxId_t sha1Ctx;
	GciCtxId_t md5Ctx;
	GciCtxId_t hashCtx;
	GciCtxId_t rsaCtx;

	st_gciSignConfig_t rsaConf;

	en_gciResult_t err;

	size_t ac_sign_len;

	assert(ps_sslCtx != NULL);
	assert(pc_tbvParams != NULL);

	/*TIME_STAMP(TS_DHE_VERIF_SIGN_BEGIN);*/

	ps_hsElem = ps_sslCtx->ps_hsElem;
	ps_secPar = &ps_sslCtx->s_secParams;

	if (ps_sslCtx->e_ver >= E_TLS_1_2) {
		ps_sslCtx->s_secParams.s_signAlg.c_hash = pc_encSign[0];
		ps_sslCtx->s_secParams.s_signAlg.c_sign = pc_encSign[1];
		pc_encSign += 2;
		sz_ecnSignLen -= 2;
	}

	/* generate hash that has to be verified: MD5 and SHA1
	 * of (ClientRandom, ServerRandom, DHParams).
	 */
	/* If hash algorithm for a signature is invalid this
	 * means that we are using TLS version prior TLS 1.2
	 * and signature should be composed using a
	 * concatenation of md5 and sha1*/
	if (ps_sslCtx->s_secParams.s_signAlg.c_hash == en_gciHashAlgo_Invalid) {
		/* message digest contexts will be used to verify DH server parameter */

		//OLD-CW: cr_digestInit(&cwt_md5Ctx, NULL, 0, E_SSL_HASH_MD5);
		if (gciHashNewCtx(en_gciHashAlgo_MD5, &md5Ctx) != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, ps_hsElem->ac_cliRand,CLI_RANDSIZE,E_SSL_HASH_MD5);
		err = gciHashUpdate(md5Ctx, ps_hsElem->ac_cliRand, CLI_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, ps_hsElem->ac_srvRand, SRV_RANDSIZE, E_SSL_HASH_MD5);
		err = gciHashUpdate(md5Ctx, ps_hsElem->ac_srvRand, SRV_RANDSIZE);

		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, pc_tbvParams, sz_inLen, E_SSL_HASH_MD5);
		err = gciHashUpdate(md5Ctx, pc_tbvParams, sz_inLen);

		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cwt_md5Ctx, ac_sign, NULL, E_SSL_HASH_MD5);
		err = gciHashFinish(md5Ctx, ac_sign, &ac_sign_len);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestInit(&cwt_sha1Ctx, NULL, 0, E_SSL_HASH_SHA1);
		err = gciHashNewCtx(en_gciHashAlgo_SHA1, &sha1Ctx);

		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, ps_hsElem->ac_cliRand, CLI_RANDSIZE, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, ps_hsElem->ac_cliRand, CLI_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, ps_hsElem->ac_srvRand, SRV_RANDSIZE, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, ps_hsElem->ac_srvRand, SRV_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, pc_tbvParams, sz_inLen, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, pc_tbvParams, sz_inLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cwt_sha1Ctx, &ac_sign[GCI_MD5_SIZE], NULL, E_SSL_HASH_SHA1);
		err = gciHashFinish(sha1Ctx, ac_sign, &ac_sign_len);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		hashLen = GCI_MD5_SHA1_SIZE_BYTES;
	}

	else {
		/* message digest contexts will be used to verify DH server parameter */
		//OLD-CW: gci_hashCtx_t  cwt_hashCtx;

		hashLen = loc_getHashSize(ps_sslCtx->s_secParams.s_signAlg.c_hash);

		//TODO see how to know the hash algorthm and adapt it with hash from gci
		//OLD-CW: cr_digestInit(&cwt_hashCtx, NULL, 0, ps_secPar->s_signAlg.c_hash);
		err = gciHashNewCtx(ps_secPar->s_signAlg.c_hash, &hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_hashCtx, ps_hsElem->ac_cliRand, CLI_RANDSIZE, ps_secPar->s_signAlg.c_hash);
		err = gciHashUpdate(hashCtx, ps_hsElem->ac_cliRand, CLI_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_hashCtx, ps_hsElem->ac_srvRand, SRV_RANDSIZE, ps_secPar->s_signAlg.c_hash);
		err = gciHashUpdate(hashCtx, ps_hsElem->ac_srvRand, SRV_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_hashCtx, pc_tbvParams, sz_inLen, ps_secPar->s_signAlg.c_hash);
		err = gciHashUpdate(hashCtx, pc_tbvParams, sz_inLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cwt_hashCtx, ac_sign, NULL, ps_secPar->s_signAlg.c_hash);
		err = gciHashFinish(hashCtx, ac_sign, &ac_sign_len);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

	}

	/* length of the signature */
	i_signLen = *pc_encSign * 256 + pc_encSign[1];

	if (sz_ecnSignLen != (size_t) i_signLen + 2) {
		/* => Length of signature given in message
		 * not compatible with message length */
		LOG_ERR(
				"Length of signature given in message " "not compatible with message length");
		e_result = E_SSL_ERROR_LENGTH;

	}

	else {
		/* pc_hsBuff now pointing to the signature data */
		pc_encSign += 2;

		switch (ps_sslCtx->s_secParams.s_signAlg.c_sign) {
		case en_gciSignAlgo_RSA:

			/* Decode signature using peers public key*/

			//OLD-CW:
//			if (cw_rsa_sign_decode(pc_encSign, i_signLen, ac_decSign, &sz_decSignLen, &ps_hsElem->gci_peerPubKey) != CW_OK){
//				LOG_ERR("Failed to decode a signature");
//				e_result = E_SSL_ERROR_GENERAL;
//			}

			rsaConf.algo = en_gciSignAlgo_RSA;
			rsaConf.hash = en_gciHashAlgo_None;
			rsaConf.un_signConfig.signConfigRsa.padding = en_gciPadding_None;

			//RSA public key coming from a Certificate -> see sslCert_verifyChain in ssl_certHelper.c
			err = gciSignVerifyNewCtx(&rsaConf, ps_hsElem->gci_rsaCliPubKey,
					&rsaCtx);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

			err = gciSignUpdate(rsaCtx, ac_sign, ac_sign_len);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

			err = gciSignVerifyFinish(rsaCtx, pc_encSign, i_signLen);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

			if (ps_sslCtx->e_ver >= E_TLS_1_2) {
				s_derdCtx_t s_derdCtx;
				e_derdRet_t e_derErr = E_SSL_DER_OK;
				s_sslOctetStr_t s_sigOctStr = { .cwt_len = sz_decSignLen,
						.pc_data = ac_decSign, };

				if (sslDerd_initDecCtx(&s_derdCtx,
						&s_sigOctStr) == SSL_DER_ASN1_UNDEF) {
					LOG_ERR(
							"Failed to decode ASN.1 sequence" "representing the signature");
					e_result = E_SSL_ERROR_GENERAL;
				} else {
					/* Check if we a re working with ASN.1 encoded sequence */
					if (s_derdCtx.c_tag != SSL_DER_ASN1_CSEQUENCE) {
						LOG_ERR(
								"Signature DER ASN.1 should start with Sequence identifier");
						e_derErr = E_SSL_DER_ERR_NO_CSEQUENCE;
					}

					/* Check if we a re working with ASN.1 encoded sequence */
					if ((e_derErr != E_SSL_DER_OK)
							|| (sslDerd_getNextValue(&s_derdCtx)
									!= SSL_DER_ASN1_CSEQUENCE)) {
						LOG_ERR(
								"Signature DER ASN.1 should start with Sequence identifier");
						e_derErr = E_SSL_DER_ERR_NO_CSEQUENCE;
					}

					if (e_derErr == E_SSL_DER_OK) {
						/* Currently we aren't interested in hashAlg */
						sslDerd_getSign(&s_derdCtx, NULL, ac_decSign,
								&sz_decSignLen);
					}
				}
			}

			break;
		case en_gciSignAlgo_DSA:
		case en_gciSignAlgo_None:
		default:
			e_result = E_SSL_ERROR_GENERAL;
			break;
		}

		/* Check if calculated hash is equal to calculated one */
		//OlD-CW: if ((hashLen != sz_decSignLen) || (memcmp(ac_sign, ac_decSign, hashLen) != 0))
		if ((hashLen != sz_decSignLen)
				|| (memcpy(ac_sign, ac_decSign, hashLen) != 0)) {
			LOG_ERR(
					"Failed to verify signature of server DH parameter " "in ServerKeyExchange message");
			e_result = E_SSL_ERROR_GENERAL;
		}
	}

	//Release the contexts

	err = gciCtxRelease(md5Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	err = gciCtxRelease(hashCtx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	err = gciCtxRelease(rsaCtx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	return (e_result);
}

/* \brief Calculate hash of a given data using selected hash algorithm
 * (from signature algorithm) and encrypt with a peers public key
 * \param ps_sslCtx         : Pointer to the ssl connection context
 * \param pc_in             : Pointer to the hash buffer to be hashed
 * \param sz_inLen          : length of a given data
 * \param pc_out            : Pointer to the data where to put signature
 * \param sz_outLen         : Pointer to the variable where to store signature
 *                            length
 *
 * \return E_SSL_NO_ERROR
 * \return E_SSL_ERROR_GENERAL
 */
static e_sslError_t loc_signHash(s_sslCtx_t* ps_sslCtx, uint8_t* pc_in,
		size_t sz_inLen, uint8_t* pc_out, size_t* sz_outLen) {
	s_sslHsElem_t* ps_hsElem;
	e_sslError_t e_result = E_SSL_NO_ERROR;
	/* In case of TLS 1.2 we allocate more memory for ASN.1 DER encoding */
	/* Here we use c_hashLen as a real hash length */
	uint8_t c_hashLen = GCI_MAX_HASHSIZE_BYTES;
	/* But need to allocate as much memmory as it requires by possibly encoded
	 * signature*/
	uint8_t ac_hash[GCI_MAX_HASHSIZE_BYTES +
	SSL_DER_ASN1_MAX_OID_OCTET + 20];
	uint8_t c_signOff = 0;
	uint8_t c_hashType;
	uint8_t c_signType;
	size_t sz_signLen;

	//OLD-CW: gci_md5Ctx_t    cwt_md5Ctx;
	//OLD-CW: gci_sha1Ctx_t   cwt_sha1Ctx;
	//OLD-CW: gci_hashCtx_t   cwt_hashCtx;

	GciCtxId_t md5Ctx;
	GciCtxId_t sha1Ctx;
	GciCtxId_t hashCtx;
	GciCtxId_t signCtx;

	st_gciSignConfig_t signConf;

	en_gciResult_t err;
	size_t ac_hash_len;

	assert(ps_sslCtx != NULL);
	assert(pc_in != NULL);

	TIME_STAMP(TS_DHE_SIGN_BEGIN);

	ps_hsElem = ps_sslCtx->ps_hsElem;
	c_hashType = ps_sslCtx->s_secParams.s_signAlg.c_hash;
	c_signType = ps_sslCtx->s_secParams.s_signAlg.c_sign;

	if (ps_sslCtx->e_ver >= E_TLS_1_2) {
		pc_out[0] = c_hashType;
		pc_out[1] = c_signType;
		c_signOff = 2;
	}

	if (c_hashType == en_gciHashAlgo_Invalid) {

		c_hashLen = GCI_MD5_SHA1_SIZE_BYTES;

		/* generate data that has to be signed afterwards */
		/*! MD5(ClientRandom, ServerRandom, DiffieHellmanParamaeters) */

		//OLD-CW: cr_digestInit(&cwt_md5Ctx, NULL, 0, E_SSL_HASH_MD5);
		err = gciHashNewCtx(en_gciHashAlgo_MD5, &md5Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, ps_hsElem->ac_cliRand, CLI_RANDSIZE, E_SSL_HASH_MD5);
		err = gciHashUpdate(md5Ctx, ps_hsElem->ac_cliRand, CLI_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, ps_hsElem->ac_srvRand, SRV_RANDSIZE, E_SSL_HASH_MD5);
		err = gciHashUpdate(md5Ctx, ps_hsElem->ac_srvRand, SRV_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, pc_in, sz_inLen, E_SSL_HASH_MD5);
		err = gciHashUpdate(md5Ctx, pc_in, sz_inLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cwt_md5Ctx, ac_hash, NULL, E_SSL_HASH_MD5);
		err = gciHashFinish(md5Ctx, ac_hash, &ac_hash_len);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		/*! SHA1(ClientRandom, ServerRandom, DiffieHellmanParamaeters) */

		//OLD-CW: cr_digestInit(&cwt_sha1Ctx, NULL, 0, E_SSL_HASH_SHA1);
		err = gciHashNewCtx(en_gciHashAlgo_SHA1, &sha1Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, ps_hsElem->ac_cliRand, CLI_RANDSIZE, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, ps_hsElem->ac_cliRand, CLI_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, ps_hsElem->ac_srvRand, SRV_RANDSIZE, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, ps_hsElem->ac_srvRand, SRV_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, pc_in, sz_inLen, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, pc_in, sz_inLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//cr_digestFinish(&cwt_sha1Ctx, &ac_hash[GCI_MD5_SIZE], NULL, E_SSL_HASH_SHA1);
		err = gciHashFinish(sha1Ctx, ac_hash, &ac_hash_len);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

	}

	else {

		c_hashLen = loc_getHashSize(c_hashType);

		/* generate data that has to be signed afterwards */
		/*! HASH(ClientRandom, ServerRandom, DiffieHellmanParamaeters) */

		//OLD-CW: err|=cr_digestInit(&cwt_hashCtx, NULL, 0, c_hashType);
		err = gciHashNewCtx(c_hashType, &hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: err|=cr_digestUpdate(&cwt_hashCtx, ps_hsElem->ac_cliRand, CLI_RANDSIZE, c_hashType);
		err = gciHashUpdate(hashCtx, ps_hsElem->ac_cliRand, CLI_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: err|=cr_digestUpdate(&cwt_hashCtx, ps_hsElem->ac_srvRand, SRV_RANDSIZE, c_hashType);
		err = gciHashUpdate(hashCtx, ps_hsElem->ac_srvRand, SRV_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW:err|=cr_digestUpdate(&cwt_hashCtx, c, c_hashType);
		err = gciHashUpdate(hashCtx, ps_hsElem->ac_srvRand, SRV_RANDSIZE);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: err|=cr_digestFinish(&cwt_hashCtx, ac_hash, NULL, c_hashType);
		err = gciHashFinish(hashCtx, ac_hash, &ac_hash_len);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//begin vpy
		LOG_INFO("Client Random:");
		LOG_HEX(ps_hsElem->ac_cliRand, CLI_RANDSIZE);

		LOG_INFO("Server Random");
		LOG_HEX(ps_hsElem->ac_srvRand, SRV_RANDSIZE);

		LOG_INFO("Parameter");
		LOG_HEX(pc_in, sz_inLen);
		//end vpy
	}

	LOG_INFO("Hash value for a signature");
	LOG_HEX(ac_hash, c_hashLen);

	/*! calc bytes left in socketbuffer */
	/*! FIXME This is not a best way of calculating space left */
	sz_signLen = (sizeof(ps_sslCtx->ac_socBuf)
			- ((size_t) pc_in - (size_t) ps_sslCtx->ac_socBuf));

	TIME_STAMP(TS_DHE_SIGN_HASHED);

	switch (c_signType) {
	case en_gciSignAlgo_RSA: {
		if (ps_sslCtx->e_ver >= E_TLS_1_2) {
			s_derdCtx_t s_derdCtx;
			uint8_t c_signLen = GCI_MAX_HASHSIZE_BYTES
					+ SSL_DER_ASN1_MAX_OID_OCTET + 22;
			/* This array will be temporally used by DER Decoder module */
			uint8_t ac_sign[c_signLen];
			s_sslOctetStr_t s_sigOctStr;

			memset(ac_sign, 0x00, c_signLen);
			s_sigOctStr.cwt_len = c_signLen;
			s_sigOctStr.pc_data = ac_sign;

			sslDerd_initEncCtx(&s_derdCtx, &s_sigOctStr);

			sslDerd_setSign(&s_derdCtx, c_hashType, &ac_hash[0], c_hashLen);

			if (s_derdCtx.s_octBuf.cwt_len <= sizeof(ac_hash)) {
				memmove(ac_hash, s_derdCtx.s_octBuf.pc_data,
						s_derdCtx.s_octBuf.cwt_len);
				c_hashLen = s_derdCtx.s_octBuf.cwt_len;
				LOG_INFO("Signature before encryption");
				LOG_HEX(ac_hash, c_hashLen);
			}

		}

		LOG_INFO("signature before encryption");
		LOG_HEX(ac_hash, c_hashLen);

		//Encryption means using a padding a not cipher encrypt

		//OLD-CW: e_result = cw_rsa_sign_encode(ac_hash, c_hashLen, pc_out + c_signOff + 2, &sz_signLen, ps_sslCtx->ps_sslSett->pgci_rsaMyprivKeyID);

		signConf.algo = en_gciSignAlgo_RSA;
		signConf.hash = en_gciHashAlgo_None;
		signConf.un_signConfig.signConfigRsa.padding = en_gciPadding_PKCS1;

		//Private key coming from a PEM file with the Certificates -> see _sslSoc_sett_import_RSAprivKey in ssl_socket.c
		err = gciSignGenNewCtx(&signConf,
				ps_sslCtx->ps_sslSett->pgci_rsaMyPrivKey, &signCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciSignUpdate(signCtx, pc_out + c_signOff + 2, sz_signLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciSignGenFinish(signCtx, pc_out + c_signOff + 2, &sz_signLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

	}
		break;

	case en_gciSignAlgo_ECDSA:
		//begin vpy
		LOG_INFO("hash before signature");
		LOG_HEX(ac_hash, c_hashLen);

		//OLD-CW: mp_toradix(ps_sslCtx->ps_sslSett->p_ECCMyPrivKey->k, buffer, 16);
		//OLD-CW: printf("Private key: %s\n", buffer);

		//OLD-CW: e_result = cw_ecc_sign_encode(ac_hash, c_hashLen, pc_out + c_signOff + 2, &sz_signLen, ps_sslCtx->ps_sslSett->p_ECCMyPrivKey);

		signConf.algo = en_gciSignAlgo_ECDSA;
		signConf.hash = en_gciHashAlgo_None;

		//Private key coming from a PEM file with the Certificates -> see _sslSoc_sett_import_ECCprivKey in ssl_socket.c
		err = gciSignGenNewCtx(&signConf,
				ps_sslCtx->ps_sslSett->p_ECCMyPrivKey, &signCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciSignUpdate(signCtx, pc_out + c_signOff + 2, sz_signLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciSignGenFinish(signCtx, pc_out + c_signOff + 2, &sz_signLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		LOG_INFO("Signature after encryption");
		LOG_HEX(pc_out + c_signOff + 2, sz_signLen);

		break;

	case en_gciSignAlgo_DSA:
	case en_gciSignAlgo_None:
	default:
		//OLD-CW: e_result = CW_ERROR;
		e_result = E_SSL_ERROR;
		break;
	}

	TIME_STAMP(TS_DHE_SIGN_END);

	/* and sign the hashes by rsa encryption */
	//OLD-CW: if (e_result != CW_OK)
	if (e_result != E_SSL_NO_ERROR) {
		*sz_outLen = 0;
		LOG_ERR("%p| RSA/ECDSA encrypt not successful", ps_sslCtx);
		e_result = E_SSL_ERROR_GENERAL;
	} else {
		/* add length of signature */
		(void) ssl_writeInteger(pc_out + c_signOff, sz_signLen, 2);

		/* c_signOff will be not zero only for TLS 1.2 */
		*sz_outLen = sz_signLen + c_signOff + 2;
	}

	//Release the contexts

	err = gciCtxRelease(sha1Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	err = gciCtxRelease(md5Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	err = gciCtxRelease(hashCtx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	err = gciCtxRelease(signCtx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	return (e_result);
}

static const uint8_t* const loc_getFinLabel(s_sslCtx_t *ps_sslCtx,
		uint8_t isCli) {
	const uint8_t* pc_ret = NULL;
	e_sslVer_t e_ver = ps_sslCtx->e_ver;

	switch (e_ver) {
	case E_SSL_3_0:
		if (isCli) {
			pc_ret = rac_SSLlabelCliFin;
		} else {
			pc_ret = rac_SSLlabelSrvFin;
		}
		break;
	case E_TLS_1_0:
	case E_TLS_1_1:
	case E_TLS_1_2:
		if (isCli) {
			pc_ret = rac_TLSlabelCliFin;
		} else {
			pc_ret = rac_TLSlabelSrvFin;
		}
		break;
	default:
		LOG_ERR("%p| Unexpected  version %d", ps_sslCtx, e_ver);
		break;
	}

	return pc_ret;
}

static void loc_setDefPrf(s_sslCtx_t *ps_sslCtx) {
	assert(ps_sslCtx != NULL);

	switch (ps_sslCtx->e_ver) {
	/* In this versions we assume targets support at least md5 and sha1 */
	case E_SSL_3_0:
	case E_TLS_1_0:
	case E_TLS_1_1:
		ps_sslCtx->s_secParams.e_prf = E_SSL_PRF_MD5_SHA1;
		break;
		/* In this ver. prf defined by cipher suite bus default is P_PRF256 */
	case E_TLS_1_2:
		ps_sslCtx->s_secParams.e_prf = E_SSL_PRF_SHA256;
		break;
	default:
		ps_sslCtx->s_secParams.e_prf = E_SSL_PRF_UNDEF;
		break;
	}
}

static void loc_hash(e_hashOp_t e_hashOp, s_sslCtx_t* ps_sslCtx, uint8_t* pc_in,
		size_t sz_inLen) {
	en_gciHashAlgo_t hashAlgo;

	en_gciResult_t err;

	/* Depending on a used psudo random function type we will work with
	 * two hashes md5 and sha1 or only one selected by prf
	 *  */
	if (ps_sslCtx->s_secParams.e_prf == E_SSL_PRF_MD5_SHA1) {
		switch (e_hashOp) {
		case E_HASHOP_INIT:

			TIME_STAMP(TS_HASH_INIT_BEGIN);

			//OLD-CW: cr_digestInit(&ps_sslCtx->ps_hsElem->u_hashCtx.s_md5Sha1.gci_md5Ctx, NULL, 0, E_SSL_HASH_MD5);
			err = gciHashNewCtx(en_gciHashAlgo_MD5,
					&ps_sslCtx->ps_hsElem->u_hashCtx.md5Ctx);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

			//OLD-CW: cr_digestInit(&ps_sslCtx->ps_hsElem->u_hashCtx.s_md5Sha1.gci_sha1Ctx, NULL, 0, E_SSL_HASH_SHA1);
			err = gciHashNewCtx(en_gciHashAlgo_SHA1,
					&ps_sslCtx->ps_hsElem->u_hashCtx.sha1Ctx);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

			TIME_STAMP(TS_HASH_INIT_END);

			break;

		case E_HASHOP_UPDATE:

			TIME_STAMP(TS_HASH_UPDATE_BEGIN);

			//OLD-CW: cr_digestUpdate(&ps_sslCtx->ps_hsElem->u_hashCtx.s_md5Sha1.gci_md5Ctx, pc_in, sz_inLen, E_SSL_HASH_MD5);
			err = gciHashUpdate(ps_sslCtx->ps_hsElem->u_hashCtx.md5Ctx, pc_in,
					sz_inLen);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

			//OLD-CW: cr_digestUpdate(&ps_sslCtx->ps_hsElem->u_hashCtx.s_md5Sha1.gci_sha1Ctx, pc_in, sz_inLen, E_SSL_HASH_SHA1);
			err = gciHashUpdate(ps_sslCtx->ps_hsElem->u_hashCtx.sha1Ctx,
					pc_in, sz_inLen);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

			TIME_STAMP(TS_HASH_UPDATE_END);

			break;
		case E_HASHOP_FINISH:
			break;
		default:
			break;
		}

	}
	//SHA256 or UNDEF
	else {
		hashAlgo = loc_getHashTypeByPrf(ps_sslCtx->s_secParams.e_prf);

		switch (e_hashOp) {
		case E_HASHOP_INIT:

			TIME_STAMP(TS_HASH_INIT_BEGIN);

			//OLD-CW: cr_digestInit(&ps_sslCtx->ps_hsElem->u_hashCtx.gci_hashCtx, NULL, 0, c_hashType);
			err = gciHashNewCtx(hashAlgo,
					&ps_sslCtx->ps_hsElem->u_hashCtx.hashCtx);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

			TIME_STAMP(TS_HASH_INIT_END);

			break;
		case E_HASHOP_UPDATE:

			TIME_STAMP(TS_HASH_UPDATE_BEGIN);

			//OLD-CW: cr_digestUpdate(&ps_sslCtx->ps_hsElem->u_hashCtx.gci_hashCtx, pc_in, sz_inLen, c_hashType);
			err = gciHashUpdate(ps_sslCtx->ps_hsElem->u_hashCtx.hashCtx,
					pc_in, sz_inLen);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

			TIME_STAMP(TS_HASH_UPDATE_END);

			break;
		case E_HASHOP_FINISH:
			break;
		default:
			break;
		}
	}
}

static void loc_compHash(s_sslCtx_t* ps_sslCtx, const uint8_t* pc_label,
		uint8_t* pc_res) {
	e_sslVer_t e_ver = ps_sslCtx->e_ver;

	TIME_STAMP(TS_COMP_HASH_BEGIN);

	switch (e_ver) {
	case E_SSL_3_0:
		loc_compHashSSL(ps_sslCtx, pc_label, pc_res);
		break;
	case E_TLS_1_0:
	case E_TLS_1_1:
	case E_TLS_1_2:
		loc_compHashTLS(ps_sslCtx, pc_label, pc_res);
		break;
	default:
		LOG_ERR("%p| Unexpected  version %d", ps_sslCtx, e_ver);
		break;
	}

	TIME_STAMP(TS_COMP_HASH_END);
}

/******************************************************************************
 * Compute the verification hashes for both MD5 and SHA1 hashes
 * For the client authentication: sender == NULL
 ******************************************************************************/
static void loc_compHashSSL(s_sslCtx_t *ps_sslCtx, const uint8_t *pc_snd,
		uint8_t *pc_res) {
	uint8_t ac_tmpSha1Hash[20];
	uint8_t ac_tmpMd5Hash[16];
	//OLd-CW: gci_sha1Ctx_t cwt_sha1Ctx;
	//OLD-Cw: gci_md5Ctx_t cwt_md5Ctx;

	GciCtxId_t md5Ctx;
	GciCtxId_t sha1Ctx;

	s_sslHsElem_t *ps_handshElem;

	size_t ac_tmpSha1Hash_len;
	size_t ac_tmpMd5Hash_len;

	en_gciResult_t err;

	assert(ps_sslCtx != NULL);
	assert(pc_res != NULL);

	ps_handshElem = ps_sslCtx->ps_hsElem;

	LOG1_INFO("loc_compHash, param: %s", (pc_snd!=NULL)?(char*)pc_snd:"NULL");

	/* The calculation of the handshake verification hashes requires a copy   */
	/* of the handshake hashes which are held in ctx->pcwt_sha1Ctx and            */
	/* ctx->pcwt_md5Ctx */

	//OLD-CW: memcpy(&cwt_sha1Ctx, &ps_handshElem->u_hashCtx.s_md5Sha1.gci_sha1Ctx, sizeof(gci_sha1Ctx_t));
	err = gciHashCtxClone(ps_handshElem->u_hashCtx.sha1Ctx, &sha1Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	/* Calculation of the inner hash, no initialisation is needed (was        */
	/* implizit done by copying the context of the existing handshake hash */
	if (pc_snd != NULL) {
		//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, pc_snd, 4, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, pc_snd, 4);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}
	}

	//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, (uint8_t*) ps_handshElem->s_sessElem.ac_msSec, MSSEC_SIZE, E_SSL_HASH_SHA1);
	err = gciHashUpdate(sha1Ctx, ps_handshElem->s_sessElem.ac_msSec,
			MSSEC_SIZE);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, (uint8_t*) rac_macPad1, 40, E_SSL_HASH_SHA1);
	err = gciHashUpdate(sha1Ctx, rac_macPad1, 40);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestFinish(&cwt_sha1Ctx, ac_tmpSha1Hash, NULL, E_SSL_HASH_SHA1);
	err = gciHashFinish(sha1Ctx, ac_tmpSha1Hash, &ac_tmpSha1Hash_len);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//Release the context
	err = gciCtxRelease(sha1Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	/* The inner hash is now available, compute now the outer hash, using     */
	/* result of the previous inner hash */

	//OLD-CW: cr_digestInit(&cwt_sha1Ctx, NULL, 0, E_SSL_HASH_SHA1);
	err = gciHashNewCtx(en_gciHashAlgo_SHA1, &sha1Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, (uint8_t*) ps_handshElem->s_sessElem.ac_msSec, MSSEC_SIZE, E_SSL_HASH_SHA1);
	err = gciHashUpdate(sha1Ctx, ps_handshElem->s_sessElem.ac_msSec,
			MSSEC_SIZE);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, (uint8_t*) rac_macPad2, 40, E_SSL_HASH_SHA1);
	err = gciHashUpdate(sha1Ctx, rac_macPad2, 40);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestUpdate(&cwt_sha1Ctx, ac_tmpSha1Hash, 20, E_SSL_HASH_SHA1);
	err = gciHashUpdate(sha1Ctx, ac_tmpSha1Hash, 20);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestFinish(&cwt_sha1Ctx, pc_res + 16, NULL, E_SSL_HASH_SHA1);
	err = gciHashFinish(sha1Ctx, pc_res + 16, NULL);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//Release the context
	err = gciCtxRelease(sha1Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	/* The same procedure applies for MD5 */
	/* Copy of the context */

	//OLD-CW: memcpy(&cwt_md5Ctx, &ps_handshElem->u_hashCtx.s_md5Sha1.gci_md5Ctx, sizeof(gci_md5Ctx_t));
	err = gciHashCtxClone(ps_handshElem->u_hashCtx.md5Ctx, &md5Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//Release the context
	err = gciCtxRelease(ps_handshElem->u_hashCtx.md5Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	/* Calculation of the inner hash */
	if (pc_snd != 0) {
		//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, pc_snd, 4, E_SSL_HASH_MD5);
		err = gciHashUpdate(md5Ctx, pc_snd, 4);
	}

	//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, (uint8_t*) ps_handshElem->s_sessElem.ac_msSec, MSSEC_SIZE, E_SSL_HASH_MD5);
	err = gciHashUpdate(md5Ctx, ps_handshElem->s_sessElem.ac_msSec,
			MSSEC_SIZE);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, (uint8_t*) rac_macPad1, MSSEC_SIZE, E_SSL_HASH_MD5);
	err = gciHashUpdate(md5Ctx, rac_macPad1, MSSEC_SIZE);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestFinish(&cwt_md5Ctx, ac_tmpMd5Hash, NULL, E_SSL_HASH_MD5);
	err = gciHashFinish(md5Ctx, ac_tmpMd5Hash, &ac_tmpMd5Hash_len);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//Release the context
	err = gciCtxRelease(sha1Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	/* Calculation of the outer hash */
	//OLD-CW: cr_digestInit(&cwt_md5Ctx, NULL, 0, E_SSL_HASH_MD5);
	err = gciHashNewCtx(en_gciHashAlgo_MD5, &md5Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, (uint8_t*) ps_handshElem->s_sessElem.ac_msSec, MSSEC_SIZE, E_SSL_HASH_MD5);
	err = gciHashUpdate(md5Ctx, ps_handshElem->s_sessElem.ac_msSec,
			MSSEC_SIZE);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, (uint8_t*) rac_macPad2, 48, E_SSL_HASH_MD5);
	err = gciHashUpdate(md5Ctx, rac_macPad2, 48);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestUpdate(&cwt_md5Ctx, ac_tmpMd5Hash, 16, E_SSL_HASH_MD5);
	err = gciHashUpdate(md5Ctx, ac_tmpMd5Hash, 16);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//OLD-CW: cr_digestFinish(&cwt_md5Ctx, pc_res, NULL, E_SSL_HASH_MD5);
	err = gciHashFinish(md5Ctx, pc_res, NULL);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//Release the context
	err = gciCtxRelease(md5Ctx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	return;
}

/*
 * Compute digests (MD5 and SHA-1) of all handshake messages sent/received so
 * far. If pc_expansion is not a NULL pointer the TLS PRF is invoked using the
 * hashes and the string pointed to by pc_expansion as the label. If
 * pc_expansion is a NULL pointer the result can be used to compute the TLS
 * CertificateVerify data.
 */
static void loc_compHashTLS(s_sslCtx_t* ps_sslCtx, const uint8_t *pc_label,
		uint8_t* pc_result) {

	assert(ps_sslCtx != NULL);
	assert(pc_result != NULL);
	uint8_t c_hashLen;

	en_gciResult_t err;

	c_hashLen = loc_getHashSizeByPrf(ps_sslCtx->s_secParams.e_prf);

	if (ps_sslCtx->s_secParams.e_prf == E_SSL_PRF_MD5_SHA1) {
		//OLD-CW: gci_md5Ctx_t cwt_md5Ctx;
		//OLD-CW: gci_sha1Ctx_t cwt_sha1Ctx;
		uint8_t ac_md5hash[GCI_MD5_SIZE_BYTES];
		uint8_t ac_sha1hash[GCI_SHA1_SIZE_BYTES];

		GciCtxId_t md5Ctx;
		GciCtxId_t sha1Ctx;

		/*
		 * Verification Hashes for the finished message are in TLS not that complex
		 * as in SSL
		 * simply the prf applied with mastersecret as key, the expansion string
		 * and the hashresults of the handshake messages as payload
		 */
		//OLD-CW: memcpy(&cwt_md5Ctx, &ps_sslCtx->ps_hsElem->u_hashCtx.s_md5Sha1.gci_md5Ctx, sizeof(gci_md5Ctx_t));
		err = gciHashCtxClone(ps_sslCtx->ps_hsElem->u_hashCtx.md5Ctx,
				&md5Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: memcpy(&cwt_sha1Ctx, &ps_sslCtx->ps_hsElem->u_hashCtx.s_md5Sha1.gci_sha1Ctx, sizeof(gci_sha1Ctx_t));
		err = gciHashCtxClone(ps_sslCtx->ps_hsElem->u_hashCtx.sha1Ctx,
				&sha1Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cwt_md5Ctx, ac_md5hash, NULL, E_SSL_HASH_MD5);
		err = gciHashFinish(md5Ctx, ac_md5hash, NULL);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cwt_sha1Ctx, ac_sha1hash, NULL,E_SSL_HASH_SHA1);
		err = gciHashFinish(sha1Ctx, ac_sha1hash, NULL);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		if (pc_label != NULL) {
			loc_prfTLS(E_SSL_PRF_MD5_SHA1,
					ps_sslCtx->ps_hsElem->s_sessElem.ac_msSec, MSSEC_SIZE,
					pc_label, strlen((char const*) pc_label), ac_md5hash,
					GCI_MD5_SIZE_BYTES, ac_sha1hash, GCI_SHA1_SIZE_BYTES,
					pc_result, VERIF_HASHSIZE_TLS);
		} else {
			//OLD-CW: memcpy(pc_result, ac_md5hash, GCI_MD5_SIZE);
			memcpy(pc_result, ac_md5hash, GCI_MD5_SIZE_BYTES);
			//OLD-CW: memcpy(pc_result + GCI_MD5_SIZE, ac_sha1hash, GCI_SHA1_SIZE);
			memcpy(pc_result + GCI_MD5_SIZE_BYTES, ac_sha1hash,
					GCI_SHA1_SIZE_BYTES);
		}

		//Release the context
		err = gciCtxRelease(ps_sslCtx->ps_hsElem->u_hashCtx.md5Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciCtxRelease(ps_sslCtx->ps_hsElem->u_hashCtx.sha1Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciCtxRelease(md5Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciCtxRelease(sha1Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

	}

	else {
		//OLD-CW: gci_hashCtx_t    cwt_hashCtx;
		GciCtxId_t hashCtx;
		uint8_t ac_hash[c_hashLen];
		//OLD-CW: uint8_t         c_hashType;
		en_gciHashAlgo_t hashAlgo;

		//OLD-CW: c_hashType = loc_getHashTypeByPrf( ps_sslCtx->s_secParams.e_prf);
		hashAlgo = loc_getHashTypeByPrf(ps_sslCtx->s_secParams.e_prf);

		//OLD-CW: memcpy(&cwt_hashCtx, &ps_sslCtx->ps_hsElem->u_hashCtx.gci_hashCtx, sizeof(gci_hashCtx_t));
		err = gciHashCtxClone(ps_sslCtx->ps_hsElem->u_hashCtx.hashCtx,
				&hashCtx);

		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cwt_hashCtx, ac_hash, NULL, c_hashType);
		err = gciHashFinish(hashCtx, ac_hash, NULL);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		/* TODO: remove */
		LOG_INFO("The Handshake Hash:");
		LOG_HEX(ac_hash, c_hashLen);

		if (pc_label != NULL) {
			loc_prfTLS(ps_sslCtx->s_secParams.e_prf,
					ps_sslCtx->ps_hsElem->s_sessElem.ac_msSec, MSSEC_SIZE,
					pc_label, strlen((char const*) pc_label), ac_hash,
					c_hashLen,
					NULL, 0, pc_result, ps_sslCtx->s_sslGut.c_verifyDataLen);
		}

		else {
			//OLD-CW: memcpy(pc_result, ac_hash, c_hashLen);
			memcpy(pc_result, ac_hash, c_hashLen);
		}

		//Release the contexts

		err = gciCtxRelease(ps_sslCtx->ps_hsElem->u_hashCtx.hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciCtxRelease(hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}
	}

	return;
}

//OLD-CW: static size_t loc_compMac(s_sslCtx_t *ps_sslCtx,
//		uint8_t    *pc_result, size_t l_resultLen,
//		uint8_t    *pc_inData, uint16_t i_inDataLen,
//		uint8_t    c_msgType,  uint8_t c_dir,
//		e_sslHashAlg_t c_hmacType)
static size_t loc_compMac(s_sslCtx_t *ps_sslCtx, uint8_t *pc_result,
		size_t l_resultLen, uint8_t *pc_inData, uint16_t i_inDataLen,
		uint8_t c_msgType, uint8_t c_dir, en_gciHashAlgo_t hashAlgo) {
	size_t cwt_len = 0;
	e_sslVer_t e_ver = ps_sslCtx->e_ver;

	TIME_STAMP(TS_COMP_MAC_BEGIN);

	switch (e_ver) {
	case E_SSL_3_0:
		cwt_len = loc_compMacSSL(ps_sslCtx, pc_result, pc_inData, i_inDataLen,
				c_msgType, c_dir, hashAlgo);
		break;
	case E_TLS_1_0:
	case E_TLS_1_1:
	case E_TLS_1_2:
		cwt_len = loc_compMacTLS(ps_sslCtx, pc_result, l_resultLen, pc_inData,
				i_inDataLen, c_msgType, c_dir, hashAlgo);
		break;
	default:
		LOG_ERR("%p| Unexpected  version %d", ps_sslCtx, e_ver);
		break;
	}

	TIME_STAMP(TS_COMP_MAC_END);

	return cwt_len;
}

//OLD-CW: static size_t loc_compMacSSL(s_sslCtx_t  *ps_sslCtx,  uint8_t    *result,
//		uint8_t     *pc_inData,  uint16_t   i_inDataLen,
//		uint8_t     c_msgType,   uint8_t    c_ioDir,
//		e_sslHashAlg_t  e_hashType)
static size_t loc_compMacSSL(s_sslCtx_t *ps_sslCtx, uint8_t *result,
		uint8_t *pc_inData, uint16_t i_inDataLen, uint8_t c_msgType,
		uint8_t c_ioDir, en_gciHashAlgo_t hashAlgo) {
	/* It should be possible to use the result area for the intermediate      */
	/* result of the first hash ... */
	static uint8_t ac_hashBuf[20];
	static uint8_t as_temp[12];
	uint8_t* pc_seqNum = 0;
	size_t cwt_retLen = 0;
	//gci_hashCtx_t    cw_hashCtx;
	GciCtxId_t hashCtx;

	en_gciResult_t err;

	/*! MAC secret */
	uint8_t* pc_sec;

	assert(ps_sslCtx != NULL);
	assert(result != NULL);
	assert(pc_inData != NULL);

	loc_selectSeqNum(ps_sslCtx, c_ioDir, &pc_seqNum, &pc_sec);

	memcpy(as_temp, pc_seqNum, 8);
	as_temp[8] = c_msgType;

	(void) ssl_writeInteger(&as_temp[9], i_inDataLen, 2);

	LOG1_INFO("loc_compMAC Contentstring");
	LOG1_INFO("Direction: %s, client: %s hmac type = %s",
			(c_ioDir == SEND)?"SEND":"RECEIVE",
			(ps_sslCtx->b_isCli == TRUE)?"TRUE":"FALSE",
			sslDiag_getHashAlg(hashAlgo));
	LOG2_HEX(as_temp, 11);

	/* Check which hash algorithm to use (0 means MD5, 1 means SHA1) */
	//OLD-CW: if (hashAlgo == E_SSL_HASH_SHA1)
	if (hashAlgo == en_gciHashAlgo_SHA1) {
		//OLD-CW: cr_digestInit(&cw_hashCtx,NULL, 0, hashAlgo);
		err = gciHashNewCtx(hashAlgo, &hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, pc_sec, GCI_SHA1_SIZE, hashAlgo);
		err = gciHashUpdate(hashCtx, pc_sec, GCI_SHA1_SIZE_BYTES);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, (uint8_t*) rac_macPad1, 40, hashAlgo);
		err = gciHashUpdate(hashCtx, rac_macPad1, 40);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, as_temp,   11, hashAlgo);
		err = gciHashUpdate(hashCtx, as_temp, 11);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, pc_inData, i_inDataLen, hashAlgo);
		err = gciHashUpdate(hashCtx, pc_inData, i_inDataLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cw_hashCtx, ac_hashBuf, NULL, hashAlgo);
		err = gciHashFinish(hashCtx, ac_hashBuf, NULL);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//Release the context
		err = gciCtxRelease(hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestInit(&cw_hashCtx, NULL, 0, hashAlgo);
		err = gciHashNewCtx(hashAlgo, &hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, pc_sec, GCI_SHA1_SIZE, hashAlgo);
		err = gciHashUpdate(hashCtx, pc_sec, GCI_SHA1_SIZE_BYTES);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, (uint8_t*) rac_macPad2, 40, hashAlgo);
		err = gciHashUpdate(hashCtx, rac_macPad2, 40);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, ac_hashBuf, GCI_SHA1_SIZE, hashAlgo);
		err = gciHashUpdate(hashCtx, ac_hashBuf, GCI_SHA1_SIZE_BYTES);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cw_hashCtx, result, NULL, hashAlgo);
		err = gciHashFinish(hashCtx, result, NULL);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//Release the context
		err = gciCtxRelease(hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		cwt_retLen = GCI_SHA1_SIZE_BYTES;
	} else if (hashAlgo == en_gciHashAlgo_MD5) {

		//OLD-CW: cr_digestInit(&cw_hashCtx, NULL, 0, hashAlgo);
		err = gciHashNewCtx(hashAlgo, &hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, pc_sec, GCI_MD5_SIZE, hashAlgo);
		err = gciHashUpdate(hashCtx, pc_sec, GCI_MD5_SIZE_BYTES);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, (uint8_t*) rac_macPad1, 48, hashAlgo);
		err = gciHashUpdate(hashCtx, rac_macPad1, 48);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, as_temp, 11, hashAlgo);
		err = gciHashUpdate(hashCtx, as_temp, 11);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, pc_inData, i_inDataLen, hashAlgo);
		err = gciHashUpdate(hashCtx, pc_inData, i_inDataLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cw_hashCtx, ac_hashBuf, NULL, hashAlgo);
		err = gciHashFinish(hashCtx, ac_hashBuf, NULL);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//Release the context
		err = gciCtxRelease(hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestInit(&cw_hashCtx, NULL, 0, hashAlgo);
		err = gciHashNewCtx(hashAlgo, &hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, pc_sec, GCI_MD5_SIZE, hashAlgo);
		err = gciHashUpdate(hashCtx, pc_sec, GCI_MD5_SIZE_BYTES);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, (uint8_t*) rac_macPad2, 48, hashAlgo);
		err = gciHashUpdate(hashCtx, rac_macPad2, 48);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cw_hashCtx, ac_hashBuf, GCI_MD5_SIZE, hashAlgo);
		err = gciHashUpdate(hashCtx, ac_hashBuf, GCI_MD5_SIZE_BYTES);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cw_hashCtx, result, NULL, hashAlgo);
		err = gciHashFinish(hashCtx, result, NULL);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//Release the context
		err = gciCtxRelease(hashCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		cwt_retLen = GCI_MD5_SIZE_BYTES;
	}

	LOG_INFO("result:");
	LOG_HEX(result, cwt_retLen);

	loc_incrSeqNum(pc_seqNum);

	return cwt_retLen;
}

//OLD-CW: static size_t loc_compMacTLS(s_sslCtx_t  *ps_sslCtx,
//		uint8_t  *pc_out, size_t l_outLen,
//		uint8_t  *pc_in,  uint16_t i_inLen,
//		uint8_t  c_msgType,  uint8_t c_iodir,
//		e_sslHashAlg_t  e_hashType)
static size_t loc_compMacTLS(s_sslCtx_t *ps_sslCtx, uint8_t *pc_out,
		size_t l_outLen, uint8_t *pc_in, uint16_t i_inLen, uint8_t c_msgType,
		uint8_t c_iodir, en_gciHashAlgo_t hashAlgo) {
	uint8_t ac_secret[14];
	uint8_t *pc_seqNum;
	uint8_t *pc_macSecret;
	/* TODO NEW CRYPT. Change a type to index witch will be defined in conf*/
	//gci_hmacCtx_t    cwt_hmacCtx;
	GciCtxId_t hmacCtx;
	en_gciResult_t err;

	int i_retCheck;

	//OLD-CW: CW_MEMSET(ac_secret, 0, sizeof(ac_secret));
	memset(ac_secret, 0, sizeof(ac_secret));
	i_retCheck = 0;
	/* select hmac 'secret' and corresponding Sequence Number */
	loc_selectSeqNum(ps_sslCtx, c_iodir, &pc_seqNum, &pc_macSecret);

	/* rfc2246.txt:1033
	 * The MAC is generated as:
	 *
	 *   HMAC_hash(MAC_write_secret, seq_num + TLSCompressed.type +
	 *                 TLSCompressed.version + TLSCompressed.length +
	 *                 TLSCompressed.fragment));
	 */
	/* build startsequence of hmac'ed data */
	/* seq_num */

	//OLD-CW: memcpy(ac_secret, pc_seqNum, 8);
	memcpy(ac_secret, pc_seqNum, 8);
	/* TLSCompressed.type */
	ac_secret[8] = c_msgType;
	/* TLSCompressed.version.major */
	ac_secret[9] = SSL_VERSION_GET_MAJ(ps_sslCtx->e_ver);
	/* TLSCompressed.version.minor */
	ac_secret[10] = SSL_VERSION_GET_MIN(ps_sslCtx->e_ver);
	if (ps_sslCtx->e_ver == E_VER_DCARE) {
		LOG_ERR("No Correct Version set! %s",
				sslDiag_getVersion(ps_sslCtx->e_ver));
		LOG_ERR("HMAC finished with errors");
		l_outLen = 0;
	}

	else {
		/* TLSCompressed.length */
		(void) ssl_writeInteger(&ac_secret[11], i_inLen, 2);

		if (i_retCheck >= 0) {
			/* MAC_write_secret. 20 byte is a length of mac secret*/

			//OLD-CW: i_retCheck += cr_digestInit(&cwt_hmacCtx, pc_macSecret, ps_sslCtx->s_secParams.c_hmacLen ,hashAlgo);
			err = gciHashNewCtx(hashAlgo, &hmacCtx);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
				i_retCheck += 1;
			}

			/* seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length */

			//OLD-CW: i_retCheck += cr_digestUpdate(&cwt_hmacCtx, ac_secret, 13,hashAlgo);
			err = gciHashUpdate(hmacCtx, ac_secret, 13);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
				i_retCheck += 1;
			}

			/* TLSCompressed.fragment */

			//OLD-CW: i_retCheck += cr_digestUpdate(&cwt_hmacCtx,pc_in, i_inLen,hashAlgo);
			err = gciHashUpdate(hmacCtx, pc_in, i_inLen);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
				i_retCheck += 1;
			}

			//OLD-CW: i_retCheck += cr_digestFinish(&cwt_hmacCtx,pc_out, &l_outLen,hashAlgo);
			err = gciHashFinish(hmacCtx, pc_out, &l_outLen);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
				i_retCheck += 1;
			}

			//Release the context
			err = gciCtxRelease(hmacCtx);
			if (err != en_gciResult_Ok) {
				//TODO: return from error state
			}

		}
	}

//OLD-CW: if (i_retCheck < 0) {
	if (i_retCheck > 0) {
		l_outLen = 0;
		LOG_ERR("HMAC finished with errors");
	}

	else {
		loc_incrSeqNum(pc_seqNum);
	}

	return (size_t) l_outLen;
}

/*! \brief Compute stream of hash using HMAC function
 *
 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
 * HMAC_hash(secret, A(2) + seed) +
 * HMAC_hash(secret, A(3) + seed) + ...
 * Where + indicates concatenation.
 * A() is defined as:
 * A(0) = seed
 * A(i) = HMAC_hash(secret, A(i-1))
 *
 * \param e_hashType           : Type of a hash for P_hash
 * \param pc_secret            : Secret
 * \param c_secLen
 * \param pc_label
 * \param c_labelLen
 * \param pc_seed
 * \param c_seedLen
 * \param pc_xSeed
 * \param c_xSeedLen
 * \param pc_out
 * \param l_outLen *
 *
 * \return  none
 */
/*
 */
//OLD-CW: static void loc_pHash(e_sslHashAlg_t e_hashType,
//		uint8_t*      pc_secret, size_t  sz_secLen,
//		const  uint8_t*      pc_label,  uint8_t c_labelLen,
//		uint8_t*      pc_seed,   uint8_t c_seedLen,
//		uint8_t*      pc_xSeed,  uint8_t c_xSeedLen,
//		uint8_t*      pc_out,    size_t  sz_outLen)
//{

static void loc_pHash(en_gciHashAlgo_t hashAlgo, uint8_t* pc_secret,
		size_t sz_secLen, const uint8_t* pc_label, uint8_t c_labelLen,
		uint8_t* pc_seed, uint8_t c_seedLen, uint8_t* pc_xSeed,
		uint8_t c_xSeedLen, uint8_t* pc_out, size_t sz_outLen) {
	size_t sz_realLen = 0;
	size_t sz_hmacLen = 0;
	//OLD-CW: gci_hmacCtx_t    cwt_hmacCtx;
	GciCtxId_t hmacCtx;

	st_gciSignConfig_t hmacConf;

	GciKeyId_t secretKeyID;
	st_gciKey_t secretKey;

	int32_t i_retCheck = 0;
	sz_hmacLen = loc_getHashSize(hashAlgo);
	uint8_t ac_hmac[sz_hmacLen];

	en_gciResult_t err;

	//OLD-CW:
	/*i_retCheck += cr_digestInit(&cwt_hmacCtx, pc_secret, sz_secLen, hashAlgo);


	 i_retCheck += cr_digestUpdate(&cwt_hmacCtx, pc_label, c_labelLen, hashAlgo);


	 i_retCheck += cr_digestUpdate(&cwt_hmacCtx, pc_seed, c_seedLen, hashAlgo);

	 if (c_xSeedLen != 0)
	 {
	 i_retCheck += cr_digestUpdate(&cwt_hmacCtx, pc_xSeed, c_xSeedLen, hashAlgo);
	 }
	 i_retCheck += cr_digestFinish(&cwt_hmacCtx, ac_hmac, &sz_hmacLen, hashAlgo);

	 while (i_retCheck == 0)
	 {
	 i_retCheck += cr_digestInit(&cwt_hmacCtx, pc_secret, sz_secLen, hashAlgo);
	 i_retCheck += cr_digestUpdate(&cwt_hmacCtx, ac_hmac, sz_hmacLen, hashAlgo);
	 i_retCheck += cr_digestUpdate(&cwt_hmacCtx, pc_label, c_labelLen, hashAlgo);
	 i_retCheck += cr_digestUpdate(&cwt_hmacCtx, pc_seed,c_seedLen, hashAlgo);
	 if (c_xSeedLen != 0)
	 {
	 i_retCheck += cr_digestUpdate(&cwt_hmacCtx, pc_xSeed,c_xSeedLen, hashAlgo);
	 }

	 i_retCheck += cr_digestFinish(&cwt_hmacCtx, &pc_out[sz_realLen],&sz_hmacLen, hashAlgo);

	 sz_realLen += sz_hmacLen;

	 if (sz_realLen >= sz_outLen)
	 {
	 break;
	 }

	 i_retCheck += cw_hmac(hashAlgo, pc_secret, sz_secLen,
	 ac_hmac, sz_hmacLen,
	 ac_hmac, &sz_hmacLen);
	 }
	 */

	//See page 138 "SSL and TLS - Theory and practice" from Rolf Oppliger

	hmacConf.algo = en_gciSignAlgo_HMAC;
	hmacConf.hash = hashAlgo;
	secretKey.type = en_gciKeyType_Hmac;
	secretKey.un_key.keysym.len = sz_secLen;
	memcpy(secretKey.un_key.keysym.data, pc_secret, sz_secLen);

	err = gciKeyPut(&secretKey, &secretKeyID);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//HMAC is defined as a signature in gci
	err = gciSignGenNewCtx(&hmacConf, secretKeyID, &hmacCtx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	err = gciSignUpdate(hmacCtx, pc_label, c_labelLen);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	err = gciSignUpdate(hmacCtx, pc_seed, c_seedLen);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	err = gciSignGenFinish(hmacCtx, ac_hmac, &sz_hmacLen);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//Release the context
	err = gciCtxRelease(hmacCtx);
	if (err != en_gciResult_Ok) {
		//TODO: return from error state
	}

	//TODO sw - what for error to stop the loop ?

	while (err == en_gciResult_Ok) {

		err = gciSignGenNewCtx(&hmacConf, secretKeyID, &hmacCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciSignUpdate(hmacCtx, ac_hmac, sz_hmacLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciSignUpdate(hmacCtx, pc_label, c_labelLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciSignUpdate(hmacCtx, pc_seed, c_seedLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		err = gciSignGenFinish(hmacCtx, ac_hmac, &sz_hmacLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//Release the context
		err = gciCtxRelease(hmacCtx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

	}

	memcpy(pc_out, ac_hmac, sz_hmacLen);
	sz_outLen = sz_hmacLen;

}

static e_sslError_t loc_prf(s_sslCtx_t* ps_sslCtx, uint8_t* pc_secret,
		size_t sz_secLen, const uint8_t* pc_label, uint8_t c_lbLen,
		uint8_t* pc_par1, uint8_t c_par1Len, uint8_t* pc_par2,
		uint8_t c_par2Len, uint8_t* pc_result, size_t sz_outLen) {
	e_sslError_t err = E_SSL_NO_ERROR;

	LOG1_INFO("(%s)", sslDiag_getVersion(ps_sslCtx->e_ver));

	TIME_STAMP(TS_PRF_BEGIN);

	switch (ps_sslCtx->e_ver) {
	case E_SSL_3_0:
		loc_prfSSL(pc_secret, sz_secLen, pc_par1, c_par1Len, pc_par2, c_par2Len,
				pc_result, sz_outLen);
		break;
	case E_TLS_1_0:
	case E_TLS_1_1:
	case E_TLS_1_2:
		LOG1_INFO("Computing prf for TLS with label (%s)", pc_label);
		loc_prfTLS(ps_sslCtx->s_secParams.e_prf, pc_secret, sz_secLen, pc_label,
				c_lbLen, pc_par1, c_par1Len, pc_par2, c_par2Len, pc_result,
				sz_outLen);
		break;
	default:
		LOG_ERR("Wrong SSL Version: %s", sslDiag_getVersion(ps_sslCtx->e_ver));
		err = E_SSL_ERROR_VERSION;
		break;
	}

	TIME_STAMP(TS_PRF_END);

	return err;
}

/*============================================================================*/
/*!

 \brief     Calculates the keyblock based on the mastersecret resp.
 the premastersecret and the exchanged random values,

 This is actually not a correct naming as it doesn't generate a pseudo random
 material. This might be misleading as there is no official prf function in SSLv3

 Mastersecret and the random values are used to produce a block of a
 predetermined length, which is used for all keying material needed

 Limitations: the length of the generated keyblock is a multiple of 16
 the result area must be large enough to receive the generated block
 to avoid any buffer overflow
 There is no length checking

 TODO correct naming
 \param     pc_secret     Pointer to the head of the list
 \param     cwt_secLen     Pointer to the element that will be hanged in the list
 \param     pc_par1       Pointer to the certificate that will be assigned to
 the element that enters the list
 \param     cwt_param1Len      Pointer to a cert_db element that will be assigned to
 the element that enters the list

 \return    s_sslCertList_t* Pointer to the head of the list. This will never be NULL
 */
/*============================================================================*/
static void loc_prfSSL(uint8_t* pc_sec, size_t cwt_secLen, uint8_t* pc_par1,
		uint8_t cwt_par1Len, uint8_t* pc_par2, uint8_t cwt_par2Len,
		uint8_t* pc_out, size_t cwt_outLen) {
	uint8_t i;
	int i_bytes;
	uint8_t *pc_tmp;
	uint8_t c_mixCount;
	uint8_t ac_mix[20];
	uint8_t secBuf[48];
	uint8_t sha1_hash[GCI_SHA1_SIZE_BYTES];

	/* Two local copies of Hash-Contexts are needed */
	//OLD-CW: gci_sha1Ctx_t cwt_sha1KbCtx;
	//OLD-CW: gci_md5Ctx_t cwt_md5KbCtx;
	GciCtxId_t sha1Ctx;
	GciCtxId_t md5Ctx;

	en_gciResult_t err;

	assert(pc_sec != NULL);
	assert(pc_par1 != NULL);
	assert(pc_par2 != NULL);
	assert(pc_out != NULL);
	assert(cwt_outLen <= 320);

	i_bytes = cwt_outLen;

	if ((pc_out == pc_sec) && (cwt_secLen <= 48)) {
		//OLD-CW: memcpy(secBuf, pc_sec, cwt_secLen);
		memcpy(secBuf, pc_sec, cwt_secLen);
		pc_sec = secBuf;
	} else if ((pc_out == pc_sec) && (cwt_secLen > 48))
		LOG1_ERR("Memcpy not possible, buffer too small");

	LOG1_INFO("loc_compKeyBlkMasSec, size requested: %zu", cwt_outLen);
	LOG2_INFO("random_1");
	LOG2_HEX(pc_par1, 32);
	LOG1_INFO("random_2");
	LOG2_HEX(pc_par2, 32);
	LOG1_INFO("Master- or preMaster-secret");
	LOG2_HEX(pc_sec, 48);

	c_mixCount = 0;

	while (i_bytes > 0) {
		i_bytes -= GCI_MD5_SIZE_BYTES;

		/* Generate the mixerstring */
		pc_tmp = ac_mix;
		c_mixCount++;

		/* Fill the mixer-string with the information needed */
		for (i = 0; i < c_mixCount; i++) {
			*pc_tmp++ = c_mixCount + 0x40;
		}

		/* The inner hash */
		//OLD-CW: cr_digestInit(&cwt_sha1KbCtx, NULL, 0, E_SSL_HASH_SHA1);
		err = gciHashNewCtx(en_gciHashAlgo_SHA1, &sha1Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1KbCtx, ac_mix, c_mixCount, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, ac_mix, c_mixCount);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1KbCtx, pc_sec, cwt_secLen, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, pc_sec, cwt_secLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1KbCtx, pc_par1, cwt_par1Len, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, pc_par1, cwt_par1Len);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_sha1KbCtx, pc_par2, cwt_par2Len, E_SSL_HASH_SHA1);
		err = gciHashUpdate(sha1Ctx, pc_par2, cwt_par2Len);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cwt_sha1KbCtx, sha1_hash, NULL, E_SSL_HASH_SHA1);
		err = gciHashFinish(sha1Ctx, sha1_hash, NULL);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		/* The outer hash */

		//OLD-CW: cr_digestInit(&cwt_md5KbCtx, NULL, 0, E_SSL_HASH_MD5);
		err = gciHashNewCtx(en_gciHashAlgo_MD5, &md5Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_md5KbCtx, pc_sec, cwt_secLen, E_SSL_HASH_MD5);
		err = gciHashUpdate(md5Ctx, pc_sec, cwt_secLen);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestUpdate(&cwt_md5KbCtx, sha1_hash, GCI_SHA1_SIZE, E_SSL_HASH_MD5);
		err = gciHashUpdate(md5Ctx, sha1_hash, GCI_SHA1_SIZE_BYTES);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//OLD-CW: cr_digestFinish(&cwt_md5KbCtx, pc_out, NULL, E_SSL_HASH_MD5);
		err = gciHashFinish(md5Ctx, pc_out, NULL);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//Release the contexts

		err = gciCtxRelease(md5Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		//Release the context
		err = gciCtxRelease(sha1Ctx);
		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		pc_out += GCI_MD5_SIZE_BYTES;
	}
}

static void loc_prfTLS(e_sslPrf_t e_prf, uint8_t* pc_secret,
		size_t sz_secretLen, const uint8_t* pc_label, uint8_t c_labelLen,
		uint8_t* pc_seed1, uint8_t c_seed1Len, uint8_t* pc_seed2,
		uint8_t c_seed2Len, uint8_t* pc_out, size_t sz_outLen) {
	uint8_t c_prfResSize = sz_outLen + loc_getHashSizeByPrf(e_prf);

	uint8_t e_hmacType;

	assert(pc_secret != NULL);
	assert(pc_out != NULL);

	if (e_prf == E_SSL_PRF_MD5_SHA1) {
		size_t i;
		size_t sz_len;
		/* First and second parts of a result prf streams */
		uint8_t c_prf1Res[c_prfResSize];
		uint8_t c_prf2Res[c_prfResSize];

		/* First and second parts of a secret */
		uint8_t* pc_sec1;
		uint8_t* pc_sec2;

		//OLD-CW: CW_MEMSET(c_prf1Res, 0, c_prfResSize);
		memset(c_prf1Res, 0, c_prfResSize);
		//OLD-CW: CW_MEMSET(c_prf2Res, 0, c_prfResSize);
		memset(c_prf2Res, 0, c_prfResSize);

		sz_len = sz_secretLen / 2;
		pc_sec1 = pc_secret;
		pc_sec2 = &pc_secret[sz_len];
		sz_len += (sz_secretLen & 1);

		/*OLD-CW: loc_pHash(E_SSL_HASH_MD5,
		 pc_sec1,  sz_len,
		 pc_label, c_labelLen,
		 pc_seed1, c_seed1Len,
		 pc_seed2, c_seed2Len,
		 c_prf1Res,sz_outLen);

		 */
		loc_pHash(en_gciHashAlgo_MD5, pc_sec1, sz_len, pc_label, c_labelLen, pc_seed1,
				c_seed1Len, pc_seed2, c_seed2Len, c_prf1Res, sz_outLen);

		/*OLD-CW: loc_pHash(E_SSL_HASH_SHA1,
		 pc_sec2,  sz_len,
		 pc_label, c_labelLen,
		 pc_seed1, c_seed1Len,
		 pc_seed2, c_seed2Len,
		 c_prf2Res,sz_outLen);
		 */

		loc_pHash(en_gciHashAlgo_SHA1, pc_sec1, sz_len, pc_label, c_labelLen,
				pc_seed1, c_seed1Len, pc_seed2, c_seed2Len, c_prf1Res,
				sz_outLen);

		for (i = 0; i < sz_outLen; i++) {
			pc_out[i] = c_prf1Res[i] ^ c_prf2Res[i];
		}
	} else {
		e_hmacType = loc_getHashTypeByPrf(e_prf);
		uint8_t c_prfRes[c_prfResSize];
		loc_pHash(e_hmacType, pc_secret, sz_secretLen, pc_label, c_labelLen,
				pc_seed1, c_seed1Len, pc_seed2, c_seed2Len, c_prfRes,
				sz_outLen);
		memcpy(pc_out, c_prfRes, sz_outLen);
	}

}

/*
 * The function adds a random size from 1 to 255 bytes to the datablock
 * it returns the number of bytes added
 */
static uint32_t loc_addPadding(s_sslCtx_t* ps_sslCtx, uint8_t *pc_data,
		uint32_t l_actLen, uint32_t l_blkSize) {
	uint32_t l_rand = 0;
	uint8_t c_padLen = 0;
	e_sslVer_t e_ver = ps_sslCtx->e_ver;

	en_gciResult_t err;

	switch (e_ver) {
	case E_SSL_3_0:
		/* define the padlen */
		c_padLen = l_blkSize - (l_actLen % l_blkSize);
		break;
	case E_TLS_1_0:
	case E_TLS_1_1:
	case E_TLS_1_2:
		/* We read a 32bit random.. */
		//OLD-CW: cw_prng_read((uint8_t*) &l_rand, 4);
		err = gciRngGen(4, (uint8_t*) l_rand);

		if (err != en_gciResult_Ok) {
			//TODO: return from error state
		}

		/* ..and break it down to a small value */
		c_padLen = l_rand % SSL_TLS_MAX_PADLEN;
		/* We make some padding adding (nice rhyme *g*) if its too small */
		if (c_padLen < l_blkSize) {
			c_padLen += l_blkSize;
		}
		/* now we define the real padlen */
		c_padLen = c_padLen - ((l_actLen + c_padLen) % l_blkSize);
		/* TODO: Redmine ticket #2090 */
		/*c_padLen = (l_actLen + 1) % l_blkSize;*/
#ifdef SSL_FORCE_PRNG_SEEDING
		cw_prng_seed(&c_padLen, 1);
#endif
		break;
	default:
		LOG_ERR("%p| Unexpected  version %d", ps_sslCtx, e_ver);
		return c_padLen;
	}

	l_rand = 0;
	/* we have to adjust the pointer */
	pc_data = &pc_data[l_actLen];
	/* we write c_padLen times (c_padLen-1) at the end of the data provided */
	while (l_rand++ < c_padLen) {
		*pc_data++ = c_padLen - 1;
	}

	return c_padLen;
}

static uint32_t loc_rmPadding(s_sslCtx_t* ps_sslCtx, uint8_t *pc_data,
		uint32_t l_len, uint32_t l_blkSize) {
	e_sslVer_t e_ver = ps_sslCtx->e_ver;
	uint8_t c_padLen = pc_data[l_len - 1] + 1;
	int16_t i;
	uint8_t c_cmp;

	LOG2_INFO("Padding Length to strip: %d", c_padLen);

	/*    if (c_padLen < l_blkSize) {
	 LOG_ERR("Error on Length to strip PadLen (%d) < CipherBlockLen (%d) "
	 "not allowed!",c_padLen,l_blkSize);
	 c_padLen = 0;
	 }*/

	if (l_len < c_padLen) {
		LOG_ERR("Wants to strip more than available... req:%i, available: %u",
				c_padLen, l_len);
		c_padLen = 0;
	}

	if (c_padLen != 0) {
		switch (e_ver) {
		case E_SSL_3_0:
			break;
		case E_TLS_1_0:
		case E_TLS_1_1:
		case E_TLS_1_2:
			c_cmp = c_padLen - 1;
			for (i = l_len - (uint32_t) c_padLen; i < l_len; i++) {
				if (pc_data[i] != c_cmp) {
					LOG_ERR("Error in padding");
					c_padLen = 0;
					break;
				}
			}
			break;
		default:
			LOG_ERR("%p| Unexpected  version (%d)", ps_sslCtx, e_ver);
			break;
		}
	}

	return c_padLen;
}

static size_t loc_cpCompositeHs(s_sslCtx_t* ps_sslCtx, uint8_t* pc_to,
		uint8_t* pc_from, size_t cwt_len) {
	size_t cwt_resLen = 0;
	size_t cwt_offset = 0;

	/* TODO: don't use assert for this...send an 'decode_error' alert instead */
	assert(cwt_len > (HS_HEADERLEN + 1));

	switch (ps_sslCtx->e_ver) {
	case E_SSL_3_0:
		/* TODO Check specs or google about this. For instance in ssl3 client
		 * key exch msg there are MIGHT BE implementations which are not
		 * include length field, because ssl3 specs doesn't say anything
		 * about this   */
		if (ps_sslCtx->s_secParams.e_kst != en_gciKeyPairType_DH) {
			cwt_resLen = cwt_len - HS_HEADERLEN;
			cwt_offset = HS_HEADERLEN;
			break;
		}
	case E_TLS_1_0:
	case E_TLS_1_1:
	case E_TLS_1_2:
		switch (ps_sslCtx->s_secParams.e_kst) {
		case en_gciKeyPairType_ECDH:
			//vpy: in case of ECDHE key exchange, rsLen++, ofset--, because length is coded with only 1 byte (instead of 2 bytes for DH)
			cwt_resLen = cwt_len - HS_HEADERLEN - 1;
			cwt_offset = HS_HEADERLEN + 1;
			break;
		default:
			cwt_resLen = cwt_len - HS_HEADERLEN - 2;
			cwt_offset = HS_HEADERLEN + 2;
			break;
		}
		break;
	default:
		if (ps_sslCtx->s_secParams.e_kst != en_gciKeyPairType_DH) {
			cwt_resLen = cwt_len - HS_HEADERLEN;
			cwt_offset = HS_HEADERLEN;
		} else {
			LOG_ERR("%p| Unexpected version (%d)", ps_sslCtx, ps_sslCtx->e_ver);
		}
		break;
	}

	if ((cwt_resLen) && (cwt_offset)) {
		//OLD-CW: CW_MEMMOVE(pc_to, pc_from + cwt_offset, cwt_resLen);
		memmove(pc_to, pc_from + cwt_offset, cwt_resLen);
	}

	return cwt_resLen;
}

/*===========================================================================*/
/*===========================================================================*/
/*===========================================================================*/
/*               END OF VERSION DEPENDANT FUNCTIONS                          */
/*===========================================================================*/
/*===========================================================================*/
/*===========================================================================*/

/***************************************************************************
 * Compute the SSLv3 MAC of a given message. The MAC algorithm is based
 * either on SHA1 or MD5. Which one to use can be selected with <macType>.
 * In SSL the data sent in each direction is protected by its own MAC. The
 * parameter <direction> specifies the direction for which the MAC is
 * calculated. The memory area in <result> must be large enough to hold the
 * computed MAC (16 or 20 bytes, depending on the used hash algorithm)
 ***************************************************************************/
static void loc_incrSeqNum(uint8_t* pc_seqNum) {
	int i;
	for (i = 7; i >= 0; i--) {
		pc_seqNum[i]++;
		if (pc_seqNum[i] != 0) {
			break;
		}
	}
	return;
}

static void loc_selectSeqNum(s_sslCtx_t *ps_sslCtx, uint8_t c_iodir,
		uint8_t **ppc_seqNum, uint8_t **ppc_macSecret) {
	if (c_iodir == SEND) {
		if (ps_sslCtx->b_isCli == TRUE) {
			*ppc_seqNum = ps_sslCtx->s_sslGut.ac_cliSeqNum;
			*ppc_macSecret = ps_sslCtx->s_secParams.ac_cliSecret;
		} else {
			*ppc_seqNum = ps_sslCtx->s_sslGut.ac_srvrSeqNum;
			*ppc_macSecret = ps_sslCtx->s_secParams.ac_srvSecret;
		}
	} else {
		if (ps_sslCtx->b_isCli == TRUE) {
			*ppc_seqNum = ps_sslCtx->s_sslGut.ac_srvrSeqNum;
			*ppc_macSecret = ps_sslCtx->s_secParams.ac_srvSecret;
		} else {
			*ppc_seqNum = ps_sslCtx->s_sslGut.ac_cliSeqNum;
			*ppc_macSecret = ps_sslCtx->s_secParams.ac_cliSecret;
		}
	}
	return;
}

/* The function calculates all keys needed for the active connection
 *
 * All neccessary information is available in the context
 * The keyblock is calculated based on the mastersecret and the
 * exchanged random values
 * The content of the generated keyblock is used to derive all keying material
 * Initializes the contexts of the used ciphers for bulk encryption for
 * both directions
 */

static void loc_compKey(s_sslCtx_t * ps_sslCtx, uint8_t b_srvKey) {
	uint8_t c_keyBlkLen = 2 * ps_sslCtx->s_secParams.c_hmacLen
			+ 2 * ps_sslCtx->s_secParams.c_keyLen
			+ 2 * ps_sslCtx->s_secParams.c_blockLen;

	uint8_t ac_keyBlk[c_keyBlkLen];
	s_sslHsElem_t* ps_hsElem;
	s_sslSecParams_t* ps_secPar;
	//gci_rc4Ctx_t*        cwt_rc4Ctx;
	GciCtxId_t rc4Ctx;
	//gci_aesCtx_t*        cwt_aesCtx;
	GciCtxId_t aesCtx;
	//gci_3desCtx*         cwt_tdesCtx;
	GciCtxId_t tdesCtx;
	uint8_t c_macOff;
	uint8_t c_keyOff;
	uint8_t c_ivOff;

	en_gciResult_t err;
	st_gciCipherConfig_t ciphConf;
	GciKeyId_t keyID;
	st_gciKey_t symKey;

	assert(ps_sslCtx != NULL);

	TIME_STAMP(TS_COMP_KEY_BEGIN);

	LOG1_INFO("Compute key for %s ", (b_srvKey==TRUE)?"Server":"Client");
	ps_hsElem = ps_sslCtx->ps_hsElem;
	ps_secPar = &ps_sslCtx->s_secParams;

	/* Creating key block with size of c_keyBlkLen.
	 * Then, the key_block is partitioned as follows:
	 * client_write_MAC_key[ps_secPar->c_hmacLen]
	 * server_write_MAC_key[ps_secPar->c_hmacLen]
	 * client_write_key[ps_secPar->c_keyLen]
	 * server_write_key[ps_secPar->c_keyLen]
	 * client_write_IV[ps_secPar->c_blockLen]
	 * server_write_IV[ps_secPar->c_blockLen]
	 * */
	loc_prf(ps_sslCtx, ps_hsElem->s_sessElem.ac_msSec, MSSEC_SIZE,
			rac_TLSlabelKeyExp, strlen((const char *) rac_TLSlabelKeyExp),
			ps_hsElem->ac_srvRand, SRV_RANDSIZE, ps_hsElem->ac_cliRand,
			CLI_RANDSIZE, ac_keyBlk, c_keyBlkLen);

	/*
	 * The sequence number must be reset when generating the new keying material
	 */
	if (b_srvKey == TRUE) {
		//OLD-CW: cwt_rc4Ctx = &(ps_secPar->u_srvKey.gci_srvRc4Ctx);
		rc4Ctx = &(ps_secPar->u_srvKey.srvRc4Ctx);
		//OLD-CW: cwt_tdesCtx = &(ps_secPar->u_srvKey.gci_srv3DesCtx);
		tdesCtx = &(ps_secPar->u_srvKey.srv3DesCtx);
		//OLD-CW: cwt_aesCtx = &(ps_secPar->u_srvKey.gci_srvAesCtx);
		aesCtx = &(ps_secPar->u_srvKey.srvAesCtx);

		c_macOff = ps_secPar->c_hmacLen;
		c_keyOff = 2 * c_macOff + ps_secPar->c_keyLen;
		c_ivOff = 2 * c_macOff + 2 * ps_secPar->c_keyLen
				+ ps_secPar->c_blockLen;

		//OLD-CW: CW_MEMSET(ps_sslCtx->s_sslGut.ac_srvrSeqNum, 0, 8);
		memset(ps_sslCtx->s_sslGut.ac_srvrSeqNum, 0, 8);
		memcpy(ps_secPar->ac_srvSecret, &(ac_keyBlk[c_macOff]),
				ps_secPar->c_hmacLen);
	} /* if */
	else {
		//OLD-CW: cwt_rc4Ctx = &(ps_secPar->u_cliKey.gci_cliRc4Ctx);
		rc4Ctx = &(ps_secPar->u_cliKey.cliRc4Ctx);
		//OLD-CW: cwt_tdesCtx = &(ps_secPar->u_cliKey.gci_cli3DesCtx);
		tdesCtx = &(ps_secPar->u_cliKey.cli3DesCtx);
		//OLD-CW: cwt_aesCtx = &(ps_secPar->u_cliKey.gci_cliAesCtx);
		aesCtx = &(ps_secPar->u_cliKey.cliAesCtx);

		c_macOff = 0;
		c_keyOff = 2 * ps_secPar->c_hmacLen;
		c_ivOff = 2 * ps_secPar->c_hmacLen + 2 * ps_secPar->c_keyLen;

		//OLD-CW: CW_MEMSET(ps_sslCtx->s_sslGut.ac_cliSeqNum, 0, 8);
		memset(ps_sslCtx->s_sslGut.ac_cliSeqNum, 0, 8);
		//OLD-CW: memcpy(ps_secPar->ac_cliSecret,&(ac_keyBlk[c_macOff]), ps_secPar->c_hmacLen);
		memcpy(ps_secPar->ac_cliSecret, &(ac_keyBlk[c_macOff]),
				ps_secPar->c_hmacLen);

		LOG2_INFO("MAC Key");
		LOG2_HEX(&(ac_keyBlk[c_macOff]), ps_secPar->c_hmacLen);
	} /* else */

	//Save the key and get an ID of it
	symKey.type = en_gciKeyType_Sym;
	symKey.un_key.keysym.len = ps_secPar->c_keyLen;
	memcpy(symKey.un_key.keysym.data, ac_keyBlk, ps_secPar->c_keyLen);

	err = gciKeyPut(&symKey, &keyID);
	if (err != en_gciResult_Ok) {
		//return error state
	}

	//add new ciphers here
	switch (ps_sslCtx->s_sslGut.e_pendCipSpec) {
	case TLS_RSA_WITH_RC4_128_MD5:
	case TLS_RSA_WITH_RC4_128_SHA: {
		//OLD-CW: cw_rc4_init(cwt_rc4Ctx, &(ac_keyBlk[c_keyOff]), ps_secPar->c_keyLen);

		//rc4Ctx = keyID -> see loc_smMacEncrypt
		err = gciKeyGet(rc4Ctx, &(ac_keyBlk[c_keyOff]));
		if (err != en_gciResult_Ok) {
			//return error from state
		}

		LOG2_INFO("Key");
		LOG2_HEX(&(ac_keyBlk[c_keyOff]), ps_secPar->c_keyLen);
		break;
	}
#ifdef AES_AND_3DES_ENABLED
	case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
	case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: //vpy
	case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: //vpy
	{
		//OLD-CW: cw_3des_init(cwt_tdesCtx,&(ac_keyBlk[c_keyOff]), ps_secPar->c_keyLen, &(ac_keyBlk[c_ivOff]), ps_secPar->c_blockLen, 0);

		//tdesCtx = keyID -> see loc_smMacEncrypt
		err = gciKeyGet(tdesCtx, &(ac_keyBlk[c_keyOff]));
		if (err != en_gciResult_Ok) {
			//return error from state
		}

		LOG2_INFO("Key");
		LOG2_HEX(&(ac_keyBlk[c_keyOff]), ps_secPar->c_keyLen);
		LOG2_INFO("IV");
		LOG2_HEX(&(ac_keyBlk[c_keyOff]), ps_secPar->c_blockLen);
		break;
	}
	case TLS_RSA_WITH_AES_128_CBC_SHA:
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
	case TLS_RSA_WITH_AES_256_CBC_SHA:
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: //vpy
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: //vpy
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: //vpy
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: //vpy
	{
		//OLD-CW: cw_aes_init(cwt_aesCtx, &(ac_keyBlk[c_keyOff]), ps_secPar->c_keyLen, &(ac_keyBlk[c_ivOff]), ps_secPar->c_blockLen, 0);

		//aesCtx = keyID -> see loc_smMacEncrypt
		err = gciKeyGet(aesCtx, &(ac_keyBlk[c_keyOff]));
		if (err != en_gciResult_Ok) {
			//return error from state
		}

		LOG2_INFO("Key");
		LOG2_HEX(&(ac_keyBlk[c_keyOff]), ps_secPar->c_keyLen);
		LOG2_INFO("IV");
		LOG2_HEX(&(ac_keyBlk[c_keyOff]), ps_secPar->c_blockLen);
		break;
	}
#endif
	default:
		break;
	}/* switch */

	TIME_STAMP(TS_COMP_KEY_END);

}

static e_sslPendAct_t loc_selVer(s_sslCtx_t* ps_sslCtx, e_sslVer_t e_ver) {
	int retVal = 0;
	s_sslHsElem_t *ps_hsElem = ps_sslCtx->ps_hsElem;
	s_sslGut_t *ps_sslGut = &ps_sslCtx->s_sslGut;

	/*
	 * Remember the offered version in the Client Hello,
	 * it is required later in the ClientKeyExchange
	 */
	ps_hsElem->e_offerVer = e_ver;

	if ((ps_sslCtx->e_ver == E_VER_DCARE)
			|| (ps_hsElem->e_offerVer > ps_sslCtx->e_ver)) {
		int ret;
		/*
		 * check the received version
		 */
		ret = sslRec_fetchCorrectVersion(ps_sslCtx, ps_hsElem->e_offerVer);

		/*
		 * evaluate only the error case that the offered version is
		 * not supported because it's a sooner one
		 */
		if (ret < 0) {
			LOG_ERR(" Version %i.%i not allowed, min: %s, max %s ",
					SSL_VERSION_GET_MAJ(ps_hsElem->e_offerVer),
					SSL_VERSION_GET_MIN(ps_hsElem->e_offerVer),
					sslDiag_getVersion(ps_sslCtx->ps_sslSett->e_minVer),
					sslDiag_getVersion(ps_sslCtx->ps_sslSett->e_maxVer));
			ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
			if (ps_hsElem->e_offerVer > E_SSL_3_0) {
				ps_sslGut->e_alertType = E_SSL_ALERT_PROTO_VER;
				ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
				/* Session not longer useable for resumption E_PENDACT_SCACHE_RM */
				retVal = E_PENDACT_SCACHE_RM;
			} else {
				retVal = E_PENDACT_PROTOERR;
			}
		} /* if */
	}/* if */
	/*
	 * look here if the highest supported version of the client
	 * that is connecting is lower than the version that has to be
	 * used. If it is lower then cancel the handshake.
	 */
	else if (ps_hsElem->e_offerVer < ps_sslCtx->e_ver) {
		LOG_ERR("%s not allowed, must use %s",
				sslDiag_getVersion(ps_hsElem->e_offerVer),
				sslDiag_getVersion(ps_sslCtx->e_ver));
		ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
		if (ps_hsElem->e_offerVer > E_SSL_3_0) {
			ps_sslGut->e_alertType = E_SSL_ALERT_PROTO_VER;
			ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
			/* Session not longer useable for resumption E_PENDACT_SCACHE_RM */
			retVal = E_PENDACT_SCACHE_RM;
		} /* if */
		else {
			retVal = E_PENDACT_PROTOERR;
		} /* else */
	} /* else if */

	switch (ps_sslCtx->e_ver) {
	case E_SSL_3_0:
		ps_sslCtx->s_sslGut.c_verifyDataLen = VERIF_HASHSIZE;
		break;
	case E_TLS_1_0:
	case E_TLS_1_1:
		ps_sslCtx->s_sslGut.c_verifyDataLen = VERIF_HASHSIZE_TLS;
		break;
	case E_TLS_1_2:
		/* TODO TLS 1.2 ADD dependance on a cipher suite */
		ps_sslCtx->s_sslGut.c_verifyDataLen = VERIF_HASHSIZE_TLS;
		break;
	default:
		LOG_ERR("Version is not known, can not set c_verifyDataLen");
		break;
	} /* switch */

	return retVal;
} /* loc_selectVer */

static void loc_setSecParams(s_sslCtx_t* ps_sslCtx, e_sslCipSpec_t e_cipSpec) {
	e_sslVer_t e_ver;
	s_sslSecParams_t* ps_secPar;

	ps_secPar = &ps_sslCtx->s_secParams;
	e_ver = ps_sslCtx->e_ver;

	//add new ciphers here
	switch (e_cipSpec) {
	case TLS_RSA_WITH_RC4_128_MD5:
		ps_secPar->e_kst = en_gciKeyPairType_RSA;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_RC4;
		ps_secPar->b_isBlkCip = FALSE;
		ps_secPar->e_hmacType = en_gciHashAlgo_MD5;
		ps_secPar->c_keyLen = 16;
		break;
	case TLS_RSA_WITH_RC4_128_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_RSA;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_RC4;
		ps_secPar->b_isBlkCip = FALSE;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 16;
		break;
#ifdef AES_AND_3DES_ENABLED
	case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_RSA;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_3DES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 8;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 24;
		break;
	case TLS_RSA_WITH_AES_128_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_RSA;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 16;
		break;
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
		ps_secPar->e_kst = en_gciKeyPairType_RSA;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA256;
		ps_secPar->c_keyLen = 16;
		break;
	case TLS_RSA_WITH_AES_256_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_RSA;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 32;
		break;
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		ps_secPar->e_kst = en_gciKeyPairType_RSA;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA256;
		ps_secPar->c_keyLen = 32;
		break;
	case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_DH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_3DES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 8;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 24;
		break;
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_DH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 16;
		break;
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_DH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 32;
		break;
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
		ps_secPar->e_kst = en_gciKeyPairType_DH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA256;
		ps_secPar->c_keyLen = 16;
		break;
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
		ps_secPar->e_kst = en_gciKeyPairType_DH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA256;
		ps_secPar->c_keyLen = 32;
		break;

		//begin vpy
	case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_ECDH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_ECDSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_3DES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 8;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 24;
		break;

	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_ECDH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_ECDSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 16;
		break;

	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_ECDH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_ECDSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 32;
		break;

	case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_ECDH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_3DES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 8;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 24;
		break;

	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_ECDH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 16;
		break;

	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		ps_secPar->e_kst = en_gciKeyPairType_ECDH;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
		ps_secPar->e_cipType = en_gciCipherAlgo_AES;
		ps_secPar->b_isBlkCip = TRUE;
		ps_secPar->c_blockLen = 16;
		ps_secPar->e_hmacType = en_gciHashAlgo_SHA1;
		ps_secPar->c_keyLen = 32;
		break;
		//end vpy
#endif
	default:
		ps_secPar->e_kst = en_gciKeyPairType_Invalid;
		ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_Invalid;
		ps_secPar->e_cipType = en_gciCipherAlgo_Invalid;
		ps_secPar->b_isBlkCip = FALSE;
		ps_secPar->c_blockLen = 0;
		ps_secPar->e_hmacType = en_gciHashAlgo_Invalid;
		ps_secPar->c_keyLen = 0;
		break;
	}

	ps_secPar->c_hmacLen = loc_getHashSize(ps_secPar->e_hmacType);

	switch (e_ver) {
	case E_SSL_3_0:
	case E_TLS_1_0:
	case E_TLS_1_1:
		ps_secPar->e_prf = E_SSL_PRF_MD5_SHA1;
		break;
	case E_TLS_1_2:

		/* If we resume negotiation we should as a default values set
		 * values from a session cache */
		if (ps_sslCtx->c_isResumed == TRUE) {
			ps_secPar->s_signAlg.c_sign =
					ps_sslCtx->ps_hsElem->s_sessElem.s_signAlg.c_sign;
			ps_secPar->s_signAlg.c_hash =
					ps_sslCtx->ps_hsElem->s_sessElem.s_signAlg.c_hash;
		} else {
			/* By default TLS 1.2 specify to use SHA1 as a hash for all
			 * supported signatures */
			switch (ps_secPar->e_kst) {
//			OLD-CW: case GCI_KEY_PAIR_DHE_RSA:
//			case GCI_KEY_PAIR_RSA:
//			case GCI_KEY_PAIR_ECDHE_RSA: //vpy
//				ps_secPar->s_signAlg.c_sign = GCI_SIGN_RSA;
//				ps_secPar->s_signAlg.c_hash = GCI_HASH_SHA1;
//				break;
//			case GCI_KEY_PAIR_DHE_DSS:
//				ps_secPar->s_signAlg.c_sign = GCI_SIGN_DSA;
//				ps_secPar->s_signAlg.c_hash = GCI_HASH_SHA1;
//				break;
//			//begin vpy
//			case GCI_KEY_PAIR_ECDHE_ECDSA:
//				ps_secPar->s_signAlg.c_sign = GCI_SIGN_ECDSA;
//				ps_secPar->s_signAlg.c_hash = GCI_HASH_SHA1;
//				break;
//			//end vpy
			case en_gciKeyPairType_DH:
			case en_gciKeyPairType_RSA:
			case en_gciKeyPairType_ECDH:
				ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_RSA;
				ps_secPar->s_signAlg.c_hash = en_gciHashAlgo_SHA1;
				break;

			default:
				ps_secPar->s_signAlg.c_sign = en_gciSignAlgo_Invalid;
				ps_secPar->s_signAlg.c_hash = en_gciHashAlgo_Invalid;
			}
		}
		switch (ps_secPar->e_hmacType) {
		case en_gciHashAlgo_None:
		case en_gciHashAlgo_MD5:
		case en_gciHashAlgo_SHA1:
		case en_gciHashAlgo_SHA256:
			ps_secPar->e_prf = E_SSL_PRF_SHA256;
			break;
		default:
			ps_secPar->e_prf = E_SSL_PRF_UNDEF;
			break;
		}
		break;
	default:
		ps_secPar->e_prf = E_SSL_PRF_UNDEF;
		break;
	}
}

/* Select a supported Cipher from the given list
 *
 * SSL V2: cipherSpecListLen > 0, each entry is 3 bytes wide, amount of entrys is "cipherSpecListLen / 3"
 * SSL V3: cipherSpecListLen = 0, effective length is coded within the first 2 bytes of cipherSpecList
 *       each entry is 2 bytes wide, amount of entrys is length / 2;
 */
static uint8_t* loc_matchCipherSpec(s_sslCtx_t* ps_sslCtx,
		uint8_t *pc_cipSpecList, uint16_t i_cipSpecListLen, uint16_t u_bufLen) {
	e_sslCipSpec_t *pe_selCip;
	e_sslCipSpec_t pe_oldPendCip;
	s_sslGut_t *ps_sslGuts;
	int32_t i, j;
	int32_t l_inc; /* Why are these of type int32_t? */
	int32_t l_start; /* Why not uint8_t? */
	uint8_t *pc_ret;
	uint8_t c_secureReneg;

	assert(pc_cipSpecList != NULL);
	assert(ps_sslCtx != NULL);

	pc_ret = NULL;
	c_secureReneg = FALSE;
	ps_sslGuts = &ps_sslCtx->s_sslGut;
	pe_selCip = &ps_sslGuts->e_pendCipSpec;

	/*
	 * Remember the old pending, in case this procedure fails
	 */
	pe_oldPendCip = *pe_selCip;
	*pe_selCip = TLS_NULL_WITH_NULL_NULL;

	if (i_cipSpecListLen == 0) /* Indicates SSL V3 cipher spec list */
	{
		/*
		 * | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 ...
		 * |  len  |  CS1  |  CS2  |  CS3  ...
		 *           ^ start
		 *           x- inc -x- inc -x
		 */

		/* make sure there are at least two bytes in the buffer to read */
		if (u_bufLen >= 2) {
			i_cipSpecListLen = (*pc_cipSpecList * 256 + *(pc_cipSpecList + 1));
			l_inc = 2;
			l_start = 2;
			pc_ret = pc_cipSpecList + i_cipSpecListLen + 2;

			if (pc_ret > pc_cipSpecList + u_bufLen) {
				/* list pretends to be longer than buffer */
				i_cipSpecListLen = 0;
				l_inc = 0;
				l_start = 0;

				/* point to the end of the buffer */
				pc_ret = pc_cipSpecList + u_bufLen;
			}

		} else {
			/* invalid list provided => don't process it */
			i_cipSpecListLen = 0;
			l_inc = 0;
			l_start = 0;

			/* point to the end of the buffer */
			pc_ret = pc_cipSpecList + u_bufLen;
		}
	} else {
		/*
		 * | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 ...
		 * |    CS1    |    CS2    |    CS3    ...
		 *       ^ start
		 *       x-   inc   -x-   inc   -x
		 */
		l_inc = 3;
		l_start = 1;
	}

	for (i = 0;
			(i < SSL_CIPSPEC_COUNT) && (*pe_selCip == TLS_NULL_WITH_NULL_NULL);
			i++) {
		j = l_start;

		/* iterate through list of cipher suites present in Hello message */
		for (; j < i_cipSpecListLen + l_start - 1; j += l_inc) {

			/*
			 * Read cipherSpec
			 * Declare here as this is a for scope
			 */
			e_sslCipSpec_t cipherSpec = (e_sslCipSpec_t) ssl_readInteger(
					&(pc_cipSpecList[j]), 2);

			/*
			 * Check if version is greater than SSL2.0,
			 * renegotiation must be enabled
			 * and the TLS_EMPTY_RENEGOTIATION_INFO_SCSV has been received
			 */
			if ((ps_sslCtx->c_isRenegOn == TRUE)
					&& (cipherSpec == TLS_EMPTY_RENEGOTIATION_INFO_SCSV)) {
				/* [RFC5746] 3.7.  Server Behavior: Secure Renegotiation
				 *
				 *    o  When a ClientHello is received, the server MUST verify that it
				 *       does not contain the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.  If
				 *       the SCSV is present, the server MUST abort the handshake.
				 */
				if (ps_sslCtx->c_secReneg == TRUE) {
					pc_ret = NULL;
					break;
				} /* if */
				/* [RFC5746] 3.6.  Server Behavior: Initial Handshake
				 *
				 *    o  When a ClientHello is received, the server MUST check if it
				 *       includes the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.  If it does,
				 *       set the c_secureReneg flag to TRUE.
				 */
				else {
					c_secureReneg = TRUE;
				} /* else */
			}
			/*
			 * Remember the first and only the first mutual cipherSpec
			 */
			else if ((cipherSpec == ps_sslGuts->ae_cipSpecs[i])
					&& (*pe_selCip == TLS_NULL_WITH_NULL_NULL)
					&& (ps_sslGuts->ae_cipSpecs[i] != TLS_NULL_WITH_NULL_NULL)) // vpy: do not choose TLS NULL... as it's not really a cipher suite
					{
				*pe_selCip = cipherSpec;
			}/* if */
		}/* for */
	} /* for */
	/*
	 * Remember the c_secureReneg indication and set the parameters only
	 * if all is fine or if we've processed a SSLv2 ClientHello
	 */
	if ((pc_ret != NULL) || (l_inc == 3)) {
		ps_sslCtx->c_secReneg = c_secureReneg;
		loc_setSecParams(ps_sslCtx, *pe_selCip);
		if (ps_sslCtx->e_ver == E_TLS_1_2) {
			ps_sslCtx->s_secParams.s_signAlg.c_hash = en_gciHashAlgo_SHA1;
		} else {
			/* For all other versions it's assumed that sha1 + md5 are
			 * supported */
			ps_sslCtx->s_secParams.s_signAlg.c_hash = en_gciHashAlgo_Invalid;
		}
	}
	/*
	 * Otherwise restore the old pendingCipher
	 */
	else {
		*pe_selCip = pe_oldPendCip;
	}

	return pc_ret;
} /* loc_matchCipherSpec() */

//vpy: this function is only called from loc_protocolHand, when a Client Hello message is received
static int32_t loc_processExtens(s_sslCtx_t* ps_sslCtx, uint8_t* pc_extsStart,
		uint8_t* pc_hsEnd) {
	e_tlsExt_t e_curExt;
	uint8_t* pc_curExt;
	int32_t l_curExtLen;
	size_t l_extsLen;

	s_sslGut_t* ps_g;
	uint8_t b_isCli;
	int8_t c_ret = 0;

	assert(ps_sslCtx != NULL);
	assert(pc_extsStart != NULL);
	assert(pc_hsEnd != NULL);

	ps_g = &ps_sslCtx->s_sslGut;
	b_isCli = ps_sslCtx->b_isCli;
	pc_curExt = pc_extsStart;

	en_gciResult_t err;
	/*
	 * Read length field indicating total extension length
	 */
	l_extsLen = (int32_t) ssl_readInteger(pc_curExt, 2);
	/* 2 bytes for length field*/
	pc_curExt += 2;

	if ((pc_extsStart + l_extsLen + 2) > pc_hsEnd) {
		LOG_ERR(
				"Extensions are longer (%zu) than remaining " "handshake length (%i)",
				l_extsLen, (pc_hsEnd - pc_extsStart));
		c_ret = -1;
	} /* if */

	while ((pc_curExt < pc_hsEnd) && (c_ret >= 0)) {
		/*
		 * Read the current extension.
		 */
		e_curExt = (e_tlsExt_t) ssl_readInteger(pc_curExt, 2);
		pc_curExt += 2;

		/*
		 * Read its length
		 */
		l_curExtLen = (int32_t) ssl_readInteger(pc_curExt, 2);
		pc_curExt += 2;

		/* make sure the extension is not longer
		 * than the total list of extensions */
		if (pc_curExt + l_curExtLen > pc_extsStart + l_extsLen + 2) {
			LOG_ERR("Extension is longer than total list of extensions");
			c_ret = -1;
			break;
		}

		switch (e_curExt) {
		case TLS_EXTENSION_RENEGOTIATION_INFO: {
			/* Last verified data length sent in finished message */
			int32_t l_lvdLen;

			LOG1_INFO("Processing extension %s with length %i",
					sslDiag_getExtension(e_curExt), l_curExtLen);
			/* Everything is ok */
			c_ret = 1;

			l_lvdLen = ps_g->c_verifyDataLen;

			/*
			 * Check if this is not an initial handshake
			 */
			if ((!b_isCli && (ps_g->e_rxCipSpec == TLS_UNDEFINED))
					|| (b_isCli && (ps_g->e_txCipSpec == TLS_UNDEFINED))) {
				/*
				 * This is an initial handshake, so the extension MUST be
				 * empty, otherwise the handshake must be canceled
				 */
				if ((l_curExtLen != 1) || (*pc_curExt != 0)) {
					c_ret = -4;
				}/* if */
			}
			/* So this is a re-negotiation */
			else {
				if ((!b_isCli && (*pc_curExt != l_lvdLen))
						|| (b_isCli && (*pc_curExt != (l_lvdLen * 2)))) {
					/*
					 * Length was not OK
					 */
					c_ret = -3;
				} else {
					/*
					 * Check if the first part of the
					 * "renegotiated_connection"part is OK
					 */
					if (memcmp(pc_curExt + 1, ps_g->ac_cliVerifyData, l_lvdLen)
							!= 0) {
						/*
						 * First part was not OK
						 */
						c_ret = -1;
					}
					/*
					 * If this is a client, verify the second part of the
					 * "renegotiated_connection" part
					 */
					else if (ps_sslCtx->b_isCli == TRUE) {
						/*
						 * Check if the second part of the "renegotiated_connection" part is OK
						 */
						if (memcmp(pc_curExt + 1 + l_lvdLen,
								ps_g->ac_srvVerifyData, l_lvdLen) != 0) {
							/*
							 * Second part was not OK
							 */
							c_ret = -2;
						} /* if */
					} /* else if */
				}
			}

			/*
			 * Set c_secureReneg indication
			 */
			if (c_ret < 0) {
				ps_sslCtx->c_secReneg = FALSE;
			} else {
				ps_sslCtx->c_secReneg = TRUE;
			}
		}
			break;

		case TLS_EXTENSION_SIGNATURE_ALGORITHMS: {
			/* Clients MUST NOT offer it if they are offering prior versions.
			 However, even if clients do offer it, the rules specified
			 require servers to ignore extensions they do not understand.
			 */
			LOG1_INFO("Processing extension %s with length %i",
					sslDiag_getExtension(e_curExt), l_curExtLen);

			if (ps_sslCtx->e_ver > E_TLS_1_1) {
				uint16_t i_tmpLen;
				i_tmpLen = ssl_readInteger(pc_curExt, 2);
				/*
				 * According to RFC5246 4.3. Vectors ( Variable-length vectors)
				 */
				if (i_tmpLen == (l_curExtLen - 2)) {
					pc_curExt += 2;
					l_curExtLen -= 2;
					/* Parse and process signature_algorithms extension */
					c_ret = loc_procExtSignAlg(ps_sslCtx, pc_curExt,
							l_curExtLen);
				} else {
					/*
					 * Length was not OK
					 */
					c_ret = -3;
				}
			}
			break;
		}

		case TLS_EXTENSION_ELLIPTIC_CURVES: //vpy

			LOG1_INFO("Processing extension %s with length %i",
					sslDiag_getExtension(e_curExt), l_curExtLen);
			//TODO vpy: in a function
			//example: c_ret = processExt_EllipticCurves(...);

			if (ps_sslCtx->e_ver == E_TLS_1_2) {
				uint16_t i_tmpLen;
				uint16_t i_tmpCurve;
				ps_sslCtx->s_secParams.eccChoosenCurve = 0xFFFF;

				//get locally supported curves
				size_t numberOfCurves;
				uint16_t supportedCurves[25]; //RFC 4492 5.1.1: Officially 25 curves are supported - It was an uint16_t

				//OLD-CW: numberOfCurves = cw_ecc_getSupportedCurves(supportedCurves);
				err = gciGetInfo(en_gciInfo_CurveName, supportedCurves,
						&numberOfCurves);
				if (err != en_gciResult_Ok) {
					//TODO return an error
				}

				//get number of proposed curves
				i_tmpLen = ssl_readInteger(pc_curExt, 2) / 2; //one curve is 2 bytes, so number of curves is the half of the length
				pc_curExt += 2;
				l_curExtLen -= 2;

				//loop for each proposed curve
				int i;
				for (i = 0; i < i_tmpLen; i++) {
					//read curve i
					i_tmpCurve = ssl_readInteger(pc_curExt, 2);
					pc_curExt += 2;
					l_curExtLen -= 2;

					//loop the curves supported locally
					uint8_t j;
					for (j = 0;
							(j < numberOfCurves
									&& ps_sslCtx->s_secParams.eccChoosenCurve
											== 0xFFFF); j++) {
						//If a correspondance is found, store and break, because we want the first correspondance between peers
						if (i_tmpCurve == supportedCurves[j]) {
							ps_sslCtx->s_secParams.eccChoosenCurve = i_tmpCurve;
						}
					}
				}

				//If no matching curves, remove ECDHE from list of supported cipher suites
				if (ps_sslCtx->s_secParams.eccChoosenCurve == 0xFFFF) {
					int i = 0;
					//loop all cipher suites provided
					for (i = 0; i < SSL_CIPSPEC_COUNT; i++) {
						switch (ps_g->ae_cipSpecs[i]) {
						case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
						case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
						case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
						case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
						case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
						case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
							//remove every ECDHE curve
							ps_g->ae_cipSpecs[i] = TLS_NULL_WITH_NULL_NULL;
							break;
						default:
							break;
						}
					}
				}
			}
			c_ret = 0;
			break;

		case TLS_EXTENSION_EC_POINT_FORMATS: //vpy

			LOG1_INFO("Processing extension %s with length %i",
					sslDiag_getExtension(e_curExt), l_curExtLen);

			// uncompressed point only is supported
			//Normally, uncompressed point MUST be proposed and supported by all peers
			//TODO vpy: in a function
			//example: c_ret = processExt_ECPointFormats(...);
			if (ps_sslCtx->e_ver == E_TLS_1_2) {
				uint16_t i_tmpLen;

				//Read number (length) of point formats are transmitted
				i_tmpLen = ssl_readInteger(pc_curExt, 1);
				pc_curExt++;
				l_curExtLen--;

				uint8_t format_ok = 0;
				if (i_tmpLen == l_curExtLen) {
					int i;
					//loop for all point formats
					for (i = 0; i < i_tmpLen; i++) {
						//if uncompressed point format is transmitted, continue
						if (pc_curExt[i] == 0) {
							format_ok = 1;
						}
					}
					if (format_ok != 1) {
						//Uncompressed format not supported, remove all ECC cipher suites
						for (i = 0; i < SSL_CIPSPEC_COUNT; i++) {
							switch (ps_g->ae_cipSpecs[i]) {
							case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
							case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
							case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
							case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
							case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
							case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
								ps_g->ae_cipSpecs[i] = TLS_NULL_WITH_NULL_NULL;
								break;
							default:
								break;
							}
						}
					}
					c_ret = 0;
				} else {
					/*
					 * Length was not OK
					 */
					c_ret = -1;
				}
			}
			break;

		default:
			LOG1_INFO("Extension %s with length %i has been ignored",
					sslDiag_getExtension(e_curExt), l_curExtLen);
			c_ret = 0;
			break;
		}

		if (c_ret >= 0) {
			/* jump over current extension */
			pc_curExt += l_curExtLen;
		}

	}

	return c_ret;
} /* loc_processExtens() */

/*
 * Parse and process signature_algorithms extension
 */
static int32_t loc_procExtSignAlg(s_sslCtx_t* ps_sslCtx, uint8_t* pc_ext,
		uint32_t l_len) {
	/* Change return variable to a positive value only in specific cases */
	int8_t c_ret = -1;
	uint8_t c_curHash;
	uint8_t c_curSign;
	uint8_t i;
	/* Variable to store signature and hash algorithm */

	assert(ps_sslCtx != NULL);
	assert(pc_ext != NULL);

	LOG1_INFO("Processing extension %s with length %i",
			sslDiag_getExtension(TLS_EXTENSION_SIGNATURE_ALGORITHMS), l_len);

	while (l_len >= 2) {
		c_curHash = (uint8_t) (ssl_readInteger(pc_ext, 2) >> 8);
		c_curSign = (uint8_t) (ssl_readInteger(pc_ext, 2) & 0xFF);
		LOG2_INFO("Extension proposed %s and %s pair)",
				sslDiag_getHashAlg(c_curHash), sslDiag_getSignAlg(c_curSign));

		/* TODO: ADD DSA ECDSA signatures support */
		if (ps_sslCtx->b_isCli) {
			for (i = 0; i < SSL_MAX_EXTS; i++) {
				/* According to TLS 1.2 specification. Check if we previously
				 * signature algorithms extension */
				if (ps_sslCtx->ps_hsElem->pe_reqExts[i]
						== TLS_EXTENSION_SIGNATURE_ALGORITHMS) {
					ps_sslCtx->s_secParams.s_signAlg.c_hash = c_curHash;
					ps_sslCtx->s_secParams.s_signAlg.c_sign = c_curSign;
					c_ret = 1;
					l_len = 2;
				}
			}
		} else {
			/* This is smth related to an embedded implementation as we agreed to
			 * work with only one given signature type in a given certificate and
			 * if received HELLO EXTENSIO doesn't have this pair we have to reject
			 * the connection*/
			/* TODO TLS 1.2 Should we ignore ANON signature or send an alert? */
			if ((ps_sslCtx->ps_sslSett->s_certSignHashAlg.c_sign == c_curSign)
					&& (ps_sslCtx->ps_sslSett->s_certSignHashAlg.c_hash
							== c_curHash) && (c_curSign != en_gciSignAlgo_None)) {
				ps_sslCtx->s_secParams.s_signAlg.c_hash = c_curHash;
				ps_sslCtx->s_secParams.s_signAlg.c_sign = c_curSign;

				/* We also need to store sign hash algorithm in session element */
				ps_sslCtx->ps_hsElem->s_sessElem.s_signAlg.c_hash = c_curHash;
				ps_sslCtx->ps_hsElem->s_sessElem.s_signAlg.c_sign = c_curSign;

				LOG_INFO("Hash %s and signature %s algorithms are selected",
						sslDiag_getHashAlg(c_curHash),
						sslDiag_getSignAlg(c_curSign));
				l_len = 2;
				c_ret = 1;
			} else {
				LOG2_WARN("Hash %s and signature %s algorithms are't supported",
						sslDiag_getHashAlg(c_curHash),
						sslDiag_getSignAlg(c_curSign));
			}
		}
		/* move to next combination */
		pc_ext += 2;
		l_len -= 2;
	}

	return c_ret;
}

static uint8_t* loc_appendExtens(s_sslCtx_t* ps_sslCtx, uint8_t* pc_in) {
	uint8_t* pc_out = NULL;
	uint8_t* pc_outStamp = NULL;
	int32_t l_outLen = 0;
	uint16_t i_extType = 0;

	en_gciResult_t err;

	assert(ps_sslCtx != NULL);
	assert(pc_in != NULL);

	if (ps_sslCtx->b_isCli) //is client ?
	{
		/*
		 * Jump over extensions length field
		 */
		pc_out = pc_in + 2;

		if ((ps_sslCtx->c_isRenegOn == TRUE)
				&& (ps_sslCtx->c_secReneg == TRUE)) {

			/*
			 * Add the extension type
			 */
			i_extType = TLS_EXTENSION_RENEGOTIATION_INFO;
			ssl_writeInteger(pc_out, i_extType, 2);
			pc_out += 2;

			/*
			 * Check if this is an initial handshake
			 */
			if (((ps_sslCtx->b_isCli == FALSE)
					&& (ps_sslCtx->s_sslGut.e_rxCipSpec == TLS_UNDEFINED))
					|| ((ps_sslCtx->b_isCli == TRUE)
							&& (ps_sslCtx->s_sslGut.e_txCipSpec == TLS_UNDEFINED))) {
				/*
				 * It is an initial handshake, so add an empty renegotiation_info extension
				 */
				*pc_out++ = 0x00;
				*pc_out++ = 0x01;
				*pc_out++ = 0x00;
			} /* if */
			else {
				/*
				 * Save original start address
				 * and increment write pointer by 3 =>
				 *  2 bytes of total extension length + 1 byte of "renegotiated_connection" length
				 */
				pc_outStamp = pc_out;
				pc_out += 3;
				l_outLen = ps_sslCtx->s_sslGut.c_verifyDataLen;
				/*
				 * At first copy the client verify data and increment the write pointer
				 */
				memcpy(pc_out, &ps_sslCtx->s_sslGut.ac_cliVerifyData[0],
						l_outLen);
				pc_out += l_outLen;
				/*
				 * Check if we're a server
				 */
				if (ps_sslCtx->b_isCli == FALSE) {
					/*
					 * We're a server so append the server verify data as well and
					 * increment the write pointer
					 */
					memcpy(pc_out, &ps_sslCtx->s_sslGut.ac_srvVerifyData[0],
							l_outLen);
					pc_out += l_outLen;
					/*
					 * Double the effective length
					 */
					l_outLen += l_outLen;
				}
				/*
				 * Generate the total extension length as:
				 * "renegotiated_connection" length field (1b) +
				 * "renegotiated_connection" length (12/24/36/72 bytes)
				 */
				ssl_writeInteger(pc_outStamp, (l_outLen + 1), 2);
				/*
				 * Add the "renegotiated_connection" length field
				 */
				*(pc_outStamp + 2) = (uint8_t) l_outLen;
			} /* else */
		} /* if */

		if ((ps_sslCtx->e_ver == E_TLS_1_2)
				&& (ps_sslCtx->ps_sslSett->s_certSignHashAlg.c_sign
						!= en_gciSignAlgo_Invalid)
				&& (ps_sslCtx->ps_sslSett->s_certSignHashAlg.c_hash
						!= en_gciHashAlgo_Invalid)) {
			uint16_t i_signHashAlg;
			uint8_t i;
			uint8_t c_hash = en_gciHashAlgo_Invalid;
			uint8_t c_sign = en_gciSignAlgo_Invalid;
			/*
			 * Add the extension type
			 */
			i_extType = TLS_EXTENSION_SIGNATURE_ALGORITHMS;
			ssl_writeInteger(pc_out, i_extType, 2);
			pc_out += 2;

			/*
			 * Save original start address
			 * and jump over length field which will be filled later
			 * According to RFC5246 4.3. Vectors
			 * Variable-length vectors are defined by specifying a subrange of legal
			 * lengths, inclusively, using the notation <floor..ceiling>. When
			 * these are encoded, the actual length precedes the vector’s contents
			 * in the byte stream.
			 */
			pc_outStamp = pc_out;
			pc_out += 4;

			for (i = 0; i < (sizeof(rai_tlsSHAlgs) / sizeof(rai_tlsSHAlgs[0]));
					i++) {
				i_signHashAlg = rai_tlsSHAlgs[i];
				ssl_writeInteger(pc_out, i_signHashAlg, 2);
				pc_out += 2;
				l_outLen += 2;
			}

			/*
			 * Generate the total extension length
			 */
			ssl_writeInteger(pc_outStamp + 2, l_outLen, 2);
			ssl_writeInteger(pc_outStamp, l_outLen + 2, 2);
		}

		//VPY begin
		//TLS_EXTENSION_ELLIPTIC_CURVES
		//Extension is appended only if TLS1.2 and if there is a ECC cipher suite
		if ((ps_sslCtx->e_ver == E_TLS_1_2)) {
			uint8_t i;
			char isECCPresent = 0;
			for (i = 0; i < SSL_CIPSPEC_COUNT; i++) {
				if ((ps_sslCtx->s_sslGut.ae_cipSpecs[i]
						== TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)) {
					isECCPresent = 1;
				}
			}

			if (isECCPresent == 1) {
				/*
				 * Add the extension type
				 */
				i_extType = TLS_EXTENSION_ELLIPTIC_CURVES;
				ssl_writeInteger(pc_out, i_extType, 2);
				pc_out += 2;

				//Store value of pointer to write length of extension at the end
				pc_outStamp = pc_out;
				pc_out += 4;

				//Reset extension length
				l_outLen = 0;

				uint16_t supportedCurves[25]; //RFC 4492, 5.1.1: Officially supported: 25 curves uint16_t
				//OLD-CW: uint8_t numberOfCurves = cw_ecc_getSupportedCurves(supportedCurves);
				size_t numberOfCurves;
				err = gciGetInfo(en_gciInfo_CurveName, supportedCurves,
						&numberOfCurves);
				uint8_t i;
				for (i = 0; i < numberOfCurves; i++) {
					ssl_writeInteger(pc_out, supportedCurves[i], 2);
					pc_out += 2;
					l_outLen += 2;
				}

				/*
				 * Generate the extension length
				 */
				ssl_writeInteger(pc_outStamp, l_outLen + 2, 2); //Length
				ssl_writeInteger(pc_outStamp + 2, l_outLen, 2); //Eliptic curves length
			}
		}

		//TLS_EXTENSION_EC_POINT_FORMATS
		//Extension is appended only if TLS1.2 and if there is a ECC cipher suite
		if (ps_sslCtx->e_ver == E_TLS_1_2) {
			uint8_t i;
			char isECCPresent = 0;
			for (i = 0; i < SSL_CIPSPEC_COUNT; i++) {
				if ((ps_sslCtx->s_sslGut.ae_cipSpecs[i]
						== TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.ae_cipSpecs[i]
								== TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)) {
					isECCPresent = 1;
				}
			}

			if (isECCPresent == 1) {
				/*
				 * Add the extension type
				 */
				i_extType = TLS_EXTENSION_EC_POINT_FORMATS;
				ssl_writeInteger(pc_out, i_extType, 2);
				pc_out += 2;

				//Store value of pointer to write length of extension at the end
				pc_outStamp = pc_out;
				pc_out += 3;

				//Reset extension length
				l_outLen = 0;

				//Only uncompressed format is supported
				l_outLen = 1;
				ssl_writeInteger(pc_out, 0, 1);
				pc_out += 1;
				/*
				 * Generate the extension length
				 */
				ssl_writeInteger(pc_outStamp, l_outLen + 1, 2); //Length
				ssl_writeInteger(pc_outStamp + 2, l_outLen, 1); //Ec points format length
			}
		}
		//VPY end

		/*
		 * If an extension has been added, insert the length
		 */
		if (pc_out != (pc_in + 2)) {
			ssl_writeInteger(pc_in, (pc_out - pc_in) - 2, 2);
		} /* if */
		else {
			pc_out = pc_in;
		} /* else */

		return pc_out;
	} else //is server
	{
		/*
		 * Jump over extensions length field
		 */
		pc_out = pc_in + 2;

		//		vpy: Commented because it was implemented before, but the function doesn't look like to be called when generation a Server Hello.
		//		//TLS_EXTENSION_SIGNATURE_ALGORITHMS
		//		if ((ps_sslCtx->e_ver == E_TLS_1_2) &&
		//				(ps_sslCtx->ps_sslSett->s_certSignHashAlg.c_sign != GCI_SIGN_INVALID) &&
		//				(ps_sslCtx->ps_sslSett->s_certSignHashAlg.c_hash != E_SSL_HASH_INVALID))
		//		{
		//			uint16_t    i_signHashAlg;
		//			uint8_t     i;
		//			uint8_t     c_hash = E_SSL_HASH_INVALID;
		//			uint8_t     c_sign = GCI_SIGN_INVALID;
		//			/*
		//			 * Add the extension type
		//			 */
		//			i_extType = TLS_EXTENSION_SIGNATURE_ALGORITHMS;
		//			ssl_writeInteger(pc_out, i_extType, 2);
		//			pc_out+=2;
		//
		//			/*
		//			 * Save original start address
		//			 * and jump over length field which will be filled later
		//			 * According to RFC5246 4.3. Vectors
		//			 * Variable-length vectors are defined by specifying a subrange of legal
		//			 * lengths, inclusively, using the notation <floor..ceiling>. When
		//			 * these are encoded, the actual length precedes the vector’s contents
		//			 * in the byte stream.
		//			 */
		//			pc_outStamp = pc_out;
		//			pc_out+=4;
		//
		//			c_hash = ps_sslCtx->s_secParams.s_signAlg.c_hash;
		//			c_sign = ps_sslCtx->s_secParams.s_signAlg.c_sign;
		//			i_signHashAlg = (c_hash << 8) + (c_sign & 0xFF);
		//			ssl_writeInteger(pc_out, i_signHashAlg, 2);
		//			pc_out+=2;
		//			l_outLen+=2;
		//
		//			/*
		//			 * Generate the total extension length
		//			 */
		//			ssl_writeInteger(pc_outStamp+2, l_outLen, 2);
		//			ssl_writeInteger(pc_outStamp, l_outLen+2, 2);
		//		}

		//begin vpy
		//TLS_EXTENSION_EC_POINT_FORMATS
		//Extension is appened only if TLS1.2
		if ((ps_sslCtx->e_ver == E_TLS_1_2)
				&& ((ps_sslCtx->s_sslGut.e_pendCipSpec
						== TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.e_pendCipSpec
								== TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.e_pendCipSpec
								== TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.e_pendCipSpec
								== TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.e_pendCipSpec
								== TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
						|| (ps_sslCtx->s_sslGut.e_pendCipSpec
								== TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA))) {
			/*
			 * Add the extension type
			 */
			i_extType = TLS_EXTENSION_EC_POINT_FORMATS;
			ssl_writeInteger(pc_out, i_extType, 2);
			pc_out += 2;

			//Store value of pointer to write length of extension at the end
			pc_outStamp = pc_out;
			pc_out += 3;

			//Reset extension length
			l_outLen = 0;

			//Only uncompressed format is supported
			l_outLen = 1;
			ssl_writeInteger(pc_out, 0, 1);
			pc_out += 1;
			/*
			 * Generate the extension length
			 */
			ssl_writeInteger(pc_outStamp, l_outLen + 1, 2); //Length
			ssl_writeInteger(pc_outStamp + 2, l_outLen, 1); //Ec points format length
		}
		//end vpy

		/*
		 * If an extension has been added, insert the length
		 */
		if (pc_out != (pc_in + 2)) {
			ssl_writeInteger(pc_in, (pc_out - pc_in) - 2, 2);
		} /* if */
		else {
			pc_out = pc_in;
		} /* else */

		return pc_out;
	}
} /* loc_appendExtens() */

/***************************************************************************
 * Builds the 5 bytes long record header
 ***************************************************************************/

static int loc_buildRecordHeader(s_sslCtx_t * ps_sslCtx, uint8_t *pc_rec,
		size_t cwt_recLen, uint8_t c_recType) {
	assert(ps_sslCtx != NULL);
	assert(pc_rec != NULL);

	/* Setup of the 5 byte long header structure */
	pc_rec[0] = c_recType;

	if ((ps_sslCtx->e_ver >= SSL_MIN_SSL_TLS_VERSION_SUPPORTED)
			&& (ps_sslCtx->e_ver <= SSL_MAX_SSL_TLS_VERSION_SUPPORTED)) {
		pc_rec[1] = SSL_VERSION_GET_MAJ(ps_sslCtx->e_ver);
		pc_rec[2] = SSL_VERSION_GET_MIN(ps_sslCtx->e_ver);
	} else {
		LOG_ERR("Version %i.%i is not supported, so we default to %s",
				SSL_VERSION_GET_MAJ(ps_sslCtx->e_ver),
				SSL_VERSION_GET_MIN(ps_sslCtx->e_ver),
				sslDiag_getVersion(SSL_DEFAULT_SSL_TLS_VERSION));
		/*
		 * default to version SSL_DEFAULT_SSL_TLS_VERSION
		 */
		pc_rec[1] = SSL_VERSION_GET_MAJ(SSL_DEFAULT_SSL_TLS_VERSION);
		pc_rec[2] = SSL_VERSION_GET_MIN(SSL_DEFAULT_SSL_TLS_VERSION);
		ps_sslCtx->e_ver = SSL_DEFAULT_SSL_TLS_VERSION;
	}

	(void) ssl_writeInteger(&pc_rec[3], cwt_recLen, 2);

	return E_SSL_OK;
}

/* *********************************************************************** */
/* *********************************************************************** */
/* TG */
void ssl_destroyKeys(s_sslCtx_t * ps_sslCtx) {
	/* Generates a MacError, at least at next receive operation */
	/* It is not easy to destroy the encryption keys */
	sslConf_rand((uint8_t*) &ps_sslCtx->s_secParams.ac_cliSecret,
			sizeof(ps_sslCtx->s_secParams.ac_cliSecret));
	sslConf_rand((uint8_t*) &ps_sslCtx->s_secParams.ac_srvSecret,
			sizeof(ps_sslCtx->s_secParams.ac_srvSecret));
	sslConf_rand((uint8_t*) &ps_sslCtx->s_secParams.u_cliKey,
			sizeof(ps_sslCtx->s_secParams.u_cliKey));
	sslConf_rand((uint8_t*) &ps_sslCtx->s_secParams.u_srvKey,
			sizeof(ps_sslCtx->s_secParams.u_srvKey));
	km_dhe_releaseKey();
	//OLD-CW: ps_sslCtx->s_secParams.pgci_dheKey = NULL;
	ps_sslCtx->s_secParams.dheCtx = -1;
	LOG_INFO("!!!!!!!!!!!!s_secParams have been destroyed!!!!!!!!!!!!");
}

/* *********************************************************************** */
/* *********************************************************************** */

static e_sslPendAct_t loc_protocolResp(s_sslCtx_t * ps_sslCtx, uint8_t *pc_rec,
		size_t *pcwt_recLen, uint8_t *pc_inData, size_t cwt_inDataLen) {
	/* What should be done on next step */
	e_sslPendAct_t e_pendAct;
	uint8_t *pc_write;
	uint32_t cnt;
	uint32_t l_blockLen;
	uint32_t i;
	size_t cwt_hashLen;
	s_sslGut_t *ps_sslGut;
	s_sslHsElem_t *ps_hsElem;
	s_sslSecParams_t *ps_secPar;
	size_t cwt_exportLen;
	e_sslResult_t e_ret = E_SSL_OK;

	en_gciResult_t err;
	st_gciDhConfig_t dhConf;
	GciCtxId_t dhCtx;

	st_gciDhConfig_t ecdhConf;
	GciCtxId_t ecdhCtx;

	st_gciKey_t dhCliPubKey = { .type = en_gciKeyType_DhPub };
	st_gciKey_t dhSrvPubKey = { .type = en_gciKeyType_DhPub };
	st_gciKey_t dhSecretKey = { .type = en_gciKeyType_DhSecret };

	st_gciKey_t ecdhCliPubKey = { .type = en_gciKeyType_EcdhPub };
	st_gciKey_t ecdhSrvPubKey = { .type = en_gciKeyType_EcdhPub };
	st_gciKey_t ecdhSecretKey = { .type = en_gciKeyType_EcdhSecret };

	/* used as temporary storage for various
	 * labels (e.g. client finished, ...) */
	const uint8_t* lbl;

	assert(ps_sslCtx != NULL);
	assert(pc_rec != NULL);
	assert(pcwt_recLen != NULL);
	assert(pc_inData != NULL);

	ps_sslGut = &ps_sslCtx->s_sslGut;
	ps_hsElem = ps_sslCtx->ps_hsElem;
	ps_secPar = &ps_sslCtx->s_secParams;

	ps_sslGut->e_recordType = E_SSL_RT_HANDSHAKE;
	e_pendAct = E_PENDACT_MAC_ENCRYPT_HANDSHAKE;
	pc_write = pc_rec;
	cwt_hashLen = 0;
	l_blockLen = 0;
	LOG1_INFO("%p| ProtRespGen State: %s ASM: %s", ps_sslCtx,
			sslDiag_getSMState(ps_sslGut->e_smState),
			sslDiag_getAssembly(ps_sslGut->e_asmCtrl));
	switch (ps_sslGut->e_smState) {
	case E_SSL_SM_SEND_WARN_ALERT:
	case E_SSL_SM_SEND_FATAL_ALERT:
		/* Hashlen is 0 (only handshakes are included in the handshake    */
		LOG1_INFO("%p| Sending %s %s Alert", ps_sslCtx,
				(ps_sslGut->e_smState == E_SSL_SM_SEND_FATAL_ALERT) ?
						"fatal" : "warning",
				sslDiag_getAlert(ps_sslGut->e_alertType));
		/* hashes */
		ps_sslGut->e_recordType = E_SSL_RT_ALERT;
		*pcwt_recLen = 2;

		if (ps_sslGut->e_smState == E_SSL_SM_SEND_FATAL_ALERT) {
			pc_rec[0] = FATAL; /* Fatal Error */
			ps_sslCtx->c_isResumed = FALSE;
		} else {
			pc_rec[0] = WARNING; /* Warning alert */
		}

		switch (ps_sslGut->e_asmCtrl) {
		case E_SSL_ASM_START:
			pc_rec[1] = ps_sslGut->e_alertType;
			ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;
			if (ps_sslGut->e_alertType == E_SSL_ALERT_CLOSE_NOTIFY) {
				ps_sslGut->e_smState = E_SSL_SM_SHUTDOWN_COMPLETE;
			}
			break;

		case E_SSL_ASM_STEP1:
			pc_rec[1] = E_SSL_ALERT_CLOSE_NOTIFY; /* Close notify */
			ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;
			break;
		case E_SSL_ASM_STEP2:
		case E_SSL_ASM_STEP3:
		case E_SSL_ASM_STEP4:
		case E_SSL_ASM_FINISH:
		default:
			break;
		}

		e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;
		break;
		/*
		 * Only required for a client implementation
		 */
	case E_SSL_SM_SEND_CLIENT_HELLO:
		switch (ps_sslGut->e_asmCtrl) {
		case E_SSL_ASM_START:
			LOG1_INFO("%p| SEND_CLIENT_HELLO ASM_START (ClientHello)",
					ps_sslCtx);

			ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP1;
			e_pendAct = E_PENDACT_SCACHE_FIND;
			break;

		case E_SSL_ASM_STEP1:
			LOG1_INFO("%p| SEND_CLIENT_HELLO ASM_STEP1 (ClientHello)",
					ps_sslCtx);
			memcpy(pc_rec, (void*) rac_cliHello, sizeof(rac_cliHello));
			pc_write = pc_rec + sizeof(rac_cliHello);

			if (ps_sslCtx->c_isResumed == TRUE) {
				ps_sslCtx->e_ver = ps_hsElem->s_sessElem.e_lastUsedVer;
			} else if (ps_sslCtx->e_ver == E_VER_DCARE) {
				ps_sslCtx->e_ver = ps_sslCtx->ps_sslSett->e_maxVer;
			}

			*pc_write++ = SSL_VERSION_GET_MAJ(ps_sslCtx->e_ver);
			*pc_write++ = SSL_VERSION_GET_MIN(ps_sslCtx->e_ver);

			ps_hsElem->e_offerVer = ps_sslCtx->e_ver;

			loc_setDefPrf(ps_sslCtx);

			loc_hash(E_HASHOP_INIT, ps_sslCtx, NULL, 0);

			memcpy(pc_write, ps_hsElem->ac_cliRand, CLI_RANDSIZE);
			pc_write += CLI_RANDSIZE;

			/* The ID of a session the client wishes to use for this connection.
			 This field should be empty if no session_id is available or the
			 client wishes to generate new security parameters. */
			if (ps_sslCtx->c_isResumed == TRUE) {
				/* write length (size) of Session ID */
				*pc_write++ = SESSID_SIZE;
				/* write Session ID */
				memcpy(pc_write, ps_hsElem->s_sessElem.ac_id,
				SESSID_SIZE);
				pc_write += SESSID_SIZE;
			} else {
				/* Session ID of zero length */
				*pc_write++ = 0x00;
			}

			/*
			 * Add all supported Cipher Suites
			 */
			cnt = 2; /* jump over length */
			for (i = 0; i < SSL_CIPSPEC_COUNT; i++) {
				uint16_t cipSpec = ps_sslGut->ae_cipSpecs[i];
				if (cipSpec != TLS_NULL_WITH_NULL_NULL) {
					ssl_writeInteger(&pc_write[cnt], cipSpec, 2);
					cnt += 2;
				}
			}

			(void) ssl_writeInteger(pc_write, cnt - 2, 2);
			pc_write += cnt;

			*pc_write++ = 0x01; /* 1 compression method supported */
			*pc_write++ = 0x00; /* No compression */

			pc_write = loc_appendExtens(ps_sslCtx, pc_write);

			cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;
			(void) *ssl_writeInteger(pc_rec + 1, cwt_hashLen - HS_HEADERLEN, 3);
			ps_sslGut->e_recordType = E_SSL_RT_HANDSHAKE;
			ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;
			ps_sslGut->e_smState = E_SSL_SM_WAIT_SERVER_HELLO;
			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

			TIME_STAMP(TS_SENT_HS_CLIENT_HELLO);

			break;
		case E_SSL_ASM_STEP2:
		case E_SSL_ASM_STEP3:
		case E_SSL_ASM_STEP4:
		case E_SSL_ASM_FINISH:
		default:
			break;
		}

		break;

	case E_SSL_SM_SEND_SERVER_HELLO:

		switch (ps_sslGut->e_asmCtrl) {
		case E_SSL_ASM_START: /* Prepare Server Hello */

			LOG1_INFO("%p| SEND_SERVER_HELLO ASM_START (ServerHello)",
					ps_sslCtx);

			memcpy(pc_rec, (void*) rac_srvHello, sizeof(rac_srvHello));
			pc_write = pc_rec + sizeof(rac_srvHello);
			if (ps_sslCtx->e_ver == E_VER_DCARE) {
				/*
				 * This should never happen, since the version must have been
				 * set when the client hello was processed!
				 */
				LOG_ERR(
						"%p| Protocol version not set correctly, " "stop handshake here!",
						ps_sslCtx);
				ps_sslCtx->e_ver = SSL_DEFAULT_SSL_TLS_VERSION;
				ps_sslCtx->e_lastError = E_SSL_ERROR_SM;
				ps_sslGut->e_alertType = E_SSL_ALERT_HANDSH_FAIL;
				ps_sslGut->e_asmCtrl = E_SSL_ASM_START;
				ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
				return E_PENDACT_SEND_FATAL_ERROR;
			}
			*pc_write++ = SSL_VERSION_GET_MAJ(ps_sslCtx->e_ver);
			*pc_write++ = SSL_VERSION_GET_MIN(ps_sslCtx->e_ver);
			/* */

			/* ===============================================
			 Temporarily use stream of 0x12 as Server Random
			 (this was used for a quick proof-of-concept for an attack)
			 memset(ps_hsElem->ac_srvRand, 0x12, SRV_RANDSIZE);
			 ================================================== */

			memcpy(pc_write, ps_hsElem->ac_srvRand, SRV_RANDSIZE);
			pc_write += SRV_RANDSIZE;

			/* Insert length of the s_desc */
			*pc_write++ = SESSID_SIZE;
			memcpy(pc_write, ps_hsElem->s_sessElem.ac_id, SESSID_SIZE);

			pc_write += SESSID_SIZE;

			/* Now add the selected cipher suite */
			*pc_write++ = (ps_sslGut->e_pendCipSpec >> 8) & 0x0FF;
			*pc_write++ = ps_sslGut->e_pendCipSpec & 0x0FF;
			*pc_write++ = 0x00; /* No compression */

			pc_write = loc_appendExtens(ps_sslCtx, pc_write);

			/* Calculate length */
			cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;
			/*write length*/
			ssl_writeInteger(pc_rec + 1, cwt_hashLen - HS_HEADERLEN, 3);

			ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP1;
			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

			TIME_STAMP(TS_SENT_HS_SERVER_HELLO);

			break;

		case E_SSL_ASM_STEP1: {
			int iRet;
			LOG1_INFO("%p| SEND_SERVER_HELLO ASM_STEP1 (Certificate)",
					ps_sslCtx);
			memcpy(pc_rec, (void*) rac_cert, sizeof(rac_cert));
			pc_write = pc_rec + sizeof(rac_cert);

			cwt_hashLen = (size_t) (sizeof(ps_sslCtx->ac_socBuf)
					- ((size_t) pc_write - (size_t) ps_sslCtx->ac_socBuf));

			iRet = sslConf_getCertChain(
					ps_sslCtx->ps_sslSett->ps_certChainListHead, NULL, pc_write,
					&cwt_hashLen);
			if (iRet != E_SSL_OK) {
				if (iRet == E_SSL_ERROR) {
					ps_sslGut->e_alertType = E_SSL_ALERT_HANDSH_FAIL;
				} else if (iRet == E_SSL_LEN) {
					ps_sslGut->e_alertType = E_SSL_ALERT_REC_OFLOW;
				}
				ps_sslGut->e_asmCtrl = E_SSL_ASM_START;
				ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
				return (E_PENDACT_SEND_FATAL_ERROR);
			}

			pc_write += cwt_hashLen;

			(void) *ssl_writeInteger(pc_rec + 1, cwt_hashLen, 3);

			cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;

			switch (ps_secPar->e_kst) {
			case en_gciKeyPairType_RSA:
				/* Check if we need to authenticate the client */
				if ((ps_sslCtx->e_authLvl & ~E_SSL_MUST_VERF_SRVCERT)
						!= E_SSL_NO_AUTH) {
					ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP3;
				} else {
					/* We don't have to authenticate the client */
					ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP4;
				}
				break;
			case en_gciKeyPairType_DH:
			case en_gciKeyPairType_ECDH:
				ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP2;
				break;
			default:
				LOG_INFO("%p| Key share type is not supported", ps_sslCtx);
				ps_sslGut->e_asmCtrl = E_SSL_ASM_START;
				ps_sslGut->e_alertType = E_SSL_ALERT_HANDSH_FAIL;
				ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
				return (E_PENDACT_SEND_FATAL_ERROR);
			}

			TIME_STAMP(TS_SENT_HS_CERTIFICATE);

			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;
			break;
		}
		case E_SSL_ASM_STEP2: {
			LOG1_INFO("%p| SEND_SERVER_HELLO (SrvKeyExch)", ps_sslCtx);
			/* copy record header */
			memcpy(pc_rec, rac_srvKeyExch, sizeof(rac_srvKeyExch));
			/*! adjust write pointer */
			pc_write = pc_rec + sizeof(rac_srvKeyExch);

			//Server "chooses" the domain parameters
			switch (ps_secPar->e_kst) {
			case en_gciKeyPairType_ECDH:

				dhConf.type = en_gciDhType_Ecdh;
				//TODO sw - fix a curve intern

				err = gciDhNewCtx(&dhConf, &ps_secPar->eccCtx);
				if (err != en_gciResult_Ok) {
					//TODO return an error
				}

				err = gciDhGenKey(ps_secPar->eccCtx,
						ps_secPar->ecdhSrvPubKey);

				//OLD-CW: if(cw_ecc_makeKey(&(ps_secPar->eccKey), ps_secPar->eccChoosenCurve)!=CRYPT_OK)
				if (err != en_gciResult_Ok) {
					LOG_INFO("%p| Couldn't create new ECHE key", ps_sslCtx);
					return (E_PENDACT_COM_CIPHER_CLOSE);
				}

				//OLD-CW: ps_secPar->c_useEccKey = TRUE; //store the fact we used a ECC key, to be able to free it at the end!

				/*! calc bytes left in socketbuffer */
				cwt_exportLen = (sizeof(ps_sslCtx->ac_socBuf)
						- ((size_t) pc_write - (size_t) ps_sslCtx->ac_socBuf));

				/* export the formerly generated public ECDHE values */
				/*OLD-CW: if(cw_ecc_export_public((pc_write+4), &cwt_exportLen, &(ps_secPar->eccKey))!=CRYPT_OK)
				 {
				 LOG_INFO("%p| Couldn't export the ECHE key", ps_sslCtx);
				 return (E_PENDACT_COM_CIPHER_CLOSE);
				 }*/

				*pc_write++ = 0x03; //Named curve

				*pc_write++ = 0x00; //MSB name of curve
				*pc_write++ = ps_secPar->eccChoosenCurve; //LSB name of curve

				cwt_exportLen += 3; //Do not forget type, name and length of curve for global length

				//Get the big number of the server public key with his ID
				err = gciKeyGet(ps_secPar->ecdhSrvPubKey, &ecdhSrvPubKey);
				if (err != en_gciResult_Ok) {
					//return error state
				}

				//Add the length of the server public key
				*pc_write++ = ecdhSrvPubKey.un_key.keyEcdhPub.coord.x.len
						+ ecdhSrvPubKey.un_key.keyEcdhPub.coord.y.len;

				cwt_exportLen++;

				//Add the x-coordinate of the server public key
				memcpy(pc_write, ecdhSrvPubKey.un_key.keyEcdhPub.coord.x.data,
						ecdhSrvPubKey.un_key.keyEcdhPub.coord.x.len);

				cwt_exportLen += ecdhSrvPubKey.un_key.keyEcdhPub.coord.x.len;
				*pc_write += ecdhSrvPubKey.un_key.keyEcdhPub.coord.x.len;

				//Add the y-coordinate of the server public key
				memcpy(pc_write, ecdhSrvPubKey.un_key.keyEcdhPub.coord.y.data,
						ecdhSrvPubKey.un_key.keyEcdhPub.coord.y.len);

				cwt_exportLen += ecdhSrvPubKey.un_key.keyEcdhPub.coord.y.len;

				*pc_write++ = ecdhSrvPubKey.un_key.keyEcdhPub.coord.x.len;

				break;

			default:

				/* Try to get a Diffie Hellman Ephemeral Key
				 * forward secrecy */

				//OLD-CW: if ((ps_secPar->pgci_dheKey = km_dhe_getKey()) == NULL) - like generate key
				err = km_dhe_getKey(ps_secPar->dhePeerPubKey);

				if (err != en_gciResult_Ok) {
					LOG_INFO("%p| Couldn't fetch the DHE key", ps_sslCtx);
					return (E_PENDACT_COM_CIPHER_CLOSE);
				}

				err = gciKeyGet(ps_secPar->dhePeerPubKey, &dhSrvPubKey);
				if (err != en_gciResult_Ok) {
					//TODO return error from state
				}

				ps_secPar->c_useDheKey = TRUE;
				/*! calc bytes left in socketbuffer */
				cwt_exportLen = (sizeof(ps_sslCtx->ac_socBuf)
						- ((size_t) pc_write - (size_t) ps_sslCtx->ac_socBuf));

				/* export the formerly generated public DHE values */
				//OLD-CW: cw_dhe_export_pgY(pc_write, &cwt_exportLen, ps_secPar->pgci_dheKey, &ps_hsElem->pgci_dheP);
				//Add prime length of the server public key
				*pc_write++ = dhSrvPubKey.un_key.keyDhPub.param->p.len;

				//Add prime data of the server public key
				memcpy(pc_write, dhSrvPubKey.un_key.keyDhPub.param->p.data,
						dhSrvPubKey.un_key.keyDhPub.param->p.len);
				*pc_write += dhSrvPubKey.un_key.keyDhPub.param->p.len;

				//Add generator length of the server public key
				*pc_write++ = dhSrvPubKey.un_key.keyDhPub.param->g.len;

				//Add generator data of the server public key
				memcpy(pc_write, dhSrvPubKey.un_key.keyDhPub.param->g.data,
						dhSrvPubKey.un_key.keyDhPub.param->g.len);
				*pc_write += dhSrvPubKey.un_key.keyDhPub.param->g.len;

				//Add the server public key length
				*pc_write++ = dhSrvPubKey.un_key.keyDhPub.key.len;

				//Add big number of the server public key
				memcpy(pc_write, dhSrvPubKey.un_key.keyDhPub.key.data,
						dhSrvPubKey.un_key.keyDhPub.key.len);
				*pc_write += dhSrvPubKey.un_key.keyDhPub.key.len;

				break;
			}

			/* Generate hash of
			 * pc_write -> (ClientRandom, ServerRandom, DHParamaeters)
			 * then encrypt with my private key */
			if (loc_signHash(ps_sslCtx, pc_write, cwt_exportLen,
					pc_write + cwt_exportLen, &cwt_hashLen) != E_SSL_NO_ERROR) {
				LOG_ERR("%p| RSA/ECDSA encrypt not successful", ps_sslCtx);
				return (E_PENDACT_COM_CIPHER_CLOSE);
			}

			LOG_INFO("Signature after encryption");
			LOG_HEX(pc_write + cwt_exportLen, cwt_hashLen);

			/* add length at start of record */
			(void) ssl_writeInteger(pc_rec + 1, cwt_exportLen + cwt_hashLen, 3);

			/* Final length is calculated as follows
			 * Length of a pgy part, length of a signed hash and length
			 * of a header */
			cwt_hashLen = *pcwt_recLen = cwt_exportLen + cwt_hashLen
					+ sizeof(rac_srvKeyExch);

			/* Check if we have to authenticate the client */
			if ((ps_sslCtx->e_authLvl & ~E_SSL_MUST_VERF_SRVCERT)
					!= E_SSL_NO_AUTH) {
				ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP3;
			}
			/* We don't have to authenticate the client */
			else {
				ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP4;
			}

			/* we finish this record afterwards */
			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

			TIME_STAMP(TS_SENT_HS_SRV_KEY_EX);

			break;
		}
		case E_SSL_ASM_STEP3: {
			LOG1_INFO("%p| SEND_SERVER_HELLO ASM_STEP3 (CertRequest)",
					ps_sslCtx);
			if (ps_sslCtx->ps_sslSett->ps_caCertsListHead == NULL) {
				LOG1_ERR(
						"%p| CertRequest should be constructed, " "but list is not initialised!",
						ps_sslCtx);
				if ((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH)
						== E_SSL_MUST_AUTH) {
					LOG_ERR(
							"%p| Client Authentication is mandatory, " "so cancel the handshake here",
							ps_sslCtx);

					/* only now we recognised that we do not have enough
					 * information to perform the handshake (cannot
					 * assemble the CertificateRequest message) */
					ps_sslGut->e_alertType = E_SSL_ALERT_HANDSH_FAIL;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					ps_sslGut->e_asmCtrl = E_SSL_ASM_START;
					return (E_PENDACT_SEND_FATAL_ERROR);
				} else {
					LOG1_INFO(
							"%p| Client Authentication is not " "mandatory, so fall through to send " "ServerHelloDone",
							ps_sslCtx);
					ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP4;
					/*
					 * Fall through to E_SSL_ASM_STEP4 to send ServerHelloDone
					 */
				}
			} /* if */
			else {
				/* Global settings */
				s_sslSett_t* ps_gSett = ps_sslCtx->ps_sslSett;
				memcpy(pc_rec, (void*) rac_certReq, sizeof(rac_certReq));
				pc_write = pc_rec + sizeof(rac_certReq);

				if (ps_sslCtx->e_ver == E_TLS_1_2) {
					uint16_t i_signHashAlg;
					uint8_t i;

					ssl_writeInteger(pc_write,
							(sizeof(rai_tlsSHAlgs) / sizeof(rai_tlsSHAlgs[0]))
									* 2, 2);
					pc_write += 2;
					cwt_hashLen += 2;

					for (i = 0;
							i
									< (sizeof(rai_tlsSHAlgs)
											/ sizeof(rai_tlsSHAlgs[0])); i++) {
						i_signHashAlg = rai_tlsSHAlgs[i];
						ssl_writeInteger(pc_write, i_signHashAlg, 2);
						pc_write += 2;
						cwt_hashLen += 2;
					}
				}

				size_t listLen = pc_rec + *pcwt_recLen - pc_write;

				sslConf_getCertReqList(ps_gSett->ps_caCertsListHead, pc_write,
						&listLen);
				cwt_hashLen += listLen;
				pc_write += listLen;

				cwt_hashLen += 2;

				(void) *ssl_writeInteger(pc_rec + 1, cwt_hashLen, 3);

				cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;
				ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP4;
				e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

				TIME_STAMP(TS_SENT_HS_CERT_REQ);

				break;
			} /* else */
		}
		case E_SSL_ASM_STEP4:
			LOG1_INFO("%p| SEND_SERVER_HELLO ASM_STEP4 (SrvHelloDone)",
					ps_sslCtx);
			memcpy(pc_rec, (void*) rac_srvHelloDone, sizeof(rac_srvHelloDone));
			*pcwt_recLen = sizeof(rac_srvHelloDone);
			cwt_hashLen = sizeof(rac_srvHelloDone);

			ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;

			/* Check if we need to authenticate the client */
			if ((ps_sslCtx->e_authLvl & ~E_SSL_MUST_VERF_SRVCERT)
					!= E_SSL_NO_AUTH) {
				ps_sslGut->e_smState = E_SSL_SM_WAIT_CLIENT_CERTIFICATE;
			}
			/* We don't have to authenticate the client */
			else {
				ps_sslGut->e_smState = E_SSL_SM_WAIT_CLIENT_KEYEXCHANGE;
			}
			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

			TIME_STAMP(TS_SENT_HS_SRV_HELLO_DONE);

			break;
		case E_SSL_ASM_FINISH:
		default:
			break;
		}
		break; /* End of E_SSL_SM_SEND_SERVER_HELLO */

	case E_SSL_SM_SEND_CLIENT_FINISH:

		switch (ps_sslGut->e_asmCtrl) {
		case E_SSL_ASM_START:
			if (ps_sslGut->b_isCertReqReceived == TRUE) {
				LOG1_INFO("%p| SEND_CLIENT_FINISH ASM_START (Cert)", ps_sslCtx);
				memcpy(pc_rec, (void*) rac_cert, sizeof(rac_cert));
				pc_write = pc_rec + sizeof(rac_cert);
				if (ps_sslCtx->ps_lastCliAuthCertChain != NULL) {
					cwt_hashLen =
							(size_t) (sizeof(ps_sslCtx->ac_socBuf)
									- ((size_t) pc_write
											- (size_t) ps_sslCtx->ac_socBuf));
					/*
					 * We add the certificate chain up to the CA certificate that is known to the server
					 */
					e_ret = sslConf_getCertChain(
							ps_sslCtx->ps_sslSett->ps_certChainListHead,
							sslCert_getNext(ps_sslCtx->ps_lastCliAuthCertChain),
							pc_write, &cwt_hashLen);
					if (e_ret != E_SSL_OK) {
						if (e_ret == E_SSL_ERROR) {
							ps_sslGut->e_alertType = E_SSL_ALERT_HANDSH_FAIL;
						} else if (e_ret == E_SSL_LEN) {
							ps_sslGut->e_alertType = E_SSL_ALERT_REC_OFLOW;
						}
						ps_sslGut->e_asmCtrl = E_SSL_ASM_START;
						ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
						return (E_PENDACT_SEND_FATAL_ERROR);
					} /* if */
				} /* if */
				else {
					sslCert_initChain(pc_write, 3);
					cwt_hashLen = 3;
				}

				pc_write += cwt_hashLen;

				(void) *ssl_writeInteger(pc_rec + 1, cwt_hashLen, 3);

				cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;
				ps_sslGut->e_recordType = E_SSL_RT_HANDSHAKE;
				ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP1;
				break;
			}
		case E_SSL_ASM_STEP1:
			LOG1_INFO("%p| SEND_CLIENT_FINISH ASM_STEP1 (CliKeyExchange)",
					ps_sslCtx);
			memcpy(pc_rec, (void*) rac_cliKeyExch, sizeof(rac_cliKeyExch));
			pc_write = pc_rec + sizeof(rac_cliKeyExch);
			switch (ps_sslCtx->s_secParams.e_kst) {
			case en_gciKeyPairType_RSA:
				/* Client generates the premaster secret as 2 bytes containing
				 * the SSL Version (0x03, 0xXX), followed by 46 random bytes  */
				if (ps_sslCtx->e_ver == E_VER_DCARE) {
					LOG_ERR("%p| This shouldn't happen here, no version set!",
							ps_sslCtx);
					return (E_PENDACT_COM_CIPHER_CLOSE);
				}

				/* and set version */
				/*pc_write[0] = SSL_VERSION_GET_MAJ(ps_hsElem->e_offerVer);*/
				/*pc_write[1] = SSL_VERSION_GET_MIN(ps_hsElem->e_offerVer);*/
				ssl_writeInteger(pc_write, ps_hsElem->e_offerVer, 2);
				//OLD-CW: cw_prng_read(&pc_write[2], 46);
				err = gciRngGen(46, &pc_write[2]);
				if (err != en_gciResult_Ok) {
					//TODO return state from error
				}

				memcpy(ps_hsElem->s_sessElem.ac_msSec, pc_write, PREMSSEC_SIZE);
				LOG2_INFO("%p| Decrypted PreMasterSecret", ps_sslCtx);
				LOG2_HEX(ps_hsElem->s_sessElem.ac_msSec, PREMSSEC_SIZE);
				/*
				 * Calculate buffer size that is left for PKCS#1 encryption
				 */
				cwt_hashLen = (size_t) (sizeof(ps_sslCtx->ac_socBuf)
						- ((size_t) pc_write - (size_t) ps_sslCtx->ac_socBuf));
				/*
				 * Decrement by the offset
				 */
				cwt_hashLen -= IFSSL30_LENOFF(ps_sslCtx->e_ver);

				TIME_STAMP(TS_PMS_ENCRYPT_BEGIN);

				/* The premaster secret is encrypted in PKCS#1 V1.5 Style */

				//OLD-CW: if (cw_rsa_encrypt(ps_hsElem->s_sessElem.ac_msSec, PREMSSEC_SIZE, pc_write + IFSSL30_LENOFF(ps_sslCtx->e_ver), &cwt_hashLen, &ps_hsElem->gci_peerPubKey) != CW_OK)
				GciCtxId_t rsaCtx;
				//No config used for an asymmetric cipher
				//Public key coming from the certificate from the server
				err = gciCipherNewCtx(NULL, ps_hsElem->gci_rsaCliPubKey,
						&rsaCtx);
				if (err != en_gciResult_Ok) {
					//TODO return state from error
				}

				err = gciCipherEncrypt(rsaCtx, ps_hsElem->s_sessElem.ac_msSec,
						PREMSSEC_SIZE,
						pc_write + IFSSL30_LENOFF(ps_sslCtx->e_ver),
						&cwt_hashLen);
				if (err != en_gciResult_Ok) {
					LOG_ERR("%p| PKCS#1 encrypt not successful", ps_sslCtx);
					ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
					return (E_PENDACT_COM_CIPHER_CLOSE);
				}

				//Release the context
				err = gciCtxRelease(rsaCtx);
				if (err != en_gciResult_Ok) {
					//TODO return error from state
				}

				TIME_STAMP(TS_PMS_ENCRYPT_END);

				ssl_writeInteger(pc_rec + 1,
						cwt_hashLen + IFSSL30_LENOFF(ps_sslCtx->e_ver), 3);
				ssl_writeInteger(pc_write, cwt_hashLen,
						IFSSL30_LENOFF(ps_sslCtx->e_ver));
				pc_write += cwt_hashLen + IFSSL30_LENOFF(ps_sslCtx->e_ver);
				cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;
				ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP2;
				ps_sslGut->e_recordType = E_SSL_RT_HANDSHAKE;
				e_pendAct = E_PENDACT_PKCS1_ENCRYPT;
				break;

			case en_gciKeyPairType_DH:

				cwt_hashLen = (size_t) (sizeof(ps_sslCtx->ac_socBuf)
						- ((size_t) pc_write - (size_t) ps_sslCtx->ac_socBuf));

				TIME_STAMP(TS_DHE_CALC_SHARED_SEC_BEGIN);

				//Get the big number of the Server public key
				err = gciKeyGet(ps_hsElem->gci_dheSrvPubKey, &dhSrvPubKey);
				if (err != en_gciResult_Ok) {
					//return error state
				}

				dhConf.type = en_gciDhType_Dh;

				//Get the domain parameters from the Server public key (Server Key Exchange in loc_protocolHand)
				dhConf.un_dhParam.dhParamDomain->g.len =
						dhSrvPubKey.un_key.keyDhPub.param->g.len;

				memcpy(dhConf.un_dhParam.dhParamDomain->g.data,
						dhSrvPubKey.un_key.keyDhPub.param->g.data,
						dhSrvPubKey.un_key.keyDhPub.param->g.len);

				dhConf.un_dhParam.dhParamDomain->p.len =
						dhSrvPubKey.un_key.keyDhPub.param->p.len;

				memcpy(dhConf.un_dhParam.dhParamDomain->p.data,
						dhSrvPubKey.un_key.keyDhPub.param->p.data,
						dhSrvPubKey.un_key.keyDhPub.param->p.len);

				err = gciDhNewCtx(&dhConf, &dhCtx);
				if (err != en_gciResult_Ok) {
					//TODO return state from error
				}

				err = gciDhGenKey(dhCtx, ps_hsElem->gci_dheCliPubKey);
				if (err != en_gciResult_Ok) {
					//TODO return state from error
				}

				/* calculate dh shared secret */

				//Context which contains the private key of the client
				err = gciDhCalcSharedSecret(dhCtx,
						ps_hsElem->gci_dheSrvPubKey, &ps_hsElem->gci_dheSecKey);

				//if (cw_dhe_sharedSec_with_p(&ps_hsElem->gci_dheCliPrivKey, &ps_hsElem->gci_dheSrvPubKey, &ps_hsElem->pgci_dheP, pc_write, &cwt_hashLen) != CW_OK)
				if (err != en_gciResult_Ok) {
					LOG_ERR("%p| DHE shared secret calculation not successful",
							ps_sslCtx);
					ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
					return (E_PENDACT_COM_CIPHER_CLOSE);
				}

				//Release the context
				err = gciCtxRelease(dhCtx);
				if (err != en_gciResult_Ok) {
					//TODO return error from state
				}

				TIME_STAMP(TS_DHE_CALC_SHARED_SEC_END);

				//Get the big number of the secret key
				err = gciKeyGet(&ps_hsElem->gci_dheSecKey, &dhSecretKey);

				/* transform DHE shared secret to MasterSecret */
//							OLD-CW: ps_sslCtx->e_lastError =
//									loc_prf(ps_sslCtx,
//											pc_write, cwt_hashLen,
//											rac_TLSlabelMsSec, strlen((const char *)rac_TLSlabelMsSec),
//											ps_hsElem->ac_cliRand, CLI_RANDSIZE,
//											ps_hsElem->ac_srvRand, SRV_RANDSIZE,
//											ps_hsElem->s_sessElem.ac_msSec, MSSEC_SIZE);
				ps_sslCtx->e_lastError = loc_prf(ps_sslCtx,
						dhSecretKey.un_key.keyDhSecret.data,
						dhSecretKey.un_key.keyDhSecret.len, rac_TLSlabelMsSec,
						strlen((const char *) rac_TLSlabelMsSec),
						ps_hsElem->ac_cliRand, CLI_RANDSIZE,
						ps_hsElem->ac_srvRand, SRV_RANDSIZE,
						ps_hsElem->s_sessElem.ac_msSec, MSSEC_SIZE);

				if (ps_sslCtx->e_lastError < 0)
					return (E_PENDACT_COM_CIPHER_CLOSE);

//							cwt_hashLen = (size_t) (sizeof(ps_sslCtx->ac_socBuf)
//									- ((size_t) pc_write
//											- (size_t) ps_sslCtx->ac_socBuf));
				cwt_hashLen = (size_t) (sizeof(ps_sslCtx->ac_socBuf)
						- (dhSecretKey.un_key.keyDhSecret.len
								- (size_t) ps_sslCtx->ac_socBuf));

				/* export our private dh parameter Y */
				/*OLD-CW: if (cw_dhe_export_Y(pc_write, &cwt_hashLen,
				 &ps_hsElem->gci_dheCliPrivKey) != CW_OK)
				 {
				 LOG_ERR("%p| DHE export not successful", ps_sslCtx);
				 ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
				 return (E_PENDACT_COM_CIPHER_CLOSE);
				 }*/

				//Get the big number of the client public key
				err = gciKeyGet(ps_hsElem->gci_dheCliPubKey, &dhCliPubKey);
				if (err != en_gciResult_Ok) {
					//TODO return state from error
				}

				//Add the length of client's public key to the buffer
				*pc_write++ = dhCliPubKey.un_key.keyDhPub.key.len;

				*pc_write += dhCliPubKey.un_key.keyDhPub.key.len;

				//Add the client's public key to the buffer
				*pc_write++ = dhCliPubKey.un_key.keyDhPub.key.data;
				cwt_hashLen = dhCliPubKey.un_key.keyDhPub.key.len;

				ssl_writeInteger(pc_rec + 1, cwt_hashLen, 3);
				pc_write += cwt_hashLen;
				cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;

				ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP2;
				ps_sslGut->e_recordType = E_SSL_RT_HANDSHAKE;
				e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

				TIME_STAMP(TS_SENT_HS_CLI_KEY_EX);
				break;

			case en_gciKeyPairType_ECDH:

				//begin vpy
				cwt_hashLen = (size_t) (sizeof(ps_sslCtx->ac_socBuf)
						- ((size_t) pc_write - (size_t) ps_sslCtx->ac_socBuf));

				TIME_STAMP(TS_ECDHE_CALC_SHARED_SEC_BEGIN);

				//Get the big number of the Server public key (Server Key Exchange in loc_protocolHand)
				err = gciKeyGet(ps_hsElem->eccPubKeyPeer, &ecdhCliPubKey);
				if (err != en_gciResult_Ok) {
					//TODO return state from error
				}

				ecdhConf.type = en_gciDhType_Ecdh;

				//Get the elliptic curve coming from the Server public key
				ecdhConf.un_dhParam.dhParamCurveName = ecdhCliPubKey.un_key.keyEcdhPub.curve;

				err = gciDhNewCtx(&ecdhConf, &ecdhCtx);
				if (err != en_gciResult_Ok) {
					//TODO return state from error
				}

				/* Generate ECC private Key */

				err = gciDhGenKey(ecdhCtx, ps_secPar->ecdhCliPubKey);
				if (err != en_gciResult_Ok) {
					//TODO return state from error
				}

				//if(cw_ecc_makeKey(&(ps_secPar->eccKey), ps_hsElem->eccCurve)!=CRYPT_OK)
				if (err != en_gciResult_Ok) {
					LOG_INFO("%p| Couldn't create a new ECHE key", ps_sslCtx);
					ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
					return (E_PENDACT_COM_CIPHER_CLOSE);
				}

				//Release the context
				err = gciCtxRelease(ecdhCtx);
				if (err != en_gciResult_Ok) {
					//TODO return error from state
				}

				/* calculate ecdhe shared secret with the public key coming from the server key exchange*/

				//Here eccPubKeyPeer is the ecc public key of the server + private key of the client is in the context
				err = gciDhCalcSharedSecret(ecdhCtx,
						ps_hsElem->eccPubKeyPeer, ps_hsElem->gci_ecdheSecKey);

				//if(cw_ecc_sharedSecret(&(ps_secPar->eccKey), &(ps_hsElem->eccPubKeyPeer), pc_write, &cwt_hashLen)!=CRYPT_OK)
				if (err != en_gciResult_Ok) {
					LOG_ERR(
							"%p| ECDHE shared secret calculation not successful",
							ps_sslCtx);
					ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
					return (E_PENDACT_COM_CIPHER_CLOSE);
				}

				//Get the big number of the secret key
				err = gciKeyGet(ps_hsElem->gci_ecdheSecKey, &ecdhSecretKey);
				if (err != en_gciResult_Ok) {
					//TODO return state
				}

				TIME_STAMP(TS_ECDHE_CALC_SHARED_SEC_END);

				/* transform ECDHE shared secret to MasterSecret */
//							OLD-CW: ps_sslCtx->e_lastError =
//									loc_prf(ps_sslCtx,
//											pc_write, cwt_hashLen,
//											rac_TLSlabelMsSec, strlen((const char *)rac_TLSlabelMsSec),
//											ps_hsElem->ac_cliRand, CLI_RANDSIZE,
//											ps_hsElem->ac_srvRand, SRV_RANDSIZE,
//											ps_hsElem->s_sessElem.ac_msSec, MSSEC_SIZE);
				ps_sslCtx->e_lastError = loc_prf(ps_sslCtx,
						ecdhSecretKey.un_key.keyEcdhSecret.data,
						ecdhSecretKey.un_key.keyEcdhSecret.len, rac_TLSlabelMsSec,
						strlen((const char *) rac_TLSlabelMsSec),
						ps_hsElem->ac_cliRand, CLI_RANDSIZE,
						ps_hsElem->ac_srvRand, SRV_RANDSIZE,
						ps_hsElem->s_sessElem.ac_msSec, MSSEC_SIZE);

				if (ps_sslCtx->e_lastError < 0)
					return (E_PENDACT_COM_CIPHER_CLOSE);

//							OLD-CW: cwt_hashLen = (size_t) (sizeof(ps_sslCtx->ac_socBuf)
//													- ((size_t) pc_write
//													- (size_t) ps_sslCtx->ac_socBuf));

				cwt_hashLen = (size_t) (sizeof(ps_sslCtx->ac_socBuf)
						- (ecdhSecretKey.un_key.keyEcdhSecret.len
								- (size_t) ps_sslCtx->ac_socBuf));

				//Get the big number of the public key
				err = gciKeyGet(ps_secPar->ecdhCliPubKey, &ecdhCliPubKey);

				//Add the length of the x-coordinate of the client's public key
				*pc_write++ = ecdhCliPubKey.un_key.keyEcdhPub.coord.x.len;

				//Add the x-coordinate of the client's public key
				memcpy(pc_write, ecdhCliPubKey.un_key.keyEcdhPub.coord.x.data,
						ecdhCliPubKey.un_key.keyEcdhPub.coord.x.len);

				*pc_write += ecdhCliPubKey.un_key.keyEcdhPub.coord.x.len;

				//Add the length of the y-coordinate of the client's public key
				*pc_write++ = ecdhCliPubKey.un_key.keyEcdhPub.coord.y.data;

				//Add the y-coordinate of the client's public key
				memcpy(pc_write, ecdhCliPubKey.un_key.keyEcdhPub.coord.y.data,
						ecdhCliPubKey.un_key.keyEcdhPub.coord.y.len);

				*pc_write += ecdhCliPubKey.un_key.keyEcdhPub.coord.y.len;

				/* export our public ECDHE key*/
//							if(cw_ecc_export_public(pc_write+1, &cwt_hashLen, &ps_secPar->eccKey)!=CRYPT_OK)
//
//							{
//								LOG_ERR("%p| DHE export not successful", ps_sslCtx);
//								ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
//								return (E_PENDACT_COM_CIPHER_CLOSE);
//							}
				//OLD-CW: *pc_write = cwt_hashLen;
				*pc_write = ecdhCliPubKey.un_key.keyEcdhPub.coord.x.len
						+ ecdhCliPubKey.un_key.keyEcdhPub.coord.y.len + 2;

				ssl_writeInteger(pc_rec + 1, cwt_hashLen + 1, 3);
				pc_write += (cwt_hashLen + 1);
				cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;

				ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP2;
				ps_sslGut->e_recordType = E_SSL_RT_HANDSHAKE;
				e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

				TIME_STAMP(TS_SENT_HS_CLI_KEY_EX);

				//end vpy
				break;

//						OLD-CW: case GCI_KEY_PAIR_ECDHE_ECDSA:
//
//							//TODO vpy ECDSA: implement
//							LOG_ERR("%p| ECDSA not implemented", ps_sslCtx);
//							break;

			default:
				LOG_ERR("%p| Handshake Type 0x%X can't be handled", ps_sslCtx,
						ps_secPar->e_kst);
				ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
				return (E_PENDACT_COM_CIPHER_CLOSE);
				break;
			}
			break;
		case E_SSL_ASM_STEP2:
			if ((ps_sslGut->b_isCertReqReceived == TRUE)
					&& (ps_sslCtx->ps_lastCliAuthCertChain != NULL)) {

				LOG1_INFO("%p| SEND_CLIENT_FINISH ASM_STEP2 (CertVerify)",
						ps_sslCtx);
				memcpy(pc_rec, (void*) rac_certVerify, sizeof(rac_certVerify));
				pc_write = pc_rec + sizeof(rac_certVerify);

				uint8_t c_hashLen = GCI_MAX_HASHSIZE_BYTES;

				/* compute the verification data
				 * for the CertificateVerify message */
				loc_compHash(ps_sslCtx, NULL, pc_write + 2);

				uint8_t c_hashType = ps_sslCtx->s_secParams.s_signAlg.c_hash;
				uint8_t c_signType = ps_sslCtx->s_secParams.s_signAlg.c_sign;

				LOG_INFO("Hash is");
				LOG_HEX(pc_write + 2, loc_getHashSize(c_hashType));

				cwt_hashLen = (size_t) (sizeof(ps_sslCtx->ac_socBuf)
						- ((uint32_t) (pc_write + 2)
								- (uint32_t) ps_sslCtx->ac_socBuf));

				if (ps_sslCtx->e_ver >= E_TLS_1_2) {
					s_derdCtx_t s_derdCtx;
					uint8_t c_signLen = GCI_MAX_HASHSIZE_BYTES +
					SSL_DER_ASN1_MAX_OID_OCTET + 22;
					/* This array will be temporally used by DER Decoder module */
					uint8_t ac_sign[c_signLen];
					s_sslOctetStr_t s_sigOctStr;
					uint8_t ac_hash[GCI_MAX_HASHSIZE_BYTES +
					SSL_DER_ASN1_MAX_OID_OCTET + 20];

					c_hashLen = loc_getHashSize(c_hashType);

					memcpy(&ac_hash[0], pc_write + 2, c_hashLen);

					pc_write[0] = c_hashType;
					pc_write[1] = c_signType;
					pc_write += 2;

					memset(ac_sign, 0x00, c_signLen);
					s_sigOctStr.cwt_len = c_signLen;
					s_sigOctStr.pc_data = ac_sign;

					sslDerd_initEncCtx(&s_derdCtx, &s_sigOctStr);

					sslDerd_setSign(&s_derdCtx, c_hashType, &ac_hash[0],
							c_hashLen);

					if (s_derdCtx.s_octBuf.cwt_len <= sizeof(ac_hash)) {
						memmove(pc_write + 2, s_derdCtx.s_octBuf.pc_data,
								s_derdCtx.s_octBuf.cwt_len);
						c_hashLen = s_derdCtx.s_octBuf.cwt_len;
						LOG_INFO("Signature before encryption");
						LOG_HEX(pc_write + 2, c_hashLen);
					}

				} else {
					c_hashLen = 36;
				}

				TIME_STAMP(TS_CRT_VERF_SIGN_BEGIN);
				/*
				 e_result = cw_rsa_sign_encode(ac_hash, c_hashLen,
				 pc_out + c_signOff + 2, &sz_signLen,
				 ps_sslCtx->ps_sslSett->pcwt_rsaMyPrivKey);
				 */
				GciCtxId_t rsaCtx;
				st_gciSignConfig_t rsaConf;

				rsaConf.algo = en_gciSignAlgo_RSA;
				rsaConf.hash = en_gciHashAlgo_None;
				rsaConf.un_signConfig.signConfigRsa.padding = en_gciPadding_PKCS1;

				//TODO sw - the private come from the PEM file with the certificate -> see _sslSoc_sett_import_RSAprivKey
				err = gciSignGenNewCtx(&rsaConf,
						ps_sslCtx->ps_sslSett->pgci_rsaMyPrivKey, &rsaCtx);
				if (err != en_gciResult_Ok) {
					//TODO return state
				}

				err = gciSignUpdate(rsaCtx, pc_write + 2, c_hashLen);
				if (err != en_gciResult_Ok) {
					//TODO return state
				}

				err = gciSignGenFinish(rsaCtx, pc_write + 2, &cwt_hashLen);

				//OLD-CW: if (cw_rsa_sign_encode(pc_write + 2, c_hashLen, pc_write + 2, &cwt_hashLen,
				//ps_sslCtx->ps_sslSett->pgci_rsaMyPrivKey) != CW_OK)

				if (err != en_gciResult_Ok) {
					LOG_ERR("%p| PKCS#1 Sign Hash not successful", ps_sslCtx);
					return (E_PENDACT_COM_CIPHER_CLOSE);
				}

				else {
					LOG_INFO("Signature after encryption");
					LOG_HEX(pc_write + 2, cwt_hashLen);
				}

				//Release the context
				err = gciCtxRelease(rsaCtx);
				if (err != en_gciResult_Ok) {
					//TODO return error from state
				}

				TIME_STAMP(TS_CRT_VERF_SIGN_END);

				pc_write += 2; /* the length of the encrypted verification hashes is written extra */
				ssl_writeInteger(pc_write - 2, cwt_hashLen, 2);
				if (ps_sslCtx->e_ver >= E_TLS_1_2) {
					ssl_writeInteger(pc_rec + 1, cwt_hashLen + 4, 3);
				} else {
					ssl_writeInteger(pc_rec + 1, cwt_hashLen + 2, 3);
				}
				pc_write += cwt_hashLen;
				cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;
				ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP3;
				e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;
				ps_sslGut->e_recordType = E_SSL_RT_HANDSHAKE;

				TIME_STAMP(TS_SENT_HS_CERT_VERIFY);

				break;
			}
		case E_SSL_ASM_STEP3:
			LOG1_INFO("%p| SEND_CLIENT_FINISH ASM_STEP3 (ChangeCipherSpec)",
					ps_sslCtx);
			ps_sslGut->e_recordType = E_SSL_RT_CHANGE_CIPSPEC;
			*pc_rec = 0x01; /* Very short */
			*pcwt_recLen = 1;
			cwt_hashLen = 0; /* Change cipher spec is not included in the hash */
			ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP4;
			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;
			break;
		case E_SSL_ASM_STEP4:
			LOG1_INFO("%p| SEND_CLIENT_FINISH ASM_STEP4 (Finished)", ps_sslCtx);
			loc_compKey(ps_sslCtx, FALSE);
			/* Don't forget the change of the cipher specification        */
			/* (indicated in the header block ) */
			ps_sslGut->e_txCipSpec = ps_sslGut->e_pendCipSpec;
			pc_write = pc_rec;

			memcpy(pc_write, (void*) rac_srvFinish, sizeof(rac_srvFinish));
			pc_write += sizeof(rac_srvFinish);
			*pc_write++ = ps_sslGut->c_verifyDataLen;

			/* get finish label for client finished message */
			lbl = loc_getFinLabel(ps_sslCtx, TRUE);

			/* calculate verification hash for client finished message */
			loc_compHash(ps_sslCtx, lbl, pc_write);

			memcpy(ps_sslGut->ac_cliVerifyData, pc_write,
					ps_sslGut->c_verifyDataLen);
			pc_write += ps_sslGut->c_verifyDataLen;
			cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;
			LOG_INFO("recLen = %d", cwt_hashLen);

			ps_sslGut->e_recordType = E_SSL_RT_HANDSHAKE;
			ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;
			ps_sslGut->b_isComposite = FALSE;
			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;
			if (ps_sslCtx->c_isResumed == TRUE) {
//								if (ps_sslCtx->s_secParams.c_useDheKey == TRUE)
//								{
//									//OLD-CW: km_dhe_releaseKey();
//									err = gci_key_delete(ps_sslCtx->s_secParams.pgci_dheKey);
//									if(err != GCI_OK)
//									{
//										//TODO return state
//									}
//									ps_sslCtx->s_secParams.c_useDheKey = FALSE;
//								}
				ps_sslGut->e_smState = E_SSL_SM_APPDATA_EXCHANGE;
				LOG1_INFO("%p| Send Finish -> APPDATA_EXCHANGE ", ps_sslCtx);
			} else {
				ps_sslGut->e_smState = E_SSL_SM_WAIT_SERVER_FINISH;
				LOG_INFO("%p| Send Finish -> WAIT_SERVER_FINISH ", ps_sslCtx);
			}

			TIME_STAMP(TS_SENT_HS_FINISH);

			break;
		case E_SSL_ASM_FINISH:
		default:
			break;
		}
		break;

	case E_SSL_SM_SEND_SERVER_FINISH:

		switch (ps_sslGut->e_asmCtrl) {
		case E_SSL_ASM_START: /* Change Cipher Spec */
			LOG1_INFO("%p | SEND_SERVER_FINISH ASM_START", ps_sslCtx);
			ps_sslGut->e_recordType = E_SSL_RT_CHANGE_CIPSPEC;
			*pc_rec = 0x01; /* Very short */
			*pcwt_recLen = 1;
			cwt_hashLen = 0; /* Change cipher spec is not included in the hash */

			ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP1;
			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

			TIME_STAMP(TS_SENT_CCS);

			break;

		case E_SSL_ASM_STEP1:
			LOG1_INFO("%p| SEND_SERVER_FINISH ASM_STEP1", ps_sslCtx);
			/* Generate the new key material */
			loc_compKey(ps_sslCtx, TRUE);

			/* Don't forget the change of the cipher specification        */
			/* (indicated in the header block ) */
			ps_sslGut->e_txCipSpec = ps_sslGut->e_pendCipSpec;
			pc_write = pc_rec;

			memcpy(pc_write, (void*) rac_srvFinish, sizeof(rac_srvFinish));
			pc_write += sizeof(rac_srvFinish);

			/* Calculate the content of the finished section */
			*pc_write++ = ps_sslCtx->s_sslGut.c_verifyDataLen;

			/* get finish label for server finished message */
			lbl = loc_getFinLabel(ps_sslCtx, FALSE);

			/* calculate verification hash for server finished message */
			loc_compHash(ps_sslCtx, lbl, pc_write);

			memcpy(ps_sslCtx->s_sslGut.ac_srvVerifyData, pc_write,
					ps_sslCtx->s_sslGut.c_verifyDataLen);
			pc_write += ps_sslCtx->s_sslGut.c_verifyDataLen;
			cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;
			LOG_INFO("pcwt_recLen = %d", pc_write - pc_rec);
			ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;

			if (ps_sslCtx->s_secParams.c_useDheKey == TRUE) {
				km_dhe_releaseKey();
				ps_sslCtx->s_secParams.c_useDheKey = FALSE;
			}

			ps_sslGut->e_smState = E_SSL_SM_APPDATA_EXCHANGE;
			break;
		case E_SSL_ASM_STEP2:
		case E_SSL_ASM_STEP3:
		case E_SSL_ASM_STEP4:
		case E_SSL_ASM_FINISH:
		default:
			break;
		}
		break;

	case E_SSL_SM_SEND_SERVER_HELLO_FINISH:

		switch (ps_sslGut->e_asmCtrl) {
		case E_SSL_ASM_START: /* Prepare Server Hello */
			LOG1_INFO("%p| SEND_SERVER_HELLO_FINISH ASM_START", ps_sslCtx);
			memcpy(pc_rec, (void*) rac_srvHello, sizeof(rac_srvHello));
			pc_write = pc_rec + sizeof(rac_srvHello);
			/* sj check behaviour - should be fine, session resumption works well */
			if (ps_sslCtx->e_ver == E_VER_DCARE) {
				LOG_INFO(
						"%p| Protocol version not set correctly, use " "last used version out of session cache",
						ps_sslCtx);
				ps_sslCtx->e_ver = ps_hsElem->s_sessElem.e_lastUsedVer;
			}
			*pc_write++ = SSL_VERSION_GET_MAJ(ps_sslCtx->e_ver);
			*pc_write++ = SSL_VERSION_GET_MIN(ps_sslCtx->e_ver);

			/* */
			memcpy(pc_write, ps_hsElem->ac_srvRand, SRV_RANDSIZE);
			pc_write += SRV_RANDSIZE;

			/* Insert length of the s_desc */
			*pc_write++ = SESSID_SIZE;
			memcpy(pc_write, ps_hsElem->s_sessElem.ac_id, SESSID_SIZE);

			pc_write += SESSID_SIZE;

			/* Now add the selected cipher suite */
			*pc_write++ = (ps_sslGut->e_pendCipSpec >> 8) & 0x0FF;
			*pc_write++ = ps_sslGut->e_pendCipSpec & 0x0FF;
			*pc_write++ = 0x00; /* No compression */
			//TODO vpy: WTF hello finish ?
			// TLS_EXTENSION_SIGNATURE_ALGORITHMS required ?
			pc_write = loc_appendExtens(ps_sslCtx, pc_write);

			cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;

			ssl_writeInteger(pc_rec + 1, cwt_hashLen - HS_HEADERLEN, 3);

			ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP1;
			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

			TIME_STAMP(TS_SENT_HS_SERVER_HELLO);

			break;

		case E_SSL_ASM_STEP1: /* Change Cipher Spec */
			LOG1_INFO("%p| SEND_SERVER_HELLO_FINISH ASM_STEP1", ps_sslCtx);
			ps_sslGut->e_recordType = E_SSL_RT_CHANGE_CIPSPEC;
			*pc_rec = 0x01; /* Very short */
			*pcwt_recLen = 1;
			cwt_hashLen = 0; /* Change cipher spec is not included in the hash */

			ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP2;
			e_pendAct = E_PENDACT_MAC_ENCRYPT_REC;

			TIME_STAMP(TS_SENT_CCS);

			break;

		case E_SSL_ASM_STEP2:
			LOG1_INFO("%p| SEND_SERVER_HELLO_FINISH ASM_STEP2", ps_sslCtx);
			/* Generate the new key material */
			loc_compKey(ps_sslCtx, TRUE);

			/* Don't forget the change of the cipher specification        */
			/* (indicated in the header block) */
			ps_sslGut->e_txCipSpec = ps_sslGut->e_pendCipSpec;
			pc_write = pc_rec;

			memcpy(pc_write, (void*) rac_srvFinish, sizeof(rac_srvFinish));
			pc_write += sizeof(rac_srvFinish);

			/* Calculate the content of the finished section */
			*pc_write++ = ps_sslGut->c_verifyDataLen;

			/* get finish label for server finished message */
			lbl = loc_getFinLabel(ps_sslCtx, FALSE);

			/* calculate verification hash for server finished message */
			loc_compHash(ps_sslCtx, lbl, pc_write);

			memcpy(ps_sslGut->ac_srvVerifyData, pc_write,
					ps_sslGut->c_verifyDataLen);
			pc_write += ps_sslGut->c_verifyDataLen;
			cwt_hashLen = *pcwt_recLen = pc_write - pc_rec;

			ps_sslGut->e_smState = E_SSL_SM_WAIT_CHANGE_CIPHERSPEC;
			ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;
			break;

		default:
			ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;
			break;
		}
		break;

	case E_SSL_SM_SEND_SHUTDOWN:
		LOG1_INFO("%p| Sending close notify", ps_sslCtx);
		ps_sslGut->e_recordType = E_SSL_RT_ALERT;
		*pcwt_recLen = 2;
		pc_rec[0] = 2; /* Fatal alert */
		pc_rec[1] = E_SSL_ALERT_CLOSE_NOTIFY; /* Close notify */
		ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;
		ps_sslGut->e_smState = E_SSL_SM_SHUTDOWN_SENT;
		e_pendAct = E_PENDACT_MAC_ENCRYPT_HANDSHAKE;
		break;

	default:
		ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;
		break;
	}

	loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_rec + l_blockLen,
			cwt_hashLen - l_blockLen);

	LOG2_HEX(pc_rec, *pcwt_recLen);

	DbgPrintDigestStates(DBG_LOW, &ps_hsElem->gci_sha1Ctx, &ps_hsElem->gci_md5Ctx);

	return (e_pendAct);
}/* loc_protocolResp() */

/* *********************************************************************** */
/* *********************************************************************** */

static e_sslPendAct_t loc_v2UpwardHandler(s_sslCtx_t * ps_sslCtx,
		uint8_t *pc_rec, size_t cwt_recLen) {
#if SSL_NO_SSLV2_HELLO == TRUE
	LOG_ERR("%p| E_PENDACT_PROTOERR",ps_sslCtx);
	return(E_PENDACT_PROTOERR);

#else
	uint16_t i_cipSpecLen;
	size_t cwt_sessIdLen;
	size_t cwt_cliChallengeLen;
	e_sslPendAct_t e_pendAct;

	s_sslGut_t *ps_sslGut;
	s_sslHsElem_t *ps_hsElem;

	assert(ps_sslCtx != NULL);
	assert(pc_rec != NULL);

	ps_sslGut = &ps_sslCtx->s_sslGut;
	ps_hsElem = ps_sslCtx->ps_hsElem;

	/* SSLv2 client hello handler */
	if (ps_sslGut->e_smState != E_SSL_SM_WAIT_CLIENT_HELLO) {
		LOG_ERR("%p| E_PENDACT_PROTOERR", ps_sslCtx);
		return (E_PENDACT_PROTOERR);
	}

	if (pc_rec[2] != 0x01) {
		LOG_ERR("%p| E_PENDACT_PROTOERR", ps_sslCtx);
		return (E_PENDACT_PROTOERR);
	}

	/* select the correct version out of the version we received in the client hello */
	e_pendAct = loc_selVer(ps_sslCtx, SSL_VERSION_READ(&pc_rec[3]));
	if (e_pendAct != 0) {
		return e_pendAct;
	}

	/* Calculate length */
	cwt_recLen = (pc_rec[0] & 0x7F) * 256 + pc_rec[1];

	/* Process the SSLv2.0 client hello message here */
	i_cipSpecLen = pc_rec[5] * 256 + pc_rec[6]; /* len of cipher spec*/
	cwt_sessIdLen = pc_rec[7] * 256 + pc_rec[8]; /* len of session ID */
	cwt_cliChallengeLen = pc_rec[9] * 256 + pc_rec[10]; /* len of client challenge / random */

	/* Check for usable cipherspecs */
	/* Get all cipherspecs and look up in the supportet cipherspec table.     */
	/* Each matched cipherspec will be marked. If there is no mark, send      */
	/* appropriate error message. Select the most appropriate algorithm */
	loc_matchCipherSpec(ps_sslCtx, pc_rec + 11, i_cipSpecLen, cwt_recLen - 11);

	/* OPTIMIZE Save client challenge / random */
	memset(ps_hsElem->ac_cliRand, 0x00, 32);
	memcpy(ps_hsElem->ac_cliRand + 32 - cwt_cliChallengeLen,
			pc_rec + 11 + i_cipSpecLen + cwt_sessIdLen, cwt_cliChallengeLen);

	/* Initialize the handshake hashes */
	loc_hash(E_HASHOP_INIT, ps_sslCtx, NULL, 0);

	loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_rec + 2, cwt_recLen);

	LOG1_INFO("%p| v2 CLIENT_HELLO", ps_sslCtx);
	LOG2_HEX(pc_rec + 2, cwt_recLen);

	ps_sslCtx->c_isResumed = FALSE;

	/* Dont forget the state for the next processing */
	ps_sslGut->e_smState = E_SSL_SM_SEND_SERVER_HELLO;

	return (E_PENDACT_PROTORESPGEN);

#endif /* SSLV2 */
}

/* *********************************************************************** */
/* *********************************************************************** */
static e_sslPendAct_t loc_protocolHand(s_sslCtx_t * ps_sslCtx, uint8_t c_event,
		uint8_t *pc_rec, size_t cwt_recLen, uint8_t *pc_wData,
		size_t *cwt_wDataLen) {
	e_sslPendAct_t action = E_PENDACT_GEN_WAIT_EVENT;
	/* Handshake buffer */
	uint8_t *pc_hsBuff;
	size_t cwt_hsBuffLen;
	uint8_t *pc_hsBuffEnd;

	/* Processed bytes */
	size_t cwt_procRecBytes;
	size_t cwt_len;

	s_sslOctetStr_t ClientCert;

	s_sslGut_t *ps_sslGut;
	s_sslHsElem_t *ps_hsElem;
	s_sslSecParams_t *ps_secPar;

	en_gciResult_t err;

	/* used as temporary storage for various
	 * labels (e.g. client finished, ...) */
	const uint8_t* lbl;

	assert(ps_sslCtx != NULL);
	assert(pc_rec != NULL);
	assert(pc_wData != NULL);
	assert(cwt_wDataLen != NULL);

	ps_sslGut = &ps_sslCtx->s_sslGut;
	ps_secPar = &ps_sslCtx->s_secParams;
	ps_hsElem = ps_sslCtx->ps_hsElem;
	pc_hsBuff = ps_hsElem->ac_hsBuf;

	LOG2_INFO("loc_protocolHand(...): ");
	LOG2_HEX(pc_rec, cwt_recLen);

	switch (c_event) {
	case E_PENDACT_SRV_PKCS1_DECRYPT:
	case E_PENDACT_SRV_DHECALCSHARED:
	case E_PENDACT_SRV_ECDHECALCSHARED: //vpy
	{
		loc_prf(ps_sslCtx, pc_rec, *cwt_wDataLen, rac_TLSlabelMsSec,
				strlen((const char *) rac_TLSlabelMsSec), ps_hsElem->ac_cliRand,
				CLI_RANDSIZE, ps_hsElem->ac_srvRand, SRV_RANDSIZE,
				ps_hsElem->s_sessElem.ac_msSec,
				MSSEC_SIZE);

		LOG_INFO("Client random");
		LOG_HEX(ps_hsElem->ac_cliRand, 32);

		LOG_INFO("Server random");
		LOG_HEX(ps_hsElem->ac_srvRand, 32);

		LOG_INFO("Master secret");
		LOG_HEX(ps_hsElem->s_sessElem.ac_msSec, 48);

		if (ps_sslGut->b_isComposite == FALSE) {
			return (E_PENDACT_GEN_WAIT_EVENT);
		} /* if */

		/* In case of composite record: fall through to composite handling */
		break;

	} /* case E_PENDACT_SRV_PKCS1_DECRYPT || case E_PENDACT_SRV_DHECALCSHARED */
	case E_PENDACT_SRV_CLICERTCHAIN: {
		/* Process result of client cert chain check */
		E_SSL_VERIFRES *p_result = (E_SSL_VERIFRES*) pc_rec;
		if (*p_result != E_SSL_VERIFRES_SUCCESS) {
			if ((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH)
					|| (ps_sslCtx->e_authLvl & E_SSL_SHOULD_AUTH)) {
				LOG_ERR(
						"%p| Certificate can't be verified, stop handshake here",
						ps_sslCtx);
				ps_sslGut->e_alertType = E_SSL_ALERT_BAD_CERT;
				ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
				return E_PENDACT_SCACHE_RM;
			} else {
				LOG_WARN(
						"%p| Certificate can't be verified, but we continue " "since verification of the clients certificate " "is not mandatory",
						ps_sslCtx);
			} /* else */
		}

		if (ps_sslGut->b_isComposite == FALSE) {
			return E_PENDACT_GEN_WAIT_EVENT;
		}
		break;
	} /* case E_PENDACT_SRV_CLICERTCHAIN */
	case E_PENDACT_SRV_CERTVERIFY: {
		/* Result from Client certificate verification hash check */
		E_SSL_VERIFRES *p_result = (E_SSL_VERIFRES*) pc_rec;
		if (*p_result == E_SSL_VERIFRES_SUCCESS) {
			ps_hsElem->s_sessElem.l_authId = ps_sslGut->l_pendCliAuthId;
		}

		else if ((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH)
				|| (ps_sslCtx->e_authLvl & E_SSL_SHOULD_AUTH)) {
			LOG_ERR("%p| Certificate can't be verified, stop handshake here",
					ps_sslCtx);
			ps_sslGut->e_alertType = E_SSL_ALERT_BAD_CERT;
			ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
			return E_PENDACT_SCACHE_RM;
		}

		else {
			LOG_WARN(
					"%p| Certificate can't be verified, but we continue " "since verification of the clients certificate " "is not mandatory",
					ps_sslCtx);
		}

		return (E_PENDACT_GEN_WAIT_EVENT);
	} /* case E_PENDACT_SRV_CERTVERIFY */
	case E_PENDACT_CLI_SRVCERTCHAIN: {
		/*
		 * Check if the certificate of the server was successfully verified
		 */
		E_SSL_VERIFRES *p_result = (E_SSL_VERIFRES*) pc_rec;
		if (*p_result != E_SSL_VERIFRES_SUCCESS) {
			if ((ps_sslCtx->e_authLvl & E_SSL_MUST_VERF_SRVCERT)
					== E_SSL_MUST_VERF_SRVCERT) {
				LOG_ERR(
						"%p| Certificate can't be verified, stop handshake here",
						ps_sslCtx);
				ps_sslGut->e_alertType = E_SSL_ALERT_UNKNOWN_CA;
				ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
				return E_PENDACT_SCACHE_RM;
			} /* if */
			else {
				LOG_WARN(
						"%p| Certificate can't be verified, but we continue " "since verification of the server certificate " "is not mandatory",
						ps_sslCtx);
			}
		} /* if */

		if (ps_sslGut->b_isComposite == FALSE) {
			return E_PENDACT_GEN_WAIT_EVENT;
		} /* if */
		break;
	} /* case E_PENDACT_CLI_SRVCERTCHAIN */
	default:
		break;
	} /* switch */

	/*
	 * Do processing of composite handshakes (multiple handshakes in one record)
	 * This happens only when client authentication is enabled and currently in process
	 * At this point we've just processed the certificate from the client and we must
	 * process the following handshake messages ClientKeyExchange(opt.)
	 * and CertificateVerify(mand.)
	 */
	if ((ps_sslCtx->b_isCli == FALSE) && (ps_sslGut->b_isComposite == TRUE)) {
		/* Process content of a composite Client authentication */
		if (ps_sslGut->e_smState == E_SSL_SM_WAIT_CLIENT_KEYEXCHANGE) {
			cwt_hsBuffLen = pc_hsBuff[2] * 256 + pc_hsBuff[3] + HS_HEADERLEN;
			if (*pc_hsBuff == CLIENT_KEY_EXCHANGE) {
				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff, cwt_hsBuffLen);

				LOG1_INFO("%p| Received CLIENT_KEY_EXCHANGE (composite)",
						ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);

				*cwt_wDataLen = loc_cpCompositeHs(ps_sslCtx, pc_wData,
						pc_hsBuff, cwt_hsBuffLen);

				ps_sslGut->e_smState = E_SSL_SM_WAIT_CLIENT_CERT_VERIFY;

				switch (ps_secPar->e_kst) {
				case en_gciKeyPairType_RSA:
					return E_PENDACT_ASYM_PKCS1_DECRYPT;
				case en_gciKeyPairType_DH:
					return E_PENDACT_ASYM_DHECALCSHARED;
				default:
					return E_PENDACT_GEN_WAIT_EVENT;
				} /* switch */
			} /* if */
			else {
				LOG1_ERR(
						"%p| CLIENT_KEY_EXCHANGE (composite) expected " "but not received",
						ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);
				return (E_PENDACT_GEN_WAIT_EVENT);
			} /* else */
		} else if (ps_sslGut->e_smState == E_SSL_SM_WAIT_CLIENT_CERT_VERIFY) {
			/*! we have to process the handshake buffer */
			pc_hsBuff = ps_hsElem->ac_hsBuf;
			/*! calculate length of former handshake(client key exchagne) */
			cwt_hsBuffLen = pc_hsBuff[2] * 256 + pc_hsBuff[3] + HS_HEADERLEN;
			/*! check if there's a message left or not */
			if (cwt_hsBuffLen + REC_HEADERLEN >= ps_hsElem->gci_hsBufLen) {
				ps_sslGut->b_isComposite = FALSE;
				LOG1_INFO("%p| Composite Handling finished", ps_sslCtx);
				return (E_PENDACT_GEN_WAIT_EVENT);
			} /* if */

			/*! step over client key exchange */
			pc_hsBuff += cwt_hsBuffLen; /* Start of next Handshake */
			/*! calculate length of certificate verify */
			cwt_hsBuffLen = pc_hsBuff[2] * 256 + pc_hsBuff[3] + HS_HEADERLEN;

			if (*pc_hsBuff == CERTIFICATE_VERIFY) {
				/* Compute the Verification Hashes */
				loc_compHash(ps_sslCtx, NULL, pc_wData);

				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff, cwt_hsBuffLen);

				LOG1_INFO("%p| CertVerify(composite)", ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);

				cwt_len = (pc_hsBuff[4] << 8) + pc_hsBuff[5];

				memcpy(pc_wData + VERIF_HASHSIZE, pc_hsBuff + 6, cwt_len);
				*cwt_wDataLen = cwt_len + VERIF_HASHSIZE;

				ps_sslGut->b_isComposite = FALSE;
				ps_sslGut->e_smState = E_SSL_SM_WAIT_CHANGE_CIPHERSPEC;

				return (E_PENDACT_ASYM_CERTVERIFY);
			} /* if */
			else {
				LOG1_INFO("%p| CertVerify(composite) expected but not received",
						ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);
				return (E_PENDACT_GEN_WAIT_EVENT);
			} /* else */
		} /* else if */
		else
			return (E_PENDACT_GEN_WAIT_EVENT);
	} /* if */

	/* Message is either Handshake, Change cipher spec, alert */
	switch (*pc_rec) {
	case E_SSL_RT_CHANGE_CIPSPEC: {
		uint8_t b_isMsSecNull = 0;
		uint8_t i = 0;

		TIME_STAMP(TS_RECEIVED_CCS);

		LOG1_INFO("%p| received ChangeCipherSpec", ps_sslCtx);

		/*
		 * Against TLS CCS injection (see CVE-2014-0224)
		 */
		for (i = 0; i < MSSEC_SIZE; i++) {
			b_isMsSecNull &= ps_hsElem->s_sessElem.ac_msSec[i];
		}

		if (!b_isMsSecNull) {
			/* Calculates the key material for the receive side using the master secret */
			loc_compKey(ps_sslCtx, ps_sslCtx->b_isCli);
			if (ps_sslCtx->b_isCli)
				ps_sslGut->e_smState = E_SSL_SM_WAIT_SERVER_FINISH;
			else
				ps_sslGut->e_smState = E_SSL_SM_WAIT_CLIENT_FINISH;

			/* Activate new Cipherspec */
			ps_sslGut->e_rxCipSpec = ps_sslGut->e_pendCipSpec;
			action = E_PENDACT_GEN_WAIT_EVENT;
		} else {
			ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
			ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
			action = E_PENDACT_COM_CIPHER_CLOSE;
		}

		break;
	}
		/* --------------------- ALERT ----------------------------- */
	case E_SSL_RT_ALERT: {

		TIME_STAMP(TS_RECEIVED_ALERT);

		/* "no certificate error" is only ignored if certificate is not mandatory */
		uint32_t l_blkLen = 0;
		if ((ps_sslCtx->e_ver > E_TLS_1_0)
				&& (ps_sslCtx->s_secParams.b_isBlkCip == TRUE)
				&& (ps_sslCtx->s_sslGut.e_rxCipSpec != TLS_UNDEFINED)) {
			l_blkLen = ps_sslCtx->s_secParams.c_blockLen;
		}
		LOG_INFO("%p| received %s Alert: %s", ps_sslCtx,
				(pc_rec[5 + l_blkLen] == 2) ? "fatal" : "warning",
				sslDiag_getAlert((e_sslAlertType_t )pc_rec[6 + l_blkLen]));
		if (pc_rec[6 + l_blkLen] == E_SSL_ALERT_NO_CERT) {
			if ((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH) != E_SSL_MUST_AUTH) {
				action = E_PENDACT_GEN_WAIT_EVENT;
				break;
			}
		}

		/* handle Close Notify Alert */
		if (pc_rec[6 + l_blkLen] == E_SSL_ALERT_CLOSE_NOTIFY) {
			/*
			 * In every case, do an insertion in the session cache
			 */
			action = E_PENDACT_SCACHE_INS;
#if SSL_WAIT_FOR_SHUTDOWN
			if( ps_sslGut->e_smState == E_SSL_SM_SHUTDOWN_SENT )
			{
				ps_sslGut->e_smState = E_SSL_SM_SHUTDOWN_COMPLETE;
				break;
			}
			ps_sslGut->e_alertType = E_SSL_ALERT_CLOSE_NOTIFY;
			ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
#else
			ps_hsElem->s_sessElem.e_cipSpec = ps_sslGut->e_txCipSpec;
			ps_hsElem->s_sessElem.e_lastUsedVer = ps_sslCtx->e_ver;
			ps_hsElem->s_sessElem.s_signAlg.c_sign =
					ps_secPar->s_signAlg.c_sign;
			ps_hsElem->s_sessElem.s_signAlg.c_hash =
					ps_secPar->s_signAlg.c_hash;
			ps_sslGut->e_smState = E_SSL_SM_SHUTDOWN_COMPLETE;
#endif
			break;
		}
		/* Ignore all warnings: Warning: 5th byte == 0 */
		if (pc_rec[5 + l_blkLen] == WARNING) {
			action = E_PENDACT_GEN_WAIT_EVENT;
			break;
		}

		ps_sslGut->e_alertType = E_SSL_ALERT_CLOSE_NOTIFY;
		/* ps_sslGut->e_smState = E_PENDACT_PROTOERR; */

		/* Session not longer useable for resumption E_PENDACT_SCACHE_RM */
		action = E_PENDACT_COM_CIPHER_CLOSE;
		break;
	}

		/* ------------------ E_PENDACT_HANDSHAKE ---------------------------- */

		/* A handshake record consists of one or more fields.
		 * Each field has a 4 byte long header, consisting of the field type
		 * and a 3 byte long length-field. Due to the fact that records longer than
		 * 16284 bytes are not supported, the first byte must be 0.
		 * Repeat until all E_PENDACT_HANDSHAKE-fields are processed */
	case E_SSL_RT_HANDSHAKE: {
		cwt_procRecBytes = REC_HEADERLEN;

		/* Repeat until all E_PENDACT_HANDSHAKE-fields are processed */
		do {
			pc_hsBuff = pc_rec + cwt_procRecBytes;
			if ((ps_sslCtx->e_ver > E_TLS_1_0)
					&& (ps_secPar->b_isBlkCip == TRUE)
					&& (ps_sslGut->e_rxCipSpec != TLS_UNDEFINED)) {
				pc_hsBuff += ps_sslCtx->s_secParams.c_blockLen;
			}
			/* pc_hsBuff points now to the first character of the handshake field */

			/* The entire fieldlen is needed (content plus 4 bytes header */
			cwt_hsBuffLen = pc_hsBuff[2] * 256 + pc_hsBuff[3] + HS_HEADERLEN;
			/* Byte pc_hsBuff[1] must be 0 and is therefore ignored */

			/*
			 * detect cases where a handshake message is split across
			 * multiple records and abort the handshake in these cases
			 */
			if (pc_hsBuff + cwt_hsBuffLen
					> pc_rec + (pc_rec[3] * 256 + pc_rec[4] + 5)) {
				LOG_ERR(
						"Received a handshake message that seems " "to be split across multiple records");

				/* abort handshake */
				ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
				return E_PENDACT_PROTOERR;
			}

			/* keep track of the end of the current handshake message */
			pc_hsBuffEnd = pc_hsBuff + cwt_hsBuffLen;

			switch (pc_hsBuff[0])
			/* This means the handshake-field type */
			{
			case HELLO_REQUEST:

				TIME_STAMP(TS_RECEIVED_HS_HELLO_REQ);

				LOG_INFO("%p| Received HELLO_REQUEST", ps_sslCtx);
				ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
				return E_PENDACT_PROTOERR;

			case CLIENT_HELLO: {
				uint8_t* pc_tmpRead;

				TIME_STAMP(TS_RECEIVED_HS_CLIENT_HELLO);

				/* This is SSLv3 client hello processing */
				LOG1_INFO("%p| Received CLIENT_HELLO", ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);

				if (ps_sslGut->e_smState != E_SSL_SM_WAIT_CLIENT_HELLO) {
					if (ps_sslGut->e_smState != E_SSL_SM_APPDATA_EXCHANGE) {
						LOG_ERR(
								"%p| E_PENDACT_PROTOERR, state should " "be WAIT_CLIENT_HELLO but state is %s",
								ps_sslCtx,
								sslDiag_getSMState(ps_sslGut->e_smState));

						/* send an unexpected_message alert */
						ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
						ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
						ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
						return E_PENDACT_SCACHE_RM;

					} /* if */
					else if (ps_sslCtx->c_isRenegOn == FALSE) {
						LOG_INFO(
								"%p| Client tries to renegotiate, but " "renegotiation has been disabled",
								ps_sslCtx);
						ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
						ps_sslGut->e_alertType = E_SSL_ALERT_NO_RENEG;
						ps_sslGut->e_smState = E_SSL_SM_SEND_WARN_ALERT;
						return E_PENDACT_SEND_WARNING;
					}
					LOG_INFO("%p| Client initiated renegotiation", ps_sslCtx);
				} /* if */
				/*
				 * Per default a session is marked as not resumable when receiving a client hello
				 */
				ps_sslCtx->c_isResumed = FALSE;

				/* make sure there are at least 39 bytes (= 4[header] +
				 * 2[version] + 32[random] + 1[Session ID length]) */
				if (pc_hsBuff + CLI_RANDSIZE + 7 > pc_hsBuffEnd) {
					LOG_ERR("ClientHello message too short");
					/* send decode_error alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_DECODE_ERR;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				/* Select the correct version out of the version we
				 * received.
				 */
				action = loc_selVer(ps_sslCtx, SSL_VERSION_READ(&pc_hsBuff[4]));
				if (action != 0) {
					return action;
				} /* if */

				/*
				 * Save the Client random.
				 */
				memcpy(ps_hsElem->ac_cliRand, pc_hsBuff + 6, CLI_RANDSIZE);

				/*
				 * Remember length of the Session ID
				 */
				cwt_len = pc_hsBuff[CLI_RANDSIZE + 6];

				/* make sure there are at least 39 + cwt_len bytes */
				if (pc_hsBuff + CLI_RANDSIZE + 7 + cwt_len > pc_hsBuffEnd) {
					LOG_ERR("ClientHello message too short");
					/* send decode_error alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_DECODE_ERR;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				//points on cipher suites length's first byte (of 2)
				pc_tmpRead = pc_hsBuff + (CLI_RANDSIZE + 7) + cwt_len;

				//Points on the compression method
				pc_tmpRead = pc_tmpRead + 2 + 256 * (*pc_tmpRead)
						+ *(pc_tmpRead + 1);

				//				/*
				//				 * Select a cipherspec out of the proposed ones
				//				 */
				//				//TODO vpy: choose ECC only if curves and point format from client are compatible with ours
				//				//pc_tmpRead points on the first element after the cipher suites list in the client hello
				//				pc_tmpRead = loc_matchCipherSpec(ps_sslCtx,
				//						pc_hsBuff + CLI_RANDSIZE + 7 + cwt_len, 0,
				//						pc_hsBuffEnd - pc_hsBuff + CLI_RANDSIZE + 7 + cwt_len); //fixme vpy: brackets missing in substraction ? pc_hsBuffEnd - (pc_hsBuff + CLI_RANDSIZE + 7 + cwt_len) ??
				//
				//				/* abort the handshake by sending an HandshakeFailure
				//				 * alert since we could find any cipher suite that is
				//				 * supported by both the client and the server */
				//				if (ps_sslGut->e_pendCipSpec == TLS_NULL_WITH_NULL_NULL) {
				//					LOG_ERR("Couldn't find any cipher suite supported "
				//							"by both client and server");
				//					ps_sslGut->e_alertType = E_SSL_ALERT_HANDSH_FAIL;
				//					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
				//					return E_PENDACT_SCACHE_RM;
				//				}
				//
				//
				//
				//				/*
				//				 * loc_matchCipherSpec returns only NULL if we're in c_secureReneg state
				//				 * and the client sent a TLS_EMPTY_RENEGOTIATION_INFO_SCSV
				//				 */
				//				if (pc_tmpRead == NULL)
				//				{
				//					LOG_ERR("%p| E_PENDACT_PROTOERR, we're in "
				//							"c_secReneg state and client sent a "
				//							"TLS_EMPTY_RENEGOTIATION_INFO_SCSV", ps_sslCtx);
				//					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
				//					return E_PENDACT_PROTOERR;
				//				} /* if */

				/*
				 * Sanitize the length of the Session ID, we can't handle other sizes
				 */
				if (cwt_len > SESSID_SIZE) {
					LOG_ERR(
							"Length of Session ID in ClientHello (%u " "bytes) larger than maximum (%u bytes)",
							cwt_len, SESSID_SIZE);
					/* send an illegal_parameter alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_ILLEGAL_PARAM;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				} /* if */

				/* make sure there are enough bytes left in
				 * buffer to read the compression methods list */
				if (pc_tmpRead + 1 > pc_hsBuffEnd) {
					LOG_ERR("ClientHello message too short");
					/* send decode_error alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_DECODE_ERR;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				/*
				 * pRead points to the compression methods (cm), jump over them
				 * | 0 | 1 | 2 |...
				 * |len|cm1|cm2|...
				 */
				pc_tmpRead += (*pc_tmpRead) + 1;

				/* make sure we didn't jump past the end of the buffer */
				if (pc_tmpRead > pc_hsBuffEnd) {
					LOG_ERR("ClientHello message too short");
					/* send decode_error alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_DECODE_ERR;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				if ((pc_hsBuff + cwt_hsBuffLen) > pc_tmpRead) {
					if (loc_processExtens(ps_sslCtx, pc_tmpRead,
							(pc_hsBuff + cwt_hsBuffLen)) < 0) {
						if ((ps_sslCtx->e_ver == E_TLS_1_1)
								|| (ps_sslCtx->e_ver == E_TLS_1_2)) {
							ps_sslGut->e_alertType = E_SSL_ALERT_UNSUP_EXT;
							ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
							return E_PENDACT_SCACHE_RM;
						} else {
							ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
							return E_PENDACT_PROTOERR;
						}

					} /* if */
				} /* if */

				/*
				 * Select a cipherspec out of the proposed ones
				 */
				//TODO vpy: choose ECC only if curves and point format from client are compatible with ours
				//pc_tmpRead points on the first element after the cipher suites list in the client hello
				pc_tmpRead = loc_matchCipherSpec(ps_sslCtx,
						pc_hsBuff + CLI_RANDSIZE + 7 + cwt_len, 0,
						pc_hsBuffEnd - pc_hsBuff + CLI_RANDSIZE + 7 + cwt_len); //fixme vpy: brackets missing in substraction ? pc_hsBuffEnd - (pc_hsBuff + CLI_RANDSIZE + 7 + cwt_len) ??

				/* abort the handshake by sending an HandshakeFailure
				 * alert since we could find any cipher suite that is
				 * supported by both the client and the server */
				if (ps_sslGut->e_pendCipSpec == TLS_NULL_WITH_NULL_NULL) {
					LOG_ERR(
							"Couldn't find any cipher suite supported " "by both client and server");
					ps_sslGut->e_alertType = E_SSL_ALERT_HANDSH_FAIL;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				/*
				 * loc_matchCipherSpec returns only NULL if we're in c_secureReneg state
				 * and the client sent a TLS_EMPTY_RENEGOTIATION_INFO_SCSV
				 */
				if (pc_tmpRead == NULL) {
					LOG_ERR(
							"%p| E_PENDACT_PROTOERR, we're in " "c_secReneg state and client sent a " "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
							ps_sslCtx);
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					return E_PENDACT_PROTOERR;
				} /* if */

				/*
				 * When the client initiated a renegotiation, create a new session ID
				 */
				if (ps_sslGut->e_smState == E_SSL_SM_APPDATA_EXCHANGE) {
					int i;
					for (i = 0; i < SESSID_SIZE; i++) {
						/* Mix actual SessionID and client random together */
						ps_hsElem->s_sessElem.ac_id[i] ^=
								(ps_hsElem->s_sessElem.ac_id[SESSID_SIZE - i]
										+ ps_hsElem->ac_cliRand[i]);
					} /* for */
					/*
					 * Prevent Session Resumption when renegotiating
					 */
					cwt_len = 0;
				} /* if */

				/*
				 * If a Session ID has been received, try to find it in the session cache
				 */
				if (cwt_len > 0) {
					memcpy(ps_hsElem->s_sessElem.ac_id, pc_hsBuff + 39,
							cwt_len);
					action = E_PENDACT_SCACHE_GET;
				}
				/*
				 * Otherwise create server hello immediately
				 */
				else {
					action = E_PENDACT_PROTORESPGEN;
				}

				ps_sslGut->e_smState = E_SSL_SM_SEND_SERVER_HELLO;

				/* Initialize the handshake hashes */
				loc_hash(E_HASHOP_INIT, ps_sslCtx, NULL, 0);

				/* Update the handshake hashes */
				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff, cwt_hsBuffLen);

				break; /* CLIENT_HELLO */
			}

			case SERVER_HELLO:

				TIME_STAMP(TS_RECEIVED_HS_SERVER_HELLO);

				if (ps_sslGut->e_smState != E_SSL_SM_WAIT_SERVER_HELLO) {
					LOG_ERR(
							"%p| E_PENDACT_PROTOERR, state should be " "WAIT_SERVER_HELLO but state is %s",
							ps_sslCtx,
							sslDiag_getSMState(ps_sslGut->e_smState));

					/* send an unexpected_message alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}
				/* Update the handshake hashes */
				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff, cwt_hsBuffLen);

				LOG1_INFO("%p| Received SERVER_HELLO", ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);

				/* make sure there are at least 38 bytes left in the
				 * buffer (= 4[Type + Length] + 2[Version] + 32[random]
				 * + 1[Session ID length]) */
				if (pc_hsBuff + SRV_RANDSIZE + 7 > pc_hsBuffEnd) {
					LOG_ERR("ServerHello message too short");
					/* send decode_error alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_DECODE_ERR;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				pc_hsBuff += 4; /* We jump over Type(1B) Length(3B) */

				if (*pc_hsBuff != 0x03) {
					LOG_ERR("%p| Version Error. Need Version %s, got %d.%d",
							ps_sslCtx, sslDiag_getVersion(ps_sslCtx->e_ver),
							*pc_hsBuff, pc_hsBuff[1]);
					ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
					return E_PENDACT_PROTOERR;
				}
				if (ps_sslCtx->e_ver == E_VER_DCARE) {
					e_sslVer_t tmpVersion = SSL_VERSION_READ(pc_hsBuff);

					if (tmpVersion < ps_sslCtx->ps_sslSett->e_minVer) {
						LOG_ERR("%p| %d.%d not allowed, minimum %s required",
								ps_sslCtx, *pc_hsBuff, pc_hsBuff[1],
								sslDiag_getVersion(
										ps_sslCtx->ps_sslSett->e_minVer));
						ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
						return E_PENDACT_PROTOERR;
					} else if (tmpVersion > ps_sslCtx->ps_sslSett->e_maxVer) {
						LOG_ERR("%p| %d.%d not allowed, maximum %s allowed",
								ps_sslCtx, *pc_hsBuff, pc_hsBuff[1],
								sslDiag_getVersion(
										ps_sslCtx->ps_sslSett->e_maxVer));
						ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
						return E_PENDACT_PROTOERR;
					} else {
						ps_sslCtx->e_ver = tmpVersion;
					}
				} else {
					if (SSL_VERSION_READ(pc_hsBuff) != ps_sslCtx->e_ver) {
						LOG_ERR("%p| Version Error. Need Version %s, got %d.%d",
								ps_sslCtx, sslDiag_getVersion(ps_sslCtx->e_ver),
								*pc_hsBuff, pc_hsBuff[1]);
						ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
						return E_PENDACT_PROTOERR;
					}
				}

				/*
				 * ToDo make this better, like the server?!?
				 */

				switch (ps_sslCtx->e_ver) {
				case E_SSL_3_0:
					ps_sslGut->c_verifyDataLen = VERIF_HASHSIZE;
					break;
				case E_TLS_1_0:
				case E_TLS_1_1:
					ps_sslGut->c_verifyDataLen = VERIF_HASHSIZE_TLS;
					break;
				case E_TLS_1_2:
					/* TODO TLS 1.2 ADD dependance on a cipher suite */
					ps_sslCtx->s_sslGut.c_verifyDataLen = VERIF_HASHSIZE_TLS;
					break;
				default:
					LOG_ERR(
							"%p| Version is not known, can't set " "c_verifyDataLen",
							ps_sslCtx);
					break;
				} /* switch */

				pc_hsBuff += 2;

				memcpy(ps_hsElem->ac_srvRand, pc_hsBuff, SRV_RANDSIZE);
				pc_hsBuff += SRV_RANDSIZE; /* We jump over ServerRandom(32B) */
				cwt_len = *pc_hsBuff++; /* We read ID len */
				if (cwt_len == 0) {
					ps_sslCtx->c_isResumed = FALSE;
					LOG1_INFO(
							"%p| No Session ID received! " "Resumption disabled.",
							ps_sslCtx);
				} else {

					/* make sure the Session ID is not longer
					 * than the message buffer */
					if (pc_hsBuff + cwt_len > pc_hsBuffEnd) {
						LOG_ERR("ServerHello message too short");
						/* send decode_error alert */
						ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
						ps_sslGut->e_alertType = E_SSL_ALERT_DECODE_ERR;
						ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
						return E_PENDACT_SCACHE_RM;
					}

					if (cwt_len > SESSID_SIZE) {
						LOG_ERR(
								"Length of Session ID in ServerHello (%u " "bytes) larger than maximum (%u bytes)",
								cwt_len, SESSID_SIZE);
						/* send an illegal_parameter alert */
						ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
						ps_sslGut->e_alertType = E_SSL_ALERT_ILLEGAL_PARAM;
						ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
						return E_PENDACT_SCACHE_RM;
					}
					if (ps_sslCtx->c_isResumed == TRUE) {
						if (memcmp(ps_hsElem->s_sessElem.ac_id, pc_hsBuff,
								cwt_len) != 0) {
							LOG1_INFO(
									"%p| Session ID received but not " "equal! Resumption disabled.",
									ps_sslCtx);
							LOG2_RAW("\nShould be:");
							LOG2_HEX(ps_hsElem->s_sessElem.ac_id, cwt_len);
							LOG2_RAW("is:");
							LOG2_HEX(pc_hsBuff, cwt_len);
							ps_sslCtx->c_isResumed = FALSE;
							memcpy(ps_hsElem->s_sessElem.ac_id, pc_hsBuff,
									cwt_len);
							ps_hsElem->s_sessElem.s_desc =
									sslSesCache_getNewSessId(
											ps_sslCtx->ps_sslSett->ps_sessCache);
						} /* if */
						else {
							LOG1_INFO(
									"%p| Session ID received! " "Resumption enabled.",
									ps_sslCtx);
						} /* else */
					} /* if */
					else {
						memcpy(ps_hsElem->s_sessElem.ac_id, pc_hsBuff, cwt_len);
					} /* else */
					pc_hsBuff += cwt_len;
				}

				/* make sure there is enough data in the message
				 * buffer to read the chosen cipher suite */
				if (pc_hsBuff + 2 > pc_hsBuffEnd) {
					LOG_ERR("ServerHello message too short");
					/* send decode_error alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_DECODE_ERR;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				/*
				 * Remember chosen e_cipSpec
				 * TODO: check for unknown/unsupported cipher suite (#1367)
				 */
				ps_sslGut->e_pendCipSpec = (e_sslCipSpec_t) ssl_readInteger(
						pc_hsBuff, 2);

				pc_hsBuff += 2;
				loc_setSecParams(ps_sslCtx, ps_sslGut->e_pendCipSpec);
				LOG1_INFO("%p| Received e_cipSpec: %s", ps_sslCtx,
						sslDiag_getCipherSuite(ps_sslGut->e_pendCipSpec));

				if (ps_sslCtx->c_isResumed == TRUE)
					ps_sslGut->e_smState = E_SSL_SM_WAIT_CHANGE_CIPHERSPEC;
				else
					ps_sslGut->e_smState = E_SSL_SM_WAIT_CERT;

				action = E_PENDACT_GEN_WAIT_EVENT;

				/* > at this point we are left to read compression_method
				 * and ServerHello extensions */

				/* move beyond compression_method field ignoring its
				 * value.
				 * TODO: we should cancel the handshake in case
				 * compression_method is not "none" */
				pc_hsBuff += 1;

				/* > pc_hsBuff now pointing to the beginning
				 * of the Hello extension list (if present) */

				LOG_INFO("Length of ServerHello extensions: %u bytes",
						pc_hsBuffEnd - pc_hsBuff);
				LOG_HEX_NAME("ServerHello extensions", pc_hsBuff,
						pc_hsBuffEnd - pc_hsBuff);

				//Extensions
				uint16_t extLength = (*pc_hsBuff) * 256 + *(pc_hsBuff + 1);
				pc_hsBuff += 2;
				//pc_hsBuff points now on first byte of extension

				//read extension type
				uint16_t i_tmp = ssl_readInteger(pc_hsBuff, 2);
				pc_hsBuff += 2;
				switch (i_tmp) {
				case TLS_EXTENSION_EC_POINT_FORMATS:

					//read length of extension
					i_tmp = ssl_readInteger(pc_hsBuff, 2);
					pc_hsBuff += 2;

					//read length of point formats
					i_tmp = ssl_readInteger(pc_hsBuff, 1);
					pc_hsBuff += 1;

					//pc_hsBuff points yet on the first byte of point format
					//should loop for each point format and check if 0 is availbable
					uint8_t i;
					uint8_t isOk = 0;
					for (i = 0; i < i_tmp; i++) {
						if (*pc_hsBuff == 0) {
							isOk = 1;
						}
						pc_hsBuff++;
					}
					//Problem: server doesn't support uncompressed point format. Should never happen
					if (isOk == 0) {
						LOG_ERR(
								"server doesn't support uncompressed point format");

						/* send an illegal_parameter alert */
						ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
						ps_sslGut->e_alertType = E_SSL_ALERT_ILLEGAL_PARAM;
						ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
						return E_PENDACT_SCACHE_RM;
					}
					break;

				default:
					//unrecognized extension
					break;
				}

				break; /* SERVER_HELLO */

			case CERTIFICATE:

				TIME_STAMP(TS_RECEIVED_HS_CERT);

				if (ps_sslGut->e_smState == E_SSL_SM_WAIT_CLIENT_CERTIFICATE) {
					/* Step 1: Test for one of the following situations:       */
					/*   - Record contains only this CERTIFICATE-Handshake     */
					/*   - Record contains                                     */
					/*      + CERTIFICATE-handshake                            */
					/*      + CLIENT_KEY_EXCHANGE-handshake                    */
					/*      + CERTIFICATE_VERIFIY-handshake                    */
					/*                                                         */
					/* Depending on the result the processing will be done:    */
					/*   - verifiy the certificate-chain directly              */
					/*   - save CLIENT_KEY_EXCHANGE (max 256 Bytes) and the    */
					/*     CERTIFICATE_VERIFY (max 256 Bytes) first (and flag  */
					/*     it) */
					ps_sslGut->b_isComposite = FALSE;

					/* Update the handshake hashes */
					loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff,
							cwt_hsBuffLen);

					LOG1_INFO("%p| Received CERTIFICATE(Client Authentication)",
							ps_sslCtx);
					LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);
					cwt_len = cwt_hsBuffLen - HS_HEADERLEN;

					/*
					 * If there are other handshake messages in this record, save them
					 */
					if (cwt_recLen - cwt_hsBuffLen > REC_HEADERLEN) {
						ps_sslGut->b_isComposite = TRUE;
						LOG1_INFO("%p| performing Composite Handling",
								ps_sslCtx);
						/* Save the 2 other handshakes for later use */
						if (cwt_recLen - cwt_hsBuffLen
								< ps_hsElem->gci_hsBufLen) {
							memcpy(ps_hsElem->ac_hsBuf,
									pc_hsBuff + cwt_hsBuffLen,
									cwt_recLen - cwt_hsBuffLen);
							ps_hsElem->gci_hsBufLen = cwt_recLen
									- cwt_hsBuffLen;
						} else {
							LOG_ERR("%p| E_PENDACT_PROTOERR", ps_sslCtx);
							action = E_PENDACT_PROTOERR;
							break;
						}
					}

					ps_sslGut->e_smState = E_SSL_SM_WAIT_CLIENT_KEYEXCHANGE;

					/*
					 * check if there's really a certificate
					 */
					if (ssl_readInteger(pc_hsBuff + HS_HEADERLEN, 3) > 0) {

						/* Move the Certificate to the output area */
						memmove(pc_wData, pc_hsBuff + HS_HEADERLEN, cwt_len);
						*cwt_wDataLen = cwt_len;

						/* Decode the certificate */
						ClientCert.pc_data = pc_wData + 6;
						ClientCert.cwt_len = cwt_len - 6;

						sslCert_decodeInit(&ps_sslGut->s_peerCertInfo,
								&ClientCert);

						sslCert_decodeCert(&ps_sslGut->s_peerCertInfo);

						sslCert_decodeTbsCert(&ps_sslGut->s_peerCertInfo);

						if (sslConf_certHook(ps_sslCtx,
								&ps_sslGut->s_peerCertInfo) != TRUE) {
							/* Customer did not accept the certificate */
							LOG_ERR("%p| Certificate was not accepted",
									ps_sslCtx);
							ps_sslGut->e_alertType = E_SSL_ALERT_BAD_CERT;
							ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
							return E_PENDACT_SCACHE_RM;
						}
						return E_PENDACT_ASYM_CLICERTCHAIN;
					} else {
						/*
						 * According to TLS 1.1 the client SHOULD
						 *           to TLS 1.2 the client MUST
						 * After a certificate_request, if no certificates are available,
						 * clients SHOULD/MUST send an empty certificate list.
						 */
						if ((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH)
								== E_SSL_MUST_AUTH) {
							/* refuse connection => send alert */
							/* Customer did not accept the certificate */
							LOG_ERR(
									"%p| Empty Certificate message was not accepted" " according to authentication behavior E_SSL_MUST_AUTH",
									ps_sslCtx);
							ps_sslGut->e_alertType = E_SSL_ALERT_HANDSH_FAIL;
							ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
							return E_PENDACT_SCACHE_RM;
						} else {
							/* client didn't present a certificate => don't care */
							action = E_PENDACT_GEN_WAIT_EVENT;
						}
					}
				} /* ps_sslGut->e_smState == E_SSL_SM_WAIT_CLIENT_CERTIFICATE */
				else if (ps_sslGut->e_smState == E_SSL_SM_WAIT_CERT) {
					/* Update the handshake hashes */
					loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff,
							cwt_hsBuffLen);

					LOG1_INFO("%p| Received CERTIFICATE", ps_sslCtx);
					/* TODO remove this line afterwards */
					LOG_INFO(
							"ac_hsBuf pointer = %p and hsBufLen = %zu " "local hsBuf = %p",
							ps_hsElem->ac_hsBuf, ps_hsElem->gci_hsBufLen,
							pc_hsBuff);
					LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);
					cwt_len = cwt_hsBuffLen - HS_HEADERLEN;

					/*
					 * Move the Certificate to the output area
					 */
					memmove(pc_wData, pc_hsBuff + HS_HEADERLEN, cwt_len);
					*cwt_wDataLen = cwt_len;

					if (ps_sslCtx->s_secParams.e_kst == en_gciKeyPairType_RSA) {
						if ((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH)
								== E_SSL_MUST_AUTH)
							ps_sslGut->e_smState = E_SSL_SM_WAIT_CERT_REQUEST;
						else
							ps_sslGut->e_smState =
									E_SSL_SM_WAIT_SERVER_HELLO_DONE;
					} else
						ps_sslGut->e_smState = E_SSL_SM_WAIT_SERVER_KEYEXCHANGE;

					action = E_PENDACT_ASYM_SRVCERTCHAIN;
				} else /* if(ps_sslGut->e_smState == E_SSL_SM_WAIT_CERT) */
				{
					LOG_ERR("%p| E_PENDACT_PROTOERR, state is %s", ps_sslCtx,
							sslDiag_getSMState(ps_sslGut->e_smState));

					/* send an unexpected_message alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}
				break; /* CERTIFICATE */

			case SERVER_KEY_EXCHANGE: {
				uint8_t* pc_pqy;
				uint8_t* pc_ecc;

				TIME_STAMP(TS_RECEIVED_HS_SRV_KEY_EX);

				/* => we just received the ServerKey-
				 * Exchange message from the server */

				if (ps_sslGut->e_smState != E_SSL_SM_WAIT_SERVER_KEYEXCHANGE) {
					LOG_ERR("Received unexpected ServerKeyExchange message");

					/* send an unexpected_message alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				/* Update the handshake hashes */
				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff, cwt_hsBuffLen);

				LOG1_INFO("%p| Received SERVER_KEY_EXCHANGE", ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);

				cwt_len = cwt_hsBuffLen - HS_HEADERLEN;
				pc_hsBuff += HS_HEADERLEN;

				//Depends of the cipher suite used
				switch (ps_secPar->e_kst) {
				//ECC
				case en_gciKeyPairType_ECDH:

					//store beginning of ECC parameter for signature verification (WTF?)
					pc_ecc = pc_hsBuff;
					LOG_INFO("cwt_len = %zu", cwt_len);

					//read curve type (1B)
					//In the current implementation, curve type MUST be "named curve" (0x03). If not, cancel handshake
					if (*pc_hsBuff != 0x3) {
						LOG_ERR("Received unexpected curve type: %zu",
								*pc_hsBuff);

						ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
						return (E_PENDACT_PROTOERR);
					}
					pc_hsBuff++;

					//read curve name (2B)
					//TODO vpy: Fusion with ps_secPar->eccChoosenCurve ?
					ps_hsElem->eccCurve = ssl_readInteger(pc_hsBuff, 2);
					pc_hsBuff += 2;

					//get supported curves
					size_t numberOfCurves;
					uint16_t supportedCurves[25]; //RFC4492, 5.1.1 Max 25 curves

					//OLD-CW: numberOfCurves = cw_ecc_getSupportedCurves(supportedCurves);
					err = gciGetInfo(en_gciInfo_CurveName, supportedCurves,
							&numberOfCurves);
					if (err != en_gciResult_Ok) {
						//TODO return state
					}

					uint8_t i;
					uint8_t isOk = 0;

					//Loop in all supported curves to look for correspondence with received curve
					for (i = 0; i < numberOfCurves; i++) {
						if (supportedCurves[i] == ps_hsElem->eccCurve) {
							isOk = 1;
						}
					}

					if (isOk != 1) {
						LOG_ERR("Received unsupported curve");

						ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
						return (E_PENDACT_PROTOERR);
					}

					//read curve length (1B)
					cwt_len = *pc_hsBuff;
					pc_hsBuff++;

					GciKeyId_t eccPubID;
					st_gciKey_t eccPub;

					//read/import pubkey from the buffer (ANSI x9.63)

					//Read the first byte to be sure he has the value 4, 6 or 7 (to be valid)
					if ((*pc_hsBuff != 4) && (*pc_hsBuff != 6)
							&& (*pc_hsBuff != 7)) {
						//TODO return state from error
					}

					pc_hsBuff++;

					//the x-coordinate has a length of the half of the public key's length
					eccPub.un_key.keyEcdhPub.coord.x.len = pc_hsBuff;

					pc_hsBuff++;

					memcpy(eccPub.un_key.keyEcdhPub.coord.x.data, pc_hsBuff,
							eccPub.un_key.keyEcdhPub.coord.x.len);

					pc_hsBuff += eccPub.un_key.keyEcdhPub.coord.x.len;

					//the y-coordinate has a length of the rest of the half of the public key's length
					eccPub.un_key.keyEcdhPub.coord.y.len = pc_hsBuff;

					pc_hsBuff++;

					memcpy(eccPub.un_key.keyEcdhPub.coord.y.data, pc_hsBuff,
							eccPub.un_key.keyEcdhPub.coord.y.len);

					pc_hsBuff += eccPub.un_key.keyEcdhPub.coord.y.len;

					//store the key to become an ID of it
					err = gciKeyPut(&eccPub, ps_hsElem->eccPubKeyPeer);
					if (err != en_gciResult_Ok) {
						//TODO return state from error
					}

//						OLD-CW: if(cw_ecc_import_public(pc_hsBuff, cwt_len, &(ps_hsElem->eccPubKeyPeer)) != CRYPT_OK)
//						if(err != GCI_OK)
//						{
//							LOG_ERR("Unable to import ECC PubKey of the peer");
//
//							ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
//							return (E_PENDACT_PROTOERR);
//						}

					//TODO sw - not sure that will work
					cwt_len = pc_hsBuff - pc_ecc;

					/* at first hash
					 * pc_pqy-> (ClientRandom, ServerRandom, DHParams)
					 * then encrypt hash with cwt_peerPubKey
					 * then compare with a received signature
					 * pc_hsBuff -> (signLen, signature)
					 * */

					if (loc_verifySign(ps_sslCtx, pc_ecc, cwt_len, pc_hsBuff,
							cwt_hsBuffLen - HS_HEADERLEN - cwt_len)
							!= E_SSL_NO_ERROR) {
						LOG_ERR("%p| E_PENDACT_PROTOERR, state is %s",
								ps_sslCtx,
								sslDiag_getSMState(ps_sslGut->e_smState));
						ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
						return (E_PENDACT_PROTOERR);
					} else {
						LOG_INFO(
								"Verification of signature of " "server DH parameters succeeded");
					}

					break;

					//NOT ECC (Diffie-Hellman)
				default:
					//OLD-CW: pc_pqy = pc_hsBuff;
					LOG_INFO("cwt_len = %zu", cwt_len);
					en_gciDhType_t dhType;
					st_gciKey_t srvPub;
					//TODO sw - reception of the public key of the server + generate of a dh key pair like below
//						OLD-CW: if (cw_dhe_import_make_privKey(pc_hsBuff, cwt_len,
//								&ps_hsElem->gci_dheCliPrivKey,
//								&ps_hsElem->gci_dheSrvPubKey,
//								&ps_hsElem->pgci_dheP) != CW_OK)
//						{
//							LOG_ERR("%p| E_PENDACT_PROTOERR, state is %s", ps_sslCtx,
//									sslDiag_getSMState(ps_sslGut->e_smState));
//							ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
//							return (E_PENDACT_PROTOERR);
//						}

					//import the datas
					//TODO sw - not sure it works -> compare with wireshark

					dhType = en_gciDhType_Dh;

					//Read the length of the prime
					srvPub.un_key.keyDhPub.param->p.len = pc_hsBuff;
					pc_hsBuff++;

					//Copy the prime data
					memcpy(srvPub.un_key.keyDhPub.param->p.data, pc_hsBuff,
							srvPub.un_key.keyDhPub.param->p.len);
					pc_hsBuff += srvPub.un_key.keyDhPub.param->p.len;

					//Read the length of the generator
					srvPub.un_key.keyDhPub.param->g.len = pc_hsBuff;

					pc_hsBuff++;

					//Copy the generator data
					memcpy(srvPub.un_key.keyDhPub.param->g.data, pc_hsBuff,
							srvPub.un_key.keyDhPub.param->g.len);
					pc_hsBuff += srvPub.un_key.keyDhPub.param->g.len;

					//Read the server public key length
					srvPub.un_key.keyDhPub.key.len = pc_hsBuff;
					pc_hsBuff++;

					//Copy the server public key
					memcpy(srvPub.un_key.keyDhPub.key.data, pc_hsBuff,
							srvPub.un_key.keyDhPub.key.len);

					pc_hsBuff += srvPub.un_key.keyDhPub.key.len;

					pc_hsBuff++;

					//Store the key and become an ID
					err = gciKeyPut(srvPub.un_key.keyDhPub.key.data,
							ps_hsElem->gci_dheSrvPubKey);
					if (err != en_gciResult_Ok) {
						//return error from state
					}

					/* jump over p */
//						pc_hsBuff += *pc_hsBuff * 256 + pc_hsBuff[1] + 2;
//						/* jump over q */
//						pc_hsBuff += *pc_hsBuff * 256 + pc_hsBuff[1] + 2;
//						/* jump over Ys */
//						pc_hsBuff += *pc_hsBuff * 256 + pc_hsBuff[1] + 2;
					/* this is the length of (p, q, Ys) for now */
					cwt_len = pc_hsBuff - pc_pqy;

					/* at first hash
					 * pc_pqy-> (ClientRandom, ServerRandom, DHParams)
					 * then encrypt hash with cwt_peerPubKey
					 * then compare with a received signature
					 * pc_hsBuff -> (signLen, signature)
					 * */

					if (loc_verifySign(ps_sslCtx, pc_pqy, cwt_len, pc_hsBuff,
							cwt_hsBuffLen - HS_HEADERLEN - cwt_len)
							!= E_SSL_NO_ERROR) {
						LOG_ERR("%p| E_PENDACT_PROTOERR, state is %s",
								ps_sslCtx,
								sslDiag_getSMState(ps_sslGut->e_smState));
						ps_sslCtx->e_lastError = E_SSL_ERROR_CRYPTO;
						return (E_PENDACT_PROTOERR);
					} else {
						LOG_INFO(
								"Verification of signature of " "server DH parameters succeeded");
					}
					break;
				}

				/* switch to next state */
				if ((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH) == E_SSL_MUST_AUTH)
					ps_sslGut->e_smState = E_SSL_SM_WAIT_CERT_REQUEST;
				else
					ps_sslGut->e_smState = E_SSL_SM_WAIT_SERVER_HELLO_DONE;
			}
				break; /* SERVER_KEY_EXCHANGE */

			case CERTIFICATE_REQUEST:

				TIME_STAMP(TS_RECEIVED_HS_CERT_REQ);

				if ((ps_sslGut->e_smState != E_SSL_SM_WAIT_SERVER_HELLO_DONE)
						&& (ps_sslGut->e_smState != E_SSL_SM_WAIT_CERT_REQUEST)) {
					LOG_ERR(
							"%p| E_PENDACT_PROTOERR, state should be " "WAIT_SERVER_HELLO_DONE or WAIT_CERT_REQUEST " "but state is %s",
							ps_sslCtx,
							sslDiag_getSMState(ps_sslGut->e_smState));

					/* send an unexpected_message alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}
				/* Update hash state */
				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff, cwt_hsBuffLen);

				/*
				 * Remember that we've received a CertificateRequest, because we MUST send
				 * (even an empty) Certificate message since TLS 1.1
				 */
				ps_sslGut->b_isCertReqReceived = TRUE;
				/*
				 * Reset the pointer to the last element that is required to be sent to do Client Authentication
				 */
				ps_sslCtx->ps_lastCliAuthCertChain = NULL;
				LOG1_INFO("%p| Received CERTIFICATE_REQUEST", ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);
				/*
				 * Check if there's a list of CA Certificates for Client Authentication
				 */
				if (ps_sslCtx->ps_sslSett->ps_certChainListHead == NULL) {
					if ((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH)
							== E_SSL_MUST_AUTH) {
						LOG_INFO(
								"%p| Received Certificate Request " "and we must authenticate, but no " "Client Certificate available",
								ps_sslCtx);
						return (E_PENDACT_PROTOERR);
					} else {
						LOG1_INFO(
								"%p| Received Certificate Request " "and no Client Certificate available, " "but we must not authenticate",
								ps_sslCtx);

						/* TODO: need to send an empty Certificate
						 * message for version >= TLS v1.2 */
					}
				} else {
					cwt_len = cwt_hsBuffLen - HS_HEADERLEN;
					pc_hsBuff += HS_HEADERLEN;
					ps_sslCtx->ps_lastCliAuthCertChain = sslConf_cmpCertReqList(
							ps_sslCtx,
							ps_sslCtx->ps_sslSett->ps_certChainListHead,
							pc_hsBuff, cwt_len);
					/*
					 * Check if there was a certificate in our chain that is supported by the server
					 */
					if (ps_sslCtx->ps_lastCliAuthCertChain == NULL) {
						if ((ps_sslCtx->e_authLvl & E_SSL_MUST_AUTH)
								== E_SSL_MUST_AUTH) {
							LOG_INFO(
									"%p| Received Certificate Request " "and we must authenticate, but our " "certificate can't be handled " "by the server",
									ps_sslCtx);
							return (E_PENDACT_PROTOERR);
						} else {
							LOG1_INFO(
									"%p| Received Certificate Request " "and our certificate can't be " "handled by the server, but we " "must not authenticate",
									ps_sslCtx);
						}
					}
				}
				ps_sslGut->e_smState = E_SSL_SM_WAIT_SERVER_HELLO_DONE;
				action = E_PENDACT_GEN_WAIT_EVENT;
				break; /* CERTIFICATE_REQUEST */

			case SERVER_HELLO_DONE:

				TIME_STAMP(TS_RECEIVED_HS_SRV_HELLO_DONE);

				if (ps_sslGut->e_smState != E_SSL_SM_WAIT_SERVER_HELLO_DONE) {
					LOG_ERR(
							"%p| E_PENDACT_PROTOERR, state should be " "WAIT_SERVER_HELLO_DONE but state is %s",
							ps_sslCtx,
							sslDiag_getSMState(ps_sslGut->e_smState));

					/* send an unexpected_message alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}
				/* Update hash state */
				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff, cwt_hsBuffLen);

				LOG1_INFO("%p| Received SERVER_HELLO_DONE", ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);
				cwt_len = cwt_hsBuffLen - HS_HEADERLEN;
				ps_sslGut->e_smState = E_SSL_SM_SEND_CLIENT_FINISH;
				ps_hsElem->s_sessElem.e_cipSpec = ps_sslGut->e_txCipSpec;
				ps_hsElem->s_sessElem.e_lastUsedVer = ps_sslCtx->e_ver;
				action = E_PENDACT_PROTORESPGEN;

				break; /* SERVER_HELLO_DONE */

			case CLIENT_KEY_EXCHANGE: {
				TIME_STAMP(TS_RECEIVED_HS_CLI_KEY_EX);

				switch (ps_sslCtx->e_authLvl) {
				case E_SSL_NO_AUTH:
				case E_SSL_SHOULD_AUTH:
				case E_SSL_MUST_VERF_SRVCERT:
				case E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_SHOULD_AUTH:
					if (ps_sslGut->e_smState != E_SSL_SM_WAIT_CLIENT_KEYEXCHANGE
							&& ps_sslGut->e_smState
									!= E_SSL_SM_WAIT_CLIENT_CERTIFICATE) {
						LOG_ERR(
								"%p| E_PENDACT_PROTOERR, state " "should be WAIT_CLIENT_KEYEXCHANGE/CERTIFICATE " "but state is %s",
								ps_sslCtx,
								sslDiag_getSMState(ps_sslGut->e_smState));

						/* send an unexpected_message alert */
						ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
						ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
						ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
						return E_PENDACT_SCACHE_RM;
					}
					break;

				default:
				case E_SSL_MUST_AUTH:
				case E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_MUST_AUTH:
					if (ps_sslGut->e_smState
							!= E_SSL_SM_WAIT_CLIENT_KEYEXCHANGE) {
						LOG_ERR(
								"%p| E_PENDACT_PROTOERR, state " "should be E_SSL_SM_WAIT_CLIENT_KEYEXCHANGE " "but state is %s",
								ps_sslCtx,
								sslDiag_getSMState(ps_sslGut->e_smState));

						/* send an unexpected_message alert */
						ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
						ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
						ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
						return E_PENDACT_SCACHE_RM;
					}
					break;
				}

				/* CLIENT_KEY_EXCHANGE indicates a client key exchange     */
				/* message. Premaster Secret, encrypted with server's      */
				/* public key */
				ps_sslGut->b_isComposite = FALSE;

				/* length is not fixed */
				/* Update hash state */
				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff, cwt_hsBuffLen);

				LOG1_INFO("%p| Received CLIENT_KEY_EXCHANGE", ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);

				*cwt_wDataLen = loc_cpCompositeHs(ps_sslCtx, pc_wData,
						pc_hsBuff, cwt_hsBuffLen);

				switch (ps_sslCtx->s_secParams.e_kst) {
				case en_gciKeyPairType_RSA:
					action = E_PENDACT_ASYM_PKCS1_DECRYPT;
					break;
				case en_gciKeyPairType_DH:
					action = E_PENDACT_ASYM_DHECALCSHARED;
					break;

				case en_gciKeyPairType_ECDH:
					action = E_PENDACT_ASYM_ECDHECALCSHARED;
					break;
				default:

					break;
				}

				ps_sslGut->e_smState = E_SSL_SM_WAIT_CLIENT_CERT_VERIFY;

				break; /* CLIENT_KEY_EXCHANGE */
			}
			case CERTIFICATE_VERIFY:

				TIME_STAMP(TS_RECEIVED_HS_CERT_VERIFY);

				if (ps_sslGut->e_smState != E_SSL_SM_WAIT_CLIENT_CERT_VERIFY) {
					LOG_ERR(
							"%p| E_PENDACT_PROTOERR, state should be " "WAIT_CLIENT_CERT_VERIFY but state is %s",
							ps_sslCtx,
							sslDiag_getSMState(ps_sslGut->e_smState));

					/* send an unexpected_message alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				LOG1_INFO("%p| Received CertificateVerify", ps_sslCtx);
				LOG2_HEX(pc_hsBuff, cwt_hsBuffLen);

				/* TG *//* Only for non composite handshake */
				/* This part must be updated to support browsers like OPERA */

				/* Compute the Verification Hashes
				 * sj quick hack! we need a buffer to save the verification hashes
				 * so we use the handshake buffer that isn't needed anymore
				 */
				loc_compHash(ps_sslCtx, NULL, ps_hsElem->ac_hsBuf);

				LOG1_INFO("%p| Expecting hash", ps_sslCtx);
				LOG2_HEX(ps_hsElem->ac_hsBuf,
						loc_getHashSizeByPrf(ps_sslCtx->s_secParams.e_prf));

				/* Update hash state */
				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff, cwt_hsBuffLen);

				if (ps_sslCtx->e_ver > E_TLS_1_1) {

					/* TODO: move this to asymmetric crypto */

					cwt_len = pc_hsBuff[6] * 256 + pc_hsBuff[7];

					/* In case of TLS 1.2 we have prepended hash oid */
					size_t sz_decSignLen = GCI_MAX_HASHSIZE_BYTES
							+ SSL_DER_ASN1_OID_HASH_MAX_LEN;
					uint8_t ac_decSign[sz_decSignLen];
					GciCtxId_t rsaCtx;
					st_gciSignConfig_t rsaConf;

					switch (pc_hsBuff[5]) {
					case en_gciSignAlgo_RSA:

						/* Decode signature using peers public key*/
						rsaConf.algo = en_gciSignAlgo_RSA;
						rsaConf.hash = en_gciHashAlgo_None;
						rsaConf.un_signConfig.signConfigRsa.padding = en_gciPadding_PKCS1;

						//RSA Public key of the client
						err = gciSignVerifyNewCtx(&rsaConf,
								ps_hsElem->gci_rsaCliPubKey, &rsaCtx);
						if (err != en_gciResult_Ok) {
							//TODO return state
						}

						err = gciSignUpdate(rsaCtx, pc_hsBuff + 8, cwt_len);
						if (err != en_gciResult_Ok) {
							//TODO return state
						}

						err = gciSignVerifyFinish(rsaCtx, ac_decSign,
								&sz_decSignLen);

						//OLD-CW: if (cw_rsa_sign_decode(pc_hsBuff + 8, cwt_len, ac_decSign, &sz_decSignLen, &ps_hsElem->gci_peerPubKey) != CW_OK)
						if (err != en_gciResult_Ok) {
							LOG_ERR("Failed to decode a signature");
							ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
							ps_sslGut->e_alertType = E_SSL_ALERT_BAD_CERT;
							ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
							return E_PENDACT_SCACHE_RM;
						}

						//Release the context
						err = gciCtxRelease(rsaCtx);
						if (err != en_gciResult_Ok) {
							//TODO return error from state
						}

						s_derdCtx_t s_derdCtx;
						e_derdRet_t e_derErr = E_SSL_DER_OK;
						s_sslOctetStr_t s_sigOctStr =
								{ .cwt_len = sz_decSignLen, .pc_data =
										ac_decSign, };

						if (sslDerd_initDecCtx(&s_derdCtx,
								&s_sigOctStr) == SSL_DER_ASN1_UNDEF) {
							LOG_ERR(
									"Failed to decode ASN.1 sequence" "representing the signature");
							ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
							ps_sslGut->e_alertType = E_SSL_ALERT_DECODE_ERR;
							ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
							return E_PENDACT_SCACHE_RM;
						} else {
							/* Check if we a re working with ASN.1 encoded sequence */
							if (s_derdCtx.c_tag != SSL_DER_ASN1_CSEQUENCE) {
								LOG_ERR(
										"Signature DER ASN.1 should start with Sequence identifier");
								e_derErr = E_SSL_DER_ERR_NO_CSEQUENCE;
							}

							/* Check if we a re working with ASN.1 encoded sequence */
							if ((e_derErr != E_SSL_DER_OK)
									|| (sslDerd_getNextValue(&s_derdCtx)
											!= SSL_DER_ASN1_CSEQUENCE)) {
								LOG_ERR(
										"Signature DER ASN.1 should start with Sequence identifier");
								e_derErr = E_SSL_DER_ERR_NO_CSEQUENCE;
							}

							if (e_derErr == E_SSL_DER_OK) {
								/* Currentlz we don't interested in hashAlg */
								sslDerd_getSign(&s_derdCtx, NULL, ac_decSign,
										&sz_decSignLen);

								LOG1_INFO("%p| Found hash", ps_sslCtx);
								LOG2_HEX(ac_decSign, sz_decSignLen);

							}

							*cwt_wDataLen = 1;
							if (memcmp(ps_hsElem->ac_hsBuf, ac_decSign,
									sz_decSignLen) == 0) {
								pc_wData[0] = 1;
							} else {
								pc_wData[0] = 0;
							}

						}

						break;
					case en_gciSignAlgo_DSA:
					case en_gciSignAlgo_None:
					default:
						ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
						ps_sslGut->e_alertType = E_SSL_ALERT_DECODE_ERR;
						ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
						return E_PENDACT_SCACHE_RM;
						break;
					}

				} else {

					cwt_len = pc_hsBuff[4] * 256 + pc_hsBuff[5];
					memcpy(ps_hsElem->ac_hsBuf + VERIF_HASHSIZE, pc_hsBuff + 6,
							cwt_len);
					*cwt_wDataLen = cwt_len + VERIF_HASHSIZE;
					memcpy(pc_wData, ps_hsElem->ac_hsBuf, *cwt_wDataLen);

				}

				/* Choose lowest authentication level */
				ps_hsElem->s_sessElem.l_authId = 0;

				ps_sslGut->b_isComposite = FALSE;
				ps_sslGut->e_smState = E_SSL_SM_WAIT_CHANGE_CIPHERSPEC;

				return (E_PENDACT_ASYM_CERTVERIFY);
				/* CERTIFICATE_VERIFY */

			case FINISHED: {
				TIME_STAMP(TS_RECEIVED_HS_FINISH);

				if ((ps_sslGut->e_smState != E_SSL_SM_WAIT_CLIENT_FINISH)
						&& (ps_sslGut->e_smState != E_SSL_SM_WAIT_SERVER_FINISH)) {
					LOG_ERR(
							"%p| E_PENDACT_PROTOERR, state should be " "WAIT_FOR_xx_FINISH but state is %s",
							ps_sslCtx,
							sslDiag_getSMState(ps_sslGut->e_smState));

					/* send an unexpected_message alert */
					ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
					ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
					ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
					return E_PENDACT_SCACHE_RM;
				}

				{
					uint8_t pc_hsHash[VERIF_HASHSIZE];

					/* since we are about to verify the FINISH message
					 * we just received we need to use the finish label
					 * of the peer => use !ps_sslCtx->b_isCli */
					lbl = loc_getFinLabel(ps_sslCtx, !ps_sslCtx->b_isCli);

					/* calculate the verification hash */
					loc_compHash(ps_sslCtx, lbl, pc_hsHash);

					if (memcmp(pc_hsHash, pc_hsBuff + HS_HEADERLEN,
							ps_sslCtx->s_sslGut.c_verifyDataLen) != 0) {
						/* According to the selected behavior, different responses
						 * in case of failure are possible:
						 * - Replay with an Alert record
						 * - select random key material and go on
						 */
						/* Session is not allowed for further resume: kill master secret */
						/* Calculate new random encryption material */

						/* TG */
						ssl_destroyKeys(ps_sslCtx);
						LOG_INFO(
								"%p| VerificationHashes in Finished " "not even!",
								ps_sslCtx);
					} else {
						if (ps_sslCtx->b_isCli == TRUE) {
							memcpy(ps_sslGut->ac_srvVerifyData, pc_hsHash,
									ps_sslGut->c_verifyDataLen);
						} else {
							memcpy(ps_sslGut->ac_cliVerifyData, pc_hsHash,
									ps_sslGut->c_verifyDataLen);
						}
					}
				}

				/* Hash in the client finished Handshake */
				loc_hash(E_HASHOP_UPDATE, ps_sslCtx, pc_hsBuff,
						ps_sslGut->c_verifyDataLen + HS_HEADERLEN);

				LOG1_INFO("%p| Received FINISHED", ps_sslCtx);
				LOG2_HEX(pc_hsBuff, ps_sslGut->c_verifyDataLen + HS_HEADERLEN);

				/* Save session data for resumption */
				if (ps_sslCtx->c_isResumed == FALSE) {
					if (ps_sslCtx->b_isCli == TRUE) {
						if (ps_secPar->c_useDheKey == TRUE) {
							km_dhe_releaseKey();
							ps_secPar->c_useDheKey = FALSE;
						}
						ps_sslGut->e_smState = E_SSL_SM_APPDATA_EXCHANGE;
						action = E_PENDACT_SCACHE_INS;
					} else {
						ps_hsElem->s_sessElem.e_cipSpec =
								ps_sslGut->e_txCipSpec;
						ps_hsElem->s_sessElem.e_lastUsedVer = ps_sslCtx->e_ver;
						ps_hsElem->s_sessElem.s_signAlg.c_sign =
								ps_secPar->s_signAlg.c_sign;
						ps_hsElem->s_sessElem.s_signAlg.c_hash =
								ps_secPar->s_signAlg.c_hash;
						ps_sslGut->e_smState = E_SSL_SM_SEND_SERVER_FINISH;
						action = E_PENDACT_SCACHE_INS;
					}
				} else {
					if (ps_sslCtx->b_isCli == TRUE) {
						ps_hsElem->s_sessElem.e_cipSpec =
								ps_sslGut->e_txCipSpec;
						ps_hsElem->s_sessElem.e_lastUsedVer = ps_sslCtx->e_ver;
						ps_hsElem->s_sessElem.s_signAlg.c_sign =
								ps_secPar->s_signAlg.c_sign;
						ps_hsElem->s_sessElem.s_signAlg.c_hash =
								ps_secPar->s_signAlg.c_hash;
						ps_sslGut->e_asmCtrl = E_SSL_ASM_STEP3;
						ps_sslGut->e_smState = E_SSL_SM_SEND_CLIENT_FINISH;
						action = E_PENDACT_SCACHE_INS;
					} else {
						ps_sslGut->e_smState = E_SSL_SM_APPDATA_EXCHANGE;
						action = E_PENDACT_GEN_WAIT_EVENT;
					}
				}
			}
				break; /* FINISHED */

			default:
				/* Failure */
				/* TG */
				LOG_ERR("%p| E_PENDACT_PROTOERR 0x%X unkown handshake " "type",
						ps_sslCtx, pc_hsBuff[0]);
				ps_sslCtx->e_lastError = E_SSL_ERROR_SM;
				action = E_PENDACT_PROTOERR;

				break;
			}

			cwt_procRecBytes += cwt_hsBuffLen;
		} while (cwt_procRecBytes < cwt_recLen);

		break;

		/* --------------------------------------------------------- */
	}
	default:

		if (ps_sslCtx->e_ver >= E_TLS_1_2) {
			/* For TLS >= v1.2: Send an "unexpected_message" alert */
			ps_sslGut->e_alertType = E_SSL_ALERT_UNEXP_MSG;
			ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
			action = E_PENDACT_SCACHE_RM;
			LOG_ERR("%p| E_PENDACT_SCACHE_RM", ps_sslCtx);
		} else {
			ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
			action = E_PENDACT_PROTOERR;
			LOG_ERR("%p| E_PENDACT_PROTOERR", ps_sslCtx);
		}

		break;
	}

	return (action);
}/* loc_protocolHand */

/***************************************************************************
 * Description follows here later
 *
 *
 ***************************************************************************/

static e_sslPendAct_t loc_smMacEncrypt(s_sslCtx_t * ps_sslCtx,
		uint8_t *pc_rawTxt, size_t cwt_rawTxtLen, uint8_t *pc_rec,
		size_t *pcwt_recLen, e_sslRecType_t e_recType) {
	size_t len;
	size_t cwt_maxLen = 0;
	uint32_t l_IVLen = 0;
	s_sslGut_t* ps_guts = NULL;
	s_sslSecParams_t* ps_secParams = NULL;
	//OLD-CW: gci_symCbcCtx*       cwt_cipCtx = NULL;
	GciCtxId_t cwt_cipCtx;

	st_gciCipherConfig_t ciphConf;

	en_gciResult_t err;

	assert(ps_sslCtx != NULL);
	assert(pc_rawTxt != NULL);
	assert(pc_rec != NULL);
	assert(pcwt_recLen != NULL);

	ps_guts = &ps_sslCtx->s_sslGut;
	ps_secParams = &ps_sslCtx->s_secParams;
	len = cwt_rawTxtLen;
	cwt_maxLen = sizeof(ps_sslCtx->ac_socBuf) - ps_sslCtx->l_buffLen;

	/* allow to prepend IVs if protocol version >= TLS v1.1
	 * and an active transmission cipher spec is in place */
	if ((ps_sslCtx->e_ver > E_TLS_1_0)
			&& (ps_guts->e_txCipSpec != TLS_UNDEFINED)) {
		l_IVLen = ps_sslCtx->s_secParams.c_blockLen;
	}

	if (pc_rawTxt != pc_rec) {
		memcpy(pc_rec + l_IVLen, pc_rawTxt, cwt_rawTxtLen);
	} else if (l_IVLen > 0) {
		memmove(pc_rec + l_IVLen, pc_rec, cwt_rawTxtLen);
	}
	pc_rec += l_IVLen;

	/* >>> assuming data starts at pc_rec + l_IVLen */

	LOG1_INFO("%p| Encrypting %zu bytes data using %s", ps_sslCtx, len,
			sslDiag_getCipherSuite(ps_guts->e_txCipSpec));
	LOG2_HEX(pc_rec, len);

	/* Encrypt the content depending on cipher-spec */
	switch (ps_guts->e_txCipSpec) {
	case TLS_RSA_WITH_RC4_128_MD5:

		len += loc_compMac(ps_sslCtx, pc_rec + len, cwt_maxLen, pc_rec, len,
				e_recType,
				SEND, ps_secParams->e_hmacType);

		TIME_STAMP(TS_STREAM_ENCRYPT_BEGIN);

		if (ps_sslCtx->b_isCli == TRUE) {
			//OLD-CW: cw_rc4(&ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx, pc_rec, pc_rec, len);
			ciphConf.algo = en_gciCipherAlgo_RC4;

			//no padding and block mode available for a stream cipher
			ciphConf.padding = en_gciPadding_Invalid;
			ciphConf.blockMode = en_gciBlockMode_Invalid;

			//keyID for the symmetric key (intern of the function) = cliRc4Ctx -> to get the key in loc_compKey
			err = gciCipherNewCtx(&ciphConf, -1,
					ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx);
			if (err != en_gciResult_Ok) {
				//TODO return state
			}

			err = gciCipherEncrypt(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx,
					pc_rec, sizeof(pc_rec), pc_rec, len);

			if (err != en_gciResult_Ok) {
				//TODO return state
			}

		} else {
			//OLD-CW: cw_rc4(&ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx, pc_rec, pc_rec, len);
			ciphConf.algo = en_gciCipherAlgo_RC4;

			//no padding and block mode available for a stream cipher
			ciphConf.padding = en_gciPadding_Invalid;
			ciphConf.blockMode = en_gciBlockMode_Invalid;

			//keyID for the symmetric key (intern of the function) = srvRc4Ctx -> to get the key in loc_compKey
			err = gciCipherNewCtx(&ciphConf, -1,
					ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx);
			if (err != en_gciResult_Ok) {
				//TODO return state
			}

			err = gciCipherEncrypt(ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx,
					pc_rec, sizeof(pc_rec), pc_rec, len);
			if (err != en_gciResult_Ok) {
				//TODO return state
			}

		}
		break;

		TIME_STAMP(TS_STREAM_ENCRYPT_END);

	case TLS_RSA_WITH_RC4_128_SHA:

		len += loc_compMac(ps_sslCtx, pc_rec + len, cwt_maxLen, pc_rec, len,
				e_recType,
				SEND, ps_secParams->e_hmacType);

		TIME_STAMP(TS_STREAM_ENCRYPT_BEGIN);

		if (ps_sslCtx->b_isCli == TRUE) {
			//OLD-CW: cw_rc4(&ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx, pc_rec, pc_rec, len);
			ciphConf.algo = en_gciCipherAlgo_RC4;

			//no padding and block mode available for a stream cipher
			ciphConf.padding = en_gciPadding_Invalid;
			ciphConf.blockMode = en_gciBlockMode_Invalid;


			if(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx != -1)
			{
				err = gciCtxRelease(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx);
				if(err != en_gciResult_Ok)
				{
					//Return error from state
				}
			}


			//keyID for the symmetric key (intern of the function) = cliRc4Ctx -> to get the key in loc_compKey
			err = gciCipherNewCtx(&ciphConf, -1,
					ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx);
			if (err != en_gciResult_Ok) {
				//TODO return state
			}

			err = gciCipherEncrypt(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx,
					pc_rec, sizeof(pc_rec), pc_rec, len);

			if (err != en_gciResult_Ok) {
				//TODO return state
			}
		} else {
			//OLD-CW: cw_rc4(&ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx, pc_rec, pc_rec, len);
			ciphConf.algo = en_gciCipherAlgo_RC4;

			//no padding and block mode available for a stream cipher
			ciphConf.padding = en_gciPadding_Invalid;
			ciphConf.blockMode = en_gciBlockMode_Invalid;


			if(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx != -1)
			{
				err = gciCtxRelease(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx);
				if(err != en_gciResult_Ok)
				{
					//Return error from state
				}
			}

			//keyID for the symmetric key (intern of the function) = srvRc4Ctx -> to get the key in loc_compKey
			err = gciCipherNewCtx(&ciphConf, -1, ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx);
			if (err != en_gciResult_Ok) {
				//TODO return state
			}

			err = gciCipherEncrypt(ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx,
					pc_rec, sizeof(pc_rec), pc_rec, len);
			if (err != en_gciResult_Ok) {
				//TODO return state
			}
		}

		TIME_STAMP(TS_STREAM_ENCRYPT_END);

		break;

#ifdef AES_AND_3DES_ENABLED
		//3DES
	case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
	case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
	case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		if (ps_sslCtx->b_isCli == TRUE) {
			cwt_cipCtx = &ps_sslCtx->s_secParams.u_cliKey.cli3DesCtx;
		} else {
			cwt_cipCtx = &ps_sslCtx->s_secParams.u_srvKey.srv3DesCtx;
		}

		//AES
	case TLS_RSA_WITH_AES_128_CBC_SHA:
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
	case TLS_RSA_WITH_AES_256_CBC_SHA:
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: //vpy
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: //vpy
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: //vpy
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: //vpy
		if ((ps_sslCtx->b_isCli == TRUE) && (cwt_cipCtx == -1)) //OLD-CW: (cwt_cipCtx == NULL)
				{
			cwt_cipCtx = &ps_sslCtx->s_secParams.u_cliKey.cliAesCtx;
		}

		else if (cwt_cipCtx == -1) //OLD-CW: (cwt_cipCtx == NULL)
				{
			cwt_cipCtx = &ps_sslCtx->s_secParams.u_srvKey.srvAesCtx;
		}

		len += loc_compMac(ps_sslCtx, pc_rec + len, cwt_maxLen, pc_rec, len,
				e_recType,
				SEND, ps_secParams->e_hmacType);

		len += loc_addPadding(ps_sslCtx, pc_rec, len,
				ps_sslCtx->s_secParams.c_blockLen);

		/* move write pointer to beginning of record payload
		 * and prepend IV in case protocol version >= TLS v1.1 */
		pc_rec -= l_IVLen;

		/* add IVs for versions >= TLS 1.1 here ?? */

		//OLD-CW: cw_prng_read(pc_rec, l_IVLen);
		err = gciRngGen(l_IVLen, pc_rec);
		if (err != en_gciResult_Ok) {
			//TODO return state
		}

		/* len += l_IVLen;*/

		pc_rec += l_IVLen;

		st_gciCipherConfig_t ciphConf;
		ciphConf.algo = en_gciCipherAlgo_AES;
		ciphConf.iv.len = l_IVLen;
		memcpy(ciphConf.iv.data, pc_rec - l_IVLen, l_IVLen);

		/* l_IVLen will only be different from 0 if protocol version >= TLS v1.1 */
		if (l_IVLen > 0) {
			//OLD-CW: cw_cbc_setiv(cwt_cipCtx, pc_rec - l_IVLen, l_IVLen);


			if(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx != -1)
			{
				err = gciCtxRelease(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx);
				if(err != en_gciResult_Ok)
				{
					//Return error from state
				}
			}

			//keyID for the symmetric key (intern of the function) = cwt_cipCtx -> to get the key in loc_compKey
			err = gciCipherNewCtx(&ciphConf, -1, &cwt_cipCtx);
			if (err != en_gciResult_Ok) {
				//TODO return state
			}
		}

		LOG2_INFO("%p| Data including MAC and padding", ps_sslCtx);
		LOG2_HEX(pc_rec, len);

		TIME_STAMP(TS_CBC_ENCRYPT_BEGIN);

		//OLD-CW: cw_cbc_encrypt(cwt_cipCtx, pc_rec, pc_rec, len);

		err = gciCipherEncrypt(cwt_cipCtx, pc_rec, sizeof(pc_rec), pc_rec,
				len);
		if (err != en_gciResult_Ok) {
			//TODO return state
		}

		TIME_STAMP(TS_CBC_ENCRYPT_END);

		break;

#endif

	default: /* Does include TLS_NULL_WITH_NULL_NULL (no Encryption) */
		break;
	}

	pc_rec -= l_IVLen;
	len += l_IVLen;

	if (ps_guts->e_txCipSpec != TLS_UNDEFINED) {
		LOG2_INFO("%p| Encrypted Data", ps_sslCtx);
		LOG2_HEX(pc_rec, len);
	}

#ifdef SSL_FORCE_PRNG_SEEDING
	if(len <= 32)
	{
		cw_prng_seed(pc_rec, len);
	}
#endif

	*pcwt_recLen = len;

	return (E_PENDACT_MSG_ASM);

} /* End of loc_smMacEncrypt */

/* *********************************************************************** */
/* *********************************************************************** */

static e_sslPendAct_t loc_smDecryptMacCheck(s_sslCtx_t * ps_sslCtx,
		uint8_t *pc_rawTxt, size_t *pcwt_rawTxtLen, uint8_t *pc_rec,
		size_t cwt_recLen) {
	size_t cwt_hashLen;
	uint32_t l_blkSize;
	s_sslGut_t *ps_sslGut;
	s_sslSecParams_t *ps_secParams;

	assert(ps_sslCtx != NULL);
	assert(pc_rawTxt != NULL);
	assert(pcwt_rawTxtLen != NULL);
	assert(pc_rec != NULL);

	uint8_t ac_hash[ps_sslCtx->s_secParams.c_hmacLen];
	cwt_hashLen = 0;
	l_blkSize = 0;
	ps_sslGut = &ps_sslCtx->s_sslGut;
	ps_secParams = &ps_sslCtx->s_secParams;

	en_gciResult_t err;

	LOG1_INFO("%p| Decrypting %zu bytes data using %s", ps_sslCtx,
			cwt_recLen - REC_HEADERLEN,
			sslDiag_getCipherSuite(ps_sslGut->e_rxCipSpec));
	LOG2_HEX(pc_rec, cwt_recLen);

#if DBG_SSL_BAD_RECORDS
	size_t reclen = cwt_recLen;
	memcpy(ac_badRecBuf, pc_rec, cwt_recLen);
#endif
	/* Decrypt the content depending on cipher-spec */
	//TODO vpy: support new cipher suites
	switch (ps_sslGut->e_rxCipSpec) {
	case TLS_RSA_WITH_RC4_128_MD5:

		TIME_STAMP(TS_STREAM_DECRYPT_BEGIN);

		if (ps_sslCtx->b_isCli == TRUE) {
			//OLD-CW: cw_rc4(&ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx, pc_rawTxt + REC_HEADERLEN, pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);

			err = gciCipherDecrypt(ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx,
					pc_rawTxt + REC_HEADERLEN,
					sizeof(pc_rawTxt + REC_HEADERLEN), pc_rec + REC_HEADERLEN,
					cwt_recLen - REC_HEADERLEN);

			if (err != en_gciResult_Ok) {
				//TODO return state
			}
		} else {
			//OLD-CW: cw_rc4(&ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx, pc_rawTxt + REC_HEADERLEN, pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);
			err = gciCipherDecrypt(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx,
					pc_rawTxt + REC_HEADERLEN,
					sizeof(pc_rawTxt + REC_HEADERLEN), pc_rec + REC_HEADERLEN,
					cwt_recLen - REC_HEADERLEN);
			if (err != en_gciResult_Ok) {
				//TODO return state
			}
		}

		TIME_STAMP(TS_STREAM_DECRYPT_END);

		cwt_hashLen += loc_compMac(ps_sslCtx, ac_hash,
				ps_sslCtx->s_secParams.c_hmacLen, pc_rawTxt + REC_HEADERLEN,
				cwt_recLen - REC_HEADERLEN - ps_sslCtx->s_secParams.c_hmacLen,
				pc_rec[0], RCVR, ps_secParams->e_hmacType);

		break;

		/* TODO: combine this with the previous case */
	case TLS_RSA_WITH_RC4_128_SHA:

		TIME_STAMP(TS_STREAM_DECRYPT_BEGIN);

		if (ps_sslCtx->b_isCli == TRUE) {
			//OLD-CW: cw_rc4(&ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx, pc_rawTxt + REC_HEADERLEN, pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);
			err = gciCipherDecrypt(ps_sslCtx->s_secParams.u_srvKey.srvRc4Ctx,
					pc_rawTxt + REC_HEADERLEN,
					sizeof(pc_rawTxt + REC_HEADERLEN), pc_rec + REC_HEADERLEN,
					cwt_recLen - REC_HEADERLEN);

			if (err != en_gciResult_Ok) {
				//TODO return state
			}
		} else {
			//OLD-CW: cw_rc4(&ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx, pc_rawTxt + REC_HEADERLEN, pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);

			err = gciCipherDecrypt(ps_sslCtx->s_secParams.u_cliKey.cliRc4Ctx,
					pc_rawTxt + REC_HEADERLEN,
					sizeof(pc_rawTxt + REC_HEADERLEN), pc_rec + REC_HEADERLEN,
					cwt_recLen - REC_HEADERLEN);

			if (err != en_gciResult_Ok) {
				//TODO return state
			}
		}

		TIME_STAMP(TS_STREAM_DECRYPT_END);

		cwt_hashLen = loc_compMac(ps_sslCtx, ac_hash,
				ps_sslCtx->s_secParams.c_hmacLen, pc_rawTxt + REC_HEADERLEN,
				cwt_recLen - REC_HEADERLEN - ps_sslCtx->s_secParams.c_hmacLen,
				pc_rec[0], RCVR, ps_secParams->e_hmacType);

		break;
#ifdef AES_AND_3DES_ENABLED
		/* Once again this cascading struct of switches
		 * caused by multi cryptlib support
		 */
	case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
	case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
	case TLS_RSA_WITH_AES_128_CBC_SHA:
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
	case TLS_RSA_WITH_AES_256_CBC_SHA:
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
	case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:  //vpy
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: //vpy
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: //vpy
	case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: //vpy
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: //vpy
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: //vpy
		switch (ps_sslGut->e_rxCipSpec) {
		//3DES
		case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
		case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:  //vpy
		case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: //vpy

			TIME_STAMP(TS_CBC_DECRYPT_BEGIN);

			if (ps_sslCtx->b_isCli == TRUE) {
				/* TODO: should catch encryption error */
				//OLD-CW: cw_cbc_decrypt(&ps_sslCtx->s_secParams.u_srvKey.srv3DesCtx, pc_rawTxt + REC_HEADERLEN, pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);
				err = gciCipherDecrypt(
						ps_sslCtx->s_secParams.u_srvKey.srv3DesCtx,
						pc_rawTxt + REC_HEADERLEN,
						sizeof(pc_rawTxt + REC_HEADERLEN),
						pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);
				if (err != en_gciResult_Ok) {
					//TODO return state
				}
			} else {
				/* TODO: should catch encryption error */
				//OLD-CW: cw_cbc_decrypt(&ps_sslCtx->s_secParams.u_cliKey.cli3DesCtx, pc_rawTxt + REC_HEADERLEN, pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);
				err = gciCipherDecrypt(
						ps_sslCtx->s_secParams.u_cliKey.cli3DesCtx,
						pc_rawTxt + REC_HEADERLEN,
						sizeof(pc_rawTxt + REC_HEADERLEN),
						pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);
				if (err != en_gciResult_Ok) {
					//TODO return state
				}

			}

			TIME_STAMP(TS_CBC_DECRYPT_END);

			break;

			//AES
		default:
			TIME_STAMP(TS_CBC_DECRYPT_BEGIN);

			if (ps_sslCtx->b_isCli == TRUE) {
				/* TODO: should catch encryption error */
				//OLD-CW: cw_cbc_decrypt(&ps_sslCtx->s_secParams.u_srvKey.srvAesCtx, pc_rawTxt + REC_HEADERLEN, pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);
				err = gciCipherDecrypt(
						ps_sslCtx->s_secParams.u_srvKey.srvAesCtx,
						pc_rawTxt + REC_HEADERLEN,
						sizeof(pc_rawTxt + REC_HEADERLEN),
						pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);
				if (err != en_gciResult_Ok) {
					//TODO return state
				}
			} else {
				/* TODO: should catch encryption error */
				//OLD-CW: cw_cbc_decrypt(&ps_sslCtx->s_secParams.u_cliKey.cliAesCtx, pc_rawTxt + REC_HEADERLEN, pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);
				err = gciCipherDecrypt(
						ps_sslCtx->s_secParams.u_cliKey.cliAesCtx,
						pc_rawTxt + REC_HEADERLEN,
						sizeof(pc_rawTxt + REC_HEADERLEN),
						pc_rec + REC_HEADERLEN, cwt_recLen - REC_HEADERLEN);

				if (err != en_gciResult_Ok) {
					//TODO return state
				}
			}
			TIME_STAMP(TS_CBC_DECRYPT_END);

			break;
		}

		LOG2_INFO("%p| Decrypted Data", ps_sslCtx);
		LOG2_HEX(pc_rawTxt, cwt_recLen);

		if (ps_sslCtx->e_ver > E_TLS_1_0)
			l_blkSize = ps_sslCtx->s_secParams.c_blockLen;

		cwt_recLen -= loc_rmPadding(ps_sslCtx, pc_rawTxt + REC_HEADERLEN,
				cwt_recLen - REC_HEADERLEN, l_blkSize);

		/* TODO: ignore result of loc_compMac if loc_rmPadding failed */

		cwt_hashLen = loc_compMac(ps_sslCtx, ac_hash,
				ps_sslCtx->s_secParams.c_hmacLen,
				pc_rawTxt + REC_HEADERLEN + l_blkSize,
				cwt_recLen - REC_HEADERLEN - ps_sslCtx->s_secParams.c_hmacLen
						- l_blkSize, pc_rec[0], RCVR, ps_secParams->e_hmacType);

		break;
#endif
	default: /* Does include TLS_NULL_WITH_NULL_NULL (no Encryption) */
		if (pc_rawTxt != pc_rec) {
			memmove(pc_rawTxt, pc_rec, cwt_recLen);
		}
		return (E_PENDACT_DISPATCH_MSG);
	}

	memmove(pc_rawTxt, pc_rec, REC_HEADERLEN);

	/* Check for MAC-Error */
	/* TODO: Don't assume cwt_recLen >= cwt_hashLen - l_blkSize !! */
	*pcwt_rawTxtLen = cwt_recLen - cwt_hashLen - l_blkSize;

	LOG2_INFO("%p| Decrypted Data", ps_sslCtx);
	LOG2_HEX(pc_rawTxt, cwt_recLen);

	LOG2_INFO("Checking MAC with length %u", cwt_hashLen);
	/* TODO: Use a constant-time version of memcmp for comparing cryptographic
	 * values (#1384) */
	if (memcmp(ac_hash, pc_rawTxt + *pcwt_rawTxtLen + l_blkSize, cwt_hashLen)
			!= 0) {
		LOG_ERR("%p| MAC-Check: Fail", ps_sslCtx);

		LOG_INFO("Expected:");
		LOG_HEX(ac_hash, cwt_hashLen);
		LOG_INFO("Received:");
		LOG_HEX(pc_rawTxt + *pcwt_rawTxtLen + l_blkSize, cwt_hashLen);

#if DBG_SSL_BAD_RECORDS
#if 0
		/* this is useful when the stzedn SSLconnector comes into operation to test */
		uint8_t c_char = *pc_rawTxt;
		uint8_t b_diff = FALSE;
		uint32_t i = 0;
		if(*pcwt_rawTxtLen > 16384)
		{
			b_diff = TRUE;
			i = *pcwt_rawTxtLen;
		}
		for(; (i < *pcwt_rawTxtLen) && (b_diff == FALSE); i++)
		{
			if(pc_rawTxt[i] != c_char)
			b_diff = TRUE;
			c_char++;
		}
		if(b_diff == FALSE)
		{
			SSL_DBG_PRINTF(SSL_DBG_STRING " But data was correct decrypted", DBG_FILE_NAME, __LINE__, ps_sslCtx);
		}
#endif

		SSL_DBG_PRINTF(SSL_DBG_STRING " %d bytes padding removed", DBG_FILE_NAME, __LINE__, ps_sslCtx, (reclen-cwt_recLen));

#if 0
		//creates possibly huge output :>
		SSL_DBG_PRINTF(DBG_STRING " Original Data", DBG_FILE_NAME, __LINE__);
		sslDiag_printHex(ac_badRecBuf, reclen);
		SSL_DBG_PRINTF(DBG_STRING " Decrypted Data", DBG_FILE_NAME, __LINE__);
		sslDiag_printHex(pc_rawTxt, cwt_recLen);
#else
		SSL_DBG_PRINTF(DBG_STRING " last 36bytes of Original Data", DBG_FILE_NAME, __LINE__);
		sslDiag_printHex(ac_badRecBuf + reclen - 36, 36);
#endif
		SSL_DBG_PRINTF(DBG_STRING " Hash Data from Record", DBG_FILE_NAME, __LINE__);
		sslDiag_printHex(pc_rawTxt + *pcwt_rawTxtLen + l_blkSize, cwt_hashLen);
		SSL_DBG_PRINTF(DBG_STRING " Hash Data we calculated", DBG_FILE_NAME, __LINE__);
		sslDiag_printHex(hash, cwt_hashLen);
		sslDiag_printSsl(ps_sslCtx, 1);
#endif /* DBG_SSL_BAD_RECORDS */

		ps_sslGut->e_alertType = E_SSL_ALERT_BAD_RECORD_MAC;
		ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
		return (E_PENDACT_SEND_FATAL_ERROR);
	} else {

		LOG2_INFO("MAC check was successful");

	}

	return (E_PENDACT_DISPATCH_MSG);
}

static e_sslPendAct_t loc_smLenVerCheck(s_sslCtx_t * ps_sslCtx) {
	e_sslPendAct_t ret = E_PENDACT_GEN_WAIT_EVENT;

	assert(ps_sslCtx != NULL);
	assert(ps_sslCtx->ac_socBuf != NULL);

	if (ps_sslCtx->l_buffLen >= HS_HEADERLEN) {
		int len;
		int is_SSLv2;

		len = sslRec_checkVerCompLen(ps_sslCtx, &is_SSLv2);

		/*
		 * The version that is set in the record does not fit
		 */
		if (len == -1) {
			LOG_ERR("%p| The version check was not successful", ps_sslCtx);
			ps_sslCtx->e_lastError = E_SSL_ERROR_VERSION;
			ret = E_PENDACT_PROTOERR;

		} else if (len == -2) {
			/* excessive record length */
			ps_sslCtx->s_sslGut.e_alertType = E_SSL_ALERT_UNEXP_MSG;
			ps_sslCtx->s_sslGut.e_smState = E_SSL_SM_SEND_FATAL_ALERT;
			ret = E_PENDACT_SEND_FATAL_ERROR;
		}
		/*
		 * The length of the record must be equal to the length of the buffer
		 */
		else if (len != ps_sslCtx->l_buffLen) {
			LOG_ERR(
					"%p| The length received isn't equal to the " "expected record length",
					ps_sslCtx);
			ps_sslCtx->e_lastError = E_SSL_ERROR_LENGTH;
			ret = E_PENDACT_COM_CIPHER_LENERROR;
		} /* else if */
		/*
		 * The received record is a SSL 2.0 Client Hello and must be handled otherwise
		 */
		else if (is_SSLv2 == 1) {
			ret = E_PENDACT_V2UPWARDHANDLER;
		}
		/*
		 * Check for valid Record type
		 * 0x14/0x15/0x16/0x17 & 0xFC will always be 0x14
		 */
		else if ((ps_sslCtx->ac_socBuf[0] & 0xFC) != 0x14) {
			LOG_ERR("%p| Received invalid record type %2X", ps_sslCtx,
					ps_sslCtx->ac_socBuf[0]);

			if (ps_sslCtx->e_ver >= E_TLS_1_2) {
				/* For TLS >= v1.2: Send an "unexpected_message" alert */
				ps_sslCtx->s_sslGut.e_alertType = E_SSL_ALERT_UNEXP_MSG;
				ps_sslCtx->s_sslGut.e_smState = E_SSL_SM_SEND_FATAL_ALERT;
				ret = E_PENDACT_SCACHE_RM;
			} else {
				ps_sslCtx->e_lastError = E_SSL_ERROR_PROTO;
				ret = E_PENDACT_PROTOERR;
			}
		} /* else if */
		else {
			ret = E_PENDACT_DECRYPT_MAC_CHECK;
		} /* else */
	} /* if */

	return ret;
}

/*** Global Functions *******************************************************/
/* Must be solved in an other way in the future: This prototype is
 * taken from pkcs1.c .... */

/*int ssl_verifyHash(const uint8_t rac_verHash[], size_t cwt_verHashLen,
 const uint8_t rac_sign[],    size_t cwt_sigLen,
 rpgci_rsaPubKey_t rpcw_pubKey)
 */
int ssl_verifyHash(const uint8_t rac_verHash[], size_t cwt_verHashLen,
		const uint8_t rac_sign[], size_t cwt_sigLen, GciKeyId_t pPubKey) {
	//OLD-CW: ci_bigNum_t *pcw_msg;
	st_gciBigInt_t *pcw_msg;
	//OLD-CW: gci_bigNum_t *pcw_sign;
	st_gciBigInt_t *pcw_sign;
	size_t cwt_modLen;
	size_t cwt_emLen;
	//OLD-CW: gci_rsaRet_t cwt_stat;
	uint8_t cwt_stat;
	uint8_t ac_encMsg[GCI_MAX_MSG_SIZE];

	en_gciResult_t err;

	st_gciKey_t rpcw_pubKey;

#ifdef TOMLIB_CRYPTO
	//OLD-CW: gci_bigNum_t M, S;
	//TODO sw - fixe the size of the buffers
	st_gciBigInt_t M[1024], S[1024];

	/* ****Example better than the use of malloc****
	 uint8_t var2[1024];
	 M.len = sizeof(var2);
	 M.data = var2;
	 */

	pcw_msg = &M;
	pcw_sign = &S;

	//OLD-CW: memset(pcw_msg, 0, sizeof(gci_bigNum_t));
	//OLD-CW: memset(pcw_sign, 0, sizeof(gci_bigNum_t));
	memset(pcw_msg, 0, sizeof(st_gciBigInt_t));
	memset(pcw_sign, 0, sizeof(st_gciBigInt_t));
#endif

	err = gciKeyGet(pPubKey, &rpcw_pubKey);
	if (err != en_gciResult_Ok) {
		//TODO return error from state
	}

	assert(rac_verHash != NULL);
	assert(rac_sign != NULL);
	assert(rpcw_pubKey.un_key.keyRsaPub.e.data != NULL);

#ifdef ASCOM_CRYPTO
	assert ((pPubKey->pE != NULL) &&
			(pPubKey->pN != NULL));
#elif defined (TOMLIB_CRYPTO)
	//assert((rpcw_pubKey->e != NULL) && (rpcw_pubKey->N != NULL));
	assert(
			(rpcw_pubKey.un_key.keyRsaPub.e.data != NULL) && (rpcw_pubKey.un_key.keyRsaPub.n.data != NULL));

#endif

	/* Get length of the modulus */
#ifdef ASCOM_CRYPTO
	ModLen = GetOctets (pPubKey->pN);
#elif defined (TOMLIB_CRYPTO)
	//OLD-CW: cwt_modLen = mp_unsigned_bin_size(rpcw_pubKey->N);
	rpcw_pubKey.un_key.keyRsaPub.n.len = sizeof(rpcw_pubKey.un_key.keyRsaPub.n.data);
#endif

	cwt_modLen = rpcw_pubKey.un_key.keyRsaPub.n.len;

	/* Check if the temporary buffer will be big enough */
	if (cwt_modLen > GCI_MAX_MSG_SIZE) {
		//return (CW_ERROR);
		return (en_gciResult_Err);
	}

	/* Message must be big enough to hold the encoded message */
	//OLD-CW: pcw_msg = cw_bn_create(pcw_msg, cwt_modLen * 8);
	//OLD-CW: pcw_sign = cw_bn_create(pcw_sign, cwt_modLen * 8);
	/* The signature must have the size of the modulus */
	if (cwt_sigLen != cwt_modLen) {
		//TODO SW - in this case the the size in the initiale buffer M or S
		//OLD-CW: cwt_stat = CW_ERROR;
		cwt_stat = en_gciResult_Err;
		goto loc_hashVerify_Error;
	}

	/* Convert the octet string to an integer */
	//OLD-CW: cw_rsa_os2ip(pcw_sign, (uint8_t*) rac_sign, cwt_sigLen);
	/* Make public key decryption (RSAVP1) */
	GciCtxId_t rsaCtx;
	st_gciSignConfig_t rsaConf;
	rsaConf.algo = en_gciSignAlgo_RSA;
	rsaConf.hash = en_gciHashAlgo_None;
	rsaConf.un_signConfig.signConfigRsa.padding = en_gciPadding_None;

	err = gciSignVerifyNewCtx(&rsaConf, pPubKey, &rsaCtx);
	if (err != en_gciResult_Ok) {
		//TODO return state
	}

	err = gciSignUpdate(rsaCtx, pcw_msg, sizeof(pcw_msg));
	if (err != en_gciResult_Ok) {
		//TODO return state
	}

	err = gciSignVerifyFinish(rsaCtx, pcw_sign->data, pcw_sign->len);
	if (err != en_gciResult_Ok) {
		//TODO return state
	}

	//Release the context
	err = gciCtxRelease(rsaCtx);

	if (err != en_gciResult_Ok) {
		//TODO return error from state
	}

	//OLD-CW: cwt_stat = cw_rsa_verify(pcw_msg, pcw_sign, rpcw_pubKey);

	//OLD-CW: if (cwt_stat != CW_OK)
	if (err != en_gciResult_Ok)
		goto loc_hashVerify_Error;

	/* Transform the integer to a string of length k-1 (Modulus-1) */
	cwt_emLen = cwt_modLen - 1;

//	OLD-CW: if (cw_rsa_i2osp(pcw_msg, cwt_emLen, ac_encMsg) == CW_ERROR)
//	{
//		cwt_stat = CW_ERROR;
//		goto loc_hashVerify_Error;
//	}

	/* Check if the message signature is correct */
	if (memcmp(ac_encMsg + cwt_emLen - VERIF_HASHSIZE, rac_verHash,
	VERIF_HASHSIZE) != 0) {
		//OLS-CW: cwt_stat = CW_ERROR;
		cwt_stat = en_gciResult_Err;
	} else {
		//OLD-CW: cwt_stat = CW_OK;
		cwt_stat = en_gciResult_Ok;
	}

	/* No special error handling done here */
	loc_hashVerify_Error:

//	OLD-CW: cw_bn_free(pcw_sign);
//	OLD-CW: cw_bn_free(pcw_msg);

	return (cwt_stat);

} /* End of ssl_verifyHash */

/***************************************************************************
 * ssl_serverFSM : Implementation of the SSLv3 server protocol machine
 ***************************************************************************/
/*!
 *   \brief   Implementation of the SSLv3 server protocol machine
 *
 *            Ausfuehrliche Beschreibung
 *
 *   \param   ps_sslCtx pointer to the current SSL conetxt
 *   \param   uiEvent
 *
 *   \return
 */

e_sslPendAct_t ssl_serverFSM(s_sslCtx_t *ps_sslCtx, e_sslPendAct_t e_event,
		uint8_t *pc_eventData, size_t cwt_eventDataLen, uint8_t *pc_actData,
		size_t *pcwt_actDataLen) {
	e_sslPendAct_t e_action;

	uint8_t *pc_recStart;
	uint8_t *pc_rData;
	uint8_t *pc_wDataStart;
	uint8_t *pc_wDataEnd;

	size_t cwt_rDataLen;
	size_t cwt_wDataLen;

	uint8_t b_finRec;

	/*had to initialize to calm compiler */
	e_sslRecType_t e_recordType = E_SSL_RT_NOTEXIST;

	s_sslGut_t *ps_sslGut;
	s_sslHsElem_t *ps_hsElem;

	en_gciResult_t err;

	assert(ps_sslCtx != NULL);
	assert(pc_eventData != NULL);
	assert(pc_actData != NULL);
	assert(pcwt_actDataLen != NULL);

	ps_sslGut = &ps_sslCtx->s_sslGut;
	ps_hsElem = ps_sslCtx->ps_hsElem;

	/* Start Codesection */
	pc_rData = pc_eventData;
	cwt_rDataLen = cwt_eventDataLen;

	cwt_wDataLen = 0;

	pc_wDataStart = pc_actData + REC_HEADERLEN; /* Acts as a writepointer */
	pc_recStart = pc_actData;
	pc_wDataEnd = pc_actData;

	b_finRec = FALSE;

	/* Mapping an external event to an internal event */
	switch (e_event) {
	/* Process record from the communication interface */
	case E_PENDACT_SRV_RECORD:
		e_action = loc_smLenVerCheck(ps_sslCtx);
		break;

		/* Process response from the application */
	case E_PENDACT_SRV_APPRESP:
		if (ps_sslGut->e_smState != E_SSL_SM_APPDATA_EXCHANGE) {
			LOG_ERR("%p| E_PENDACT_PROTOERR", ps_sslCtx);
			e_action = E_PENDACT_PROTOERR;
			break;
		}

		if (pc_eventData != pc_actData) {
			memmove(pc_actData, pc_eventData, cwt_eventDataLen);
		}

		e_recordType = E_SSL_RT_APPDATA;
		e_action = E_PENDACT_MAC_ENCRYPT_HANDSHAKE;

		cwt_wDataLen = cwt_eventDataLen - REC_HEADERLEN;
		ps_sslGut->e_asmCtrl = E_SSL_ASM_FINISH;
		break; /* O.K. */

		/* Process result of the public key verification of an encrypted       */
		/* verify hash */
	case E_PENDACT_SRV_CERTVERIFY:
		/* Process result of client cert chain check */
	case E_PENDACT_SRV_CLICERTCHAIN:

	case E_PENDACT_CLI_SRVCERTCHAIN:

	case E_PENDACT_CLI_PKCS1_ENCRYPT:
		/* Process result from the private key decryption */
	case E_PENDACT_SRV_PKCS1_DECRYPT:

	case E_PENDACT_SRV_DHECALCSHARED:
	case E_PENDACT_SRV_ECDHECALCSHARED:
		e_action = E_PENDACT_PROTOHANDLER;
		break;

		/* Generate a warning record */
	case E_PENDACT_SRV_WARNING:
		ps_sslGut->e_alertType = (e_sslAlertType_t) pc_eventData[0];
		ps_sslGut->e_smState = E_SSL_SM_SEND_WARN_ALERT;
		e_action = E_PENDACT_SEND_WARNING;
		break;

		/* Generate a fatal error */
	case E_PENDACT_SRV_FATAL_ERROR:
		ps_sslGut->e_alertType = (e_sslAlertType_t) pc_eventData[0];
		ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
		e_action = E_PENDACT_SEND_FATAL_ERROR;
		break;

	case E_PENDACT_SRV_SCACHE:
		switch (ps_sslGut->e_smState) {
		case E_SSL_SM_SEND_SERVER_FINISH:
		case E_SSL_SM_SEND_SERVER_HELLO:
		case E_SSL_SM_SEND_SERVER_HELLO_FINISH:
		case E_SSL_SM_SEND_WARN_ALERT:
		case E_SSL_SM_SEND_FATAL_ALERT:
		case E_SSL_SM_SEND_SHUTDOWN:
		case E_SSL_SM_SEND_CLIENT_HELLO:
		case E_SSL_SM_SEND_CLIENT_FINISH:
			e_action = E_PENDACT_PROTORESPGEN;
			break;
		case E_SSL_SM_SHUTDOWN_SENT:
		case E_SSL_SM_SHUTDOWN_COMPLETE:
			e_action = E_PENDACT_COM_CIPHER_CLOSE;
			break;
		default:
			LOG_ERR("%p| E_PENDACT_PROTOERR in state %s", ps_sslCtx,
					sslDiag_getSMState(ps_sslGut->e_smState));
			e_action = E_PENDACT_PROTOERR;
			break;
		}

		break;

		/* Event not supported */
	default:
		LOG_ERR("%p| E_PENDACT_PROTOERR, Event: %i", ps_sslCtx, e_event);
		e_action = E_PENDACT_PROTOERR;
		break;
	}

	while (e_action > E_PENDACT_EXTERNAL_ACTION) {
		/* Process internal actions as long as there is no external event reached.
		 * External events are handled by external services
		 */
		switch (e_action) {
		case E_PENDACT_DECRYPT_MAC_CHECK:
			e_action = loc_smDecryptMacCheck(ps_sslCtx, pc_eventData,
					&cwt_eventDataLen, pc_eventData, cwt_eventDataLen);
			break; /* O.K. */

			/* This is the SSL_RecordTypeDispatcher */
		case E_PENDACT_DISPATCH_MSG:
			if (pc_eventData[0] == E_SSL_RT_APPDATA) {
				memmove(pc_actData, pc_eventData, cwt_eventDataLen);
				*pcwt_actDataLen = cwt_eventDataLen;
				e_action = E_PENDACT_APP_REQUEST;
			} else {
				e_action = E_PENDACT_PROTOHANDLER;
			}
			break; /* O.K. */

		case E_PENDACT_V2UPWARDHANDLER:
			/* FIXME check for length inside this function */
			/*e_action = loc_v2UpwardHandler(ps_sslCtx, pc_eventData, cwt_eventDataLen);*/
			e_action = E_PENDACT_PROTOHANDLER;
			break;

		case E_PENDACT_PROTOHANDLER:
			cwt_wDataLen = *pcwt_actDataLen; /*! WAMs DevNote: Wieso 2000?  TG: space left */
			e_action = loc_protocolHand(ps_sslCtx, e_event, pc_eventData,
					cwt_eventDataLen, pc_recStart, &cwt_wDataLen);

			*pcwt_actDataLen = cwt_wDataLen;
			break;

		case E_PENDACT_SEND_WARNING:
		case E_PENDACT_SEND_FATAL_ERROR:
		case E_PENDACT_PROTORESPGEN:
			e_action = loc_protocolResp(ps_sslCtx, pc_wDataStart, &cwt_wDataLen,
					pc_rData, cwt_rDataLen);

			e_recordType = ps_sslGut->e_recordType;
			break;

			/* Generate a entire record, which is finished */
		case E_PENDACT_MAC_ENCRYPT_REC:
			b_finRec = TRUE;
			/* Fall through to E_PENDACT_MAC_ENCRYPT_HANDSHAKE */
			/*! WAMs DevNote: Ist es richtig, dass es hier kein break hat? TG Ja! */

		case E_PENDACT_MAC_ENCRYPT_HANDSHAKE:

			LOG2_INFO("Data to encrypt before calling loc_smMacEncrypt:");
			LOG2_HEX(pc_wDataStart, cwt_wDataLen);

			/* Calculate MAC, Encrypt Message */
			e_action = loc_smMacEncrypt(ps_sslCtx, pc_wDataStart, cwt_wDataLen,
					pc_wDataStart, &cwt_wDataLen, e_recordType);

			/* Dont fall through. Therefore error handling is possible */
			pc_wDataStart += cwt_wDataLen;
			pc_wDataEnd = pc_wDataStart;

			(void) loc_buildRecordHeader(ps_sslCtx, pc_recStart,
					pc_wDataStart - pc_recStart - REC_HEADERLEN, e_recordType);

			if (b_finRec == TRUE) {
				pc_recStart = pc_wDataStart;
				pc_wDataStart += REC_HEADERLEN;
				b_finRec = FALSE;
			}
			break; /* O.K. */

		case E_PENDACT_MSG_ASM:
			/* Uses writePointer to handle more than 1 record in one message */
			if (ps_sslGut->e_asmCtrl == E_SSL_ASM_FINISH) {
				*pcwt_actDataLen = pc_wDataEnd - pc_actData;

				e_action = E_PENDACT_COM_CIPHER_TX;
				ps_sslGut->e_asmCtrl = E_SSL_ASM_START;
				if (ps_sslGut->e_smState == E_SSL_SM_SEND_FATAL_ALERT) {
					e_action = E_PENDACT_COM_CIPHER_TXCLOSE;
				}
			} else {
				e_action = E_PENDACT_PROTORESPGEN;
			}
			break; /* O.K. */

		case E_PENDACT_PROTOERR:
			ps_sslGut->e_alertType = E_SSL_ALERT_HANDSH_FAIL;
			ps_sslGut->e_smState = E_SSL_SM_SEND_FATAL_ALERT;
			e_action = E_PENDACT_SEND_FATAL_ERROR;
			break;

		case E_PENDACT_PKCS1_DECRYPT:
			/* Premastersecret -> MasterSecret */

			loc_prf(ps_sslCtx, pc_rData, MSSEC_SIZE, rac_TLSlabelMsSec,
					strlen((const char *) rac_TLSlabelMsSec),
					ps_hsElem->ac_cliRand, CLI_RANDSIZE, ps_hsElem->ac_srvRand,
					SRV_RANDSIZE, ps_hsElem->s_sessElem.ac_msSec,
					MSSEC_SIZE);

			if (ps_sslGut->b_isComposite == FALSE)
				e_action = E_PENDACT_GEN_WAIT_EVENT;
			else
				e_action = E_PENDACT_PROTOHANDLER;
			break;

		case E_PENDACT_PKCS1_ENCRYPT:
			/* Premastersecret -> MasterSecret */

			loc_prf(ps_sslCtx, ps_hsElem->s_sessElem.ac_msSec, MSSEC_SIZE,
					rac_TLSlabelMsSec, strlen((const char *) rac_TLSlabelMsSec),
					ps_hsElem->ac_cliRand, CLI_RANDSIZE, ps_hsElem->ac_srvRand,
					SRV_RANDSIZE, ps_hsElem->s_sessElem.ac_msSec, MSSEC_SIZE);

			LOG_INFO("Client random");
			LOG_HEX(ps_hsElem->ac_cliRand, 32);

			LOG_INFO("Server random");
			LOG_HEX(ps_hsElem->ac_srvRand, 32);

			LOG_INFO("Master secret");
			LOG_HEX(ps_hsElem->s_sessElem.ac_msSec, 48);

			e_action = E_PENDACT_MAC_ENCRYPT_REC;

			break;
		default:
			return (e_action); /* Handle externaly */
		}
	}

	return (e_action);
}/* ssl_serverFSM() */

/* Some util functions not only used for SSL
 * ...
 */

/*! WAMs DevNote: Keine spezifische SSL Funktion  TG: Support Function evtl. in Memory integrieren */
/* *********************************************************************** */
/* *********************************************************************** */
/* *********************************************************************** */
/* *********************************************************************** */

/* Binary data search algorithm (according to "brutesearch" from Sedgewick: Algorithms in C) */

uint16_t CL_MemSearch(uint8_t *memory, uint16_t memoryLen, uint8_t *pattern,
		uint16_t patternLen) {
	uint16_t i, j;

	assert(memory != NULL);
	assert(pattern != NULL);

	for (i = 0; i < memoryLen; i++) {
		for (j = 0; j < patternLen; j++) {
			if (memory[i + j] != pattern[j])
				break;
		}

		if (j == patternLen) {
			return (i);
		}
	}

	return (i);
}

/****************************************************************************/
/* ssl_initCtx()                                                 */
/****************************************************************************/
int ssl_initCtx(s_sslCtx_t * ps_sslCtx, s_sslSett_t *ps_sslSett,
		s_sslHsElem_t *ps_sslHsElem) {

	assert(ps_sslCtx != NULL);
	assert(ps_sslHsElem != NULL);
	assert(ps_sslSett != NULL);

	en_gciResult_t err;

	/* Clear the memory space of the context */
	memset(ps_sslCtx, 0x00, sizeof(s_sslCtx_t));

	/* Add the SSL application context and the memory buffer for the handshake */
	/* phase to the connection context. */
	ps_sslCtx->ps_sslSett = ps_sslSett;
	ps_sslCtx->ps_hsElem = ps_sslHsElem;

	/* Wait for client hello message */
	ps_sslCtx->s_sslGut.e_smState = E_SSL_SM_WAIT_INIT;

	ps_sslCtx->s_sslGut.e_pendCipSpec = TLS_UNDEFINED;
	ps_sslCtx->s_sslGut.e_rxCipSpec = TLS_UNDEFINED;
	ps_sslCtx->s_sslGut.e_txCipSpec = TLS_UNDEFINED;

	ps_sslCtx->s_sslGut.b_isCertReqReceived = FALSE;
	ps_sslCtx->s_sslGut.b_isComposite = FALSE;

	memset(ps_sslCtx->s_sslGut.ae_cipSpecs, 0,
			sizeof(ps_sslCtx->s_sslGut.ae_cipSpecs));
#ifdef AES_AND_3DES_ENABLED
	ps_sslCtx->s_sslGut.ae_cipSpecs[0] = TLS_RSA_WITH_AES_256_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[1] = TLS_RSA_WITH_AES_256_CBC_SHA256;
	ps_sslCtx->s_sslGut.ae_cipSpecs[2] = TLS_RSA_WITH_AES_128_CBC_SHA256;
	ps_sslCtx->s_sslGut.ae_cipSpecs[3] = TLS_RSA_WITH_AES_128_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[4] = TLS_RSA_WITH_3DES_EDE_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[5] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
	ps_sslCtx->s_sslGut.ae_cipSpecs[6] = TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
	ps_sslCtx->s_sslGut.ae_cipSpecs[7] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[8] = TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[9] = TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[10] = TLS_RSA_WITH_RC4_128_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[11] = TLS_RSA_WITH_RC4_128_MD5;
	//begin vpy
	ps_sslCtx->s_sslGut.ae_cipSpecs[12] = TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[13] = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[14] = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[15] = TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[16] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[17] = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
	//end vpy
#else
	ps_sslCtx->s_sslGut.ae_cipSpecs[0] = TLS_RSA_WITH_RC4_128_SHA;
	ps_sslCtx->s_sslGut.ae_cipSpecs[1] = TLS_RSA_WITH_RC4_128_MD5;
#endif

	memset(ps_sslCtx->s_sslGut.ac_cliSeqNum, 0, 8);
	memset(ps_sslCtx->s_sslGut.ac_srvrSeqNum, 0, 8);

	/* Fill some variables with random noise */
	(void) sslConf_rand(ps_sslHsElem->ac_srvRand, SRV_RANDSIZE);
	(void) sslConf_rand(ps_sslHsElem->ac_cliRand, CLI_RANDSIZE);
	(void) sslConf_rand(ps_sslHsElem->s_sessElem.ac_msSec, MSSEC_SIZE);
	(void) sslConf_rand(ps_sslHsElem->s_sessElem.ac_id, SESSID_SIZE);
	ps_sslHsElem->s_sessElem.e_lastUsedVer = E_VER_DCARE;
	//OLD-CW: ps_sslHsElem->pgci_dheP.data = NULL;
	//OLD-CW: ps_sslHsElem->pgci_dheP.len = 0;

	/*
	 * Fetch a new session identifier
	 */
	ps_sslHsElem->s_sessElem.s_desc = sslSesCache_getNewSessId(
			ps_sslSett->ps_sessCache);

	//sw - this is not a function to generate a key
	//OLD-CW: cw_rsa_publickey_init(&ps_sslHsElem->gci_peerPubKey);

	ps_sslHsElem->gci_hsBufLen = SSL_HANDSHAKE_BUFFER_SIZE;

	/* Initialise default security parameters */

	ps_sslCtx->s_secParams.e_prf = E_SSL_PRF_UNDEF;

	ps_sslCtx->s_secParams.e_kst = en_gciKeyPairType_None;

	ps_sslCtx->s_secParams.s_signAlg.c_hash = en_gciHashAlgo_Invalid;

	ps_sslCtx->s_secParams.s_signAlg.c_sign = en_gciSignAlgo_Invalid;

	ps_sslCtx->e_authLvl = ps_sslSett->e_authLvl;

	ps_sslCtx->c_isRenegOn = ps_sslSett->c_isRenegOn;

	ps_sslCtx->read = ps_sslSett->fp_stdRead;

	ps_sslCtx->write = ps_sslSett->fp_stdWrite;

	return (E_SSL_OK);
}

/* *********************************************************************** */
/* *********************************************************************** */
/* *******  Util functions for SSL use ********************************** */
/* *********************************************************************** */
/* *********************************************************************** */

/* *********************************************************************** */

/* Generates a given numbers of 4,3,2 or 1 bytes long length information
 * in the given buffer area */

uint8_t *ssl_writeInteger(uint8_t *pucBuffer, uint32_t ulLen, int iBytes) {
	/* Optimisation: use a union for conversion from UI32 to bytes, depends on endianess */

	union {
		uint32_t ul32;
		struct ui32 {
#if __USER_LITTLE_ENDIAN == TRUE
			uint8_t c0, c1, c2, c3; /* LSB comes first in memory */
#elif __USER_BIG_ENDIAN == TRUE
		uint8_t c3,c2,c1,c0; /* MSB comes first in memory */
#endif
	} c32;
} ui32toByte;

ui32toByte.ul32 = ulLen;

switch (iBytes) {
case 4:
	*pucBuffer++ = ui32toByte.c32.c3;
case 3:
	*pucBuffer++ = ui32toByte.c32.c2;
case 2:
	*pucBuffer++ = ui32toByte.c32.c1;
case 1:
	*pucBuffer++ = ui32toByte.c32.c0;
default:
	break;
}

return (pucBuffer);
}

uint32_t ssl_readInteger(uint8_t *pucBuffer, int iBytes) {
/* Optimisation: use a union for conversion from UI32 to bytes, depends on endianess */

union {
	uint32_t ul32;
	struct ui32 {
#if __USER_LITTLE_ENDIAN == TRUE
		uint8_t c0, c1, c2, c3; /* LSB comes first in memory */
#elif __USER_BIG_ENDIAN == TRUE
	uint8_t c3,c2,c1,c0; /* MSB comes first in memory */
#endif
} c32;
} ui32toByte = { 0 };

switch (iBytes) {
case 4:
ui32toByte.c32.c3 = *pucBuffer++;
case 3:
ui32toByte.c32.c2 = *pucBuffer++;
case 2:
ui32toByte.c32.c1 = *pucBuffer++;
default:
ui32toByte.c32.c0 = *pucBuffer++;
break;
}

return ui32toByte.ul32;
}

/* *********************************************************************** */
/* *********************************************************************** */
/* *********************************************************************** */
/* *********************************************************************** */

/* ***********************************************************************
 * loc_getCliAuthID
 *
 * Delivers the customer defined identifier for the client authentication
 * *********************************************************************** */

uint32_t ssl_getCliAuthID(s_sslCtx_t * ps_sslCtx) {
return (ps_sslCtx->ps_hsElem->s_sessElem.l_authId);
}
