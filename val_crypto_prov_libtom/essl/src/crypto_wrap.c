/*============================================================================*/
/*!
 \file   crypto_wrap.c

 \author ??? by STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  Wrapper for all supported crypto libraries

 \version  $Version$

 */
/*============================================================================*/

/*==============================================================================
 INCLUDE FILES
 =============================================================================*/
#include <stdlib.h>
#include "crypto_wrap.h"
#include "ssl_certHandler.h"
#include "ssl.h"
#include "ssl_diag.h"
#include "ssl_oid.h"
#include "netGlobal.h"
#ifdef ASCOM_CRYPTO
#include "ssl_record.h"
#elif defined(TOMLIB_CRYPTO)
#include "ssl_target.h"
#include "ssl_certHelper.h"
#include "ssl_record.h"
#include "tomcrypt.h"
#if HARDWARE_AES
#include "aes.h"
#endif
#endif
#if _SYS_HAS_MALLOC_H_
#include <malloc.h>
#endif


/*==============================================================================
 MACROS
 =============================================================================*/
#ifndef DBG_FILE_NAME
/*! For debugging CW_DBG_PRINTF() use this name as file name. */
#define DBG_FILE_NAME "crypto_wrap.c"
#endif

#if !defined(CW_DBG_PRINTF)
#include <stdio.h>
#include <stdarg.h>
#define CW_DBG_PRINTF(msg, ...)  do { if (DBG_CRYPT_WRAP) printf("%s:%d:(%s): " msg,__FILE__,__LINE__, __func__, ##__VA_ARGS__); }while (0)
#endif

#define	LOGGER_ENABLE		DBG_SSL_CW_MODULE
#include "logger.h"

#if DBG_CRYPT_WRAP && _SYS_HAS_MALLOC_H_
#else
#define CW_PRINT_MEM_ERR
#endif
/*==============================================================================
 ENUMS
 =============================================================================*/

/*==============================================================================
 STRUCTURES AND OTHER TYPEDEFS
 =============================================================================*/

/*==============================================================================
 LOCAL VARIABLE DECLARATIONS
 =============================================================================*/
#ifdef TOMLIB_CRYPTO
static prng_state fortuna_prng;
static int fortunaIdx;
#endif

/*==============================================================================
 LOCAL CONSTANTS
 =============================================================================*/

/*==============================================================================
 LOCAL FUNCTION PROTOTYPES
 =============================================================================*/
#if HARDWARE_AES
static int hw_aes_128_encrypt(const char* p_data, char* p_out, char* p_key);
static int hw_aes_encrypt(const unsigned char* pt, unsigned char* ct, unsigned long len, unsigned char* IV, symmetric_key* key);
static int hw_aes_128_decrypt(const unsigned char* p_data, unsigned char* p_out, char* p_key);
#endif
/*==============================================================================
 LOCAL FUNCTIONS
 =============================================================================*/

/*==============================================================================
 API FUNCTIONS
 =============================================================================*/
/*============================================================================*/
/*  cw_mem_printUsage()                                                       */
/*============================================================================*/
void cw_mem_printUsage(void)
{
#if DBG_SSL || DBG_CRYPT_WRAP
#if _SYS_HAS_MALLOC_H_
    struct mallinfo s_info = mallinfo();

    CW_DBG_PRINTF("\nMemory allocated with malloc(): %d bytes, free memory: %d\n", s_info.uordblks, s_info.fordblks);

    malloc_stats();
#else
    static int cw_mem_printUsage_once = 1;
    if(cw_mem_printUsage_once)
    {
        CW_DBG_PRINTF("\nMacro _SYS_HAS_MALLOC_H_ is set to 0, so it is assumed that malloc.h is not available");
        cw_mem_printUsage_once = 0;
    }
#endif /* _SYS_HAS_MALLOC_H_ */
#endif /* DBG_SSL || DBG_CRYPT_WRAP */
} /* cw_mem_printUsage() */

/*============================================================================*/
/*  cw_memcopy()                                                              */
/*============================================================================*/
void* cw_memcopy(void *dest, const void *src, int n)
{
#if DBG_CRYPT_WRAP
    if(n < 0)
    {
        CW_DBG_PRINTF(DBG_STRING" memcpy error", DBG_FILE_NAME, __LINE__);
        n = 0;
    }
    else if(n > SSL_TLS_MAX_PLAINTEXTLEN)
    CW_DBG_PRINTF(DBG_STRING" memcpy of %i bytes", DBG_FILE_NAME, __LINE__, n);
#endif

    return MEMCPY(dest, src, n);
} /* cw_memcopy() */

/*============================================================================*/
/*  cw_argchk()                                                               */
/*============================================================================*/
void cw_argchk(char *v, char *s, int d)
{
#if DBG_SSL || DBG_CRYPT_WRAP
    CW_DBG_PRINTF("\ncw_argchk '%s' failure on line %d of file %s", v, d, s);
#endif
} /* cw_argchk() */

/*============================================================================*/
/*  cw_error2string()                                                         */
/*============================================================================*/
const char* cw_error2string(int err)
{
    const char* s_err;
#ifdef ASCOM_CRYPTO

    s_err = "Not implemented for ASCOM Crypto lib";

#elif defined(TOMLIB_CRYPTO)

    s_err = error_to_string(err);

#endif

    return s_err;
} /* cw_error2string() */

/*============================================================================*/
/*  cw_crypto_init()                                                          */
/*============================================================================*/
void cw_crypto_init(void)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)
    int ret;

    ltc_mp = ltm_desc;

    if (register_hash(&md5_desc) == -1)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error registering MD5.", DBG_FILE_NAME, __LINE__);
#endif
    }
    ret = md5_test();
    if ((ret != CRYPT_OK) && (ret != CRYPT_NOP))
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error testing MD5.", DBG_FILE_NAME, __LINE__);
#endif
    }
    if (register_hash(&sha1_desc) == -1)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error registering SHA1.", DBG_FILE_NAME, __LINE__);
#endif
    }
    ret = sha1_test();
    if ((ret != CRYPT_OK) && (ret != CRYPT_NOP))
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error testing SHA1.", DBG_FILE_NAME, __LINE__);
#endif
    }
    if (register_hash(&sha256_desc) == -1)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error registering SHA256.", DBG_FILE_NAME, __LINE__);
#endif
    }
    ret = sha256_test();
    if ((ret != CRYPT_OK) && (ret != CRYPT_NOP))
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error testing SHA256.", DBG_FILE_NAME, __LINE__);
#endif
    }
    if (register_prng(&fortuna_desc) == -1)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error registering fortuna", DBG_FILE_NAME, __LINE__);
#endif
    }
    ret = fortuna_test();
    if ((ret != CRYPT_OK) && (ret != CRYPT_NOP))
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error testing fortuna.", DBG_FILE_NAME, __LINE__);
#endif
    }
    if (register_prng(&rc4_desc) == -1)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error registering RC4", DBG_FILE_NAME, __LINE__);
#endif
    }
    ret = rc4_test();
    if ((ret != CRYPT_OK) && (ret != CRYPT_NOP))
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error testing RC4.", DBG_FILE_NAME, __LINE__);
#endif
    }
   if (register_cipher(&des3_desc) == -1)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error registering 3DES", DBG_FILE_NAME, __LINE__);
#endif
    }
    ret = des3_test();
    if ((ret != CRYPT_OK) && (ret != CRYPT_NOP))
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error testing 3DES.", DBG_FILE_NAME, __LINE__);
#endif
    }
    if (register_cipher(&aes_desc) == -1)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error registering AES", DBG_FILE_NAME, __LINE__);
#endif
    }
    ret = aes_test();
    if ((ret != CRYPT_OK) && (ret != CRYPT_NOP))
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" Error testing AES.", DBG_FILE_NAME, __LINE__);
#endif
    }

#if HARDWARE_AES
    cipher_descriptor[find_cipher(CR_AES_NAME)].accel_cbc_encrypt = hw_aes_encrypt;
#endif

#ifdef CW_HW_AES_TEST
    _aes_test();
#endif

#endif

    return;
} /* cw_crypto_init() */

/*==============================================================================
 PKI
 =============================================================================*/

/*============================================================================*/
/*  cw_publickey_free()                         	  						  */
/*============================================================================*/
int cw_publickey_init(Key_t* p_pubKey)
{
	assert(p_pubKey!=NULL);
	int16_t err;

	switch(p_pubKey->type)
	{
	case KEY_ECC_PUB:
		err=cw_ecc_publickey_init(&p_pubKey->key.eccPub);
		break;

	case KEY_RSA_PUB:
		err=cw_rsa_publickey_init(&p_pubKey->key.rsaPub);
		break;

	default: //We don't know the type of key we need to initialize.

		break;
	}
	return err;
}

/*============================================================================*/
/*  cw_publickey_free()                         	  						  */
/*============================================================================*/
int cw_publickey_free(Key_t* p_pubKey)
{
	assert(p_pubKey != NULL);

	switch(p_pubKey->type)
	{
	case KEY_ECC_PUB:
		cw_ecc_free(&p_pubKey->key.eccPub);
		p_pubKey->type=KEY_NONE;
		return 0;
		break;

	case KEY_RSA_PUB:
		cw_rsa_publickey_free(&p_pubKey->key.rsaPub);
		p_pubKey->type=KEY_NONE;
		return 0;
		break;

	default: //Should never happen
		p_pubKey->type=KEY_NONE;
		return -1;
		break;
	}
}









/*============================================================================*/
/*  cw_ecc_cw_ecc_convert_curveName_curveNumery()                         	  */
/*============================================================================*/
int16_t cw_ecc_convert_curveName_curveNumer(char* curveName)
{
	if(strcmp(curveName, "SECP160R1")==0)	return 16;
	else if(strcmp(curveName, "SECP192R1")==0)	return 19;
	else if(strcmp(curveName, "SECP224R1")==0)	return 21;
	else if(strcmp(curveName, "SECP256R1")==0)	return 23;
	else if(strcmp(curveName, "SECP384R1")==0)	return 24;
	else if(strcmp(curveName, "SECP521R1")==0)	return 25;
	else if(strcmp(curveName, "BRAINPOOLP256R1")==0)	return 26;
	else if(strcmp(curveName, "BRAINPOOLP384R1")==0)	return 27;
	else if(strcmp(curveName, "BRAINPOOLP512R1")==0)	return 28;
	else return -1;
}
/*============================================================================*/
/*  cw_ecc_makeKey()                                                          */
/*============================================================================*/
int cw_ecc_makeKey(ecc_key* p_privKey, uint16_t curve)
{
	int8_t 		err;
	int keySize;
	switch(curve)
	{
	case 25:
		keySize = 66;
		break;
	case 24:
		keySize = 48;
		break;
	case 23:
		keySize = 32;
		break;
	case 21:
		keySize = 28;
		break;
	case 19:
		keySize = 24;
		break;
	case 16:
		keySize = 20;
		break;
	default:
		return CRYPT_ERROR;
		break;
	}
	err = ecc_make_key(&fortuna_prng, fortunaIdx, keySize, p_privKey);

	return err;
}

/*============================================================================*/
/*  cw_ecc_export_public()                                                    */
/*============================================================================*/
int cw_ecc_export_public(uint8_t* p_dest, size_t* pcwt_destLen, ecc_key* p_key)
{
	int8_t		err;

	err = ecc_ansi_x963_export(p_key, p_dest, (long unsigned int*)pcwt_destLen);

	return err;
}

/*============================================================================*/
/*  cw_ecc_import_public()                                                    */
/*============================================================================*/
int cw_ecc_import_public(uint8_t* pc_in, size_t cwt_inLen, ecc_key* p_key)
{
	int8_t err;

	err = ecc_ansi_x963_import(pc_in, cwt_inLen, p_key);

	return err;
}

/*============================================================================*/
/*  cw_ecc_publickey_post()                                                   */
/*============================================================================*/
void cw_ecc_publickey_post(s_pubKey_t * pwsslt_pubKey, ecc_key * p_pubKey)
{
	//vpy debug
	printf("Length:%d\n", pwsslt_pubKey->uiKeyLen);
	printf("Number/ID of curve: %d\n", pwsslt_pubKey->eccCurve);
	LOG_HEX(pwsslt_pubKey->eccKeyRaw, pwsslt_pubKey->uiKeyLen);
	int res=0;
	res = cw_ecc_dp_from_OID_defined_curve_name(pwsslt_pubKey->eccCurve, &p_pubKey->dp);
	res = ecc_ansi_x963_import_ex(pwsslt_pubKey->eccKeyRaw, pwsslt_pubKey->uiKeyLen, p_pubKey, p_pubKey->dp);
	printf("ECC import from cert, res %d\n", res); //vpy debug
} /* cw_ecc_publickey_post() */


/*============================================================================*/
/*  cw_ecc_dp_from_OID_defined_curve_name()                                   */
/*============================================================================*/
int cw_ecc_dp_from_OID_defined_curve_name(uint16_t ecc_curve_OID ,ltc_ecc_set_type **dp)
{
	int err = CRYPT_OK;

	//Temporary store the name of the curve, as a string
	char curveName[20];

	switch(ecc_curve_OID)
	{
	case SSL_OID_EC_SECP160R1:
		strcpy(curveName, "SECP160R1");
		break;
	case SSL_OID_EC_SECP224R1:
		strcpy(curveName, "SECP224R1");
		break;
	case SSL_OID_EC_SECP384R1:
		strcpy(curveName, "SECP384R1");
		break;
	case SSL_OID_EC_SECP521R1:
		strcpy(curveName, "SECP521R1");
		break;
	case SSL_OID_EC_BRAINPOOLP256R1:
		strcpy(curveName, "BRAINPOOLP256R1");
		break;
	case SSL_OID_EC_BRAINPOOLP384R1:
		strcpy(curveName, "BRAINPOOLP256R1");
		break;
	case SSL_OID_EC_BRAINPOOLP512R1:
		strcpy(curveName, "BRAINPOOLP256R1");
		break;
	default:
		strcpy(curveName, "INVALID CURVE");
		break;
	}

	//Look for the curve in ltc_ecc_sets
	int x=0;
	for (x = 0; ltc_ecc_sets[x].size != 0; x++)
	{
		if(strcmp(ltc_ecc_sets[x].name, curveName)==0)
		{
			*dp = &ltc_ecc_sets[x];
			err = CRYPT_OK;
			break;
		}
	}
	//If not curve found, set an error
	if (ltc_ecc_sets[x].size == 0) {
		err = CRYPT_ERROR;
	}
	return err;
}

/*============================================================================*/
/*  cw_ecc_publickey_init()                                                   */
/*============================================================================*/
int cw_ecc_publickey_init(ecc_key *p_eccKey)
{
	assert(p_eccKey != NULL);
	//assert(6p_eccKey->dp !=NULL);
	int err;
	p_eccKey->dp = (ltc_ecc_set_type*) malloc (sizeof(ltc_ecc_set_type));

	if(p_eccKey->dp == NULL)
	{
		//Couldn't allocate memory
		err = -1;
		return err;
	}

	err = mp_init_multi(&p_eccKey->pubkey.x, &p_eccKey->pubkey.y, &p_eccKey->pubkey.z, &p_eccKey->k, NULL);
	p_eccKey->type = PK_PUBLIC;

	return err;
}

/*============================================================================*/
/*  cw_ecc_free()                                                    		  */
/*============================================================================*/
void cw_ecc_free(ecc_key* p_key)
{
	ecc_free(p_key);
}


/*============================================================================*/
/*  cw_ecc_makeSharedSecret()                                       		  */
/*============================================================================*/
int cw_ecc_sharedSecret(ecc_key* p_privateKey, ecc_key* p_publicKey, uint8_t* p_outData, size_t* cwp_outLen)
{
	int8_t err;

	err = ecc_shared_secret(p_privateKey, p_publicKey, p_outData, (long unsigned int*)cwp_outLen);

	return err;
}


/*============================================================================*/
/*  cw_ecc_sign_hash()                                                  */
/*============================================================================*/
/* p_signature = outdata */
int cw_ecc_sign_encode(uint8_t* p_inMessage, size_t cwt_inMsgLen,
        uint8_t* p_signature, size_t* cwt_sigLen, ecc_key * p_pubkey)
{
	int err;
	err = ecc_sign_hash(p_inMessage, cwt_inMsgLen, p_signature, (long unsigned int*)cwt_sigLen, &fortuna_prng, fortunaIdx, p_pubkey);
	return err;
} /* cw_rsa_sign_hash() */


/*============================================================================*/
/*  cw_ecc_hash_verify_ltc()                                            */
/*============================================================================*/
int cw_ecc_hash_verify_ltc(uint8_t* pc_sig, size_t cwt_siglen,
        uint8_t* pc_hash, size_t cwt_hashlen, int* res,
        ecc_key * ecc_pubkey)
{
	int err;
	err = ecc_verify_hash(pc_sig, cwt_siglen, pc_hash, cwt_hashlen, res, ecc_pubkey);
	return err;
} /* cw_rsa_hash_verify_ltc() */


/*============================================================================*/
/*  cw_rsa_privatekey_init()                                                  */
/*============================================================================*/
int cw_ecc_privatekey_init(unsigned char* p_buffer, size_t l_strlen,
		ecc_key* pcwt_privKey, ltc_ecc_set_type* dp)
{

	int err;
	/*!
	 *  import Privatekey
	 */
	if (pcwt_privKey->type == PK_PRIVATE)
	{
		cw_ecc_free(pcwt_privKey);
	}

	if ((err = ecc_import_full(p_buffer, l_strlen, pcwt_privKey, dp)) != CRYPT_OK)
	{
		//Error during importation
	}
	return err;
} /* cw_rsa_privatekey_init() */


/*============================================================================*/
/*  cw_ecc_getSupportedCurves                                     		  */
/*============================================================================*/
int cw_ecc_getSupportedCurves(uint16_t* p_outData)
{
	//libtomcrypt suppports 6 curves
	//25, 24, 23, 21, 19, 16
	int numberOfCurves = 0;

	*(p_outData+numberOfCurves) = 25;
	numberOfCurves++;

	*(p_outData+numberOfCurves) = 24;
	numberOfCurves++;

	*(p_outData+numberOfCurves) = 23;
	numberOfCurves++;

	*(p_outData+numberOfCurves) = 21;
	numberOfCurves++;

	*(p_outData+numberOfCurves) = 19;
	numberOfCurves++;

	*(p_outData+numberOfCurves) = 16;
	numberOfCurves++;

	return numberOfCurves;
}

/*============================================================================*/
/*  cw_dhe_makeKey()                                                          */
/*============================================================================*/
int cw_dhe_makeKey(cw_dhKey_t* p_privKey)
{
    int8_t          err = CW_ERROR;
    cw_bigNum_t     cwt_dheG;
    cw_bigNum_t     cwt_dheP;
    uint8_t         c_kIdx = 0;
    size_t       	cwt_len = SSL_DEFAULT_DHE_KEYSIZE;
    uint8_t			buf[SSL_DEFAULT_DHE_KEYSIZE];

    assert(p_privKey != NULL);

    if ((err = mp_init_multi(&cwt_dheG,&cwt_dheP,NULL)) != CRYPT_OK) {
        LOG_ERR("ltc_init_multi() failed. Reason %s",error_to_string(err));
        err = CW_ERROR;
        goto mkKeyError;
    }

    if ((err = ltc_init_multi(&p_privKey->x,&p_privKey->y,NULL)) != CRYPT_OK) {
        LOG_ERR("ltc_init_multi() failed. Reason %s",error_to_string(err));
        err = CW_ERROR;
        goto mkKeyError;
    }

    /* Find out a key index in the predefined array */
    for (c_kIdx = 0; (cwt_len > (unsigned long)sets[c_kIdx].size) && (sets[c_kIdx].size != 0); c_kIdx++);

    if (sets[c_kIdx].size == 0) {
        err = CW_ERROR;
        goto mkKeyError;
    }

    /* Get p material part */
    if ((err = mp_read_radix(&cwt_dheP, (char *)sets[c_kIdx].prime, 64)) != CRYPT_OK){
        err = CW_ERROR;
        goto mkKeyError;
    }

    /* Get g material part */
    if ((err = mp_read_radix(&cwt_dheG, (char *)sets[c_kIdx].base, 64)) != CRYPT_OK){
        err = CW_ERROR;
        goto mkKeyError;
    }

    if ((err = prng_is_valid(fortunaIdx)) != CRYPT_OK) {
        LOG_ERR("prng_is_valid: %s", error_to_string(err));
        err = CW_ERROR;
        goto mkKeyError;
    }

    if ((err = rng_make_prng(128,fortunaIdx,&fortuna_prng,NULL)) != CRYPT_OK) {
        LOG_ERR("rng_make_prng: %s", error_to_string(err));
        err = CW_ERROR;
        goto mkKeyError;
    }

    if (prng_descriptor[fortunaIdx].read(buf,cwt_len, &fortuna_prng) != cwt_len) {
        LOG_ERR("prng_descriptor[fortunaIdx].read");
        err = CW_ERROR;
        goto mkKeyError;
    }

    if ((err = mp_read_unsigned_bin(p_privKey->x,buf, cwt_len)) != CRYPT_OK) {
        LOG_ERR("mp_read_unsigned_bin failed. Reason %s",error_to_string(err));
        err = CW_ERROR;
        goto mkKeyError;
    }

    if ((err = mp_exptmod(&cwt_dheG,p_privKey->x, &cwt_dheP, p_privKey->y)) != CRYPT_OK) {
        LOG_ERR("mp_exptmod: %s", error_to_string(err));
        err = CW_ERROR;
        goto mkKeyError;
    }

    mp_clear_multi(&cwt_dheG, &cwt_dheP,NULL);
    p_privKey->type = PK_PRIVATE;
    err = CW_OK;
    goto mkKeyDone;

mkKeyError:
	mp_clear_multi(&cwt_dheP,&cwt_dheG,NULL);
	mp_clear_multi(p_privKey->x,p_privKey->y, NULL);
mkKeyDone:
    return err;
} /* cw_dhe_makeKey() */

/*============================================================================*/
/*  cw_dhe_export_Y()                                                         */
/*============================================================================*/
int cw_dhe_export_Y(uint8_t* p_dest, size_t* pcwt_destLen, cw_dhKey_t* p_key)
{
    int8_t      err = 0;
    size_t   l_destLen = 0;

    assert(p_dest != NULL);
    assert(pcwt_destLen != NULL);
    assert(p_key != NULL);

    l_destLen = (size_t) *pcwt_destLen;

    /* can we store the static header?  */
    if (*pcwt_destLen < 2) {
       LOG_ERR("CRYPT_BUFFER_OVERFLOW");
       return CW_ERROR;
    }

    if (p_key->type != PK_PRIVATE) {
        LOG_ERR("CRYPT_PK_NOT_PRIVATE");
        return CW_ERROR;
    }

    /* Get size of a public key */
    l_destLen = mp_unsigned_bin_size(p_key->y);

    if (l_destLen > (*pcwt_destLen - 2)) {
        LOG_ERR("mp_unsigned_bin_size failed. Reason: %s", error_to_string(l_destLen));
        *pcwt_destLen = 0;
        return CW_ERROR;
    }

    /* Copy data from the public key to data buffer */
    if ((err = mp_to_unsigned_bin(p_key->y, p_dest + 2)) != CRYPT_OK) {
        LOG_ERR("mp_to_unsigned_bin failed. Reason: %s", error_to_string(err));
        *pcwt_destLen = 0;
        return CW_ERROR;
    }

    p_dest[0] = l_destLen >> 8;
    p_dest[1] = l_destLen & 0xFF;

    *pcwt_destLen = (size_t) l_destLen + 2;

    return CW_OK;
} /* cw_dhe_export_Y() */

/*============================================================================*/
/*  cw_dhe_export_pqY()                                                       */
/*============================================================================*/
int cw_dhe_export_pgY(uint8_t* p_dest, size_t* pcwt_destLen,
                      cw_dhKey_t* p_key, cw_bigNum_t** pcwt_dheP)
{
    int8_t          err = 0;
    /* As we use statically allocated arrays of p and g
     * to find out them again use the same value if key size as in the
     * dh_make_key() function */
    size_t       	l_tmpLen = SSL_DEFAULT_DHE_KEYSIZE;
    int8_t          c_kIdx = 0;
    cw_bigNum_t     cwt_dheG;
    uint16_t        i_pckOff = 0;

    assert(p_dest != NULL);
    assert(pcwt_destLen != NULL);
    assert(p_key != NULL);
    if (*pcwt_dheP == NULL)
    	ltc_mp.init((void **)pcwt_dheP);

    /* init */
    if ((err = mp_init_multi(&cwt_dheG,*pcwt_dheP,NULL)) != CRYPT_OK) {
        LOG_ERR("mp_create_multi failed");
        return CW_ERROR;
    }

    /* can we store the static header?  */
    if (*pcwt_destLen < 2) {
       LOG_ERR("CRYPT_BUFFER_OVERFLOW");
       err = CW_ERROR;
       goto exportPGYError;
    }

    if (p_key->type != PK_PRIVATE) {
        LOG_ERR("CRYPT_PK_NOT_PUBLIC");
        err = CW_ERROR;
        goto exportPGYError;
    }

    /* Find out a key index in the predefined array */
    for (c_kIdx = 0; (l_tmpLen > (unsigned long)sets[c_kIdx].size) && (sets[c_kIdx].size != 0); c_kIdx++);

    if (sets[c_kIdx].size == 0) {
        err = CW_ERROR;
        goto exportPGYError;
    }

    /* Get p material part */
    if ((err = mp_read_radix(*pcwt_dheP, (char *)sets[c_kIdx].prime, 64)) != CRYPT_OK){
        err = CW_ERROR;
        goto exportPGYError;
    }

    /* Get p length part */
    l_tmpLen = mp_unsigned_bin_size(*pcwt_dheP);

    if (l_tmpLen > (*pcwt_destLen - 2)) {
        LOG_ERR("mp_unsigned_bin_size failed");
        err = CW_ERROR;
        goto exportPGYError;
    }

    /* Store p length part */
    p_dest[i_pckOff++] = l_tmpLen >> 8;
    p_dest[i_pckOff++] = l_tmpLen & 0xFF;

    /* Store p material part */
    if ((err = mp_to_unsigned_bin(*pcwt_dheP, p_dest + i_pckOff)) != CRYPT_OK) {
        LOG_ERR("mp_to_unsigned_bin failed. Reason: %s", error_to_string(err));
        err = CW_ERROR;
        goto exportPGYError;
    }

    /* Move packet pointer offset */
    i_pckOff += l_tmpLen;

    /* Get g material part */
    if ((err = mp_read_radix(&cwt_dheG, (char *)sets[c_kIdx].base, 64)) != CRYPT_OK){
        err = CW_ERROR;
        goto exportPGYError;
    }

    /* Get g length part */
    l_tmpLen = mp_unsigned_bin_size(&cwt_dheG);

    if (l_tmpLen > (*pcwt_destLen - 2)) {
        LOG_ERR("mp_unsigned_bin_size failed");
        err = CW_ERROR;
        goto exportPGYError;
    }

    /* Store g length part */
    p_dest[i_pckOff++] = l_tmpLen >> 8;
    p_dest[i_pckOff++] = l_tmpLen & 0xFF;

    /* Store g material part */
    if ((err = mp_to_unsigned_bin(&cwt_dheG, p_dest + i_pckOff)) != CRYPT_OK) {
        LOG_ERR("mp_to_unsigned_bin failed. Reason: %s", error_to_string(err));
        err = CW_ERROR;
        goto exportPGYError;
    }

    /* Move packet pointer offset */
    i_pckOff += l_tmpLen;

    /* Get size of a public key */
    l_tmpLen = mp_unsigned_bin_size(p_key->y);

    /* Store Public key length part */
    p_dest[i_pckOff++] = l_tmpLen >> 8;
    p_dest[i_pckOff++] = l_tmpLen & 0xFF;

    if ((err = mp_to_unsigned_bin(p_key->y, p_dest + i_pckOff)) != CRYPT_OK) {
        LOG_ERR("mp_to_unsigned_bin failed. Reason: %s", error_to_string(err));
        err = CW_ERROR;
        goto exportPGYError;
    }

    /* Move packet pointer offset */
    i_pckOff += l_tmpLen;

    /* Return length of a packet */
    *pcwt_destLen = (size_t)(i_pckOff);
    goto exportPGYDone;

exportPGYError:
    *pcwt_destLen = 0;

exportPGYDone:
    mp_clear(&cwt_dheG);
    return (err);

} /* cw_dhe_export_pqY() */

/*============================================================================*/
/*  loc_cw_bnRead()                                                         */
/*============================================================================*/
static uint16_t loc_cw_bnRead(uint8_t* pc_in, void* pcwt_bn)
{
    int         err;
    uint16_t    i_len = 0;

    assert(pc_in != NULL);
    assert(pcwt_bn != NULL);

    i_len = pc_in[0]*256 + pc_in[1];

    if (( err = mp_read_unsigned_bin(pcwt_bn, pc_in + 2, i_len)) != CRYPT_OK) {
        LOG_ERR("mp_read_unsigned_bin: %s", error_to_string(err));
        return CW_ERROR;
    }

    return (i_len + 2);
} /* loc_cw_bnRead() */

/*============================================================================*/
/*  cw_dhe_import_Y()                                                         */
/*============================================================================*/
int cw_dhe_import_Y(uint8_t* pc_in, size_t cwt_inLen, cw_dhKey_t* p_dheKey)
{
    int8_t             err;

    assert(pc_in != NULL);
    assert(p_dheKey != NULL);

    if ((err = ltc_mp.init(&p_dheKey->y)) != CRYPT_OK){
        LOG_ERR("mp_create failed: %s", error_to_string(err));
        return CW_ERROR;
    }

    if (( err = mp_read_unsigned_bin(p_dheKey->y, pc_in + 2, cwt_inLen)) != CRYPT_OK) {
        LOG_ERR("mp_read_unsigned_bin: %s", error_to_string(err));
        return CW_ERROR;
    }

    return (CW_OK);
} /* cw_dhe_import_Y() */

/*============================================================================*/
/*  cw_dhe_import_pqY_make_privKey()                                          */
/*============================================================================*/
int cw_dhe_import_make_privKey(uint8_t* pc_input, size_t cwt_inLen,
                               cw_dhKey_t* p_cliPrivKey, cw_dhKey_t* p_srvPubKey,
                               cw_bigNum_t** pp_dheP)
{
    int8_t      err;
    uint16_t    i_len = 0;
    cw_bigNum_t p_dheG;
    uint8_t*    buf;

    assert(pc_input != NULL);
    assert(p_cliPrivKey != NULL);
    assert(p_srvPubKey != NULL);
    assert(*pp_dheP == NULL);

    mp_init(&p_dheG);

    if ((err = ltc_init_multi((void **)pp_dheP,
                               &p_cliPrivKey->x,
                               &p_cliPrivKey->y,
                               &p_srvPubKey->y,
                               NULL)) != CRYPT_OK){
        err = CW_ERROR;
        goto impMkKeyError;
    }

    i_len = loc_cw_bnRead(pc_input, *pp_dheP);

    i_len += loc_cw_bnRead(pc_input + i_len, &p_dheG);

    i_len = loc_cw_bnRead(pc_input + i_len, p_srvPubKey->y);

    i_len -= 2;

    buf = malloc(sizeof(uint8_t) * i_len);

    if ((err = prng_is_valid(fortunaIdx)) != CRYPT_OK) {
        LOG_ERR("prng_is_valid: %s", error_to_string(err));
        err = CW_ERROR;
        goto impMkKeyError;
    }

    if ((err = rng_make_prng(128,fortunaIdx,&fortuna_prng,NULL)) != CRYPT_OK) {
        LOG_ERR("rng_make_prng: %s", error_to_string(err));
        err = CW_ERROR;
        goto impMkKeyError;
    }

    if (prng_descriptor[fortunaIdx].read(buf,i_len, &fortuna_prng) != (uint32_t)i_len) {
        LOG_ERR("prng_descriptor[fortunaIdx].read");
        err = CW_ERROR;
        goto impMkKeyError;
    }

    if ((err = mp_read_unsigned_bin(p_cliPrivKey->x,buf,i_len)) != CRYPT_OK) {
        LOG_ERR("mp_read_unsigned_bin failed. Reason %s",error_to_string(err));
        err = CW_ERROR;
        goto impMkKeyError;
    }

    if ((err = mp_exptmod(&p_dheG,p_cliPrivKey->x, *pp_dheP, p_cliPrivKey->y)) != CRYPT_OK) {
        LOG_ERR("mp_exptmod: %s", error_to_string(err));
        err = CW_ERROR;
        goto impMkKeyError;
    }

    mp_clear(&p_dheG);
    free(buf);
    p_cliPrivKey->type = PK_PRIVATE;
    err = CW_OK;
    goto impMkKeyDone;

impMkKeyError:
	mp_clear(&p_dheG);
	mp_clear_multi(*pp_dheP, p_cliPrivKey->x, NULL);
impMkKeyDone:
    return err;
} /* cw_dhe_import_pqY_make_privKey() */

/*============================================================================*/
/*  cw_dhe_sharedSec()                                                        */
/*============================================================================*/
int cw_dhe_sharedSec(cw_dhKey_t* p_privateKey, cw_dhKey_t* p_publicKey,
        uint8_t* p_outData, size_t* cwp_outLen)
{
#ifdef ASCOM_CRYPTO

    return CW_ERROR;

#elif defined(TOMLIB_CRYPTO)
    int err;
    size_t len = (uint32_t) *cwp_outLen;
    if ((err = dh_shared_secret(p_privateKey, p_publicKey, p_outData, (long unsigned int *)&len))
            != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" DHE shared secret error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
        CW_PRINT_MEM_ERR;
#endif
        *cwp_outLen = 0;
        return CW_ERROR;
    }
    *cwp_outLen = (size_t) len;
#endif

    return CW_OK;
} /* cw_dhe_sharedSec() */

/*============================================================================*/
/*  cw_dhe_sharedSec_with_p()                                                 */
/*============================================================================*/
int cw_dhe_sharedSec_with_p(cw_dhKey_t* p_privateKey, cw_dhKey_t* p_publicKey,
        cw_bigNum_t** pp_dheP, uint8_t* p_outData, size_t* cwp_outLen)
{
    int8_t       err = CW_ERROR;;
    cw_bigNum_t tmp;
    size_t    cwt_resLen = 0;


    assert(p_privateKey != NULL);
    assert(p_publicKey != NULL);
    assert(*pp_dheP != NULL);
    assert(p_outData != NULL);
    assert(cwp_outLen != NULL);

    if ((err = mp_init(&tmp)) != CRYPT_OK) {
        LOG_ERR("mp_create(&tmp) failed. Reason: %s", error_to_string(err));
        err = CW_ERROR;
        goto shSecError;
    }

    if ((err = mp_exptmod(p_publicKey->y, p_privateKey->x, *pp_dheP, &tmp)) != CRYPT_OK) {
        LOG_ERR("mp_exptmod() failed. Reason: %s", error_to_string(err));
        err = CW_ERROR;
        goto shSecError;
    }

    cwt_resLen = (size_t)mp_unsigned_bin_size(&tmp);

    if (*cwp_outLen < cwt_resLen) {
        LOG_ERR("Lengths don't match %zu cmp %zu",*cwp_outLen,cwt_resLen);
        err = CW_ERROR;
        goto shSecError;
    }

    if ((err = mp_to_unsigned_bin(&tmp,p_outData)) != CRYPT_OK) {
        err = CW_ERROR;
        goto shSecError;
    }

    *cwp_outLen = cwt_resLen;
    err = CW_OK;
shSecError:
    mp_clear(&tmp);
    return err;

} /* cw_dhe_sharedSec_with_p() */

/*============================================================================*/
/*  cw_dh_free()                                                              */
/*============================================================================*/
void cw_dh_free(cw_dhKey_t* pdh_key)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    if (pdh_key)
        dh_free(pdh_key);

#endif
    return;
} /* cw_dh_free() */

/*============================================================================*/
/*  cw_bn_free()                                                              */
/*============================================================================*/
void cw_bn_free(cw_bigNum_t* pcwt_bn)
{

    if (pcwt_bn) {
        mp_clear(pcwt_bn);
    }

    return;
} /* cw_bn_free() */

/*============================================================================*/
/*  cw_rsa_os2ip()                                                            */
/*============================================================================*/
int cw_rsa_os2ip(cw_bigNum_t * pbn_num, uint8_t* p_raw, size_t cwt_rawLen)
{
#ifdef ASCOM_CRYPTO

    CL_RsaOS2IP (pbn_num, p_raw, cwt_rawLen);

#elif defined(TOMLIB_CRYPTO)
    int err;
    if ((err = pkcs_1_os2ip(pbn_num, p_raw, cwt_rawLen)) != MP_OKAY)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" PKCS#1 OS2IP error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return (CW_ERROR);
    }

#endif
    return (CW_OK);
} /* cw_rsa_os2ip() */

/*============================================================================*/
/*  cw_rsa_i2osp()                                                            */
/*============================================================================*/
int cw_rsa_i2osp(cw_bigNum_t * pbn_num, size_t cwt_numLen,
        uint8_t* p_outData)
{
#ifdef ASCOM_CRYPTO

    if(CL_RsaI2OSP(p_outData, pbn_num, cwt_numLen) == CL_FALSE)
    return(CW_ERROR);

#elif defined(TOMLIB_CRYPTO)
    int err;
    if ((err = pkcs_1_i2osp(pbn_num, cwt_numLen, p_outData)) != MP_OKAY)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" PKCS#1 I2OSP error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return (CW_ERROR);
    }

#endif
    return (CW_OK);
} /* cw_rsa_i2osp() */

/*============================================================================*/
/*  cw_rsa_verify()                                                           */
/*============================================================================*/
int cw_rsa_verify(cw_bigNum_t * Message, cw_bigNum_t * Signature,
        rpcw_rsaPubKey_t pPubKey)
{
#ifdef ASCOM_CRYPTO

    if(CL_RsaVerify (Message, Signature, pPubKey) != CL_RSA_OK)
    return(CW_ERROR);

#elif defined(TOMLIB_CRYPTO)

    static uint8_t auc_message[CW_PKCS1_MAX_KEYSIZE],
            auc_signature[CW_PKCS1_MAX_KEYSIZE];
    size_t cwt_size_s;
    size_t cwt_size_m;
    int err;
    cwt_size_s = mp_unsigned_bin_size(Signature);
    if (cw_rsa_i2osp(Signature, cwt_size_s, auc_signature) != CW_OK)
        return (CW_ERROR);
    cwt_size_m = sizeof(auc_message);
    if ((err = rsa_exptmod(auc_signature, (unsigned long)cwt_size_s, auc_message,(unsigned long*) &cwt_size_m,
            PK_PUBLIC, (rsa_key*) pPubKey)) != CRYPT_OK)
        return (CW_ERROR);
    if (cw_rsa_os2ip(Message, auc_message, cwt_size_m) != CW_OK)
        return (CW_ERROR);

#endif
    return (CW_OK);
} /* cw_rsa_verify() */

/*============================================================================*/
/*  cw_pkcs1_v15_decrypt()                                                    */
/*============================================================================*/
int cw_pkcs1_v15_decrypt(uint8_t* p_inData, size_t cwt_inDataLen,
        uint8_t* p_outData, size_t* cwt_outDataLen,
        cw_rsaPrivKey_t * p_privkey)
{
#ifdef ASCOM_CRYPTO

    if(CL_Pkcs1DecryptV1_5(p_outData, cwt_outDataLen, p_inData,
                    cwt_inDataLen, p_privkey) != CL_RSA_OK)
    return(CW_ERROR);

#elif defined(TOMLIB_CRYPTO)
    int res, err;
    unsigned long l_outDataLen = *cwt_outDataLen;

    err = rsa_decrypt_key_ex(p_inData, cwt_inDataLen, p_outData, &l_outDataLen,
    NULL, 0, 0, LTC_PKCS_1_V1_5, &res, p_privkey);
    if(err)
        LOG_ERR("RSA Decrypt error: %s len: %zu", error_to_string(err), cwt_inDataLen);
    if (!res)
    {
        LOG_ERR("RSA Decrypt not successful!");
        return (CW_ERROR);
    }
    *cwt_outDataLen = l_outDataLen;

#endif
    return (CW_OK);
} /* cw_pkcs1_v15_decrypt() */

/*============================================================================*/
/*  cw_rsa_encrypt()                                                    */
/*============================================================================*/
int cw_rsa_encrypt(uint8_t* p_inData, size_t cwt_inDataLen,
        uint8_t* p_outData, size_t* cwt_outDataLen,
        cw_rsaPubKey_t * p_pubkey)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)
    int err;
    unsigned long l_outLen = (unsigned long) *cwt_outDataLen;

    if ((err = rsa_encrypt_key_ex(p_inData, cwt_inDataLen, p_outData, &l_outLen,
    NULL, 0, &fortuna_prng, fortunaIdx, 0, LTC_PKCS_1_V1_5, p_pubkey))
            != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" RSA Encrypt error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
        CW_PRINT_MEM_ERR;
#endif
        *cwt_outDataLen = 0;
        return (CW_ERROR);
    }
    *cwt_outDataLen = (size_t) l_outLen;
#endif
    return (CW_OK);
} /* cw_rsa_encrypt() */


/*============================================================================*/
/*  cw_rsa_sign_decode()                                                */
/*============================================================================*/
int cw_rsa_sign_decode(uint8_t* pc_encSign, size_t sz_encSignLen,
                       uint8_t* pc_decSign, size_t* sz_decSignLen,
                       cw_rsaPubKey_t * p_pubkey)
{
    assert(p_pubkey != NULL);

	//debug vpy
    printf("rsa_sign_decode. RSA key used:\n");

	char buffer[4096];
	mp_toradix(p_pubkey->e, buffer, 16);
	printf("e: %s\n", buffer);

	mp_toradix(p_pubkey->d, buffer, 16);
	printf("d: %s\n", buffer);

	mp_toradix(p_pubkey->N, buffer, 16);
	printf("N: %s\n", buffer);

    int err;
    unsigned long modulus_bitlen = mp_count_bits((p_pubkey->N));
    int is_valid = 0;

    err = rsa_exptmod(pc_encSign, (unsigned long)sz_encSignLen, pc_encSign,
                        (unsigned long *)&sz_encSignLen, PK_PUBLIC, p_pubkey);
    if (err != CRYPT_OK) {
        LOG1_ERR("Failed to decrypt signature of server DH parameter "
                "in ServerKeyExchange message: %s", error_to_string(err));
        return CW_ERROR;
    }

    if ((err = pkcs_1_v1_5_decode(pc_encSign, sz_encSignLen, LTC_PKCS_1_EMSA,
            modulus_bitlen, pc_decSign, (long unsigned int *) sz_decSignLen, &is_valid)) != CRYPT_OK) {
        LOG_ERR("Failed to decode signature of server DH parameter "
                "in ServerKeyExchange message: %s!", error_to_string(err));
        return (CW_ERROR);
    }

    return (CW_OK);
} /* cw_rsa_sign_decode() */


/*============================================================================*/
/*  cw_rsa_hash_verify_ltc()                                            */
/*============================================================================*/
int cw_rsa_hash_verify_ltc(uint8_t* pc_sig, size_t cwt_siglen,
        uint8_t* pc_hash, size_t cwt_hashlen, int hash_idx, int* res,
        cw_rsaPubKey_t * rsa_pubkey)
{
	assert(rsa_pubkey!=NULL);

	//debug vpy
	char buffer[4096];
	printf("RSA Verification: key used to verify:\n");
	mp_toradix(rsa_pubkey->e, buffer, 16);
	printf("e: %s\n", buffer);

	mp_toradix(rsa_pubkey->d, buffer, 16);
	printf("d: %s\n", buffer);

	mp_toradix(rsa_pubkey->N, buffer, 16);
	printf("N: %s\n", buffer);

	printf("signature: \n");
    sslDiag_printHex(pc_sig, cwt_siglen);


    if (rsa_verify_hash_ex(pc_sig, cwt_siglen, pc_hash, cwt_hashlen,
            LTC_PKCS_1_V1_5, hash_idx, 0, res, rsa_pubkey) == CRYPT_OK) {
        return CW_OK;
    }

    return CW_ERROR;
} /* cw_rsa_hash_verify_ltc() */


/*============================================================================*/
/*  cw_rsa_sign_hash()                                                  */
/*============================================================================*/
/* p_signature = outdata */
int cw_rsa_sign_encode(uint8_t* p_inMessage, size_t cwt_inMsgLen,
        uint8_t* p_signature, size_t* cwt_sigLen, cw_rsaPubKey_t * p_pubkey)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    int err;
    unsigned long l_outLen = (unsigned long) *cwt_sigLen;
    char tmpbuf[cwt_inMsgLen];

    if (p_signature == p_inMessage)
    {
        CW_MEMCOPY(tmpbuf, p_inMessage, cwt_inMsgLen);
        p_inMessage = (uint8_t*) tmpbuf;
    }

    unsigned long modulus_bitlen = mp_count_bits((p_pubkey->N));

	err = pkcs_1_v1_5_encode(p_inMessage, (unsigned long) cwt_inMsgLen,
	                         LTC_PKCS_1_EMSA, modulus_bitlen, NULL, 0,
	                         p_signature, (unsigned long *)&l_outLen);
	if (err != CRYPT_OK) {
		LOG1_ERR("RSA Sign Hash error: pkcs_1_v1_5_encode returned: %s", error_to_string(err));
		*cwt_sigLen = 0;
		return CW_ERROR;
	}

	err = rsa_exptmod(p_signature, (unsigned long)l_outLen, p_signature,
	                    (unsigned long *)cwt_sigLen, PK_PRIVATE, p_pubkey);
	if (err != CRYPT_OK) {
		LOG1_ERR("RSA Sign Hash error: ltc_mp.rsa_me returned: %s", error_to_string(err));
		*cwt_sigLen = 0;
		return CW_ERROR;
	}

#endif
    return (CW_OK);
} /* cw_rsa_sign_hash() */

/*============================================================================*/
/*  cw_rsa_privatekey_init()                                                  */
/*============================================================================*/
int cw_rsa_privatekey_init(unsigned char* p_buffer, size_t l_strlen,
        cw_rsaPrivKey_t* pcwt_privKey)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)
    int err;
    /*!
     *  import Privatekey
     */
    if (pcwt_privKey->type == PK_PRIVATE)
    {
        cw_rsa_privatekey_free(pcwt_privKey);
#if DBG_CRYPT_WRAP > 1
        CW_DBG_PRINTF(DBG_STRING" Non-fatal: Free'd Private Key", DBG_FILE_NAME, __LINE__);
#endif
    }
    if ((err = rsa_import(p_buffer, l_strlen, pcwt_privKey)) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP > 1
        CW_DBG_PRINTF(DBG_STRING" Non-fatal: RSA Import error(Private Key): %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
        CW_PRINT_MEM_ERR;
#endif
    }

#endif
    return err;
} /* cw_rsa_privatekey_init() */

/*============================================================================*/
/*  cw_rsa_privatekey_shrink()                                                */
/*============================================================================*/
void cw_rsa_privatekey_shrink(cw_rsaPrivKey_t* pcwt_privKey)
{
#if defined(TOMLIB_CRYPTO)
    /*
     *  call cw_rsa_publickey_shrink(), since public and private key are equal in LTC
     */
    cw_rsa_publickey_shrink((cw_rsaPubKey_t*) pcwt_privKey);

#endif
} /* cw_rsa_privatekey_shrink() */

/*============================================================================*/
/*  cw_rsa_privatekey_free()                                                  */
/*============================================================================*/
void cw_rsa_privatekey_free(cw_rsaPrivKey_t* pcwt_privKey)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)
    /*
     *  call cw_rsa_publickey_free(), since public and private key are equal in LTC
     */
    cw_rsa_publickey_free(pcwt_privKey);
#endif
    return;
} /* cw_rsa_privatekey_free() */

/*============================================================================*/
/*  cw_rsa_publickey_init()                                                   */
/*============================================================================*/
int cw_rsa_publickey_init(cw_rsaPubKey_t* pcwt_pubKey)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)
	assert(pcwt_pubKey != NULL);
    int err;
    /*!
     *  init RSA key
     */    
    if ((err = ltc_init_multi(&pcwt_pubKey->e, &pcwt_pubKey->d, &pcwt_pubKey->N,
                               &pcwt_pubKey->dQ, &pcwt_pubKey->dP, &pcwt_pubKey->qP,
                               &pcwt_pubKey->p, &pcwt_pubKey->q, NULL)) != CRYPT_OK)
    {
        LOG_ERR(" Non-fatal: RSA Init error: %s", error_to_string(err));
    }
    pcwt_pubKey->type = PK_PUBLIC;
#endif
    return err;
} /* cw_rsa_publickey_init() */

/*============================================================================*/
/*  cw_rsa_publickey_shrink()                                                 */
/*============================================================================*/
void cw_rsa_publickey_shrink(cw_rsaPubKey_t* pcwt_pubKey)
{
#if defined(TOMLIB_CRYPTO)
    assert(pcwt_pubKey != NULL);
    assert(pcwt_pubKey->e != NULL);
    assert(pcwt_pubKey->d != NULL);
    assert(pcwt_pubKey->N != NULL);
    assert(pcwt_pubKey->dQ != NULL);
    assert(pcwt_pubKey->dP != NULL);
    assert(pcwt_pubKey->qP != NULL);
    assert(pcwt_pubKey->p != NULL);
    assert(pcwt_pubKey->q != NULL);
    /*!
     *  shrink all MPI's in the RSA key
     */
    mp_shrink(pcwt_pubKey->e);
    mp_shrink(pcwt_pubKey->N);
    mp_shrink(pcwt_pubKey->d);
    mp_shrink(pcwt_pubKey->dQ);
    mp_shrink(pcwt_pubKey->dP);
    mp_shrink(pcwt_pubKey->qP);
    mp_shrink(pcwt_pubKey->p);
    mp_shrink(pcwt_pubKey->q);

#endif
} /* cw_rsa_publickey_shrink() */

/*============================================================================*/
/*  cw_rsa_publickey_free()                                                   */
/*============================================================================*/
void cw_rsa_publickey_free(cw_rsaPubKey_t* pcwt_pubKey)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    if (pcwt_pubKey)
    {
        mp_clear_multi(pcwt_pubKey->e, pcwt_pubKey->d, pcwt_pubKey->N,
                         pcwt_pubKey->dQ, pcwt_pubKey->dP, pcwt_pubKey->qP,
                         pcwt_pubKey->p, pcwt_pubKey->q, NULL);
        pcwt_pubKey->e = NULL;
        pcwt_pubKey->d = NULL;
        pcwt_pubKey->N = NULL;
        pcwt_pubKey->dQ = NULL;
        pcwt_pubKey->dP = NULL;
        pcwt_pubKey->qP = NULL;
        pcwt_pubKey->p = NULL;
        pcwt_pubKey->q = NULL;
        pcwt_pubKey->type = PK_PUBLIC;
    }

#endif
    return;
} /* cw_rsa_publickey_free() */

/*============================================================================*/
/*  cw_rsa_publickey_prep()                                                   */
/*============================================================================*/
void cw_rsa_publickey_prep(cw_rsaPubKey_t * pcwt_pubKey,
        s_pubKey_t * pwsslt_pubKey)
{
#ifdef ASCOM_CRYPTO
    pwsslt_pubKey->iAlgorithm= SSL_OID_UNDEF;
    pwsslt_pubKey->pE = NULL;
    pwsslt_pubKey->pM = NULL;
#elif defined(TOMLIB_CRYPTO)
    assert(pcwt_pubKey->e != NULL);
    assert(pcwt_pubKey->N != NULL);

    pwsslt_pubKey->iAlgorithm = SSL_OID_UNDEF;
    pwsslt_pubKey->pE = pcwt_pubKey->e;
    pwsslt_pubKey->pM = pcwt_pubKey->N;
#endif
} /* cw_rsa_publickey_prep() */

/*============================================================================*/
/*  cw_rsa_publickey_post()                                                    */
/*============================================================================*/
void cw_rsa_publickey_post(s_pubKey_t * pwsslt_pubKey,
        cw_rsaPubKey_t * pcwt_pubKey)
{
#ifdef ASCOM_CRYPTO
    pcwt_pubKey->pE= pwsslt_pubKey->pE;
    pcwt_pubKey->pN= pwsslt_pubKey->pM;
#elif defined(TOMLIB_CRYPTO)
    pcwt_pubKey->e = pwsslt_pubKey->pE;
    pcwt_pubKey->N = pwsslt_pubKey->pM;
#endif
} /* cw_rsa_publickey_post() */


/*==============================================================================
 MATH FUNCTIONS
 =============================================================================*/
/*============================================================================*/
/*  cw_bn_init()                                                              */
/*============================================================================*/
void cw_bn_init(uint8_t* p_bnBuffer, size_t cwt_bufLen)
{
#ifdef ASCOM_CRYPTO

    CL_BnInit(p_bnBuffer, cwt_bufLen);

#elif defined(TOMLIB_CRYPTO)

#endif
    return;
} /* cw_bn_init() */

/*============================================================================*/
/*  cw_bn_create()                                                            */
/*============================================================================*/
cw_bigNum_t * cw_bn_create(cw_bigNum_t * pbn_number, size_t cwt_size)
{
#ifdef ASCOM_CRYPTO

    return(CL_BnCreate(cwt_size));

#elif defined(TOMLIB_CRYPTO)

    int err;
/*    mp_destroy(pbn_number);*/
    if ((err = mp_init_size(pbn_number, (cwt_size / 8))) == MP_MEM)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" BN create error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
        CW_PRINT_MEM_ERR;
#endif
        return (NULL);
    }
    else
        return (pbn_number);

#endif
} /* cw_bn_create() */

/*============================================================================*/
/*  cw_bn_freefree()                                                          */
/*============================================================================*/
void cw_bn_freefree(void* pbn_number)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    mp_clear_multi(pbn_number, NULL);

#endif
    return;
} /* cw_bn_freefree() */

/*============================================================================*/
/*  cw_bn_set()                                                               */
/*============================================================================*/
void cw_bn_set(cw_bigNum_t * pbn_number, void* p_data, size_t cwt_dataSize)
{
#ifdef ASCOM_CRYPTO

    CL_BnSet(pbn_number, p_data, cwt_dataSize);

#elif defined(TOMLIB_CRYPTO)

    int err;
    if ((err = mp_read_unsigned_bin(pbn_number, p_data, cwt_dataSize))
            != MP_OKAY)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" BN set error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
    }

#endif
    return;
} /* cw_bn_set() */

/*============================================================================*/
/*  cw_bn_add()                                                               */
/*============================================================================*/
int cw_bn_add(cw_bigNum_t * pbn_dest, cw_bigNum_t * pbn_number1,
        cw_bigNum_t * pbn_number2)
{
#ifdef ASCOM_CRYPTO

    CL_BnAdd(pbn_dest, pbn_number1, pbn_number2);
    return(CW_OK);

#elif defined(TOMLIB_CRYPTO)

    int err;
    if ((err = mp_add(pbn_number1, pbn_number2, pbn_dest)) == MP_OKAY)
        return (CW_OK);
    else
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" BN add error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return (CW_ERROR);
    }

#endif
} /* cw_bn_add() */

/*============================================================================*/
/*  cw_bn_sub()                                                               */
/*============================================================================*/
int cw_bn_sub(cw_bigNum_t * pbn_dest, cw_bigNum_t * pbn_number1,
        cw_bigNum_t * pbn_number2)
{
#ifdef ASCOM_CRYPTO

    CL_BnSub(pbn_dest, pbn_number1, pbn_number2);
    return(CW_OK);

#elif defined(TOMLIB_CRYPTO)

    int err;
    if ((err = mp_sub(pbn_number1, pbn_number2, pbn_dest)) == MP_OKAY)
        return (CW_OK);
    else
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" BN sub error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return (CW_ERROR);
    }

#endif
} /* cw_bn_sub() */

/*============================================================================*/
/*  cw_bn_mul()                                                               */
/*============================================================================*/
int cw_bn_mul(cw_bigNum_t * pbn_dest, cw_bigNum_t * pbn_number1,
        cw_bigNum_t * pbn_number2)
{
#ifdef ASCOM_CRYPTO

    CL_BnMul(pbn_dest, pbn_number1, pbn_number2);
    return(CW_OK);

#elif defined(TOMLIB_CRYPTO)

    int err;
    if ((err = mp_mul(pbn_number1, pbn_number2, pbn_dest)) == MP_OKAY)
        return (CW_OK);
    else
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" BN mul error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return (CW_ERROR);
    }

#endif
} /* cw_bn_mul() */

/*============================================================================*/
/*  cw_bn_div()                                                               */
/*============================================================================*/
int cw_bn_div(cw_bigNum_t * pbn_quotient, cw_bigNum_t * pbn_remainder,
        cw_bigNum_t * pbn_numerator, cw_bigNum_t * pbn_denominator)
{
#ifdef ASCOM_CRYPTO

    CL_BnDiv(pbn_quotient, pbn_remainder, pbn_numerator, pbn_denominator);
    return(CW_OK);

#elif defined(TOMLIB_CRYPTO)

    int err;
    if ((err = mp_div(pbn_numerator, pbn_denominator, pbn_quotient,
            pbn_remainder)) == MP_OKAY)
        return (CW_OK);
    else
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" BN div error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return (CW_ERROR);
    }

#endif
} /* cw_bn_div() */

/*==============================================================================
 PRNG FUNCTIONS
 =============================================================================*/

/*============================================================================*/
/*  cw_prng_init()                                                            */
/*============================================================================*/
int cw_prng_init(uint8_t* p_seed, size_t ul_seedLen)
{
#ifdef ASCOM_CRYPTO

    CL_RndInit();

#elif defined(TOMLIB_CRYPTO)
    int err;

    /* start it */
    if ((err = fortuna_start(&fortuna_prng)) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" fortuna Start error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return err;
    }
    /* add entropy */
    if ((err = fortuna_add_entropy(p_seed, ul_seedLen, &fortuna_prng))
            != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" fortuna Add_entropy error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return err;
    }
    /* ready and read */
    if ((err = fortuna_ready(&fortuna_prng)) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" fortuna Ready error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return err;
    }
    fortunaIdx = find_prng(CR_PRNG_NAME);
#endif
    return err;
} /* cw_prng_init() */

/*============================================================================*/
/*  cw_prng_read()                                                            */
/*============================================================================*/
int cw_prng_read(uint8_t* p_dest, size_t cwt_len)
{
    if (cwt_len > 0)
    {
#ifdef ASCOM_CRYPTO

        CL_RndGetPseudoRandom(p_dest, cwt_len);

#elif defined(TOMLIB_CRYPTO)

        fortuna_read(p_dest, cwt_len, &fortuna_prng);

#endif
    }
    return CW_OK;
} /* cw_prng_read() */

/*============================================================================*/
/*  cw_prng_seed()                                                            */
/*============================================================================*/
void cw_prng_seed(uint8_t* p_src, size_t cwt_len)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)
    int err;
    while (cwt_len > 0)
    {
        if ((err = fortuna_add_entropy(p_src, ((cwt_len > 32) ? 32 : cwt_len),
                &fortuna_prng)) != CRYPT_OK)
        {
#if DBG_CRYPT_WRAP
            CW_DBG_PRINTF(DBG_STRING" fortuna Add_entropy error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        }
        cwt_len -= 32;
    }

#endif
    return;
} /* cw_prng_seed() */

/*============================================================================*/
/*  cw_prng_export()                                                          */
/*============================================================================*/
int cw_prng_export(uint8_t* pc_out, size_t* pl_outlen)
{
    int err = CW_ERROR;
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)
    if ((err = fortuna_export(pc_out, (unsigned long *)pl_outlen, &fortuna_prng)) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" fortuna export error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        err = CW_ERROR;
    }

#endif
    return err;
} /* cw_prng_export() */

/*============================================================================*/
/*  cw_prng_import()                                                          */
/*============================================================================*/
int cw_prng_import(uint8_t* pc_in, size_t l_inlen)
{
    int err = CW_ERROR;
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)
    if ((err = fortuna_import(pc_in, l_inlen, &fortuna_prng)) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" fortuna import error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        err = CW_ERROR;
    }
    else
    {
        /* ready and read */
        if ((err = fortuna_ready(&fortuna_prng)) != CRYPT_OK)
        {
#if DBG_CRYPT_WRAP
            CW_DBG_PRINTF(DBG_STRING" fortuna ready error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
            err = CW_ERROR;
        }
        else
        {
            fortunaIdx = find_prng(CR_PRNG_NAME);
            err = CW_OK;
        }
    }

#endif
    return err;
} /* cw_prng_import() */

/*==============================================================================
 HASH FUNCTIONS
 =============================================================================*/

/*============================================================================*/
/*  cw_oidIdent2HashIDX()                                                     */
/*============================================================================*/
int cw_oidIdent2HashIDX(int i_oid)
{
    int hashAlgo;

    switch (i_oid)
    {
    case SSL_OID_MD5_WITH_RSA_ENC:
        hashAlgo = cw_getHashIndex(CR_MD5_NAME);
        break;
    case SSL_OID_SHA1_WITH_RSA_ENC:
        hashAlgo = cw_getHashIndex(CR_SHA1_NAME);
        break;
    case SSL_OID_SHA256_WITH_RSA_ENC:
        hashAlgo = cw_getHashIndex(CR_SHA256_NAME);
        break;
    case SSL_OID_SHA256_WITH_ECDSA_ENC:
    	hashAlgo = cw_getHashIndex(CR_SHA256_NAME); //vpy
    	break;
    default:
        hashAlgo = cw_getHashIndex(CR_INVALID);
#if DBG_CRYPT_WRAP || DBG_SSL
        CW_DBG_PRINTF(DBG_STRING" Signature Algorithm unknown: %s", DBG_FILE_NAME, __LINE__, sslOid_toName(i_oid));
#endif
        break;
    }

    return hashAlgo;
} /* cw_oidIdent2HashIDX() */

/*============================================================================*/
/*  cw_getHashIndex()                                                         */
/*============================================================================*/
int cw_getHashIndex(const char* pc_name)
{
    int ret = -1;

#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    ret = find_hash(pc_name);

#endif

    return ret;
} /* cw_getHashIndex() */

/*============================================================================*/
/*  cw_hash_memory()                                                          */
/*============================================================================*/
int cw_hash_memory(int hash_idx, uint8_t* pc_in, size_t ul_inLen,
        uint8_t* pc_out, size_t* pul_outlen)
{
#if defined(TOMLIB_CRYPTO)
    int err;
    err = hash_memory_multi(hash_idx, pc_out, (unsigned long *)pul_outlen, pc_in,
                            (unsigned long)ul_inLen, NULL, NULL);
    if (err == CRYPT_OK)
        return CW_OK;
#if DBG_CRYPT_WRAP
    CW_DBG_PRINTF(DBG_STRING" hash memory error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
#endif
    return CW_ERROR;
} /* cw_hash_memory() */

/*============================================================================*/
/*  cw_hash_memory_multi()                                                    */
/*============================================================================*/
int cw_hash_memory_multi(int hash_idx, uint8_t* pc_out, size_t* pul_outlen,
        uint8_t* pc_in1, size_t ul_in1len, uint8_t* pc_in2,
        size_t ul_in2len, uint8_t* pc_in3, size_t ul_in3len)
{
#if defined(TOMLIB_CRYPTO)
    int err;
    err = hash_memory_multi(hash_idx,
                            pc_out, (unsigned long*)pul_outlen,
                            pc_in1, (unsigned long)ul_in1len,
                            pc_in2, (unsigned long)ul_in2len,
                            pc_in3, (unsigned long)ul_in3len,
                            NULL, NULL);
    if (err == CRYPT_OK)
        return CW_OK;
#if DBG_CRYPT_WRAP
    CW_DBG_PRINTF(DBG_STRING" hash memory multi error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
#endif
    return CW_ERROR;
} /* cw_hash_memory_multi() */


static uint8_t loc_getDigestId(e_sslHashAlg_t cr_hashType)
{
    int8_t  err;
    int8_t  c_hashId;

    switch(cr_hashType) {

        case E_SSL_HASH_MD5:         c_hashId = find_hash(CR_MD5_NAME);   break;
        case E_SSL_HASH_SHA1:        c_hashId = find_hash(CR_SHA1_NAME);  break;
        case E_SSL_HASH_SHA256:      c_hashId = find_hash(CR_SHA256_NAME);break;

        case E_SSL_HASH_NONE:
        case E_SSL_HASH_INVALID:
        default:
            LOG_ERR("Invalid hash type %d",cr_hashType);
            return CW_ERROR;
    }

    /* valid hash? */
    if ((err = hash_is_valid(c_hashId)) != CRYPT_OK) {
        LOG_ERR("hash is valid condition failed. Reason %s", error_to_string(err));
        return CW_ERROR;
    }

    return c_hashId;
}


/*============================================================================*/
/*  cr_digestInit()                                                            */
/*============================================================================*/
int8_t cr_digestInit( void*     p_ctx, const uint8_t*   pc_key,
                      size_t l_keyLen,e_sslHashAlg_t     e_hashType)
{
    int8_t          err = CW_OK;
    int8_t         c_hashId;
    size_t          cwt_hSize;  /*! Hash size in bytes */
    uint8_t         c_bSize;    /*! Block size in bytes */
    size_t          c_tmpSize;  /*! Temp size in bytes */
    uint8_t         i;
    uint8_t*        pc_buf;     /*! Temp buffer pointer */

    assert(p_ctx != NULL);

    c_hashId = loc_getDigestId(e_hashType);

    if (c_hashId == CW_ERROR) {
        /* Hash algorithm not known for a crypto wrapper module */
        err = CW_ERROR;
    } else {
        /* No key  presented, so calculate pure hash*/
        if (!pc_key)
        {
            if (( err = hash_descriptor[c_hashId].init((cw_hashCtx_t * )p_ctx)) != CRYPT_OK) {
                LOG_ERR("digest init failed. Reason %s", error_to_string(err));
                err =  CW_ERROR;
            }
        } else {
            cw_hmacCtx_t*   p_hmac = (cw_hmacCtx_t * )p_ctx;

            p_hmac->hash    = c_hashId;
            cwt_hSize       = hash_descriptor[c_hashId].hashsize;
            c_bSize         = hash_descriptor[c_hashId].blocksize;

            /* valid key length? */
            if (l_keyLen == 0) {
                LOG_ERR("digest init failed. Reason %s",
                         error_to_string(CRYPT_INVALID_KEYSIZE));
                return  CW_ERROR;
            }

            /* allocate ram for buf */
            pc_buf = malloc(c_bSize);
            if (pc_buf == NULL) {
                LOG_ERR("digest init failed. Failed to malloc");
                return  CW_ERROR;
            }

            /* allocate memory for key */
            p_hmac->key = malloc(c_bSize);
            if (p_hmac->key == NULL) {
               LOG_ERR("digest init failed. Failed to malloc");
               err =  CW_ERROR;
               goto hmacDone;
            }

            /* (1) make sure we have a large enough key */
            if(l_keyLen > c_bSize) {
                c_tmpSize = c_bSize;
                if ((err = hash_memory(c_hashId, pc_key, (unsigned long)l_keyLen,
                                       p_hmac->key, (unsigned long*)&c_tmpSize)) != CRYPT_OK) {
                    err =  CW_ERROR;
                    goto hmacError;
                }

                if(cwt_hSize < c_bSize) {
                    zeromem((p_hmac->key) + cwt_hSize, (size_t)(c_bSize - cwt_hSize));
                }

                l_keyLen = cwt_hSize;
            } else {
                CW_MEMCOPY(p_hmac->key, pc_key, (size_t)l_keyLen);
                if(l_keyLen < c_bSize) {
                    zeromem(p_hmac->key + l_keyLen, (size_t)(c_bSize - l_keyLen));
                }
            }

            /* Create the initial vector for step (3) */
            for(i=0; i < c_bSize;   i++) {
                pc_buf[i] = p_hmac->key[i] ^ 0x36;
            }

            /* Pre-pend that to the hash data */
            if ((err = hash_descriptor[c_hashId].init(&p_hmac->md)) != CRYPT_OK) {
                err =  CW_ERROR;
                goto hmacError;
            }

            if ((err = hash_descriptor[c_hashId].process(&p_hmac->md, pc_buf, c_bSize)) != CRYPT_OK) {
                err =  CW_ERROR;
                goto hmacError;
            }

            goto hmacDone;

            hmacError:
                if (p_hmac->key) {
                    free(p_hmac->key);
                    p_hmac->key = NULL;
                }
            hmacDone:
                free(pc_buf);

        }
    }

    return (err);
} /* cr_digestInit() */

/*============================================================================*/
/*  cr_digestUpdate()                                                          */
/*============================================================================*/
int8_t cr_digestUpdate(void*  p_ctx,  const uint8_t*    rpc_in,
                       size_t cwt_len,e_sslHashAlg_t    e_hashType)
{
    int8_t  err;
    int8_t c_hashId;

    if (cwt_len == 0)
        return (CW_OK);

    c_hashId = loc_getDigestId(e_hashType);

    if (c_hashId != CW_ERROR) {
        if (( err = hash_descriptor[c_hashId].process((hash_state *)p_ctx,rpc_in, cwt_len)) != CRYPT_OK) {
            LOG_ERR("digest update failed. Reason %s", error_to_string(err));
            err = CW_ERROR;
        }
    } else {
        err = CW_ERROR;
    }
    return (err);
} /* cr_digestUpdate() */

/*============================================================================*/
/*  cr_digestFinish()                                                          */
/*============================================================================*/
int8_t cr_digestFinish(void* p_ctx, uint8_t* pc_out, size_t* pc_outLen,
                       e_sslHashAlg_t e_hashType)
{
    size_t          cwt_hSize;  /*! Hash size in bytes */
    uint8_t         c_bSize;    /*! Block size in bytes */
    uint8_t*        pc_buf;     /*! Temp buffer pointer */
    uint8_t*        pc_isha;    /*! Temp buffer pointer */
    size_t          i;
    int8_t          err = CW_OK;
    int8_t         c_hashId;   /*! Hash id */

    c_hashId = loc_getDigestId(e_hashType);

    if (c_hashId == CW_ERROR) {
        /* Hash algorithm not known for a crypto wrapper module */
        err = CW_ERROR;
    } else {

        if (!pc_outLen) {
            /* Try to calculate pure hash */
            if ((err = hash_descriptor[c_hashId].done((cw_hashCtx_t * )p_ctx, pc_out)) != CRYPT_OK)
            {
                LOG_ERR(" digest_done error: %s", error_to_string(err));
                err = CW_ERROR;
            }
        } else {
            cw_hmacCtx_t*   p_hmac = (cw_hmacCtx_t * )p_ctx;

            cwt_hSize       = hash_descriptor[c_hashId].hashsize;
            c_bSize         = hash_descriptor[c_hashId].blocksize;

            /* allocate buffers */
            pc_buf  = malloc(c_bSize);
            pc_isha = malloc(cwt_hSize);
            if (pc_buf == NULL || pc_isha == NULL) {
               if (pc_buf != NULL) {
                  free(pc_buf);
               }
               if (pc_isha != NULL) {
                  free(pc_isha);
               }
               LOG_ERR("digest done failed. Failed to malloc");
               if (p_hmac->key)
                   free(p_hmac->key);
               return CW_ERROR;
            }

            /* Get the hash of the first HMAC vector plus the data */
            if ((err = hash_descriptor[c_hashId].done(&p_hmac->md, pc_isha)) != CRYPT_OK) {
                err = CW_ERROR;
                goto hmacFinError;
            }

            /* Create the second HMAC vector vector for step (3) */
            for(i=0; i < c_bSize; i++) {
                pc_buf[i] = p_hmac->key[i] ^ 0x5C;
            }

            /* Now calculate the "outer" hash for step (5), (6), and (7) */
            if ((err = hash_descriptor[c_hashId].init(&p_hmac->md)) != CRYPT_OK) {
                err = CW_ERROR;
                goto hmacFinError;
            }
            if ((err = hash_descriptor[c_hashId].process(&p_hmac->md, pc_buf, c_bSize)) != CRYPT_OK) {
                LOG_ERR("hmac process failed. Reason %s",error_to_string(err));
                err = CW_ERROR;
                goto hmacFinError;
            }
            if ((err = hash_descriptor[c_hashId].process(&p_hmac->md, pc_isha, cwt_hSize)) != CRYPT_OK) {
                LOG_ERR("hmac process failed. Reason %s",error_to_string(err));
                err = CW_ERROR;
                goto hmacFinError;
            }
            if ((err = hash_descriptor[c_hashId].done(&p_hmac->md, pc_buf)) != CRYPT_OK) {
                LOG_ERR("hmac done failed. Reason %s",error_to_string(err));
                err = CW_ERROR;
                goto hmacFinError;
            }

            /* copy to output  */
            for (i = 0; i < cwt_hSize && i < *pc_outLen; i++) {
                pc_out[i] = pc_buf[i];
            }
            *pc_outLen = i;

            err = CW_OK;

            hmacFinError:
            if (p_hmac->key) {
                free(p_hmac->key);
                p_hmac->key = NULL;
            }

            zeromem(pc_isha, cwt_hSize);
            zeromem(pc_buf,  cwt_hSize);
            zeromem(p_hmac, sizeof(*p_hmac));

            free(pc_isha);
            free(pc_buf);
        }
    }



    return (CW_OK);
} /* cr_digestFinish() */

/*==============================================================================
 HMAC FUNCTIONS
 =============================================================================*/

/*============================================================================*/
/*  cw_hmac()                                                            */
/*============================================================================*/
int cw_hmac(e_sslHashAlg_t     e_hashType,
            const uint8_t* pc_key,   size_t   l_keyLen,
            const uint8_t* pc_in,    size_t   l_inLen,
            uint8_t*       pc_out,   size_t*  pl_outLen)
{
    int8_t err;

    const char* rc_hmacTag;

    switch(e_hashType) {

        case E_SSL_HASH_MD5:         rc_hmacTag = CR_MD5_NAME;   break;
        case E_SSL_HASH_SHA1:        rc_hmacTag = CR_SHA1_NAME;  break;
        case E_SSL_HASH_SHA256:      rc_hmacTag = CR_SHA256_NAME;break;

        case E_SSL_HASH_NONE:
        default:                    rc_hmacTag = CR_INVALID;    break;
    }

    if ((err = hmac_memory(find_hash(rc_hmacTag),
                           pc_key,  (unsigned long)l_keyLen,
                           pc_in,   (unsigned long)l_inLen,
                           pc_out,  (unsigned long*)pl_outLen)) != CRYPT_OK)
    {
        LOG_ERR("hmac error: %s", error_to_string(err));
        return CW_ERROR;
    }
    return CW_OK;
} /* cw_hmac() */


/*==============================================================================
 CIPHER API
 =============================================================================*/

/*============================================================================*/
/*  cw_rc4_init()                                                             */
/*============================================================================*/
int cw_rc4_init(cw_rc4Ctx_t* p_ctx, uint8_t* p_key, size_t cwt_keyLength)
{
#ifdef ASCOM_CRYPTO

    wrc4_prepare_key(p_ctx, p_key, cwt_keyLength);

#elif defined(TOMLIB_CRYPTO)

    rc4_done((prng_state*) p_ctx);
    if (rc4_start((prng_state*) p_ctx) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING " RC4 Start Error", DBG_FILE_NAME, __LINE__);
#endif
        return (CW_ERROR);
    }
    /* use ???key??? as the key */
    if (rc4_add_entropy(p_key, cwt_keyLength, (prng_state*) p_ctx) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING " RC4 Add Entropy Error", DBG_FILE_NAME, __LINE__);
#endif
        return (CW_ERROR);
    }
    /* setup RC4 for use */
    if (rc4_ready((prng_state*) p_ctx) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING " RC4 Ready Error", DBG_FILE_NAME, __LINE__);
#endif
        return (CW_ERROR);
    }

#endif
    return (CW_OK);
} /* cw_rc4_init() */

/*============================================================================*/
/*  cw_rc4()                                                                  */
/*============================================================================*/
int cw_rc4(cw_rc4Ctx_t* p_ctx, uint8_t* p_inBuffer, uint8_t* p_outBuffer,
        size_t cwt_bufLength)
{
#ifdef ASCOM_CRYPTO

    wrc4(p_ctx, p_outBuffer, p_inBuffer, cwt_bufLength);

#elif defined(TOMLIB_CRYPTO)

    if (p_outBuffer != p_inBuffer)
    {
        /* first we need to copy the data from the in- to the output-buffer */
        CW_MEMCOPY(p_outBuffer, p_inBuffer, cwt_bufLength);
    }
    /* encrypt buffer */
    if (rc4_read(p_outBuffer, cwt_bufLength, (prng_state*) p_ctx)
            != cwt_bufLength)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING " RC4 Read Error", DBG_FILE_NAME, __LINE__);
#endif
        return (CW_ERROR);
    }

#endif
    return (CW_OK);
} /* cw_rc4() */

/*============================================================================*/
/*  cw_3des_init()                                                            */
/*============================================================================*/
int cw_3des_init(cw_3desCtx* p_ctx, uint8_t* p_keyData, size_t cwt_keyLen,
        uint8_t* p_initVect, size_t cwt_IVLen, uint8_t c_direction)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    int err;
    cbc_done(p_ctx);
    if ((err = cbc_start(find_cipher(CR_3DES_NAME), p_initVect, p_keyData,
            cwt_keyLen, 0, p_ctx)) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" 3des Init error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return (CW_ERROR);
    }
#endif
    return (CW_OK);
} /* cw_3des_init() */

/*============================================================================*/
/*  cw_aes_init()                                                             */
/*============================================================================*/
int cw_aes_init(cw_aesCtx_t* p_ctx, uint8_t* p_keyData, size_t cwt_keyLen,
        uint8_t* p_initVect, size_t cwt_IVLen, uint8_t c_direction)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    int err;
    cbc_done(p_ctx);
    if ((err = cbc_start(find_cipher(CR_AES_NAME), p_initVect, p_keyData,
            cwt_keyLen, 0, p_ctx)) != CRYPT_OK)
    {
#if DBG_CRYPT_WRAP
        CW_DBG_PRINTF(DBG_STRING" AES Init error: %s", DBG_FILE_NAME, __LINE__, error_to_string(err));
#endif
        return (CW_ERROR);
    }
#endif
    return (CW_OK);
} /* cw_aes_init() */

/*============================================================================*/
/*  cw_cbc_setiv()                                                          */
/*============================================================================*/
int cw_cbc_setiv(cw_cbcCtx* p_cbc, const uint8_t* IV, size_t len)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    int err;
    if ((err = cbc_setiv(IV, len, p_cbc)) != CRYPT_OK)
    {
        LOG_INFO("cbc_setiv error: %s", error_to_string(err));
        return (CW_ERROR);
    }

#endif
    return (CW_OK);
} /* cw_cbc_setiv() */

/*============================================================================*/
/*  cw_cbc_encrypt()                                                          */
/*============================================================================*/
int cw_cbc_encrypt(cw_cbcCtx* p_ctx, uint8_t* p_inBuffer, uint8_t* p_outBuffer,
        size_t cwt_bufLength)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    int err;
    if ((err = cbc_encrypt(p_inBuffer, p_outBuffer, cwt_bufLength, p_ctx))
            != CRYPT_OK)
    {
        LOG_ERR("cbc_encrypt error: %s", error_to_string(err));
        return (CW_ERROR);
    }

#endif
    return (CW_OK);
} /* cw_cbc_encrypt() */

/*============================================================================*/
/*  cw_cbc_decrypt()                                                          */
/*============================================================================*/
int cw_cbc_decrypt(cw_cbcCtx* p_ctx, uint8_t* p_inBuffer, uint8_t* p_outBuffer,
        size_t cwt_bufLength)
{
#ifdef ASCOM_CRYPTO

#elif defined(TOMLIB_CRYPTO)

    int err;
    if ((err = cbc_decrypt(p_inBuffer, p_outBuffer, cwt_bufLength, p_ctx))
            != CRYPT_OK)
    {
        LOG_ERR("cbc_dencrypt error: %s", error_to_string(err));
        return (CW_ERROR);
    }

#endif
    return (CW_OK);
} /* cw_cbc_decrypt() */

/*==============================================================================
 malloc/calloc/realloc/free wrapping for debug purpose
 =============================================================================*/
#if DBG_CRYPT_WRAP_MALLOC
/*============================================================================*/
/*

 We generate output that can be imported as CSV and so analyzed
 Structure is:

 command,function,destinationpointer,numberofbytes,__FILE__,__LINE__

 emBetter and emBetter SSL don't use dynamic memory allocation so the changes
 have to be done in the libtomcrypt and libtommath. therefore can special
 makefiles be provided that these libs use this malloc wrapping

 */
/*============================================================================*/
void* mal_loc(size_t n, const char* c, int i)
{
    void* ret;
    ret = malloc(n);
    CW_DBG_PRINTF("\r\nmalloc,alloc,%p,%li,%s,%d",ret,n,c,i);
    return ret;
} /* mal_loc() */

void fr_ee(void *aptr, const char* c, int i)
{
    CW_DBG_PRINTF("\r\nfree,free,%p,,%s,%d",aptr,c,i);
    free(aptr);
} /* fr_ee() */

void *re_alloc(void *aptr, size_t nbytes, const char* c, int i)
{
    void* ret;
    ret = realloc(aptr, nbytes);
    CW_DBG_PRINTF("\r\nrealloc,free,%p,,%s,%d", aptr,c ,i);
    CW_DBG_PRINTF("\r\n,alloc,%p,%li,%s,%d",ret,nbytes,c,i);
    return ret;
} /* re_alloc() */

void *c_alloc(size_t n, size_t s, const char* c, int i)
{
    void* ret;
    ret = calloc(n,s);
    CW_DBG_PRINTF("\r\ncalloc,alloc,%p,%li,%s,%d",ret,n*s,c ,i);
    return ret;
} /* c_alloc() */
#endif /* DBG_CRYPT_WRAP_MALLOC */

/*==============================================================================
 implementation for usage of the hardware AES accelerator in the 5in1 package
 =============================================================================*/
#if HARDWARE_AES
static int hw_aes_128_encrypt(const char* p_data, char* p_out, char* p_key)
{
    int i, k;
    char input[16], output[16], key[16];
    char *p_input, *p_output;
    p_input = input; p_output = output;
    /*
     * Base address of the aes module
     */
    int *p_base = (int*)AES_INTERFACE_0_BASE;
    i = 15; k = 0;
    for(;k<16;)
    {
        /* We swap around the key and input */
        input[k] = p_data[i];
        key[k] = p_key[i];
        i--; k++;
    } /* for */
    p_key = key;
    /*
     * Write the data registers first
     */
    if (p_data)
    {
        for (i=0; i < 4; i++)
        {
            IOWR_AES_DATA_IN_0(p_base + i, *(unsigned int*)p_input);
            p_input+=4;
        } /* for */
    } /* if */

    /*
     * Set the key
     */
    if (p_key)
    {
        for (i=0; i < 4; i++)
        {
            IOWR_AES_KEY_0(p_base + i, *(unsigned int*)p_key);
            p_key+=4;
        }
    }

    /*
     * Set the mode and wait for the encryption/decryption
     * to finish
     */
    IOWR_AES_CMD_MODE(p_base, AES_CMD_MSK_ENCRYPT);          // MaCo
    do;
    while (!IORD_AES_CMD_STATE(p_base));

    /*
     * Copy the data to the output register
     */
    for (i=0; i < 4; i++)
    {
        *(int*)p_output = IORD_AES_DATA_OUT_0(p_base + i);
        p_output+=4;
    } /* for */
    i = 15; k = 0;
    for(;k<16;)
    {
        /* We swap around the output */
        p_out[k] = output[i];
        i--; k++;
    } /* for */
    return CRYPT_OK;
} /* hw_aes_128_encrypt() */

static int hw_aes_encrypt(const unsigned char* pt, unsigned char* ct, unsigned long len, unsigned char* IV, symmetric_key* key)
{
    int i, j;
    char keybuf[16];
    for(i = j = 0; i<16; i+=4, j++)
    {
        *(uint32_t*)&keybuf[i] = ntohl(key->rijndael.eK[j]);
    }
    while(len)
    {
        /* XOR IV against plaintext */
        for(i = 0; i < 16; i++)
        {
            IV[i] ^= pt[i];
        }
        /* encrypt the data */
        hw_aes_128_encrypt(IV, ct, keybuf);
        /* Save ciphertext as IV for the next block */
        CW_MEMCOPY(IV, ct, 16);

        pt+=16;
        ct+=16;
        len--;
    }
    return CRYPT_OK;
} /* hw_aes_encrypt() */

#if HARDWARE_AES_DECRYPT
static int hw_aes_128_decrypt(const unsigned char* p_data, unsigned char* p_out, char* p_key)
{
    int i;

    /*
     * Write the data registers first
     */
    if (p_data)
    {
        for (i=0; i < 4; i++)
        {
            IOWR_AES_DATA_IN_0(i, *(unsigned long*)p_data);
            p_data+=4;
        } /* for */
    } /* if */

    /*
     * Set the key
     */
    if (p_key)
    for (i=0; i < 4; i++)
    {
        IOWR_AES_KEY_0(i, *(unsigned long*)p_key);
        p_key+=4;
    }

    /*
     * Set the mode and wait for the encryption/decryption
     * to finish
     */
    IOWR_AES_CMD_MODE(AES_CMD_MSK_DECRYPT);          // MaCo
    do;
    while (!IORD_AES_CMD_STATE());

    /*
     * Copy the data to the output register
     */
    for (i=0; i < 4; i++)
    {
        *(unsigned long*)p_out = IORD_AES_DATA_OUT_0(i);
        p_out+=4;
    } /* for */

    return CRYPT_OK;
} /* hw_aes_128_decrypt() */

#endif /* HARDWARE_AES_DECRYPT */
#endif /* HARDWARE_AES */
/*==============================================================================
 EOF - Test Section following - EOF
 =============================================================================*/

#if _CW_TEST_
/*==============================  TEST SECTION ===============================*/

#if CW_AES_TEST

#if HARDWARE_AES
char gc_PlainText_d[3][16]=
{

    {   0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},

    {   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},

    {   0x01, 0x4B, 0xAF, 0x22, 0x78, 0xA6, 0x9D, 0x33,
        0x1D, 0x51, 0x80, 0x10, 0x36, 0x43, 0xE9, 0x9A}

};
char gc_CipherText_d[3][16]=
{

    {   0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},

    {   0x3a, 0xd7, 0x8e, 0x72, 0x6c, 0x1e, 0xc0, 0x2b,
        0x7e, 0xbf, 0xe9, 0x2b, 0x23, 0xd9, 0xec, 0x34},

    {   0x67, 0x43, 0xC3, 0xD1, 0x51, 0x9A, 0xB4, 0xF2,
        0xCD, 0x9A, 0x78, 0xAB, 0x09, 0xA5, 0x11, 0xBD}

};
char gc_Key_d[3][16]=
{

    {   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},

    {   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},

    {   0xE8, 0xE9, 0xEA, 0xEB, 0xED, 0xEE, 0xEF, 0xF0,
        0xF2, 0xF3, 0xF4, 0xF5, 0xF7, 0xF8, 0xF9, 0xFA}

};
#endif /* HARDWARE_AES */

char gc_pt1[ 16 ] = /* First 16-byte block of Plain Text */
{   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
gc_pt2[ 16 ] = /* Second 16-byte block of Plain Text */
{   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

char gc_iv[ 16 ] =
{   0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

char gc_ct1[ 16 ] =
{   0xe6, 0xfc, 0x19, 0xf8, 0xd2, 0x69, 0x58, 0x85,
    0x24, 0xc0, 0x00, 0x08, 0xfb, 0x1a, 0x57, 0x2f},
gc_ct2[ 16 ] =
{   0x10, 0xc3, 0x03, 0xf7, 0xfa, 0x5a, 0xb8, 0x4c,
    0x43, 0x20, 0xfe, 0xbf, 0x72, 0x9e, 0x91, 0x3d};

char gc_key[ 16 ] =
{   0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

void _aes_test(void)
{
    char ac_buffer[16], *pc_buffer;

    cw_aesCtx_t cw_ctx;

    pc_buffer = ac_buffer;

#if HARDWARE_AES

    char *pc_pt, *pc_ct, *pc_key;
    int i;

    for(i=0; i<3; i++)
    {
        pc_pt = gc_PlainText_d[i];
        pc_ct = gc_CipherText_d[i];
        pc_key = gc_Key_d[i];
        hw_aes_128_encrypt(pc_pt, pc_buffer, pc_key);
        if(memcmp(pc_ct, pc_buffer, 16))
        {
            CW_DBG_PRINTF(DBG_STRING" Hardware AES Test No. %d not successful", DBG_FILE_NAME, __LINE__, i);
#if CW_AES_TEST == 2
            CW_DBG_PRINTF(DBG_STRING" IS:", DBG_FILE_NAME, __LINE__);
            sslDiag_printHex(pc_buffer, 16);
            CW_DBG_PRINTF(DBG_STRING" SHOULD BE:", DBG_FILE_NAME, __LINE__);
            sslDiag_printHex(pc_ct, 16);
#endif
        }
    }

#endif /* HARDWARE_AES */

    if(cw_aes_init(&cw_ctx, gc_key, 16, gc_iv, 16, 0) != CW_OK)
    {
        CW_DBG_PRINTF(DBG_STRING" AES INIT not successful", DBG_FILE_NAME, __LINE__);
        return;
    }
    if(cw_aes_encrypt(&cw_ctx, gc_pt1, pc_buffer, 16) != CW_OK)
    {
        CW_DBG_PRINTF(DBG_STRING" AES ENCRYPT not successful", DBG_FILE_NAME, __LINE__);
        return;
    }
    if(memcmp(gc_ct1, pc_buffer, 16))
    {
        CW_DBG_PRINTF(DBG_STRING" AES CBC ENCRYPT 1 not successful", DBG_FILE_NAME, __LINE__);
#if CW_AES_TEST == 2
        CW_DBG_PRINTF(DBG_STRING" IS:", DBG_FILE_NAME, __LINE__);
        sslDiag_printHex(pc_buffer, 16);
        CW_DBG_PRINTF(DBG_STRING" SHOULD BE:", DBG_FILE_NAME, __LINE__);
        sslDiag_printHex(gc_ct1, 16);
#endif
    }
    if(cw_aes_encrypt(&cw_ctx, gc_pt2, pc_buffer, 16) != CW_OK)
    {
        CW_DBG_PRINTF(DBG_STRING" AES ENCRYPT not successful", DBG_FILE_NAME, __LINE__);
        return;
    }
    if(memcmp(gc_ct2, pc_buffer, 16))
    {
        CW_DBG_PRINTF(DBG_STRING" AES CBC ENCRYPT 2 not successful", DBG_FILE_NAME, __LINE__);
#if CW_AES_TEST == 2
        CW_DBG_PRINTF(DBG_STRING" IS:", DBG_FILE_NAME, __LINE__);
        sslDiag_printHex(pc_buffer, 16);
        CW_DBG_PRINTF(DBG_STRING" SHOULD BE:", DBG_FILE_NAME, __LINE__);
        sslDiag_printHex(gc_ct2, 16);
#endif
    }

}/* void _aes_test(void) */
#endif /* CW_AES_TEST */

#endif /* _CW_TEST_ */
