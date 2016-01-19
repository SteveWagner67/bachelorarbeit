/**
 * \file 				crypto_tomcrypt.c
 * \brief 				See crypto_tomcrypt.h
 * \author				Steve Wagner
 * \date 		1		02/11/2015
 */

/*--------------------------------------------------Include--------------------------------------------------------------*/
#ifndef CRYPTO_TOM
#define CRYPTO_TOM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_tomcrypt.h"

#define LOGGER_ENABLE       DBG_SSL_PROTO_MODULE
#include "logger.h"

#endif

/*---------------------------------------------Functions from crypto_tomcrypt.h---------------------------------------------*/



/********************************/
/*  tcGetBigNum                 */
/********************************/
en_gciResult_t tcGetBigNum(const uint8_t* p_data, size_t dataLen, st_gciBigInt_t* p_bigNum)
{
    en_gciResult_t err = en_gciResult_Ok;
    int tmpErr = MP_OKAY;

    /* Big number from LibTomcrypt */
    mp_int bigNum;


    /* Init big number (from LibTomcrypt) */
    tmpErr = mp_init_size(&bigNum, dataLen);
    if(tmpErr != MP_OKAY)
    {
        err = en_gciResult_Err;
        printf("TC Error: Init big number\r\n");
    }

    /* Get the big number (from LibTomcrypt) from a buffer */
    tmpErr = mp_read_unsigned_bin(&bigNum, p_data, dataLen);
    if(tmpErr != MP_OKAY)
    {
        err = en_gciResult_Err;
        printf("TC Error: Read big number from buffer\r\n");
    }


    /* Convert big number (from LibTomcrypt) into buffer of bytes */
    tmpErr = mp_to_unsigned_bin(&bigNum, p_bigNum->data);
    if(tmpErr != MP_OKAY)
    {
        err = en_gciResult_Err;
        printf("TC Error: Convert big number to buffer of bytes\r\n");
    }

    /* Get the length of the big number (from LibTomcrypt) */
    p_bigNum->len = mp_unsigned_bin_size(&bigNum);

    /* Clear the big number (from LibTomCrypt) */
    mp_clear(&bigNum);

    return err;
}

en_gciResult_t tcImportRsaPrivKey(uint8_t* p_buffer, size_t bufLen, GciKeyId_t* p_rsaPrivKeyID, GciKeyId_t* p_rsaPubKeyID)
{
    en_gciResult_t err = en_gciResult_Ok;
    int tmpErr;

    uint8_t a_allocRsaPubE[TC_RSA_KEY_SIZE_MAX_BYTES];
    uint8_t a_allocRsaPrivD[TC_RSA_KEY_SIZE_MAX_BYTES];
    uint8_t a_allocRsaN[TC_RSA_KEY_SIZE_MAX_BYTES];
    st_gciRsaCrtPrivKey_t a_allocCrt[5*TC_RSA_KEY_SIZE_MAX_BYTES];
    uint8_t a_allocCrtP[TC_RSA_KEY_SIZE_MAX_BYTES];
    uint8_t a_allocCrtQ[TC_RSA_KEY_SIZE_MAX_BYTES];
    uint8_t a_allocCrtDP[TC_RSA_KEY_SIZE_MAX_BYTES];
    uint8_t a_allocCrtDQ[TC_RSA_KEY_SIZE_MAX_BYTES];
    uint8_t a_allocCrtQP[TC_RSA_KEY_SIZE_MAX_BYTES];
    st_gciKey_t rsaPrivKey = {.type = en_gciKeyType_RsaPriv};
    st_gciKey_t rsaPubKey  = {.type = en_gciKeyType_RsaPub };

    rsa_key bnRsaKey;
    mp_int *bnRsaN, *bnRsaE, *bnRsaD, *bnRsaCrtQP, *bnRsaCrtDP, *bnRsaCrtP, *bnRsaCrtQ, *bnRsaCrtDQ;

    /* Allocate memory */
    rsaPubKey.un_key.keyRsaPub.e.data = a_allocRsaPubE;
    rsaPubKey.un_key.keyRsaPub.n.data = a_allocRsaN;
    rsaPrivKey.un_key.keyRsaPriv.d.data = a_allocRsaPrivD;
    rsaPrivKey.un_key.keyRsaPriv.n.data = a_allocRsaN;
    rsaPrivKey.un_key.keyRsaPriv.crt = a_allocCrt;
    rsaPrivKey.un_key.keyRsaPriv.crt->dP.data = a_allocCrtDP;
    rsaPrivKey.un_key.keyRsaPriv.crt->dQ.data = a_allocCrtDQ;
    rsaPrivKey.un_key.keyRsaPriv.crt->p.data = a_allocCrtP;
    rsaPrivKey.un_key.keyRsaPriv.crt->q.data = a_allocCrtQ;
    rsaPrivKey.un_key.keyRsaPriv.crt->qP.data = a_allocCrtQP;

    /* Init the buffer */
    memset(rsaPubKey.un_key.keyRsaPub.e.data, 0, TC_RSA_KEY_SIZE_MAX_BYTES);
    memset(rsaPubKey.un_key.keyRsaPub.n.data, 0, TC_RSA_KEY_SIZE_MAX_BYTES);
    memset(rsaPrivKey.un_key.keyRsaPriv.d.data, 0, TC_RSA_KEY_SIZE_MAX_BYTES);
    memset(rsaPrivKey.un_key.keyRsaPriv.n.data, 0, TC_RSA_KEY_SIZE_MAX_BYTES);
    memset(rsaPrivKey.un_key.keyRsaPriv.crt->dP.data, 0, TC_RSA_KEY_SIZE_MAX_BYTES);
    memset(rsaPrivKey.un_key.keyRsaPriv.crt->dQ.data, 0, TC_RSA_KEY_SIZE_MAX_BYTES);
    memset(rsaPrivKey.un_key.keyRsaPriv.crt->p.data, 0, TC_RSA_KEY_SIZE_MAX_BYTES);
    memset(rsaPrivKey.un_key.keyRsaPriv.crt->q.data, 0, TC_RSA_KEY_SIZE_MAX_BYTES);
    memset(rsaPrivKey.un_key.keyRsaPriv.crt->qP.data, 0, TC_RSA_KEY_SIZE_MAX_BYTES);

    /* Import the RSA private key */
    tmpErr = rsa_import(p_buffer, (uint32_t) bufLen, &bnRsaKey);


    if(tmpErr != CRYPT_OK)
    {
        printf("TC Error in tcImportRsaPrivKey: Import RSA private key\r\n");
        err = en_gciResult_Err;
        return err;
    }


    /* Convert the big numbers to buffer of bytes */

    bnRsaN = bnRsaKey.N;
    bnRsaE = bnRsaKey.e;
    bnRsaD = bnRsaKey.d;
    bnRsaCrtDP = bnRsaKey.dP;
    bnRsaCrtDQ = bnRsaKey.dQ;
    bnRsaCrtP = bnRsaKey.p;
    bnRsaCrtQ = bnRsaKey.q;
    bnRsaCrtQP = bnRsaKey.qP;

    /* Modulus */
    mp_to_unsigned_bin(bnRsaN, rsaPubKey.un_key.keyRsaPub.n.data);
    rsaPubKey.un_key.keyRsaPub.n.len = mp_unsigned_bin_size(bnRsaN);

    mp_to_unsigned_bin(bnRsaN, rsaPrivKey.un_key.keyRsaPriv.n.data);
    rsaPrivKey.un_key.keyRsaPriv.n.len = mp_unsigned_bin_size(bnRsaN);

    /* Public exponent */
    mp_to_unsigned_bin(bnRsaE, rsaPubKey.un_key.keyRsaPub.e.data);
    rsaPubKey.un_key.keyRsaPub.e.len = mp_unsigned_bin_size(bnRsaE);

    /* Private exponent */
    mp_to_unsigned_bin(bnRsaD, rsaPrivKey.un_key.keyRsaPriv.d.data);
    rsaPrivKey.un_key.keyRsaPriv.d.len = mp_unsigned_bin_size(bnRsaD);

    /* CRT dP */
    mp_to_unsigned_bin(bnRsaCrtDP, rsaPrivKey.un_key.keyRsaPriv.crt->dP.data);
    rsaPrivKey.un_key.keyRsaPriv.crt->dP.len = mp_unsigned_bin_size(bnRsaCrtDP);

    /* CRT dQ */
    mp_to_unsigned_bin(bnRsaCrtDQ, rsaPrivKey.un_key.keyRsaPriv.crt->dQ.data);
    rsaPrivKey.un_key.keyRsaPriv.crt->dQ.len = mp_unsigned_bin_size(bnRsaCrtDQ);

    /* CRT p */
    mp_to_unsigned_bin(bnRsaCrtP, rsaPrivKey.un_key.keyRsaPriv.crt->p.data);
    rsaPrivKey.un_key.keyRsaPriv.crt->p.len = mp_unsigned_bin_size(bnRsaCrtP);

    /* CRT q */
    mp_to_unsigned_bin(bnRsaCrtQ, rsaPrivKey.un_key.keyRsaPriv.crt->q.data);
    rsaPrivKey.un_key.keyRsaPriv.crt->q.len = mp_unsigned_bin_size(bnRsaCrtQ);

    /* CRT qP */
    mp_to_unsigned_bin(bnRsaCrtQP, rsaPrivKey.un_key.keyRsaPriv.crt->qP.data);
    rsaPrivKey.un_key.keyRsaPriv.crt->qP.len = mp_unsigned_bin_size(bnRsaCrtQP);


    /* Random research */
    *p_rsaPrivKeyID = -1;
    *p_rsaPubKeyID = -1;

    /* Get an ID of the private key */
    err = gciKeyPut(&rsaPrivKey, p_rsaPrivKeyID);

    /* Get an ID of the public key */
    err = gciKeyPut(&rsaPubKey, p_rsaPubKeyID);

    mp_clear_multi(bnRsaN, bnRsaE, bnRsaD, bnRsaCrtQP, bnRsaCrtDP, bnRsaCrtP, bnRsaCrtQ, bnRsaCrtDQ);

    return err;
}

/*---------------------------------------------EOF-----------------------------------------------------------------------*/
