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

/*---------------------------------------------EOF-----------------------------------------------------------------------*/
