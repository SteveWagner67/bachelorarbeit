/*================================================================================================*/
/*!
 \file   ssl_derd.c

 \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  ASN.1/BER/DER Basic Decoder

 \version  $Version$

 */
/*
 * derd.c - Asn.1/BER/DER Basic Decoder
 * -----------------------------------------
 *
 * Last update: xx.01.2002 rsu
 * Reviewed:
 *
 * History
 *  16.01.2002  rsu  Created this file.
 *  xx.01.2002  rsu  Base implementation for certificate decoder
 *
 *
 *
 *
 * void sslDerd_initDecCtx ( s_derdCtx_t * pCtx, s_sslOctetStr_t * pOctet )
 *
 * Input:   pOctet->pc_data = 30 0D 06 09 2A 86 48 86 F7 0D 01 01 04 05 00
 *          pOctet->cwt_len  = 0F (15)
 *
 * Output:  pCtx->s_octBuf (cwt_len = 0F)
 *          pCtx->s_octDer (cwt_len = 0F)
 *          |     pCtx->s_octVal (cwt_len = 0B)
 *          |     |
 *          30 0D |                                         SEQUENCE  len = 0D (13)
 *          |     06 09 2A 86 48 86 F7 0D 01 01 04              OBJECT    len =  9
 *          |     |                                05 00        NULL      len =  0
 *          |     pCtx->l_pos
 *          pCtx->c_tag (= SEQUENCE)
 *
 *
 * after sslDerd_initDecCtx next Operation:
 *
 * int sslDerd_getNextValue ( s_derdCtx_t * pCtx );
 *
 * Input:   pCtx
 *
 * Output:  pCtx->s_octBuf (cwt_len = 0F)
 *          |     pCtx->s_octDer (cwt_len = 0B)
 *          |     |     pCtx->s_octVal (len = 09)
 *          |     |     |
 *          30 0D |     |                                   SEQUENCE  len = 0D (13)
 *                06 09 2A 86 48 86 F7 0D 01 01 04              OBJECT    len =  9
 *                |                                05 00        NULL      len =  0
 *                |                                |
 *                |                                pCtx->l_pos
 *                pCtx->c_tag (= OBJECT)
 *
 *
 *
 */

//#include "crypto_wrap.h"
#include "netGlobal.h"
#include "ssl_der.h"
#include "ssl_derd.h"
#include "ssl_certHandler.h"
#include "ssl_oid.h"

/*** Defines ****************************************************************/
#define	LOGGER_ENABLE		DBG_SSL_DERD
#include "logger.h"

/*** Global Variables *******************************************************/

/*** Local Variables ********************************************************/

/*** Forward declarations ***************************************************/

/*** Local Functions ********************************************************/
static int loc_getNextTag(s_derdCtx_t * pCtx);

/****************************************************************************
 * Get the next DER tag an moves the the decoding pointer to the VALUE of
 * the DER value.
 ****************************************************************************/
static int loc_getNextTag(s_derdCtx_t * pCtx)
{
    int len;
    uint8_t res = SSL_DER_ASN1_UNDEF;
    uint8_t lenbytes = 0;
    uint8_t i;

    assert(pCtx != NULL);
    assert(pCtx->s_octBuf.pc_data != NULL);
    assert(pCtx->s_octBuf.cwt_len > 0);

    /* minimal DER length for Next is 2 (if NULL value encoded) */
    if (pCtx->l_pos <= (pCtx->s_octBuf.cwt_len - 2))
    {
        pCtx->s_octDer.pc_data = &(pCtx->s_octBuf.pc_data[pCtx->l_pos]);

        res = pCtx->s_octBuf.pc_data[pCtx->l_pos];

        pCtx->l_pos++;
        len = pCtx->s_octBuf.pc_data[pCtx->l_pos];
        pCtx->l_pos++;

        if (len > SSL_DER_ASN1_BIGLENTHG)
        {
            lenbytes = len & SSL_DER_ASN1_BIGLENTHG;
            len = 0;

            /* check maximal length info and range (end) of pCtx->s_octBuf */
            if ((lenbytes <= SSL_DER_ASN1_MAX_SIZE_OCTET)
                    && (pCtx->l_pos < (pCtx->s_octBuf.cwt_len - lenbytes)))
            {
                for (i = 0; i < lenbytes; i++)
                {
                    len *= 0x100;
                    len += pCtx->s_octBuf.pc_data[pCtx->l_pos];
                    pCtx->l_pos++;
                }

                /* check the maximum length of an Asn.1 sequence / type */
                if (len > SSL_DER_ASN1_MAX_SEQUENCE_OCTET)
                {
                    res = SSL_DER_ASN1_UNDEF;
                    len = SSL_DER_ASN1_MAX_SEQUENCE_OCTET;
                }
            }
            else
            {
                res = SSL_DER_ASN1_UNDEF;
                len = SSL_DER_ASN1_MAX_SEQUENCE_OCTET;
            }
        }

        /* a DER NULL value is encoded ( length = 0 ) */
        if ((len > 0) || (res == SSL_DER_ASN1_UNDEF))
        {
            /* check if adress and the value of Next is inside of pCtx->s_octBuf */
            if ((pCtx->l_pos + len) <= pCtx->s_octBuf.cwt_len)
            {
                pCtx->s_octVal.pc_data = &(pCtx->s_octBuf.pc_data[pCtx->l_pos]);
            }
            else
            {
                res = SSL_DER_ASN1_UNDEF;
            }
        }
        else
        {
            pCtx->s_octVal.pc_data = NULL;
        }

        pCtx->s_octDer.cwt_len = len + lenbytes + 2;
        pCtx->s_octVal.cwt_len = len;
        pCtx->c_tag = res;
    }

    return (res);
} /* _getNextTag */

/****************************************************************************
 * Set the next DER tag an moves the the decoding pointer to the VALUE of
 * the DER value.
 ****************************************************************************/
int16_t sslDerd_setTag(s_derdCtx_t * ps_derdCtx, uint8_t c_tag, size_t* psz_lenOff)
{
    e_derdRet_t e_err = E_SSL_DER_OK;
    assert(ps_derdCtx != NULL);
    assert(ps_derdCtx->s_octBuf.pc_data != NULL);
    assert(ps_derdCtx->s_octBuf.cwt_len > 0);

    /* minimal DER length for Next is 2 (if NULL value encoded) */
    if (ps_derdCtx->l_pos <= (ps_derdCtx->s_octBuf.cwt_len))
    {
        ps_derdCtx->s_octDer.pc_data = &(ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos]);
        ps_derdCtx->s_octVal.pc_data = &(ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos]);

        ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos] = c_tag;

        ps_derdCtx->l_pos++;
        if (psz_lenOff != NULL )
            *psz_lenOff = ps_derdCtx->l_pos;
        ps_derdCtx->l_pos++;

        ps_derdCtx->s_octBuf.cwt_len = ps_derdCtx->l_pos;
        ps_derdCtx->c_tag = c_tag;
    } else {
        e_err = E_SSL_DER_ERR_ENCODING;
    }

    return (e_err);
} /* sslDerd_setTag */

/*** Global Functions *******************************************************/

/*============================================================================*/
/*  sslDerd_initDecCtx()                                                         */
/*============================================================================*/
int16_t sslDerd_initDecCtx(s_derdCtx_t *ps_derdCtx, s_sslOctetStr_t *ps_octStr)
{

    assert(ps_derdCtx != NULL);
    assert(ps_octStr != NULL);
    assert(ps_octStr->pc_data != NULL);
    assert(ps_octStr->cwt_len > 0);

    ps_derdCtx->s_octBuf = *ps_octStr;
    ps_derdCtx->s_octDer = *ps_octStr;
    ps_derdCtx->l_pos = 0;
    ps_derdCtx->s_octVal = *ps_octStr;
    ps_derdCtx->c_tag = SSL_DER_ASN1_UNDEF;
    ps_derdCtx->c_EOS = FALSE;

    return sslDerd_getNextValue(ps_derdCtx);
} /* sslDerd_initDecCtx */

/*============================================================================*/
/*  sslDerd_initDecCtx()                                                         */
/*============================================================================*/
void sslDerd_initEncCtx(s_derdCtx_t *ps_derdCtx, s_sslOctetStr_t *ps_octStr)
{
    assert(ps_derdCtx != NULL);
    assert(ps_octStr != NULL);
    assert(ps_octStr->pc_data != NULL);
    assert(ps_octStr->cwt_len > 0);

    ps_derdCtx->s_octBuf = *ps_octStr;
    ps_derdCtx->s_octDer = *ps_octStr;
    ps_derdCtx->l_pos = 0;
    ps_derdCtx->s_octVal = *ps_octStr;
    ps_derdCtx->c_tag = SSL_DER_ASN1_UNDEF;
    ps_derdCtx->c_EOS = FALSE;
} /* sslDerd_initDecCtx */

/*============================================================================*/
/*  sslDerd_scanTag()                                                         */
/*============================================================================*/
e_derdRet_t sslDerd_scanTag(s_derdCtx_t *ps_derdCtx,
        const uint8_t rac_tagList[])
{
    int16_t i = 1;
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);
    assert(rac_tagList != NULL);

    if (ps_derdCtx->c_tag != rac_tagList[0])
    {
        e_res = E_SSL_DER_ERR_WRONGTAG;
    }
    else
    {
        while ((rac_tagList[i] != 0) && (e_res == 0)
                && (i < SSL_DERD_MAXSCANTAGS))
        {
            if (sslDerd_getNextValue(ps_derdCtx) != rac_tagList[i])
            {
                e_res = E_SSL_DER_ERR_WRONGTAG;
            }
            i++;
        }
    }
    return (e_res);
} /* sslDerd_scanTag */

/*============================================================================*/
/*  sslDerd_getNextValue()                                                    */
/*============================================================================*/
int16_t sslDerd_getNextValue(s_derdCtx_t *ps_derdCtx)
{
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);

    e_res = loc_getNextTag(ps_derdCtx);

    /* if it is a non-Constructed data type */
    if ((e_res & SSL_DER_ASN1_CONSTRUCTED) != SSL_DER_ASN1_CONSTRUCTED)
    {
        /* move pointer to end of value */
        ps_derdCtx->l_pos += ps_derdCtx->s_octVal.cwt_len;

        /* is the end of the octet string reached ? */
        if (ps_derdCtx->l_pos >= ps_derdCtx->s_octBuf.cwt_len)
        {
            ps_derdCtx->c_EOS = TRUE;
        }
    }
    return (e_res);
} /* sslDerd_getNextValue */

/*============================================================================*/
/*  sslDerd_getNextEnd()                                                      */
/*============================================================================*/
e_derdRet_t sslDerd_getNextEnd(s_derdCtx_t *ps_derdCtx)
{
    e_derdRet_t res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);

    res = loc_getNextTag(ps_derdCtx);

    /* move pointer to end of value */
    ps_derdCtx->l_pos += ps_derdCtx->s_octVal.cwt_len;

    /* is the end of the octet string reached ? */
    if (ps_derdCtx->l_pos >= ps_derdCtx->s_octBuf.cwt_len)
    {
        ps_derdCtx->c_EOS = TRUE;
    }

    return (res);
} /* sslDerd_getNextValue */

/*============================================================================*/
/*  sslDerd_getNextBitStr()                                                   */
/*============================================================================*/
e_derdRet_t sslDerd_getNextBitStr(s_derdCtx_t * ps_derdCtx)
{
    assert(ps_derdCtx != NULL);
    e_derdRet_t e_res = E_SSL_DER_OK;

    if (loc_getNextTag(ps_derdCtx) != SSL_DER_ASN1_BIT_STRING)
    {
        e_res = E_SSL_DER_ERR_NO_BITSTR;
    }
    else
    {
        if (ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos] == 0)
        {
            ps_derdCtx->l_pos++;
            e_res = E_SSL_DER_OK;
        }
        else
        {
            e_res = E_SSL_DER_ERR_NO_BITSTRUCT;
        }
    }

    return (e_res);
} /* sslDerd_getNextBitStr */

/*============================================================================*/
/*  sslDerd_getUI32()                                                         */
/*============================================================================*/
e_derdRet_t sslDerd_getUI32(s_derdCtx_t * ps_derdCtx, uint32_t *pl_value)
{
    e_derdRet_t e_res = E_SSL_DER_OK;
    size_t cwt_temp;

    assert(ps_derdCtx != NULL);
    assert(pl_value != NULL);

    *pl_value = 0;

    if ((ps_derdCtx->c_tag == SSL_DER_ASN1_INTEGER)
            && (ps_derdCtx->s_octVal.cwt_len <= 5))
    {
        if (((ps_derdCtx->s_octVal.cwt_len == 5)
                && (ps_derdCtx->s_octVal.pc_data[0] != 0))
                || ((ps_derdCtx->s_octVal.pc_data[0]
                        & SSL_DER_ASN1_NEGATIV_INTEGER)
                        == SSL_DER_ASN1_NEGATIV_INTEGER))
        {
            e_res = E_SSL_DER_ERR_NO_UI32; /* it is a negative integer */
        }
        else
        {
            for (cwt_temp = 0; cwt_temp < ps_derdCtx->s_octVal.cwt_len;
                    cwt_temp++)
            {
                *pl_value *= 0x100;
                *pl_value += ps_derdCtx->s_octVal.pc_data[cwt_temp];
            }
        }
    }
    else
    {
        e_res = E_SSL_DER_ERR_NO_UI32;
    }

    return (e_res);
} /* sslDerd_getUI32 */

/*============================================================================*/
/*  sslDerd_getBool()                                                         */
/*============================================================================*/
e_derdRet_t sslDerd_getBool(s_derdCtx_t *ps_derdCtx, uint8_t *pc_value)
{
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);
    assert(pc_value != NULL);

    *pc_value = FALSE;

    if ((ps_derdCtx->c_tag == SSL_DER_ASN1_BOOLEAN)
            && (ps_derdCtx->s_octVal.cwt_len == 1))
    {
        if (ps_derdCtx->s_octVal.pc_data[0] > 0)
        {
            *pc_value = TRUE;
        }
    }
    else
    {
        e_res = E_SSL_DER_ERR_NO_BOOLEAN;
    }

    return (e_res);
} /* sslDerd_getBool */

/*============================================================================*/
/*  sslDerd_getBigNum()                                                         */
/*============================================================================*/
e_derdRet_t sslDerd_getBigNum(s_derdCtx_t *ps_derdCtx, gci_bigNum_t **ppcwt_val)
{
    e_derdRet_t e_res = E_SSL_DER_OK;
    size_t cwt_tmp = 0;

    assert(ps_derdCtx != NULL);
    assert(ppcwt_val != NULL);

    if ((ps_derdCtx->c_tag == SSL_DER_ASN1_INTEGER)
            && ((ps_derdCtx->s_octVal.pc_data[0] & SSL_DER_ASN1_NEGATIV_INTEGER)
                    != SSL_DER_ASN1_NEGATIV_INTEGER))
    {
        /*
         * eliminate leading zeros, a positive INTEGER has mostly one
         * leading zero
         */
        cwt_tmp = 0;
        while ((ps_derdCtx->s_octVal.pc_data[cwt_tmp] == 0)
                && (ps_derdCtx->l_pos < ps_derdCtx->s_octBuf.cwt_len))
        {
            cwt_tmp++;
        }
        ps_derdCtx->s_octVal.cwt_len -= cwt_tmp;

        /*
         * check used length for bignum
         */
        if (ps_derdCtx->s_octVal.cwt_len <= SSL_DER_MAX_INTEGER_LEN)
        {
        	//TODO sw ?? set a value of a BigNumber
            *ppcwt_val = cw_bn_create(*ppcwt_val,
                    (size_t) (ps_derdCtx->s_octVal.cwt_len * 8));
            cw_bn_set(*ppcwt_val, &ps_derdCtx->s_octVal.pc_data[cwt_tmp],
                    (size_t) ps_derdCtx->s_octVal.cwt_len);
        }
        else
            e_res = E_SSL_DER_ERR_NO_BIGNUM;
    }
    else
        e_res = E_SSL_DER_ERR_NO_BIGNUM;

    return (e_res);
} /* sslDerd_getBigNum */

/*============================================================================*/
/*  sslDerd_getTime()                                                         */
/*============================================================================*/
e_derdRet_t sslDerd_getTime(s_derdCtx_t *ps_derdCtx,
        ac_sslDerd_utcTime_t cwt_strTime)
{
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);
    assert(cwt_strTime != NULL);

    if ((ps_derdCtx->c_tag == SSL_DER_ASN1_UTCTIME)
            && (ps_derdCtx->s_octVal.cwt_len <= SSL_DER_ASN1_UTCTIME_LEN))
    {
        CW_MEMCOPY(&cwt_strTime[2],
                ps_derdCtx->s_octVal.pc_data,
                (size_t)ps_derdCtx->s_octVal.cwt_len);

        if (ps_derdCtx->s_octVal.pc_data[0] < '5')
        {
            cwt_strTime[0] = '2';
            cwt_strTime[1] = '0';
        }
        else
        {
            cwt_strTime[0] = '1';
            cwt_strTime[1] = '9';
        }
        cwt_strTime[ps_derdCtx->s_octVal.cwt_len + 1] = 0;
    }
    else
    {
        if ((ps_derdCtx->c_tag == SSL_DER_ASN1_GENERALIZEDTIME)
                && (ps_derdCtx->s_octVal.cwt_len
                        <= SSL_DER_ASN1_GENERALIZEDTIME_LEN))
        {
            CW_MEMCOPY(cwt_strTime,
                    ps_derdCtx->s_octVal.pc_data,
                    (size_t)ps_derdCtx->s_octVal.cwt_len);

            cwt_strTime[ps_derdCtx->s_octVal.cwt_len + 1] = 0;
        }
        else
        {
            e_res = E_SSL_DER_ERR_NO_TIME;
        }
    }
    return (e_res);
} /* sslDerd_getTime */

/*============================================================================*/
/*  sslDerd_getValidity()                                                     */
/*============================================================================*/
e_derdRet_t sslDerd_getValidity(s_derdCtx_t *ps_derdCtx,
        s_sslDerValid_t *ps_validity)
{
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);
    assert(ps_validity != NULL);

    if (ps_derdCtx->c_tag == SSL_DER_ASN1_CSEQUENCE)
    {
        e_res = sslDerd_getNextValue(ps_derdCtx);
        if (e_res != SSL_DER_ASN1_UNDEF)
        {
            /* returns E_SSL_DER_OK or E_SSL_DER_ERR_NO_TIME  */
            e_res = sslDerd_getTime(ps_derdCtx, ps_validity->cwt_strNotBefore);
            if (e_res == E_SSL_DER_OK)
            {
                e_res = sslDerd_getNextValue(ps_derdCtx);
                if (e_res != SSL_DER_ASN1_UNDEF)
                {
                    /* returns E_SSL_DER_OK or E_SSL_DER_ERR_NO_TIME  */
                    e_res = sslDerd_getTime(ps_derdCtx,
                            ps_validity->cwt_strNotAfter);
                }
                else
                {
                    e_res = E_SSL_DER_ERR_NO_NOTAFTER;
                }
            }
        }
        else
        {
            e_res = E_SSL_DER_ERR_NO_NOTBEFORE;
        }
    }
    else
    {
        e_res = E_SSL_DER_ERR_NO_VALIDITYSEQ;
    }

    return (e_res);
} /* sslDerd_getValidity */

/*============================================================================*/
/*  sslDerd_getBitStr()                                                       */
/*============================================================================*/
e_derdRet_t sslDerd_getBitStr(s_derdCtx_t *ps_derdCtx, s_sslBitStr_t *pc_bitStr)
{
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);
    assert(pc_bitStr != NULL);
    assert(ps_derdCtx->s_octVal.pc_data != NULL);

    if ((ps_derdCtx->c_tag == SSL_DER_ASN1_BIT_STRING)
            && (ps_derdCtx->s_octVal.cwt_len > 1))
    {
        pc_bitStr->cwt_len = ps_derdCtx->s_octVal.cwt_len - 1;
        pc_bitStr->pc_bitStr = &(ps_derdCtx->s_octVal.pc_data[1]);
        pc_bitStr->c_unused = ps_derdCtx->s_octVal.pc_data[0];
    }
    else
    {
        e_res = E_SSL_DER_ERR_NO_BITSTR;
    }

    return (e_res);
} /* sslDerd_getBitStr */

/*============================================================================*/
/*  sslDerd_getOctStr()                                                       */
/*============================================================================*/
e_derdRet_t sslDerd_getOctStr(s_derdCtx_t *ps_derdCtx,
                              uint8_t*     pc_encSign, size_t* pi_encSignLen)
{
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);
    assert(ps_derdCtx->s_octVal.pc_data != NULL);

    if ((ps_derdCtx->c_tag == SSL_DER_ASN1_OCTET_STRING) &&
        (ps_derdCtx->s_octVal.cwt_len > 1) &&
        (pc_encSign != NULL)) {
        *pi_encSignLen = ps_derdCtx->s_octVal.cwt_len;
        memmove(pc_encSign,ps_derdCtx->s_octVal.pc_data,*pi_encSignLen);
        LOG_INFO("signature");
        LOG_HEX(pc_encSign,*pi_encSignLen);
    }
    else
    {
        e_res = E_SSL_DER_ERR_NO_OCTETSTR;
    }

    return (e_res);
} /* sslDerd_getOctStr */


/*============================================================================*/
/*  sslDerd_getSign()                                                       */
/*============================================================================*/
e_derdRet_t sslDerd_getSign(s_derdCtx_t* 	ps_derdCtx,
							e_sslHashAlg_t*	pe_hashAlg,
                            uint8_t*     	pc_decSign, size_t* pi_decSignLen)
{
    e_derdRet_t         e_err = E_SSL_DER_OK;
    uint16_t            i_oidHashAlg;

    assert(ps_derdCtx != NULL);

    /* Check if we a re working with ASN.1 encoded sequence */
    if ((e_err != E_SSL_DER_OK) || (ps_derdCtx->c_tag != SSL_DER_ASN1_CSEQUENCE)) {
        LOG_ERR("Signature DER ASN.1 should start with Sequence identifier");
        e_err = E_SSL_DER_ERR_NO_CSEQUENCE;
    }

    /* Check if next field id OID */
    if ((e_err != E_SSL_DER_OK) ||
        (sslDerd_getNextValue(ps_derdCtx) != SSL_DER_ASN1_OBJECT)) {
        LOG_ERR("Hash OID should follow");
        e_err = E_SSL_DER_ERR_NO_OBJECT;
    }

    if (e_err == E_SSL_DER_OK) {
        i_oidHashAlg = sslOid_fromDer(ps_derdCtx->s_octVal.pc_data,
                                      ps_derdCtx->s_octVal.cwt_len);
        /*
         *  is it a tOOlkit known/supported signature algorithm
         *  --> add new algorithms here!
         */
        if ((i_oidHashAlg != SSL_OID_MD5)       &&
            (i_oidHashAlg != SSL_OID_SHA1)      &&
            (i_oidHashAlg != SSL_OID_SHA256)    &&
            (i_oidHashAlg != SSL_OID_SHA384)    &&
            (i_oidHashAlg != SSL_OID_SHA512)){
            LOG_ERR("Hash OID is not among supported ");
            e_err = E_SSL_DER_ERR_NO_HASHALG;
        } else if (pe_hashAlg != NULL){
        	*pe_hashAlg = i_oidHashAlg;
        }
    }

    /* Check if next field id NULL */
    if ((e_err != E_SSL_DER_OK) ||
        (sslDerd_getNextValue(ps_derdCtx) != SSL_DER_ASN1_NULL)) {
        LOG_ERR("NULL should follow");
        e_err = E_SSL_DER_ERR_NO_NULL;
    }

    /* Check if next field id OCTET STRING */
    if ((e_err != E_SSL_DER_OK) ||
        (sslDerd_getNextValue(ps_derdCtx) != SSL_DER_ASN1_OCTET_STRING)) {
        LOG_ERR("OCTET STRING should follow");
        e_err = E_SSL_DER_ERR_NO_OCTETSTR;
    }

    if (e_err == E_SSL_DER_OK) {
        e_err = sslDerd_getOctStr(ps_derdCtx, pc_decSign,pi_decSignLen);
    }

    return (e_err);
} /* sslDerd_getSign */

static uint8_t loc_setHashAlg(s_derdCtx_t *ps_derdCtx, int16_t c_hashAlg)
{
    uint8_t         c_tagLen = 0;
    const uint8_t*  rpc_derStr;
    uint8_t         c_derStrLen;
    size_t          sz_oidLenOff;

    /* Check if we a re working with ASN.1 encoded sequence */
    if (ps_derdCtx->c_tag != SSL_DER_ASN1_CSEQUENCE) {
        LOG_ERR("HashAlg DER ASN.1 should start with Sequence identifier");
        c_tagLen = 0;
    } else {

        rpc_derStr = sslOid_toDer(c_hashAlg,(int16_t *)&c_derStrLen);

        /* PUT OID with Hash Algorithm */
        sslDerd_setTag(ps_derdCtx, SSL_DER_ASN1_OBJECT, &sz_oidLenOff);
        memmove(&ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos], rpc_derStr, c_derStrLen);
        ps_derdCtx->s_octBuf.cwt_len += c_derStrLen;
        ps_derdCtx->l_pos += c_derStrLen;

        /* PUT NULL tag with  */
        sslDerd_setTag(ps_derdCtx, SSL_DER_ASN1_NULL, NULL);

        /* Update header fields and length */
        ps_derdCtx->s_octBuf.pc_data[sz_oidLenOff] = c_derStrLen;
        ps_derdCtx->s_octDer.pc_data = &(ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos]);
        ps_derdCtx->s_octVal.pc_data = &(ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos]);

        c_tagLen = c_derStrLen + 2 + 2;
    }

    return (c_tagLen);
}

static uint8_t loc_setSign(s_derdCtx_t *ps_derdCtx, uint8_t* pc_sign, size_t sz_signLen)
{
    uint8_t         c_tagLen = 0;
    size_t          sz_ostrLenOff;

    /* PUT Octet string tag with Hash/signature inside */
    sslDerd_setTag(ps_derdCtx, SSL_DER_ASN1_OCTET_STRING, &sz_ostrLenOff);
    memmove(&ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos], pc_sign, sz_signLen);
    ps_derdCtx->s_octBuf.cwt_len += sz_signLen;
    ps_derdCtx->l_pos += sz_signLen;

    /* Update header fields and length */
    ps_derdCtx->s_octBuf.pc_data[sz_ostrLenOff] = sz_signLen;
    ps_derdCtx->s_octDer.pc_data = &(ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos]);
    ps_derdCtx->s_octVal.pc_data = &(ps_derdCtx->s_octBuf.pc_data[ps_derdCtx->l_pos]);

    c_tagLen = sz_signLen + 2;

    return (c_tagLen);
}

/*============================================================================*/
/*  sslDerd_setSign()                                                         */
/*============================================================================*/
e_derdRet_t sslDerd_setSign(s_derdCtx_t *ps_derdCtx, uint8_t c_hashAlg,
                            uint8_t* pc_sign, size_t sz_signLen)
{
    e_derdRet_t         e_err = E_SSL_DER_OK;
    size_t              sz_cseq1LenOff = 0;
    size_t              sz_cseq2LenOff = 0;
    size_t              sz_tagLen = 0;
    int16_t             i_hashAlgOid;

    /* Check if we a re working with ASN.1 encoded sequence
     * we put SSL_DER_ASN1_CSEQUENCE tag and in the end we need to
     * finish this tag by correctly updating length field*/
    if (sslDerd_setTag(ps_derdCtx,
                       SSL_DER_ASN1_CSEQUENCE,
                       (size_t*)&sz_cseq1LenOff) !=    E_SSL_DER_OK) {
        LOG_ERR("Failed to place Sequence identifier");
        e_err = E_SSL_DER_ERR_NO_CSEQUENCE;
    }

    /* Check if we a re working with ASN.1 encoded sequence */
    if (e_err != E_SSL_DER_OK) {
        LOG_ERR("Failed to place Signature");
        e_err = E_SSL_DER_ERR_NO_CSEQUENCE;
    }

    /* Check if we a re working with ASN.1 encoded sequence */
    if (ps_derdCtx->c_tag != SSL_DER_ASN1_CSEQUENCE) {
        LOG_ERR("Signature DER ASN.1 should start with Sequence identifier");
        e_err = E_SSL_DER_ERR_NO_CSEQUENCE;
    }

    if ((e_err != E_SSL_DER_OK) ||
    	(sslDerd_setTag(ps_derdCtx,
    	                SSL_DER_ASN1_CSEQUENCE, &sz_cseq2LenOff) != E_SSL_DER_OK)) {
    	LOG_INFO("Failed to set CSEQUENCE tag");
    	e_err = E_SSL_DER_ERR_ENCODING;
    }

    if (e_err == E_SSL_DER_OK) {
        switch (c_hashAlg) {
            case E_SSL_HASH_MD5:
                i_hashAlgOid = SSL_OID_MD5;
                break;
            case E_SSL_HASH_SHA1:
                i_hashAlgOid = SSL_OID_SHA1;
                break;
            case E_SSL_HASH_SHA256:
                i_hashAlgOid = SSL_OID_SHA256;
                break;
            default:
                i_hashAlgOid = 0;
                break;
        }

        sz_tagLen = loc_setHashAlg(ps_derdCtx, i_hashAlgOid);
        ps_derdCtx->s_octBuf.pc_data[sz_cseq1LenOff] += sz_tagLen;
        ps_derdCtx->s_octBuf.pc_data[sz_cseq2LenOff] += sz_tagLen;
        sz_tagLen = loc_setSign(ps_derdCtx, pc_sign, sz_signLen);
        ps_derdCtx->s_octBuf.pc_data[sz_cseq1LenOff] += (sz_tagLen + 2);

    }

    return (sz_tagLen + 2);
} /* sslDerd_setSign */

/*============================================================================*/
/*  sslDerd_getSigAlg()                                                       */
/*============================================================================*/
e_derdRet_t sslDerd_getSigAlg(s_derdCtx_t *ps_derdCtx, int32_t *pl_sigAlg)
{
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);
    assert(pl_sigAlg != NULL);

    if ((ps_derdCtx->c_tag == SSL_DER_ASN1_CSEQUENCE)
            && (sslDerd_getNextValue(ps_derdCtx) == SSL_DER_ASN1_OBJECT))
    {
        *pl_sigAlg = sslOid_fromDer(ps_derdCtx->s_octVal.pc_data,
                ps_derdCtx->s_octVal.cwt_len);
        /*
         *  is it a tOOlkit known/supported signature algorithem
         *  --> add new algorithms here!
         */
        if ((*pl_sigAlg == SSL_OID_MD2_WITH_RSA_ENC)
                || (*pl_sigAlg == SSL_OID_MD5_WITH_RSA_ENC)
                || (*pl_sigAlg == SSL_OID_SHA1_WITH_RSA_ENC)
                || (*pl_sigAlg == SSL_OID_SHA256_WITH_RSA_ENC)
                || (*pl_sigAlg == SSL_OID_SHA384_WITH_RSA_ENC)
                || (*pl_sigAlg == SSL_OID_SHA512_WITH_RSA_ENC))
        {
            /*
             *  for RSA with MD5 or SHA1 there are no algorithem parameters
             *  defined, a NULL value must following as end of the sequence
             */
            if (sslDerd_getNextValue(ps_derdCtx) != SSL_DER_ASN1_NULL)
            {
                e_res = E_SSL_DER_ERR_NO_ALGNULLPAR;
            }
        }
        else
        {
            e_res = E_SSL_DER_ERR_UNKNOWN_ALGORITHM;
        }
    }
    else
    {
        e_res = E_SSL_DER_ERR_NO_ALGSEQOID;
    }

    return (e_res);
} /* sslDerd_getSigAlg */

/*============================================================================*/
/*  sslDerd_getSigAlg()                                                       */
/*============================================================================*/
e_derdRet_t sslDerd_getPubKeyAlg(s_derdCtx_t *ps_derdCtx, int32_t *pl_sigAlg,
        uint32_t *pl_keyLen)
{
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_derdCtx != NULL);
    assert(pl_sigAlg != NULL);
    assert(pl_keyLen != NULL);

    if ((ps_derdCtx->c_tag == SSL_DER_ASN1_CSEQUENCE)
            && (sslDerd_getNextValue(ps_derdCtx) == SSL_DER_ASN1_OBJECT))
    {
        *pl_sigAlg = sslOid_fromDer(ps_derdCtx->s_octVal.pc_data,
                ps_derdCtx->s_octVal.cwt_len);
        /*
         *  is it a tOOlkit known/supported signature algorithem
         *  --> add new algorithms here!
         */
        if (*pl_sigAlg == SSL_OID_RSA_ENCRYPTION)
        {
            /*  for rsaEncryption there are no algorithem parameters defined
             *  a NULL value must following as end of the sequence
             */
            if (sslDerd_getNextValue(ps_derdCtx) == SSL_DER_ASN1_NULL)
            {
                *pl_keyLen = 0; /* AlgorithmIdentifier with no parameters */
            }
            else
            {
                e_res = E_SSL_DER_ERR_NO_ALGNULLPAR;
            }
        }
        else
        {
            if (*pl_sigAlg == SSL_OID_X509_RSA_ENC)
            {
                /*
                 * get the keySize
                 */
                if (sslDerd_getNextValue(ps_derdCtx) == SSL_DER_ASN1_INTEGER)
                {
                    e_res = sslDerd_getUI32(ps_derdCtx, pl_keyLen);
                }
                else
                {
                    e_res = E_SSL_DER_ERR_NO_INTEGER;
                }
            }
            else
            {
                e_res = E_SSL_DER_ERR_UNKNOWN_ALGORITHM;
            }
        }
    }
    else
    {
        e_res = E_SSL_DER_ERR_NO_ALGSEQOID;
    }

    return (e_res);
} /* sslDerd_getSigAlg */

