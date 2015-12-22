/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_record.c                                               */
/*                                                                           */
/*  FUNCTIONS:                                                               */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*   This module implements the support functions for the record level       */
/*   interface (see section 2.2 in User Manual 0.96)                         */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  CAUTIONS:                                                                */
/*                                                                           */
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
/*  21.03.03     WAM           Fully revised for release 1                   */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*****************************************************************************/



//#include "crypto_wrap.h"
#include "ssl.h"
#include "ssl_diag.h"
#include "ssl_record.h"
#include "ssl_certHelper.h"
#include "ssl_conf.h"
#ifdef ASCOM_CRYPTO
#include "ssl_derd.h"
#include "crypto.h"
#endif
#include "ssl_der.h"
#include "ssl_certHandler.h"
#include "ssl_oid.h"
#include "ssl_sessCache.h"


/*** Defines ****************************************************************/
#define	LOGGER_ENABLE		DBG_SSL_RECORD
#include "logger.h"
/*** Global Variables *******************************************************/



/*** Local Variables ********************************************************/



/*** Forward declarations ***************************************************/

/* int CL_GetPublicKey(s_pubKey_t * pPubKey, s_sslOctetStr_t * pPubKeyStr); */


/*** Local Functions ********************************************************/



/*** Global Functions *******************************************************/

int sslRec_fetchCorrectVersion (s_sslCtx_t* ps_sslCtx, e_sslVer_t e_version)
{
    int retVal;
    e_sslVer_t locVersion = SSL_DEFAULT_SSL_TLS_VERSION;
    /*
     * Check the received version for minimal constraint
     */
    if(e_version < ps_sslCtx->ps_sslSett->e_minVer)
     {
        /*
         * received version is a too early version
         */
        retVal = -1;
        locVersion = ps_sslCtx->ps_sslSett->e_minVer;
     }
    else
     {
        /*
         * check if we support this version
         */
        if(e_version > ps_sslCtx->ps_sslSett->e_maxVer)
         {
            /*
             * the received version is higher than the supported
             */
            retVal = 1;
            locVersion = ps_sslCtx->ps_sslSett->e_maxVer;
         }
        else
         {
            /*
             * the received version is really fine
             */
            retVal = 0;
            locVersion = e_version;
         }
     }
    ps_sslCtx->e_ver = locVersion;

    return retVal;
}

int sslRec_checkVerCompLen (s_sslCtx_t* ps_sslCtx, int* pi_isSSLv2)
{
    uint8_t *p_record = ps_sslCtx->ac_socBuf;
    size_t ui_recordLen = ps_sslCtx->l_buffLen;
    int ret = 0;

    assert(ps_sslCtx != NULL);
    assert(p_record != NULL);

    /*
     * Default return value for SSLv2 is NO
     */
    if(pi_isSSLv2 != NULL)
        *pi_isSSLv2 = 0;

    if (ui_recordLen >= REC_HEADERLEN)
    {
        /*
         * Default return value is the case that a record > SSL2.0 has been received
         */
        ret = p_record[3] * 256 + p_record[4] + REC_HEADERLEN;

        /*
         * When we're waiting for the client hello, we ignore the proposed version
         * as described in [RFC 5246 Appendix E.1]
         */
        if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_WAIT_CLIENT_HELLO)
        {

#if SSL_NO_SSLV2_HELLO == FALSE
            /*
             * Check for a SSL V2.0 Client hello message (the only SSLV2 record supported)
             * The bit 7 set in the first byte indicates a 2 byte Header...
             */
            if ((p_record[0] & 0x80) == 0x80) /* MSB set indicates V2-Message */
            {
                /* Bit 7 is set, so this could be a SSL or TLS record.
                 * Check for a SSL V2 client hello record
                 */
                if (p_record[2] == 0x01)
                {
                    /* Received message is a client hello
                     * Decode the length info and add the length of the length field (2 bytes)
                     */
                    ret = ((p_record[0] & 0x7F) * 256 + p_record[1] + 2);

                    if(pi_isSSLv2 != NULL)
                        *pi_isSSLv2 = 1;
                } /* if */
                else
                {
                    ret = -1;
                } /* else */
            } /* if */
#endif  /* SSL_NO_SSLV2_HELLO */
        } /* if */
        else if (ps_sslCtx->s_sslGut.e_smState == E_SSL_SM_WAIT_SERVER_HELLO)
        {
            if(sslRec_fetchCorrectVersion(ps_sslCtx, SSL_VERSION_READ(&p_record[1])) != 0)
            {
                ret = -1;
            }
        } /* else if */
        else
        {
            /*
             * Check if the version fits
             */
            if (SSL_VERSION_READ(&p_record[1]) != ps_sslCtx->e_ver)
            {
                ret = -1;
            } /* if */
        } /* else */
    } /* if */

    LOG_INFO("Received record of length %i bytes\n", ret);

    if (ret > (0x4000 + 2048)) {
    	/* excessive record length */
    	LOG_ERR("Received record of excessive length (%u bytes).", ret);
    	ret = -2;
    }

    return ret;
} /* sslRec_checkVerCompLen */


/***************************************************************************
 * sslRec_getLen
 *
 * Returns the length of the record provided as argument. The length is
 * calculated from the record header structure including a version check.
 * At least 5 octets are needed to calculate the correct record len.
 * This function is used to provide an entire
 * record to the handling functions.
 ***************************************************************************/

int sslRec_getLen(s_sslCtx_t* ps_sslCtx)
{
/***************************************************************************
 * Parameters
 * *pRecord    Pointer to record octet string
 * uiRecordLen length of the record octet string
 *
 *
 * Returns
 * 7 .. 16384        Length of the entire record including the header
 * 0           Failure: record is invalid or input too short
 *
 * See also
 ***************************************************************************/

	int ret = sslRec_checkVerCompLen(ps_sslCtx, NULL);
    if (ret == -1)
        return 0;
    else
        return ret;
} /* End of sslRec_getLen */



/***************************************************************************
 * sslRec_getBytesToRead
 *
 * Returns the amount of bytes to be read to get an full SSL record. The record
 * is provided as argument. For the length calculation at least 5 bytes of the
 * record are needed. In case less bytes are read, the amount of bytes to be read
 * to get an full record will be returned.
 * Therefore the return value is as follows if the record has up to 6 bytes:
 * current len    return value
 * 0              5
 * 1              4
 * 2              3
 * 3              2
 * 4              1
 * 5              >=2, according to length field
 * >5             0...16383
 * A return value of zero indicates the record is complete!
 * This function is used to provide an entire record to the handling functions.
 ***************************************************************************/

int sslRec_getBytesToRead(s_sslCtx_t* ps_sslCtx)
{
/***************************************************************************
 * Parameters
 * *pRecord    Pointer to record octet string
 * uiRecordLen length of the record octet string
 *
 *
 * Returns
 * 1 .. 16383  Number of bytes to be read to have a full record or record header
 * 0           Record is complete
 * -1          Error
 * See also
 ***************************************************************************/
	int ret;
	int iRecordLen = ps_sslCtx->l_buffLen;

    /* Check for sufficient number of bytes for a length calculation */
    if (iRecordLen < REC_HEADERLEN)
    {
        ret = REC_HEADERLEN - iRecordLen;
    } /* if */
    else
    {
        ret = sslRec_checkVerCompLen(ps_sslCtx, NULL);
        if (ret >= 0)
        {
            ret -= iRecordLen;
        } /* if */
    } /* else */

    return ret;
} /* End of sslRec_getBytesToRead */
