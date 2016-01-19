/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_conf.c                                                 */
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
/*    None                                                                   */
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

//#include "crypto_wrap.h"

//#include "crypto_iface.h"

#include "crypto_tomcrypt.h"

#include "ssl.h"
#include "ssl_der.h"
#include "ssl_derd.h"
#include "ssl_certHandler.h"
#include "ssl_oid.h"
#include "ssl_certHelper.h"
#include "ssl_sessCache.h"
#include "ssl_time.h"
#include "ssl_conf.h"
#include "ssl_target.h"
#include "ssl_diag.h"

/*** Defines ****************************************************************/
#define	LOGGER_ENABLE		DBG_SSL_CONF
#include "logger.h"
/*** Global Variables *******************************************************/

/*** Local Variables ********************************************************/

/*** Forward declarations ***************************************************/

/*** Local Functions ********************************************************/

/*** Global Functions *******************************************************/
/*============================================================================*/
/*  sslConf_seedRand()                                                        */
/*============================================================================*/
void sslConf_seedRand(uint8_t *pc_dest, size_t cwt_bytes)
{
	en_gciResult_t err;

	//OLD-CW: cw_prng_seed(pc_dest, cwt_bytes);

	err = gciRngSeed(pc_dest, cwt_bytes);
	if(err != en_gciResult_Ok)
	{
		//TODO return error state
	}


}/* sslConf_seedRand */

/*============================================================================*/
/*  sslConf_rand()                                                            */
/*============================================================================*/
void sslConf_rand(uint8_t *pc_dest, size_t cwt_bytes)
{
	en_gciResult_t err;

    //OLD-CW: cw_prng_read(pc_dest, cwt_bytes);

    err = gciRngGen(cwt_bytes, pc_dest);
    if(err != en_gciResult_Ok)
    {
    	//TODO return error state
    }

}/* sslConf_rand */

/*============================================================================*/
/*  sslConf_getCertChain()                                                    */
/*============================================================================*/
e_sslResult_t sslConf_getCertChain(s_sslCertList_t *ps_listHead,
        s_sslCertList_t *ps_listTail, uint8_t *pc_data, size_t *pcwt_dataLen)
{
    uint8_t *pc_start;
    uint8_t *pc_ret;
    size_t cwt_len;
    size_t cwt_chainLen;
    e_sslResult_t e_res = E_SSL_OK;
    uint8_t i = 0;

    assert(ps_listHead != NULL);
    assert(pc_data != NULL);
    assert(pcwt_dataLen != NULL);

    e_res = sslCert_initChain(pc_data, *pcwt_dataLen);

    /*
     * Iterate through the list until the list end
     * or until there are no more certificates assigned
     */
    while ((ps_listHead != ps_listTail) && (ps_listHead->ps_cdbCert != NULL)
            && (e_res == E_SSL_OK))
    {
    	i++;
        /*
         * Extract the free space in the certificate chain
         */
        sslCert_getSpaceInChain(pc_data, &pc_start, &cwt_len, *pcwt_dataLen);
        /*
         * Read out the cert
         */
        if (cdb_read(ps_listHead->ps_cdbCert, pc_start, &cwt_len) == TRUE)
        {
            /*
             * Extract the real length of the cert
             * if it's length is too big return an error
             */
            pc_ret = sslCert_extractX509Len(pc_start + 1, &cwt_len);
            if (cwt_len > 0)
                cwt_len += (pc_ret - (pc_start + 1)) + 1;
            else
            {
                e_res = E_SSL_ERROR;
                break;
            }
            /*
             * Add the extracted data to the certificate chain
             */
            e_res = sslCert_addDataToChain(pc_data, &cwt_chainLen, pc_start,
                    cwt_len, *pcwt_dataLen);
        } /* if */
        else
        {
            e_res = E_SSL_ERROR;
            break;
        } /* else */

        /*
         * Fetch the next element in the list
         */
        ps_listHead = sslCert_getNext(ps_listHead);
    } /* while */

    if (e_res == E_SSL_OK)
    {
        *pcwt_dataLen = cwt_chainLen;
    }

    return (e_res);
}/* sslConf_getCertChain */

/*============================================================================*/
/*  sslConf_getCertReqList()                                                    */
/*============================================================================*/
e_sslResult_t sslConf_getCertReqList(s_sslCertList_t *ps_listHead,
        uint8_t *pc_data, size_t *pcwt_dataLen)
{
    size_t cwt_len;
    size_t cwt_totalLen;
    size_t cwt_space;
    s_sslCertList_t *ps_certEntry;
    uint8_t *pc_write;
    uint8_t *pc_subjLen;
    e_sslResult_t e_res = E_SSL_OK;

    assert(ps_listHead != NULL);
    assert(pc_data != NULL);
    assert(pcwt_dataLen != NULL);

    ps_certEntry = ps_listHead;
    /*
     * Start writing at position [2], since [0] and [1] are required for the total length
     */
    pc_write = pc_data + 2;
    cwt_totalLen = 0;
    /*
     * Iterate through the list
     */
    while ((ps_certEntry != NULL) && (e_res == E_SSL_OK))
    {
        /*
         * Calculate the space left.
         * Available space - total written length - 2 (total length offset) - 2 (current length offset)
         */
        cwt_space = (*pcwt_dataLen - cwt_totalLen - 4);
        e_res = sslCert_getSubject(ps_certEntry, pc_write + 2, &cwt_space);
        if (e_res == E_SSL_OK)
        {
            /*
             * Extract the length of the subject
             */
            pc_subjLen = sslCert_extractX509Len(pc_write + 3, &cwt_len);
            /*
             * Check if length extraction was successful.
             * p_ret points to the end of the length field,
             * (p_write + 3) points to the start of the length field,
             * so add the length of the length field to get the total length.
             */
            if (cwt_len > 0)
                cwt_len += (pc_subjLen - (pc_write + 3)) + 1;
            else
            {
                e_res = E_SSL_ERROR;
                break;
            }
            /*
             * Insert the length into the certificateRequest, before the subject
             */
            (void) ssl_writeInteger(pc_write, cwt_len, 2);
            /*
             * Adjust pointer and length counter according to length-field + data-length
             */
            pc_write += cwt_len + 2;
            cwt_totalLen += cwt_len + 2;
        } /* if */
        else
        {
            LOG_ERR("An error occurred while extracting the subj from a chain");
            LOG_ERR("list entry: %p, space left: %zu", ps_certEntry,
                    (*pcwt_dataLen - cwt_totalLen - 4));
            break;
        }

        /*
         * fetch next item in list
         */
        ps_certEntry = sslCert_getNext(ps_certEntry);
    } /* while */

    if (e_res == E_SSL_OK)
    {
        /*
         * Add the total length of the data and set the returned length value
         */
        (void) ssl_writeInteger(pc_data, cwt_totalLen, 2);

        *pcwt_dataLen = cwt_totalLen + 2;
    }

    return (e_res);
}/* sslConf_getCertReqList */

/*==============================================================================
 sslConf_cmpCertReqList()
 ==============================================================================*/
s_sslCertList_t * sslConf_cmpCertReqList(s_sslCtx_t* ps_sslCtx,
		s_sslCertList_t *ps_caCertList,
        uint8_t *pc_certReqMsg, size_t cwt_msgLen)
{
    s_sslCertList_t 	*ps_listEntry = NULL;
    s_sslOctetStr_t 	s_octCert;
    s_sslKeyCertInfo_t 	s_keyCertInfo;
    size_t 			cwt_bufLen;
    size_t 			cwt_fieldLen;
    size_t 			cwt_compLen;
    int32_t		 		l_tmpLen;
    uint8_t				*pc_tmpMsg = NULL;
    uint8_t 			*pc_subject = NULL;
    int32_t i;

    assert(pc_certReqMsg != NULL);

    /*
     * structure of the data is
     * [Number of CT's(1B)]
     * [CT1 (1B)]
     * [CT2 (1B)]
     * [CT...
     */

    /*
     * read the length of received ciphertypes
     * and step over lengthfield
     */
    cwt_fieldLen = (size_t) *pc_certReqMsg++;

    for (i = 0; i < (int) cwt_fieldLen; i++)
    {
        e_sslCliCertType_t certType = (e_sslCliCertType_t) pc_certReqMsg[i];
        /*
         * Check if the server can offer a RSA certificate
         *  if the server can do so, break immediately
         */
        if (certType == RSA_SIGN)
            break;
        /*
         * Check if the end of the list of certificates has been reached
         * and return NULL if we reached the end.
         */
        else if (i == ((int) cwt_fieldLen - 1))
        {
            goto cmpCertReqList_error;
        }
    } /* for */

    /*
     * Jump over the list of certificate types
     */
    pc_certReqMsg += cwt_fieldLen;

    if (ps_sslCtx->e_ver >= E_TLS_1_2) {
    	pc_certReqMsg += pc_certReqMsg[0] * 256 + pc_certReqMsg[1] + 2;
    }

    /*
     * structure of the following data is
     * [CA's length(2B)]
     * [CA1 length(2B)][CA1(CA1 length)]
     * [CA2 length(2B)][CA2...
     */

    /*
     * Read [CA's length(2B)]
     */
    cwt_compLen = pc_certReqMsg[0] * 256 + pc_certReqMsg[1];

    /*
     * Check if there occurred a length error in the received data
     * +3 because of the 2 len fields of CT and CA
     */
    if (cwt_msgLen < (cwt_compLen + cwt_fieldLen + 3))
    {
        LOG_ERR("Length error");
        ps_listEntry = NULL;
        goto cmpCertReqList_error;
    }
    else if (cwt_compLen == 0)
    {
        LOG1_ERR("No entries included from the server");
        ps_listEntry = NULL;
        goto cmpCertReqList_error;
    }
    /*
     * Jump over [CA's length(2B)]
     */
    pc_certReqMsg += 2;
    ps_listEntry = ps_caCertList;
    /*
     * Loop through the certificate chain
     */
    while (ps_listEntry != NULL)
    {
    	l_tmpLen = cwt_compLen;
    	pc_tmpMsg = pc_certReqMsg;

        /*
         * Check if there's an extracted CA Subject available
         * TODO Check if commented code can be removed
         */
        /*if ((ps_listEntry->ps_caCert != NULL)
                && (ps_listEntry->ps_caCert->s_caSubject.pc_data != NULL))
        {
            pc_subject = ps_listEntry->ps_caCert->s_caSubject.pc_data;
        }*/
        /* if */
        /*
         * Check if there's a certificate where it can be extracted
         */
        if (ps_listEntry->ps_cdbCert != NULL)
        {
            /*
             * Try to read the cert from cert_db
             */
            s_octCert.pc_data = cdb_read2buf(ps_listEntry->ps_cdbCert,
                    &cwt_bufLen);
            if (s_octCert.pc_data != NULL)
            {
                s_octCert.cwt_len = cwt_bufLen;
                if (sslCert_decode(&s_keyCertInfo, &s_octCert) == E_SSL_DER_OK)
                {
                    pc_subject = s_keyCertInfo.s_octIssuer.pc_data;
                } /* if */
            }/* if */
            else
            {
                LOG_ERR("Reading certificate from cert_db failed");
                ps_listEntry = NULL;
                break;
            } /* else */
        } /* else if */

        if (pc_subject != NULL)
        {
            i = 0; /* When loop should be exit */
            do
            {
                /*
                 * Read [CAx length(2B)]
                 */
                cwt_fieldLen = pc_tmpMsg[0] * 256 + pc_tmpMsg[1];
                /*
                 * Jump over [CAx length(2B)]
                 */
                pc_tmpMsg += 2;
                /*
                 * Compare received value to current entry
                 */
                if (memcmp(pc_tmpMsg, pc_subject, cwt_fieldLen) == 0)
                {
                    i = 1;
                }
                else
                {
                	pc_tmpMsg += cwt_fieldLen;
                    l_tmpLen -= cwt_fieldLen + 2;
                } /* else */
            } while ((l_tmpLen > 0) && !i);
            /* If we are here and i is set than certRegMsg was equal
             * to a stored subject*/
            if (i)
                break;

            /*
             * Check if the subject is currently located in the cert_db
             */
            if ((ps_listEntry->ps_cdbCert != NULL)
                    && ((ps_listEntry->ps_caCert == NULL)
                            || (ps_listEntry->ps_caCert->s_caSubject.pc_data
                                    == NULL)))
            {
                cdb_free();
            } /* if */
        }/* if */
        /*
         * Fetch next list entry
         */
        ps_listEntry = sslCert_getNext(ps_listEntry);
    } /* while */

    cmpCertReqList_error:
    /*
     * If we arrived here, we've found no valid cert
     */
    return (ps_listEntry);
}

/*==============================================================================
 sslConf_certHook()
 ==============================================================================*/
uint8_t sslConf_certHook(s_sslCtx_t *ps_sslCtx, s_sslKeyCertInfo_t *ps_cliCertInfo)
{
    /* Provides the information of the client certificate to the user */
    s_sslGut_t *ps_sslGut;
    s_derdCtx_t s_derdCtx;
    s_sslKeyCertSubj_t certSubject;
    //OLD-CW: rpcw_str_t rpcwt_subjName;
    const char* rpcwt_subjName;
    uint32_t l_notBefore;
    uint32_t l_notAfter;
    uint32_t l_actual;
    e_sslCertErr_t e_decodeRet;
    uint8_t c_result = TRUE;

    assert(ps_sslCtx != NULL);

    ps_sslGut = &ps_sslCtx->s_sslGut;

    LOG2_INFO("Cert Hook entered");

    /* Certificate time check */
    if (ps_sslCtx->ps_sslSett->fp_getCurTime != NULL)
    {
        l_actual = ps_sslCtx->ps_sslSett->fp_getCurTime();

        l_notBefore = unixTime(
                (uint8_t*) ps_cliCertInfo->s_validity.cwt_strNotBefore);
        l_notAfter = unixTime(
                (uint8_t*) ps_cliCertInfo->s_validity.cwt_strNotAfter);
        LOG2_INFO(" %u should be GT %u should be LT %u ", l_notBefore, l_actual,
                l_notAfter);

        if (l_notBefore > l_actual || l_actual > l_notAfter)
        {
            LOG2_ERR("Certificate is invalid!");
            c_result = FALSE;
        }
    }
    else
    {
        LOG2_INFO("fp_getCurTime function pointer not set,could't validate cert");
        LOG2_INFO("Cert is valid from: %s to %s (yyyymmddhhmmss)",
                ps_cliCertInfo->s_validity.cwt_strNotBefore,
                ps_cliCertInfo->s_validity.cwt_strNotAfter);
    }

    if (c_result == TRUE)
    {
        /*
         * This section has to be edited by every customer that
         * intends to use client authentication
         * NB: this is only an example implementation, that shows the usage of
         *     the sslCert_decodeSubjInit()/sslCert_decodeSubjGetNext()
         */
        LOG2_INFO("Begin decoding of client certificate\r\n----------");
        sslCert_decodeSubjInit(ps_cliCertInfo, &s_derdCtx);

        /*
         * Reset ClientAuthentication ID
         */
        ps_sslGut->l_pendCliAuthId = 0;

        do
        {
            /*
             * Fetch the next field
             */
            e_decodeRet = sslCert_decodeSubjGetNext(&s_derdCtx, &certSubject);
            /*
             * When the field can be printed, proceed
             */
            if (SSL_DER_ASN1_IS_STRPRINT(certSubject.strData.iStringType))
            {
#if LOGGER_LEVEL > 1
                sslDiag_printGenericString(&certSubject.strData,
                        sslOid_toName(certSubject.type));
#endif
                /*
                 * Watch out, that comparison is always done on the length of the
                 * extracted element of the subject!
                 * This must be done, since there exist possibilites to include
                 * rogue strings in the certificate, because ASN.1-encoding is
                 * different than string-encoding
                 * e.g. strings are NOT terminated by NULL!
                 */
                if (certSubject.type == SSL_OID_COMMON_NAME)
                {
                    if (strncmp("root",
                            (const char *) certSubject.strData.pc_data,
                            certSubject.strData.cwt_len) == 0)
                    {
                        ps_sslGut->l_pendCliAuthId = 4;
                    }
                    else if (strncmp("admin",
                            (const char *) certSubject.strData.pc_data,
                            certSubject.strData.cwt_len) == 0)
                    {
                        ps_sslGut->l_pendCliAuthId = 3;
                    }
                    else if (strncmp("user",
                            (const char *) certSubject.strData.pc_data,
                            certSubject.strData.cwt_len) == 0)
                    {
                        ps_sslGut->l_pendCliAuthId = 2;
                    }
                    else if (strncmp("nobody",
                            (const char *) certSubject.strData.pc_data,
                            certSubject.strData.cwt_len) == 0)
                    {
                        ps_sslGut->l_pendCliAuthId = 1;
                    }
                }
            }
            else
            {
                rpcwt_subjName = sslOid_toName(certSubject.type);
                LOG2_INFO(" %s in HEX/ASCII", rpcwt_subjName);
                LOG2_HEX(certSubject.strData.pc_data, certSubject.strData.cwt_len);
            }
            /*
             * Since there can exist multiple "commonName"s in a clients'
             * certificate, evaluate the return value and continue if that
             * was not the end of the list
             */
        } while (e_decodeRet == E_SSL_CERT_MORE_ELEMENTS_AVAILABLE);

        if (e_decodeRet != E_SSL_CERT_OK)
        {
            LOG_ERR(" Error %s occured while decoding cert subject",
                    sslDiag_getCertHandErr(e_decodeRet));
        } /* if */
    }

    return (c_result);
}

/*==============================================================================
 sslConf_asymCryptoDisp()
 ==============================================================================*/
e_sslPendAct_t sslConf_asymCryptoDisp(s_sslCtx_t *ps_sslCtx, int e_nextAction,
        uint8_t *pc_inData, size_t cwt_inLen, uint8_t *pc_outData,
        size_t *pcwt_outLen)
{

    //s_pubKey_t s_pubKeyInfo;
	st_gciKey_t s_pubKeyInfo;
    s_sslOctetStr_t s_octPeerCert;
    e_sslPendAct_t e_pendEvent;
    s_sslHsElem_t *ps_handshElem;
    int32_t l_result;
    uint8_t ac_rndBuf[46];
    //OLD-CW: gci_dhKey_t cwt_dhKeyCliY;
    // GciKeyId_t cwt_dhKeyCliY;
    s_sslCertList_t *ps_caList = NULL;
    e_sslCertErr_t e_ret;

    en_gciResult_t err;

    GciCtxId_t ciphCtx;

    st_gciKey_t ecdhPeerPubKey = {.type = en_gciKeyType_EcdhPub};

    uint8_t a_allocDhePeerPubKey[TC_DH_KEY_SIZE_MAX_BYTES];
    st_gciKey_t dhePeerPubKey 	= {.type = en_gciKeyType_DhPub};
    GciKeyId_t dhSecretKeyID;

    uint8_t a_allocDhSecretKey[TC_DH_KEY_SIZE_MAX_BYTES];
    st_gciKey_t dhSecretKey = {.type = en_gciKeyType_DhSecret};

    st_gciCipherConfig_t rsaConf;

    assert(ps_sslCtx != NULL);
    assert(pc_inData != NULL);
    assert(pc_outData != NULL);
    assert(pcwt_outLen != NULL);

    ps_handshElem = ps_sslCtx->ps_hsElem;


    //OLD-CW: cw_rsa_publickey_prep(&ps_handshElem->gci_peerPubKey, &s_pubKeyInfo);




    switch (e_nextAction)
    {
    default:
    case E_PENDACT_ASYM_PKCS1_DECRYPT:
    {
        sslConf_rand(ac_rndBuf, 46);

        TIME_STAMP(TS_PMS_DECRYPT_BEGIN);

       //OLD-CW: l_result = cw_pkcs1_v15_decrypt(pc_inData, cwt_inLen, pc_outData, pcwt_outLen, ps_sslCtx->ps_sslSett->pgci_rsaMyPrivKey);

       rsaConf.algo = en_gciCipherAlgo_RSA;
       rsaConf.blockMode = en_gciBlockMode_None;
       rsaConf.iv.data = NULL;
       rsaConf.padding = en_gciPadding_PKCS1_V1_5;

       ciphCtx = -1;

       /* New cipher context to configure the cipher and add the private key ID of RSA */
       err = gciCipherNewCtx(&rsaConf, ps_sslCtx->ps_sslSett->pgci_rsaMyPrivKey, &ciphCtx);
       if(err != en_gciResult_Ok)
       {
    	   //TODO return error state
       }

       /* "New" cipher context with the same context ID of this above to add the public key ID of RSA */
       err = gciCipherNewCtx(&rsaConf, ps_sslCtx->ps_sslSett->pgci_rsaMyPubKey, &ciphCtx);
       if(err != en_gciResult_Ok)
       {
           //TODO return error state
       }

       err = gciCipherDecrypt(ciphCtx, pc_inData, cwt_inLen, pc_outData, pcwt_outLen);


       TIME_STAMP(TS_PMS_DECRYPT_END);

       /* Ignore the result value */
        //OLD-CW: if ((l_result != CW_OK) || (*pcwt_outLen != 48))
       if((err != en_gciResult_Ok) || (*pcwt_outLen != 48))
       {
            LOG_ERR("PKCS#1 decrypt not successful");
            /* In case of an error: return client_version + 46 byte random */
            pc_outData[0] = SSL_VERSION_GET_MAJ(
                    ps_sslCtx->ps_hsElem->e_offerVer);
            pc_outData[1] = SSL_VERSION_GET_MIN(
                    ps_sslCtx->ps_hsElem->e_offerVer);
            memcpy(&pc_outData[2], ac_rndBuf, 46);
            *pcwt_outLen = 48;
       }

       //Release the context
       err = gciCtxRelease(ciphCtx);
       if(err != en_gciResult_Ok)
       {
    	   //TODO return error from state
       }


       else
       {
            /*
             * In every version since SSL 3.0 the first 2 bytes of the decrypted
             * PreMasterSecret MUST be validated to be the offered version of the client
             *
             * [RFC 5246, Chapter 7.4.7.1]
             * Note: The version number in the PreMasterSecret is the version
             * offered by the client in the ClientHello.client_version, not the
             * version negotiated for the connection. This feature is designed to
             * prevent rollback attacks.
             */

            if (SSL_VERSION_READ(&pc_outData[0]) != ps_sslCtx->ps_hsElem->e_offerVer)
                LOG_INFO("Version in PMS doesn't fit");

            /* If version is higher than SSL 3.0 the first 2 bytes of the decrypted pms MUST be the offered version of the client */
            pc_outData[0] = SSL_VERSION_GET_MAJ(
                    ps_sslCtx->ps_hsElem->e_offerVer);
            pc_outData[1] = SSL_VERSION_GET_MIN(
                    ps_sslCtx->ps_hsElem->e_offerVer);
       }

        LOG2_INFO("Decrypted PreMasterSecret");
        LOG2_HEX(pc_outData, 48);

        e_pendEvent = E_PENDACT_SRV_PKCS1_DECRYPT;
    }
        break;

    case E_PENDACT_ASYM_DHECALCSHARED:
    {

        /* reset this variable */
        //OLD-CW: memset(&cwt_dhKeyCliY, 0x00, sizeof(gci_dhKey_t));

        /* Allocate memory */
        dhePeerPubKey.un_key.keyDhPub.key.data = a_allocDhePeerPubKey;
        dhSecretKey.un_key.keyDhSecret.data = a_allocDhSecretKey;


        /* read the Yc of the client that has been transmitted in the ClientKeyExchange */

    	//Read the length of the key

        /* MSB of key-length */
    	//dhePeerPubKey.un_key.keyDhPub.key.len = *pc_inData >> 8;

    	//pc_inData++;

    	/* LSB of the key-length */
    	//dhePeerPubKey.un_key.keyDhPub.key.len += *pc_inData;

    	//pc_inData++;

        dhePeerPubKey.un_key.keyDhPub.key.len = cwt_inLen;


    	memcpy(dhePeerPubKey.un_key.keyDhPub.key.data, pc_inData, dhePeerPubKey.un_key.keyDhPub.key.len);
    	LOG_INFO("client public key:");
    	LOG_HEX(dhePeerPubKey.un_key.keyDhPub.key.data, dhePeerPubKey.un_key.keyDhPub.key.len);

    	pc_inData+=dhePeerPubKey.un_key.keyDhPub.key.len;

    	/* Get an automatic key ID */
    	ps_sslCtx->s_secParams.dhePeerPubKey = -1;

    	//Store the key and become an ID
    	err = gciKeyPut(&dhePeerPubKey, &ps_sslCtx->s_secParams.dhePeerPubKey);

       // if (cw_dhe_import_Y(pc_inData - 2, cwt_inLen, &cwt_dhKeyCliY) != CW_OK)
    	if(err != en_gciResult_Ok)
        {
            LOG_ERR("DHE import error");
        }

        else
        {

        	//OLD-CW: cwt_dhKeyCliY = *(pc_inData-2);

        	TIME_STAMP(TS_DHE_CALC_SHARED_SEC_BEGIN);

            /* now calculate the shared secret that will be used as PreMasterSecret */

        	/* Random research */
        	dhSecretKeyID = -1;

        	/* The context contains the private key of the server (our private key) */
        	err = gciDhCalcSharedSecret(ps_sslCtx->s_secParams.dheCtx, ps_sslCtx->s_secParams.dhePeerPubKey, &dhSecretKeyID);
//            if (cw_dhe_sharedSec_with_p(ps_sslCtx->s_secParams.pgci_dheKey,
//                                        &cwt_dhKeyCliY,
//                                        &ps_sslCtx->ps_hsElem->pgci_dheP,
//                                        pc_outData, pcwt_outLen) != CW_OK)
        	if(err != en_gciResult_Ok)
            {
                LOG_ERR("DHE sharedSecret error");
            }

        	/* Get the secret key with the ID */

        	err = gciKeyGet(dhSecretKeyID, &dhSecretKey);
            if(err != en_gciResult_Ok)
            {
                LOG_ERR("DHE get sharedSecret error");
            }

            /* Copy the secret in the output */
        	memcpy(pc_outData, dhSecretKey.un_key.keyDhSecret.data, dhSecretKey.un_key.keyDhSecret.len);
        	*pcwt_outLen = dhSecretKey.un_key.keyDhSecret.len;

        	TIME_STAMP(TS_DHE_CALC_SHARED_SEC_END);
        }
        /* we have to free what we malloc'ed before */

        //OLD-CW: cw_dh_free(&cwt_dhKeyCliY);
        err = gciKeyDelete(ps_sslCtx->s_secParams.dhePeerPubKey);
        if(err != en_gciResult_Ok)
        {
        	//TODO return error from state
        }

        //Release the context
        err = gciCtxRelease(ps_sslCtx->s_secParams.dheCtx);
        if(err != en_gciResult_Ok)
        {
        	//TODO return error from state
        }

        e_pendEvent = E_PENDACT_SRV_DHECALCSHARED;
    }
        break;


        //begin vpy
    case E_PENDACT_ASYM_ECDHECALCSHARED:

    	/* reset this variable */
    	//OLD-CW: memset(&(ps_handshElem->eccPubKeyPeer), 0x00, sizeof(ecc_key));

    	//read/import pubkey from the buffer (ANSI x9.63)

    	//Read the first byte to be sure he has the value 4, 6 or 7 (to be valid)
    	if((*pc_inData != 4) && (*pc_inData != 6) && (*pc_inData != 7))
    	{
    		//TODO return error state
    	}

    	pc_inData++;

    	//the x-coordinate has a length of the half of the public key's length
    	ecdhPeerPubKey.un_key.keyEcdhPub.coord.x.len = pc_inData;

    	pc_inData++;

    	memcpy(ecdhPeerPubKey.un_key.keyEcdhPub.coord.x.data, pc_inData, ecdhPeerPubKey.un_key.keyEcdhPub.coord.x.len);

    	pc_inData+=ecdhPeerPubKey.un_key.keyEcdhPub.coord.x.len;

    	//the y-coordinate has a length of the rest of the half of the public key's length
    	ecdhPeerPubKey.un_key.keyEcdhPub.coord.y.len = pc_inData;

    	pc_inData++;

    	memcpy(ecdhPeerPubKey.un_key.keyEcdhPub.coord.y.data, pc_inData, ecdhPeerPubKey.un_key.keyEcdhPub.coord.y.len);

    	pc_inData+=ecdhPeerPubKey.un_key.keyEcdhPub.coord.y.len;

    	/* Get an automatic key ID */
    	ps_handshElem->eccPubKeyPeer = -1;

    	//store the key to become an ID of it
    	err = gciKeyPut(&ecdhPeerPubKey, ps_handshElem->eccPubKeyPeer);


        /* read the public key of the client that has been transmitted in the ClientKeyExchange */
//    	OLD-CW: if(cw_ecc_import_public(pc_inData, cwt_inLen, &(ps_handshElem->eccPubKeyPeer))!=CRYPT_OK)
    	if(err != en_gciResult_Ok)
    	{
            LOG_ERR("ECDHE import error");
    	}
    	else
    	{
    		TIME_STAMP(TS_ECDHE_CALC_SHARED_SEC_BEGIN);

    		/* now calculate the shared secret that will be used as PreMasterSecret */

    		err = gciDhCalcSharedSecret(ps_sslCtx->s_secParams.eccCtx, &(ps_handshElem->eccPubKeyPeer), pc_outData);

//    		OLD-CW: if (cw_ecc_sharedSecret(&(ps_sslCtx->s_secParams.eccKey),
//    				&(ps_handshElem->eccPubKeyPeer),
//					pc_outData, pcwt_outLen) != CW_OK)
    		if(err != en_gciResult_Ok)
    		{
    			LOG_ERR("ECDHE sharedSecret error");
    		}

    		TIME_STAMP(TS_ECDHE_CALC_SHARED_SEC_END);
    	}

    	/* we have to free what we malloc'ed before */

    	//OLD-CW: cw_ecc_free(&(ps_handshElem->eccPubKeyPeer));
    	err = gciKeyDelete(&(ps_handshElem->eccPubKeyPeer));
    	if(err != en_gciResult_Ok)
    	{
    		//TODO return error state
    	}

    	//Release the context
    	err = gciCtxRelease(ps_sslCtx->s_secParams.eccCtx);
    	if(err != en_gciResult_Ok)
    	{
    		//TODO return error from state
    	}

    	e_pendEvent = E_PENDACT_SRV_ECDHECALCSHARED;

    	break;

        //end vpy
    case E_PENDACT_ASYM_CLICERTCHAIN:
    case E_PENDACT_ASYM_SRVCERTCHAIN:
    {
        /*
         * Verify the received certificate against the list of CA certificates.
         * When we act as server and we're here because we must verify the client certificate chain
         * or when we act as client and the application says that we must do the verification.
         */
        if ((e_nextAction == E_PENDACT_ASYM_CLICERTCHAIN)
                || ((ps_sslCtx->e_authLvl
                        & E_SSL_MUST_VERF_SRVCERT)
                        == E_SSL_MUST_VERF_SRVCERT))
        {
            ps_caList = ps_sslCtx->ps_sslSett->ps_caCertsListHead;
        } /* if */

        /*
         * Init the peer certificate octet string
         */
        s_octPeerCert.pc_data = pc_inData;
        s_octPeerCert.cwt_len = cwt_inLen;

        e_ret = sslCert_verifyChain(&s_octPeerCert, &ps_handshElem->gci_rsaPeerKey, ps_caList);

        if (e_ret != E_SSL_CERT_OK)
        {
            E_SSL_VERIFRES_FAILED(pc_outData);
            LOG_ERR("Verification of Certificate failed, error %s occurred",
                    sslDiag_getCertError(e_ret));
        }
        else
        {
            if (ps_caList != NULL)
            {
                E_SSL_VERIFRES_SUCCESS(pc_outData);
                LOG1_OK("Verification of Certificate successful");
            }
            else
            {
                E_SSL_VERIFRES_SKIPPED(pc_outData);
                LOG1_INFO("Verification of Certificate has been skipped");
            }

            /*
             * shrink the public key down to its minimal size to reduce
             * memory usage
             */
            //OLD-CW: cw_rsa_publickey_shrink(&ps_handshElem->gci_peerPubKey);
        }

        *pcwt_outLen = sizeof(E_SSL_VERIFRES);

        if (e_nextAction == E_PENDACT_ASYM_SRVCERTCHAIN)
            e_pendEvent = E_PENDACT_CLI_SRVCERTCHAIN;
        else
            e_pendEvent = E_PENDACT_SRV_CLICERTCHAIN;
    }
        break;

    case E_PENDACT_ASYM_CERTVERIFY:
    {

    	if (ps_sslCtx->e_ver > E_TLS_1_1) {

			if (cwt_inLen != 1 || pc_inData[0] != 1)
			{
				E_SSL_VERIFRES_FAILED(pc_outData);
				LOG_ERR("Verification of CertificateVerify failed");
			}
			else
			{
				E_SSL_VERIFRES_SUCCESS(pc_outData);
				LOG1_OK("Verification of CertificateVerify successful");
			}


    	} else {

//			OLD-CW: if (ssl_verifyHash(pc_inData, VERIF_HASHSIZE,
//					pc_inData + VERIF_HASHSIZE, cwt_inLen - VERIF_HASHSIZE,
//					&ps_handshElem->gci_peerPubKey) != CW_OK)
    		if (ssl_verifyHash(pc_inData, VERIF_HASHSIZE,
    					pc_inData + VERIF_HASHSIZE, cwt_inLen - VERIF_HASHSIZE,
    					&ps_handshElem->gci_rsaPeerKey) != en_gciResult_Ok)
			{
				E_SSL_VERIFRES_FAILED(pc_outData);
				LOG_ERR("Verification of CertificateVerify failed");
			}
			else
			{
				E_SSL_VERIFRES_SUCCESS(pc_outData);
				LOG1_OK("Verification of CertificateVerify successful");
			}

    	}

        *pcwt_outLen = sizeof(E_SSL_VERIFRES);
        e_pendEvent = E_PENDACT_SRV_CERTVERIFY;
    }
        break;

    }

    return (e_pendEvent);
}

