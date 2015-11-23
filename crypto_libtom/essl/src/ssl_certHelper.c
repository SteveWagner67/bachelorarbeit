/*============================================================================*/
/*!
 \file   ssl_cert.c

 \author ??? by STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  This module implements the certificate helper functions

 \version  $Version$

 */
/*============================================================================*/

/*==============================================================================
 INCLUDE FILES
 ==============================================================================*/
#include <limits.h>
#include "crypto_wrap.h"
#include "ssl.h"
#include "ssl_certHelper.h"
#include "ssl_diag.h"

/*==============================================================================
 MACROS
 ==============================================================================*/
#define	LOGGER_ENABLE		DBG_SSL_CERT_MODULE
#include "logger.h"

#ifndef SSL_MAX_BYTES_PER_CW_SIZE

#if (INT_MAX == SHRT_MAX)
/*
 * When int equals a short, allow to shift 1 byte into a size_t and then stop
 * otherwise an overflow can occur
 */
#   define SSL_MAX_BYTES_PER_CW_SIZE  1

#elif (INT_MAX == LONG_MAX)
/*
 * When int equals a long, allow to shift 3 bytes into a size_t and then stop
 * otherwise an overflow can occur
 */
#   define SSL_MAX_BYTES_PER_CW_SIZE  3

#else
/*
 * Other platforms aren't supported yet
 */
#   error Platform not supported
#endif

#endif /* SSL_MAX_BYTES_PER_CW_SIZE */

#ifndef SSL_SUBJECT_STORAGE_SIZE
//! Default size of the subject storage
#define SSL_SUBJECT_STORAGE_SIZE   256
#endif
/*==============================================================================
 ENUMS
 ==============================================================================*/

/*==============================================================================
 STRUCTURES AND OTHER TYPEDEFS
 ==============================================================================*/

typedef uint8_t ac_subjectArray_t[SSL_SUBJECT_STORAGE_SIZE];
typedef struct ST_SSL_SUBJECT_STORAGE
{
    ac_subjectArray_t ac_data;
    int8_t c_inUse;
} s_subjStor_t;

/*==============================================================================
 LOCAL VARIABLE DECLARATIONS
 ==============================================================================*/

static s_subjStor_t ast_certSubject[2];

/*==============================================================================
 LOCAL FUNCTION PROTOTYPES
 ==============================================================================*/
static s_sslCertList_t *loc_getPrevCert(s_sslCertList_t *p_list_head, s_sslCertList_t *p_list_element);
static s_sslOctetStr_t loc_allocSubjStor(void);
static void loc_freeSubjStor(s_sslOctetStr_t * ps_octStor);
/*==============================================================================
 LOCAL FUNCTIONS
 ==============================================================================*/

/*============================================================================*/
/*!
 \fn		  loc_getPrevCert
 \brief    Returns the previous element in the list that points to this element

 This function iterates through the list p_list_head and
 returns the element of the list that points to the given element


 \param     p_list_head       The head of the list
 \param     p_list_element    The current element of the list

 \return    s_sslCertList_t *   The previous element in the list, pointing to p_list_element
 \return    NULL              The element is either head of the list, or not in the list
 */
/*============================================================================*/
static s_sslCertList_t * loc_getPrevCert(s_sslCertList_t * ps_listHead, s_sslCertList_t * ps_listElem)
{
    s_sslCertList_t * p_ret = NULL;
    /*
     * Check that this is not the head of the list, and that it is not NULL
     */
    if ((ps_listHead != ps_listElem) && (ps_listHead != NULL))
    {
        s_sslCertList_t * p_list = ps_listHead;
        /*
         * Find the entry in the list that points to this element
         */
        for (; p_list->next != NULL; p_list = p_list->next)
        {
            if (p_list->next == ps_listElem)
            {
                p_ret = p_list;
                break;
            } /* if */
        } /* for */
    } /* if */

    return (p_ret);
} /* loc_getPrevCert */

static s_sslOctetStr_t loc_allocSubjStor(void)
{
    uint8_t i;
    s_sslOctetStr_t s_ret =
    { 0 };

    for (i = 0; i < (sizeof(ast_certSubject) / sizeof(s_subjStor_t)); i++)
    {
        if (ast_certSubject[i].c_inUse == 0)
        {
            ast_certSubject[i].c_inUse = 1;
            s_ret.pc_data = ast_certSubject[i].ac_data;
            s_ret.cwt_len = SSL_SUBJECT_STORAGE_SIZE;
            break;
        } /* if */
    } /* for */
    if (i == (sizeof(ast_certSubject) / sizeof(s_subjStor_t)))
        LOG_ERR("Get() of subject storage failed");
    return (s_ret);
} /* loc_allocSubjStor() */

static void loc_freeSubjStor(s_sslOctetStr_t *ps_octStor)
{
    if (ps_octStor != NULL)
    {
        unsigned int i;
        for (i = 0; i < (sizeof(ast_certSubject) / sizeof(s_subjStor_t)); i++)
        {
            if (ast_certSubject[i].ac_data == ps_octStor->pc_data)
            {
                CW_MEMSET(ast_certSubject[i].ac_data, 0,
                SSL_SUBJECT_STORAGE_SIZE);
                ast_certSubject[i].c_inUse = 0;
                return;
            } /* if */
        } /* for */
        LOG_ERR(" free() of subject storage failed, data pointer: %p, length: %zu",
                ps_octStor->pc_data, ps_octStor->cwt_len);
    } /* if */
    else
    {
        LOG_ERR(" free() of subject storage failed, pointer to octet string is NULL");
    } /* else */
} /* loc_freeSubjStor() */

/*==============================================================================
 API FUNCTIONS
 ==============================================================================*/

/*============================================================================*/
/*  sslCert_init()                                                            */
/*============================================================================*/
e_sslCertErr_t sslCert_init(s_sslOctetStr_t *ps_octStrCert,
                            s_sslCert_t *ps_cert,
                            gci_rsaPubKey_t *pcwt_rsaPubKey,
                            uint8_t *pc_caSubjName, uint32_t l_caSubjNameLen,
                            s_sslCert_t *ps_caRootCert,
                            s_sslCertList_t *ps_caListHead)
{
    e_sslCertErr_t e_ret;
    s_sslKeyCertInfo_t s_certInfo;
    s_sslKeyCertExt_t s_certExt;
    s_sslCert_t *ps_tmpCaRootCert = NULL;
    s_sslCertList_t *ps_caListElem = NULL;
    s_pubKey_t s_pubKey;
    int32_t l_pathLen;
    int16_t i_tmpRet;

    assert(ps_octStrCert != NULL);
    assert(ps_cert != NULL);
    assert(pcwt_rsaPubKey != NULL);

    /*
     * Decode the certificate
     */
    i_tmpRet = sslCert_decode(&s_certInfo, ps_octStrCert);
    if (i_tmpRet != E_SSL_DER_OK)
    {
        e_ret = E_SSL_CERT_ERR_DECODING_FAILED;
        goto error;
    }

    l_pathLen = SSL_CERT_PATHLEN_INVALID;
    /*
     * decode the extensions field of the cert
     * and save the pathLenConstraint
     */
    sslCert_initExtens(&s_certExt);
    sslCert_decodeExtens(&s_certInfo, &s_certExt);
    ps_cert->c_isCa = s_certExt.s_basicConstr.c_isCa;
    ps_cert->l_pathLenConstr = s_certExt.s_basicConstr.l_pathlen;
    /*
     * This certificate is equal to the root certificate,
     * so assume that this is a self signed cert
     *  OR
     * There's a root certificate given, so verify later with this
     */
    if ((ps_cert == ps_caRootCert) || (ps_caRootCert != NULL))
    {
        ps_tmpCaRootCert = ps_caRootCert;
        if (ps_tmpCaRootCert)
            l_pathLen = ps_tmpCaRootCert->l_pathLenConstr;
    } /* if */
    /*
     * There's a list of CA certificates given, so search one that fits
     */
    else if (ps_caListHead != NULL)
    {
        ps_caListElem = sslCert_getBySubject(ps_caListHead, &s_certInfo.s_octIssuer);
        /*
         * If it has not been found, fail and return
         */
        if (ps_caListElem != NULL)
        {
            ps_tmpCaRootCert = ps_caListElem->ps_caCert;
            if (ps_tmpCaRootCert)
                l_pathLen = ps_tmpCaRootCert->l_pathLenConstr;
        }
        else
        {
            ps_tmpCaRootCert = NULL;
        } /* else */
    } /* else if */
    /*
     * The user forces usage of this certificate, so allow him to do this
     */
    else
    {
        ps_tmpCaRootCert = NULL;
    } /* else if */
    /*
     * Check if the user wants to force usage
     * or the certificate to import is a CA and it is allowed to be imported
     * or the certificate to import is no CA and the root certificate is a CA
     */
    if (((ps_caRootCert == NULL) && (ps_caListHead == NULL))
            || ((ps_cert->c_isCa == TRUE) && (l_pathLen != 0) && (l_pathLen != SSL_CERT_PATHLEN_INVALID))
            || ((ps_cert->c_isCa == FALSE) && (ps_tmpCaRootCert != NULL) && (ps_tmpCaRootCert->c_isCa == TRUE)))
    {
        /*
         * Prepare the SSL public key according to the crypto lib used
         * and try to extract the public key of the certificate
         */
    	//TODO sw ?? rsa copy parameters from rsa tomcrypt to a intern structure
        cw_rsa_publickey_prep(pcwt_rsaPubKey, &s_pubKey);

        i_tmpRet = sslCert_prepPubKey(&s_pubKey, &s_certInfo.s_octPubKey);
        if (i_tmpRet != E_SSL_DER_OK)
        {
            e_ret = E_SSL_CERT_ERR_PUBLIC_KEY;
            goto error;
        }

        //TODO sw ?? rsa copy parameters from intern structure to rsa tomcrypt
        cw_rsa_publickey_post(&s_pubKey, pcwt_rsaPubKey);
        i_tmpRet = E_SSL_CERT_ERR;
        /*
         * When a root certificate has been found, try to verify this certificate
         * When the user forces to allow the usage of this cert, do so
         */
        if (ps_tmpCaRootCert != NULL)
            i_tmpRet = ssl_verifyCertSign(&s_certInfo, &ps_tmpCaRootCert->gci_caPubKey);
        else if ((ps_caRootCert == NULL) && (ps_caListHead == NULL))
            i_tmpRet = E_SSL_CERT_OK;

        if (i_tmpRet != E_SSL_CERT_OK)
        {
            e_ret = E_SSL_CERT_ERR_VERIF_FAILED;
            goto error;
        } /* if */

        /*
         * Remember the right pathLenConstraint
         */
        if (ps_tmpCaRootCert != NULL)
        {
            /*
             * When the root CA allows infinite pathlen, remember the decoded one from the cert
             * Also remember the decoded one from the cert when this cert is self-signed (a CA)
             */
            if ((ps_tmpCaRootCert->l_pathLenConstr == SSL_CERT_PATHLEN_INFINITE) || (ps_cert == ps_caRootCert))
            {
                ps_cert->l_pathLenConstr = s_certExt.s_basicConstr.l_pathlen;
            } /* if */
            else
            {
                ps_cert->l_pathLenConstr = ps_tmpCaRootCert->l_pathLenConstr - 1;
            } /* else */
        } /* if */
        else if ((ps_caRootCert == NULL) && (ps_caListHead == NULL))
        {
            ps_cert->l_pathLenConstr = s_certExt.s_basicConstr.l_pathlen;
        } /* else if */

        if (pc_caSubjName != NULL)
        {
            if (s_certInfo.s_octSubj.cwt_len > l_caSubjNameLen)
            {
                e_ret = E_SSL_CERT_ERR_SMALL_BUFFER;
                goto error;
            }
            /*
             * Copy the data, the pointer where the subject is stored now
             * and the length of the subject
             */
            CW_MEMCOPY(pc_caSubjName, s_certInfo.s_octSubj.pc_data, s_certInfo.s_octSubj.cwt_len);
            ps_cert->s_caSubject.pc_data = pc_caSubjName;
            ps_cert->s_caSubject.cwt_len = s_certInfo.s_octSubj.cwt_len;
            /*
             * finally set return value
             */
            e_ret = E_SSL_CERT_OK;
        }/* if */
        else if (ps_cert->c_isCa == FALSE)
        {
            ps_cert->s_caSubject.pc_data = NULL;
            ps_cert->s_caSubject.cwt_len = 0;
            e_ret = E_SSL_CERT_OK;
        } /* else if */
        else
        {
            e_ret = E_SSL_CERT_BUFFER_NOT_SET;
        } /* else */
    } /* if */
    else
    {
        /*
         * Do some Error handling here, since there can be multiple
         * reasons why we came here
         */
        if (l_pathLen == SSL_CERT_PATHLEN_INVALID)
        {
            if (ps_tmpCaRootCert == NULL)
            {
                if ((s_certInfo.s_octIssuer.cwt_len == s_certInfo.s_octSubj.cwt_len)
                        && (CW_MEMCMP(s_certInfo.s_octIssuer.pc_data, s_certInfo.s_octSubj.pc_data,
                                s_certInfo.s_octIssuer.cwt_len) == 0))
                {
                    e_ret = E_SSL_CERT_ERR_SELF_SIGNED;
                } /* if */
                else
                {
                    e_ret = E_SSL_CERT_ERR_NO_ROOT_AVAILABLE;
                } /* else */
            } /* if */
            else
            {
                e_ret = E_SSL_CERT_ERR_BASICCONSTRAINTS;
            } /* else */
        } /* if */
        else if (l_pathLen == 0)
        {
            e_ret = E_SSL_CERT_ERR_PATHLENCONSTRAINT;
        } /* else if */
        else
        {
            e_ret = E_SSL_CERT_ERR_NO_CA;
        } /* else */
    } /* else */

    error: return e_ret;
} /* sslCert_init */

/*============================================================================*/
/*  sslCert_free()                                                          */
/*============================================================================*/
e_sslCertErr_t sslCert_free(s_sslCert_t * ps_caCert)
{
    assert(ps_caCert != NULL);

    return (E_SSL_CERT_OK);
} /* sslCert_free */

/*============================================================================*/
/*  sslCert_addToList()                                                      */
/*============================================================================*/
s_sslCertList_t * sslCert_addToList(s_sslCertList_t *ps_listHead,
                                    s_sslCertList_t *ps_listElem,
                                    s_sslCert_t *ps_caCert,
                                    s_cdbCert_t *ps_cdbCert)
{
    s_sslCertList_t * ps_listNewHead = ps_listHead;

    assert(ps_listElem != NULL);
    /*
     * The pointers to the data will be assigned in every case
     */
    ps_listElem->ps_caCert = ps_caCert;
    ps_listElem->ps_cdbCert = ps_cdbCert;
    /*
     * Check if the entry is already in the list
     */
    if (loc_getPrevCert(ps_listHead, ps_listElem) == NULL)
    {
        /*
         * It is not in the list, so add the entry as head of the list
         */
        ps_listElem->next = ps_listHead;
        ps_listNewHead = ps_listElem;
    } /* if */

    return ps_listNewHead;
} /* sslCert_addToList */

/*============================================================================*/
/*  sslCert_rmFromList()                                                   */
/*============================================================================*/
s_sslCertList_t * sslCert_rmFromList(s_sslCertList_t *ps_head,
                                     s_sslCertList_t *ps_elem)
{
    s_sslCertList_t *ps_nextHead;
    s_sslCertList_t *ps_prevHead;

    assert(ps_head != NULL);
    assert(ps_elem != NULL);
    /*
     * Check if the entry to remove is the list head
     */
    if (ps_head == ps_elem)
    {
        ps_nextHead = ps_elem->next;
        ps_elem->next = NULL;
    } /* if */
    else
    {
        /*
         * Return the old head as new head
         */
        ps_nextHead = ps_head;
        /*
         * Find the entry in the list and remove it
         */
        ps_prevHead = loc_getPrevCert(ps_head, ps_elem);
        if (ps_prevHead != NULL)
            ps_prevHead->next = ps_elem->next;
    } /* else */

    return ps_nextHead;
} /* sslCert_rmFromList */

/*============================================================================*/
/*  sslCert_getNext()                                                     */
/*============================================================================*/
s_sslCertList_t * sslCert_getNext(s_sslCertList_t *ps_listElem)
{
    s_sslCertList_t * p_ret = NULL;

    assert(ps_listElem != NULL);
    /*
     * Simply return the next pointer
     */
    if (ps_listElem != NULL)
        p_ret = ps_listElem->next;

    return p_ret;
} /* sslCert_getNext */

/*============================================================================*/
/*  sslCert_getBySubject()                                           */
/*============================================================================*/
s_sslCertList_t * sslCert_getBySubject(s_sslCertList_t *ps_caListHead,
                                       s_sslOctetStr_t *ps_octSubj)
{
    s_sslCertList_t * ps_ret = NULL;

    assert(ps_caListHead != NULL);
    assert(ps_octSubj->pc_data != NULL);
    /*
     * Iterate through the given list and break when the certificate has been
     * found where the subject equals the given s_octIssuer
     */
    while (ps_caListHead != NULL)
    {
        s_sslOctetStr_t o_storage = loc_allocSubjStor();
        sslCert_getSubject(ps_caListHead, o_storage.pc_data, &o_storage.cwt_len);
        if ((o_storage.cwt_len > 0) && (o_storage.cwt_len == ps_octSubj->cwt_len)
                && (CW_MEMCMP(o_storage.pc_data, ps_octSubj->pc_data, ps_octSubj->cwt_len) == 0))
        {
            ps_ret = ps_caListHead;
            loc_freeSubjStor(&o_storage);
            break;
        } /* if */
        loc_freeSubjStor(&o_storage);
        ps_caListHead = sslCert_getNext(ps_caListHead);
    } /* for */

    return ps_ret;
} /* sslCert_getBySubject */

/*==============================================================================
 sslCert_getSubject()
 ==============================================================================*/
e_sslResult_t sslCert_getSubject(s_sslCertList_t *ps_entry, uint8_t *pc_dest, size_t *pcwt_space)
{
    int16_t i_ret = E_SSL_ERROR;
    s_sslCert_t *ps_caCert = ps_entry->ps_caCert;
    s_sslOctetStr_t *ps_caSubj = &ps_entry->ps_caCert->s_caSubject;
    s_sslCert_t tmp_cert;
    s_sslOctetStr_t s_octCert;
    size_t cwt_bufLen;

    assert(ps_entry != NULL);
    assert(pc_dest != NULL);
    assert(pcwt_space != NULL);

    /*
     * Check if there's an extracted CA Subject available
     */
    if ((ps_caCert != NULL) && (ps_caSubj->pc_data != NULL))
    {
        if (ps_caCert->s_caSubject.cwt_len <= *pcwt_space)
        {
            CW_MEMCOPY(pc_dest, ps_caSubj->pc_data, ps_caSubj->cwt_len);
            *pcwt_space = ps_caSubj->cwt_len;
            i_ret = E_SSL_OK;
        }
        else
        {
            *pcwt_space = 0;
            i_ret = E_SSL_LEN;
        }
    } /* if */
    /*
     * Check if there's a certificate where it can be extracted
     */
    else if (ps_entry->ps_cdbCert != NULL)
    {
        /*
         * Try to read the cert from cert_db
         */
        s_octCert.pc_data = cdb_read2buf(ps_entry->ps_cdbCert, &cwt_bufLen);
        if (s_octCert.pc_data != NULL)
        {
            s_octCert.cwt_len = cwt_bufLen;
            //TODO sw gci_key_pair_gen RSA
            cw_rsa_publickey_init(&tmp_cert.gci_caPubKey);
            i_ret = sslCert_init(&s_octCert, &tmp_cert, &tmp_cert.gci_caPubKey, pc_dest, *pcwt_space,
            NULL, NULL);

            if (i_ret == E_SSL_CERT_OK)
            {
                *pcwt_space = tmp_cert.s_caSubject.cwt_len;
                i_ret = E_SSL_OK;
            } /* if */
            else
            {
                LOG_ERR(" Init of certificate failed, reason: %s", sslDiag_getCertError(i_ret));
                *pcwt_space = 0;
                if (i_ret == E_SSL_CERT_ERR_SMALL_BUFFER)
                {
                    i_ret = E_SSL_LEN;
                } /* if */
                else
                {
                    i_ret = E_SSL_ERROR;
                } /* else */
            } /* else */
            /*
             * Free the public key
             */
            //TODO sw gci_key_delete
            cw_rsa_publickey_free(&tmp_cert.gci_caPubKey);
            /*
             * Free the cert_db entry
             */
            cdb_free();
        }/* if */
        else
        {
            *pcwt_space = 0;
            LOG_ERR("Reading certificate from cert_db failed");
        } /* else */
    } /* else if */
    else
    {
        *pcwt_space = 0;
        if ((ps_caCert == NULL) && (ps_entry->ps_cdbCert == NULL))
            LOG_ERR("caCert AND cdbCert are NULL, can't extract subject");
        else if ((ps_caCert != NULL) && (ps_caSubj->pc_data == NULL))
            LOG_ERR("caCert = %p, but Subject storage is missing", ps_caCert);
        else
            LOG_ERR("Unknown error. Entry = %p, CaCert = %p, CdbCert = %p", ps_entry, ps_caCert, ps_entry->ps_cdbCert);
    } /* else */

    return (i_ret);
} /* sslCert_getSubject() */

/*==============================================================================
 sslCert_verifyChain()
 ==============================================================================*/
e_sslResult_t sslCert_verifyChain(s_sslOctetStr_t *ps_octInData, gci_rsaPubKey_t *pcwt_rsaPubKey,
        s_sslCertList_t *ps_caListHead)
{
    e_sslCertErr_t i_ret;
    gci_rsaPubKey_t *pcwt_tmpRsaPubKey;
    s_sslOctetStr_t s_octPeerCert;
    s_sslOctetStr_t ast_tmpOct[2];
    s_sslOctetStr_t ast_tmpOctStor[2];
    s_sslOctetStr_t *ps_octRoot;
    s_sslOctetStr_t *ps_octTbv;
    s_sslOctetStr_t *ps_octRootStor;
    s_sslOctetStr_t *ps_octTbvStor;
    s_sslCert_t s_peerCert;
    s_sslCert_t ast_tmpCert[2];
    s_sslCert_t *ps_rootCert;
    s_sslCert_t *ps_tbvCert;

    /* Allocate some memory for a subject name */
    ps_octTbvStor  = &ast_tmpOctStor[1];
    *ps_octTbvStor = loc_allocSubjStor();

    /*
     * Init the peer certificate octet string
     */
    s_octPeerCert.pc_data = ps_octInData->pc_data + 6;
    s_octPeerCert.cwt_len = ssl_readInteger(ps_octInData->pc_data + 3, 3);

    i_ret = sslCert_init(&s_octPeerCert, &s_peerCert,pcwt_rsaPubKey,
            ps_octTbvStor->pc_data, ps_octTbvStor->cwt_len, NULL, ps_caListHead);

    /* Release temporary memmory storage */
    loc_freeSubjStor(ps_octTbvStor);

    /*
     * The certificate could not be verified, so check if the
     * peer sent a certificate chain
     */
    if ((i_ret != E_SSL_CERT_OK) && ((ps_octInData->cwt_len - 6) > s_octPeerCert.cwt_len))
    {
        /*
         * Init the temporary public keys
         */
    	//TODO sw gci_key_pair_gen RSA
        cw_rsa_publickey_init(&ast_tmpCert[0].gci_caPubKey);
        //TODO sw gci_key_pair_gen RSA
        cw_rsa_publickey_init(&ast_tmpCert[1].gci_caPubKey);

        /*
         * Init all other pointers
         */
        ps_octRoot = &ast_tmpOct[0];
        ps_octTbv = &ast_tmpOct[1];
        ps_rootCert = &ast_tmpCert[0];
        ps_tbvCert = &ast_tmpCert[1];
        ps_octRootStor = &ast_tmpOctStor[0];
        *ps_octRootStor = loc_allocSubjStor();

        /*
         * Start with the values of the formerly extracted certificate
         */
        *ps_octRoot = s_octPeerCert;

        /*
         * Iterate through the chain and check if there's a certificate in the list
         * of supported CA certificates, that can verify the certificate in the chain
         */
        do
        {
            /*
             * Increment the octet string to point to the next certificate in the chain
             */
            ps_octRoot->pc_data += ps_octRoot->cwt_len;
            ps_octRoot->cwt_len = ssl_readInteger(ps_octRoot->pc_data, 3);
            ps_octRoot->pc_data += 3;

            /*
             * Try to init the certificate of the chain
             */
            i_ret = sslCert_init(ps_octRoot, ps_rootCert, &ps_rootCert->gci_caPubKey, ps_octRootStor->pc_data,
                    ps_octRootStor->cwt_len,
                    NULL, ps_caListHead);

            if (i_ret != E_SSL_CERT_OK)
            {
                /*
                 * Re-Init the public key when init failed
                 */
            	//TODO sw gci_key_delete
                cw_rsa_publickey_free(&ps_rootCert->gci_caPubKey);
                //TODO sw gci_key_pair_gen RSA
                cw_rsa_publickey_init(&ps_rootCert->gci_caPubKey);
            }

            /*
             * Iterate until end of data has been reached   -> iRet != E_SSL_CERT_OK
             * or init of a cert was successful             -> iRet == E_SSL_CERT_OK
             */
        } while (((ps_octRoot->pc_data + ps_octRoot->cwt_len) < (ps_octInData->pc_data + ps_octInData->cwt_len))
                && (i_ret != E_SSL_CERT_OK));

        /*
         * When one of the certs out of the chain has been verified by
         * a cert out of the list, try to verify the peer's cert with the
         * following certs in the chain
         */
        if (i_ret == E_SSL_CERT_OK)
        {
            do
            {
                /*
                 * Start always at the peer's certificate
                 */
                *ps_octTbv = s_octPeerCert;
                /*
                 * Check if the last verified root certificate was the
                 * CA certificate that signed the peer's certificate
                 */
                if ((ps_octTbv->pc_data + ps_octTbv->cwt_len + 3) == ps_octRoot->pc_data)
                {
                    /*
                     * The next element to check is the peer's certificate,
                     * so disable import of subject
                     */
                    ps_octTbvStor = NULL;
                    /*
                     * Set the pointer of the public key that will be read
                     * out of the certificate, to the public key of the handshake element
                     * that will be required later on in the handshake process
                     */
                    pcwt_tmpRsaPubKey = pcwt_rsaPubKey;
                }
                else
                {
                    /*
                     * There are still certificates in the chain
                     * search the next that must be verified
                     */
                    do
                    {
                        ps_octTbv->pc_data += ps_octTbv->cwt_len;
                        ps_octTbv->cwt_len = ssl_readInteger(ps_octTbv->pc_data, 3);
                        ps_octTbv->pc_data += 3;
                    } while ((ps_octTbv->pc_data + ps_octTbv->cwt_len + 3) != ps_octRoot->pc_data);
                    /*
                     * Set the pointer of the public key to the temporary
                     * public key of the certificate
                     */
                    pcwt_tmpRsaPubKey = &ps_tbvCert->gci_caPubKey;
                    /*
                     * get storage for the subject
                     */
                    *ps_octTbvStor = loc_allocSubjStor();
                }
                /*
                 * Try to init the certificate, if this fails will the
                 * peer's certificate not be valid!
                 */
                i_ret = sslCert_init(ps_octTbv,
                                     ps_tbvCert,
                                     pcwt_tmpRsaPubKey,
                                     ps_octTbvStor != NULL ? ps_octTbvStor->pc_data : NULL,
                                     ps_octTbvStor != NULL ? ps_octTbvStor->cwt_len : 0,
                                     ps_rootCert,
                                     NULL);
                /*
                 * When init of cert was successful, switch around the pointers
                 */
                if (i_ret == E_SSL_CERT_OK)
                {
                	//TODO sw gci_key_delete
                    cw_rsa_publickey_free(&ps_rootCert->gci_caPubKey);
                    //TODO sw gci_key_pair_gen RSA
                    cw_rsa_publickey_init(&ps_rootCert->gci_caPubKey);
                    loc_freeSubjStor(ps_octRootStor);
                    if (ps_octRoot == &ast_tmpOct[0])
                    {
                        ps_octRoot = &ast_tmpOct[1];
                        ps_octTbv = &ast_tmpOct[0];
                        ps_rootCert = &ast_tmpCert[1];
                        ps_tbvCert = &ast_tmpCert[0];
                        ps_octRootStor = &ast_tmpOctStor[1];
                        ps_octTbvStor = &ast_tmpOctStor[0];
                    }
                    else
                    {
                        ps_octRoot = &ast_tmpOct[0];
                        ps_octTbv = &ast_tmpOct[1];
                        ps_rootCert = &ast_tmpCert[0];
                        ps_tbvCert = &ast_tmpCert[1];
                        ps_octRootStor = &ast_tmpOctStor[0];
                        ps_octTbvStor = &ast_tmpOctStor[1];
                    } /* else */
                } /* if */
            } while ((i_ret == E_SSL_CERT_OK) && (s_octPeerCert.pc_data != ps_octRoot->pc_data));
        } /* if */
        /*
         * Free the temporary allocated data
         */
        //TODO sw gci_key_delete
        cw_rsa_publickey_free(&ast_tmpCert[0].gci_caPubKey);
        //TODO sw gci_key_delete
        cw_rsa_publickey_free(&ast_tmpCert[1].gci_caPubKey);
        loc_freeSubjStor(&ast_tmpOctStor[0]);
        loc_freeSubjStor(&ast_tmpOctStor[1]);
    } /* if */

    return i_ret;
} /* sslCert_verifyChain() */

/*==============================================================================
 sslCert_initChain()
 ==============================================================================*/
e_sslResult_t sslCert_initChain(uint8_t *pc_chain, size_t cwt_len)
{
    if (cwt_len < 3)
    {
        return (E_SSL_ERROR);
    }

    pc_chain[0] = pc_chain[1] = pc_chain[2] = 0;

    return (E_SSL_OK);
} /* sslCert_verifyChain() */

/*==============================================================================
 sslCert_addDataToChain()
 ==============================================================================*/
e_sslResult_t sslCert_addDataToChain(uint8_t *pc_chain, size_t *pcwt_len,
                                     uint8_t *pc_data, size_t cwt_dataLen,
                                     size_t cwt_maxLen)
{
    size_t cwt_tmpLen;
    size_t cwt_startPos;

    assert(pc_chain != NULL);
    assert((pc_chain + 1) != NULL);
    assert((pc_chain + 2) != NULL);

    cwt_tmpLen = pc_chain[1] * 256 + pc_chain[2]; /* Len of following Data field */
    cwt_startPos = cwt_tmpLen + 3; /* First free position Initial Lenfield */

    if (cwt_startPos + cwt_dataLen + 3 >= cwt_maxLen)
        return (E_SSL_LEN);

    if ((pc_chain + cwt_startPos + 3) != pc_data)
        CW_MEMMOVE(pc_chain + cwt_startPos + 3, pc_data, cwt_dataLen);

    /* Data Len field */
    (void) ssl_writeInteger(pc_chain + cwt_startPos, cwt_dataLen, 3);

    /* Chain Len field update */
    cwt_tmpLen = cwt_tmpLen + cwt_dataLen + 3;
    (void) ssl_writeInteger(pc_chain, cwt_tmpLen, 3);

    *pcwt_len = cwt_tmpLen + 3;

    return (E_SSL_OK);
}/* sslCert_addDataToChain() */

/*==============================================================================
 sslCert_getSpaceInChain()
 ==============================================================================*/
e_sslResult_t sslCert_getSpaceInChain(uint8_t *pc_data, uint8_t **ppc_freeData,
                                  size_t *pcwt_freeLen, size_t cwt_maxLen)
{
    size_t len;

    assert(pc_data != NULL);
    assert((pc_data + 1) != NULL);
    assert((pc_data + 2) != NULL);

    len = pc_data[1] * 256 + pc_data[2]; /* Len of following Data field array */
    *ppc_freeData = pc_data + len + 3;

    *pcwt_freeLen = cwt_maxLen - len - 6; /* Maximal usable len for data */

    return (E_SSL_OK);
} /* sslCert_getSpaceInChain() */

/***************************************************************************
 * Functions handling content of certificates
 **************************************************************************/

/*==============================================================================
 sslCert_initReqList()
 ==============================================================================*/
e_sslResult_t sslCert_initReqList(uint8_t *pc_data, size_t *pcwt_dataLen)
{
    assert(pc_data != NULL);
    assert((pc_data + 1) != NULL);
    assert(pcwt_dataLen != NULL);

    if (*pcwt_dataLen < 2)
    {
        return (E_SSL_ERROR);
    }

    pc_data[0] = pc_data[1] = 0;
    *pcwt_dataLen = 2;

    return (E_SSL_OK);
}

/*==============================================================================
 sslCert_addToReqList()
 ==============================================================================*/
e_sslResult_t sslCert_addToReqList(uint8_t *pc_data, size_t *pcwt_dataLen,
                                   uint8_t *pc_cert, size_t cwt_certLen)
{
    size_t cwt_len;
    size_t cwt_pos;

    assert(pc_data != NULL);
    assert((pc_data + 1) != NULL);

    cwt_len = pc_data[0] * 256 + pc_data[1]; /* First free position */
    cwt_pos = cwt_len + 2;
    cwt_len += cwt_certLen;

    if (cwt_len > *pcwt_dataLen)
        return (E_SSL_ERROR);

    CW_MEMCOPY(pc_data + cwt_pos, pc_cert, cwt_certLen);
    (void) ssl_writeInteger(pc_data, cwt_len, 2);

    return (E_SSL_OK);
}

/***************************************************************************
 * Certificate support functions
 **************************************************************************/
/*==============================================================================
 sslCert_stripPem()
 ==============================================================================*/
e_sslResult_t sslCert_stripPem(uint8_t **ppc_base64Data,
                               size_t *pcwt_base64DataLen,
                               uint8_t *pc_pemData, size_t cwt_pemLen)
{
    uint8_t *pc_data;

    assert(pc_pemData != NULL);
    assert(pcwt_base64DataLen != NULL);

    pc_data = pc_pemData;

    /* Skip the leading '-' */
    while (cwt_pemLen > 0)
    {
        cwt_pemLen--;
        if (*pc_data++ != '-')
            break;
    }

    /* This is the identifier, skip it */
    while (cwt_pemLen > 0)
    {
        cwt_pemLen--;
        if (*pc_data++ == '-')
            break;
    }

    /* Skip the trailing '-' */
    while (cwt_pemLen > 0)
    {
        cwt_pemLen--;
        if (*pc_data++ != '-')
            break;
    }

    /* Reached End of header */
    *ppc_base64Data = pc_data;

    /* Search for the end of the base64 encoded datablock */
    while (cwt_pemLen > 0)
    {
        cwt_pemLen--;
        if (*pc_data++ == '-')
            break;
    }

    /* Calculate the length of the datablock */
    *pcwt_base64DataLen = pc_data - *ppc_base64Data - 1;

    return (E_SSL_OK);
}

/*==============================================================================
 sslCert_decodeBase64()
 ==============================================================================*/
static signed char b64_decode_table[256] =
{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 00-0F */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 10-1F */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 20-2F */
52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 30-3F */
-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, /* 40-4F */
15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 50-5F */
-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 60-6F */
41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 70-7F */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 80-8F */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 90-9F */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* A0-AF */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* B0-BF */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* C0-CF */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* D0-DF */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* E0-EF */
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 /* F0-FF */
};

size_t sslCert_decodeBase64(uint8_t *pc_binData, size_t cwt_binDataLen,
                               const char *rpc_base64Data,
                               size_t cwt_base64DataLen)
{
    /* Content ? */
    const char *rpc_c;
    uint16_t index;
    uint8_t c_phase;
    int16_t i_data;
    uint16_t i_prevData = 0;
    uint8_t ch;

    index = 0;
    c_phase = 0;

    for (rpc_c = rpc_base64Data; *rpc_c != '\0'; rpc_c++)
    {
        if (cwt_base64DataLen-- == 0)
            break;

        i_data = b64_decode_table[(int) *rpc_c];
        if (i_data >= 0)
        {
            switch (c_phase)
            {
                case 0:
                    c_phase++;
                    break;

                case 1:
                    ch = ((i_prevData << 2) | ((i_data & 0x30) >> 4));
                    if (index < cwt_binDataLen)
                        pc_binData[index++] = ch;
                    else
                        return 0;
                    c_phase++;
                    break;

                case 2:
                    ch = (((i_prevData & 0xf) << 4) | ((i_data & 0x3c) >> 2));
                    if (index < cwt_binDataLen)
                        pc_binData[index++] = ch;
                    else
                        return 0;
                    c_phase++;
                    break;

                case 3:
                    ch = (((i_prevData & 0x03) << 6) | i_data);
                    if (index < cwt_binDataLen)
                        pc_binData[index++] = ch;
                    else
                        return 0;
                    c_phase = 0;
                    break;
            } /* switch */
            i_prevData = i_data;
        } /* if */
    } /* for */
    return (index);
}

#define X509_INTEGER    0x02
#define X509_SEQUENCE   0x30

/****************************************************************************/
/* sslCert_extractX509Len                                                   */
/****************************************************************************/
uint8_t *sslCert_extractX509Len(uint8_t *pc_read, size_t *pcwt_elemLen)
{
    /* Bit 7 is ZERO: this one byte is the length! (means length is between 0 and 127)
     * Bit 7 is ONE:  the lower nibble gives the number of bytes, which forms the length,
     *    MSB first, LSB last
     */
    int32_t l_lenBytes;

    if (*pc_read & 0x80)
    { /* Bit 7 set */
        /*
         * Do allow 3 length bytes to be used in the result
         */
        int32_t shiftCount = SSL_MAX_BYTES_PER_CW_SIZE;
        *pcwt_elemLen = 0;
        l_lenBytes = *pc_read & 0x7F;
        /*
         * Iterate until either the byte-counter is empty or we've reached
         * the maximum number of bytes that can be shifted in a variable of type size_t
         */
        while (l_lenBytes && shiftCount)
        {
            pc_read++;
            l_lenBytes--;
            /*
             * Read over the first x bytes that are 0
             * This is done since there can exist rogue certificates with a length
             * field like:
             * 0x88 [x*0x00] 0xXX [some valid data]
             * This isn't in the specification, but can't be prevented, so catch it
             */
            if ((*pc_read == 0) && (shiftCount == SSL_MAX_BYTES_PER_CW_SIZE))
                continue;
            else
            {
                *pcwt_elemLen = (*pcwt_elemLen << 8) + *pc_read;
                shiftCount--;
            }
        }
        /*
         * When there are bytes left in the length field return -1 as error indication
         * that it wasn't possible to extract the length into a variable of type size_t
         */
        if ((l_lenBytes > 0) && (shiftCount == 0))
        {
            *pcwt_elemLen = -1;
        }
        /*
         * Increment the pointer to return the right position even when decoding failed!
         */
        do
        {
            pc_read++;
            l_lenBytes--;
        } while (l_lenBytes > 0);
    }
    else
    {
        *pcwt_elemLen = *pc_read++;
    }
    return (pc_read);
}

/****************************************************************************/
/* X509_element_extract                                                     */
/****************************************************************************/
uint8_t *sslCert_extractX509Elem(uint8_t *pc_read, gci_bigNum_t **ppcwt_bigNum)
{
    size_t elementLen;

    pc_read = sslCert_extractX509Len(pc_read + 1, &elementLen);
    /* fprintf(fp, "Len = %d\n", elementLen ); */

    if (ppcwt_bigNum != NULL)
    {
        /* Now, length of the second element: private modulus is known */
        if (elementLen % 16) /* not a power of two */
        {
            /* Check for the first Byte, probably zero */
            if (*pc_read == 0x00)
            {
                pc_read++;
                elementLen--;
            }
        }

        /* generate a Bignum and extract the element */
        //TODO sw ?? create BigNumber
        *ppcwt_bigNum = cw_bn_create(*ppcwt_bigNum, elementLen * 8);
        //TODO sw ?? RSA OctetString2IntegerPointer
        cw_rsa_os2ip(*ppcwt_bigNum, pc_read, elementLen);
    }

    pc_read += elementLen;

    return (pc_read);
}

