/*================================================================================================*/
/*!
 \file   ssl_certHandler.c

 \author ??? by STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  X509 certificate handling API

 \version  $Version$

 */

//#include "crypto_wrap.h"
#include "netGlobal.h"
#include "ssl_der.h"
#include "ssl_derd.h"
#include "ssl_certHandler.h"
#include "ssl_oid.h"

/*** Defines ****************************************************************/
#define	LOGGER_ENABLE		DBG_SSL_CERTHANDLER
#include "logger.h"

/*** Global Variables *******************************************************/

/*** Local Variables ********************************************************/

/*** Forward declarations ***************************************************/

/*** Local Functions ********************************************************/
//OLD-CW: static e_derdRet_t loc_getRsaPubKey(s_derdCtx_t *ps_ctx, s_pubKey_t *ps_pubKey);
static e_derdRet_t loc_getRsaPubKey(s_derdCtx_t *ps_ctx, GciKey_t *ps_pubKey);
//OLD-CW: static e_derdRet_t loc_getRsaPubKeyInfo(s_derdCtx_t *ps_ctx, s_pubKey_t *ps_pubKey);
static e_derdRet_t loc_getRsaPubKeyInfo(s_derdCtx_t *ps_ctx, GciKey_t *ps_pubKey);

/****************************************************************************
 * Decoding the following DER public key
 *
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus         INTEGERT,       --> cw_bigNum_t
 *      publicExponent  INTEGER }       --> cw_bigNum_t
 ****************************************************************************/
//OLD-CW: static e_derdRet_t loc_getRsaPubKey(s_derdCtx_t *ps_ctx, s_pubKey_t *ps_pubKey)
static e_derdRet_t loc_getRsaPubKey(s_derdCtx_t *ps_ctx, GciKey_t *ps_pubKey)
{
    int res = E_SSL_DER_OK;

    assert(ps_pubKey != NULL);
    assert(ps_ctx != NULL);

    if (sslDerd_getNextValue(ps_ctx) == SSL_DER_ASN1_CSEQUENCE)
    {
        /*
         * get the modulus
         */
        if (sslDerd_getNextValue(ps_ctx) == SSL_DER_ASN1_INTEGER)
        {
            //OLD-CW: res = sslDerd_getBigNum(ps_ctx, &ps_pubKey->pM);
        	res = sslDerd_getBigNum(ps_ctx, &ps_pubKey->key.rsaPub.n);
            if (res == E_SSL_DER_OK)
            {
                if (sslDerd_getNextValue(ps_ctx) == SSL_DER_ASN1_INTEGER)
                {
                    //OLD-CW: res = sslDerd_getBigNum(ps_ctx, &ps_pubKey->pE);
                	res = sslDerd_getBigNum(ps_ctx, &ps_pubKey->key.rsaPub.e);
                }
                else
                    res = E_SSL_DER_ERR_NO_PUBEXP; /* no exponent */
            }
        }
        else
            res = E_SSL_DER_ERR_NO_MODULUS; /* no modulus */
    }
    else
        res = E_SSL_DER_ERR_NO_CSEQUENCE; /* no RSA public key sequence */

    return res;
} /* loc_getRsaPubKey */

/****************************************************************************
 * Decoding the following DER certificate structure
 *
 *  SubjectPublicKeyInfo ::= SEQUENCE {
 *      algorithm           AlgorithmIdentifier, --> int
 *      subjectPublicKey    BIT STRING }         --> calls the algorithm dependent
 *                                                   key decoding function
 *
 *  Supportet algorithms are:
 *      rsaEncryption, OID = 1.2.840.113549.1.1.1
 ****************************************************************************/
//OLD-CW: static e_derdRet_t loc_getRsaPubKeyInfo(s_derdCtx_t *ps_ctx, s_pubKey_t *ps_pubKey)
static e_derdRet_t loc_getRsaPubKeyInfo(s_derdCtx_t *ps_ctx, GciKey_t *ps_pubKey)
{
    e_derdRet_t e_res = E_SSL_DER_OK;
    int algo;

    assert(ps_ctx != NULL);
    assert(ps_pubKey != NULL);

    if ((ps_ctx->c_tag == SSL_DER_ASN1_CSEQUENCE)
            && (sslDerd_getNextValue(ps_ctx) == SSL_DER_ASN1_CSEQUENCE))
    {
        //OLD-CW: e_res = sslDerd_getPubKeyAlg(ps_ctx, &ps_pubKey->iAlgorithm, &ps_pubKey->uiKeyLen);
    	e_res = sslDerd_getPubKeyAlg(ps_ctx, &algo, &ps_pubKey->key.rsaPub.e.len);
        if (e_res == E_SSL_DER_OK)
        {
            if (sslDerd_getNextBitStr(ps_ctx) == E_SSL_DER_OK)
            {
                //OLD-CW: switch (ps_pubKey->iAlgorithm)
            	switch (algo)
                {
                case SSL_OID_RSA_ENCRYPTION:
                case SSL_OID_X509_RSA_ENC:
                    e_res = loc_getRsaPubKey(ps_ctx, ps_pubKey);
                    break;
                default:
                    e_res = E_SSL_DER_ERR_UNKNOWN_ALGORITHM;
                    break;
                }
            }
            else
                e_res = E_SSL_DER_ERR_NO_PUBKEYBITSTR; /* no Key bit string */
        }
    }
    else
        e_res = E_SSL_DER_ERR_NO_PUBKEYSEQ; /* no OID sequence */

    return (e_res);
} /* loc_getRsaPubKeyInfo */

/****************************************************************************
 * Initialize the certificate-subject structure for decoding
 ****************************************************************************/
static void sslCert_subjInit(s_sslKeyCertSubj_t *ps_certSubj)
{
    assert(ps_certSubj != NULL);

    ps_certSubj->type = SSL_DER_ASN1_UNDEF;

    ps_certSubj->strData.iStringType = SSL_DER_ASN1_UNDEF;
    ps_certSubj->strData.pc_data = NULL;
    ps_certSubj->strData.cwt_len = 0;
}

/*** Global Functions *******************************************************/

/*============================================================================*/
/*  sslCert_decode                                                           */
/*============================================================================*/
e_derdRet_t sslCert_decode(s_sslKeyCertInfo_t *ps_certInfo,
        s_sslOctetStr_t *ps_octDerStr)
{
    e_derdRet_t i_ret;

    assert(ps_certInfo != NULL);
    assert(ps_octDerStr != NULL);

    /*
     * Init the structures
     */
    sslCert_decodeInit(ps_certInfo, ps_octDerStr);
    /*
     * Decode the certificate and return if something failed
     */
    i_ret = sslCert_decodeCert(ps_certInfo);
    if (i_ret == E_SSL_DER_OK)
    {
        i_ret = sslCert_decodeTbsCert(ps_certInfo);
    } /* if */

    return i_ret;
} /* sslCert_decode */

/*============================================================================*/
/*  sslCert_decodeInit														  */
/*============================================================================*/
void sslCert_decodeInit(s_sslKeyCertInfo_t *ps_certInfo,
        s_sslOctetStr_t *ps_octStr)
{
    assert(ps_certInfo != NULL);
    assert(ps_octStr != NULL);
    assert(ps_octStr->pc_data != NULL);
    assert(ps_octStr->cwt_len > 0);

    ps_certInfo->s_octCert = *ps_octStr;

    ps_certInfo->s_octTbsCert.pc_data = NULL;
    ps_certInfo->s_octTbsCert.pc_data = 0;

    ps_certInfo->s_octIssuer.pc_data = NULL;
    ps_certInfo->s_octIssuer.cwt_len = 0;
    ps_certInfo->s_octSubj.pc_data = NULL;
    ps_certInfo->s_octSubj.cwt_len = 0;

    ps_certInfo->s_octIssuerUId.pc_data = NULL;
    ps_certInfo->s_octIssuerUId.cwt_len = 0;
    ps_certInfo->s_octSubjUId.pc_data = NULL;
    ps_certInfo->s_octSubjUId.cwt_len = 0;

    ps_certInfo->s_octPubKey.pc_data = NULL;
    ps_certInfo->s_octPubKey.cwt_len = 0;

    ps_certInfo->s_octExts.pc_data = NULL;
    ps_certInfo->s_octExts.cwt_len = 0;

    ps_certInfo->s_sign.pc_bitStr = NULL;
    ps_certInfo->s_sign.cwt_len = 0;
    ps_certInfo->s_sign.c_unused = 0;

} /* sslCert_decodeInit */

/*============================================================================*/
/*  sslCert_decodeCert														  */
/*============================================================================*/
e_derdRet_t sslCert_decodeCert(s_sslKeyCertInfo_t *ps_certInfo)
{
    s_derdCtx_t s_derdCtx;
    e_derdRet_t e_error = E_SSL_DER_OK;
    int8_t c_return = 0;
    e_sslCertDecStep_t e_step = E_SSL_DER_INIT;
    uint8_t c_next = 0;

    assert(ps_certInfo != NULL);
    assert(ps_certInfo->s_octCert.pc_data != NULL);
    assert(ps_certInfo->s_octCert.cwt_len > 0);

    sslDerd_initDecCtx(&s_derdCtx, &ps_certInfo->s_octCert);

    /***************************************************************************
     *  Start the DER string with a SEQUENCE ?
     **************************************************************************/
    if (s_derdCtx.c_tag == SSL_DER_ASN1_CSEQUENCE)
        ps_certInfo->s_octCert = s_derdCtx.s_octBuf;
    else
        e_error = E_SSL_DER_ERR_NO_CERT;

    while ((e_error == E_SSL_DER_OK) && (!c_return))
    {
        switch (e_step)
        {
        case E_SSL_DER_INIT:
            /********************************************************************
             *  Get the TBSCertificate and move over TBSCertificate structure
             *******************************************************************/
        case E_SSL_DER_GET_TBSCERT:
            c_next = sslDerd_getNextEnd(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_CSEQUENCE)
                ps_certInfo->s_octTbsCert = s_derdCtx.s_octDer;
            else
                e_error = E_SSL_DER_ERR_NO_TBSCERT;

            e_step = E_SSL_DER_GET_TBSALGID;
            break;

            /********************************************************************
             *  Get Algorithm Identifier
             *******************************************************************/
        case E_SSL_DER_GET_TBSALGID:
            c_next = sslDerd_getNextValue(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_CSEQUENCE)
            {
                e_error = sslDerd_getSigAlg(&s_derdCtx,
                        &ps_certInfo->l_sigAlgOId);
            }
            else
                e_error = E_SSL_DER_ERR_NO_SIGALG;

            e_step = E_SSL_DER_GET_SIGNATURE;
            break;

            /********************************************************************
             *  Get Signature
             *******************************************************************/
        case E_SSL_DER_GET_SIGNATURE:
            c_next = sslDerd_getNextValue(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_BIT_STRING)
                e_error = sslDerd_getBitStr(&s_derdCtx, &ps_certInfo->s_sign);
            else
                e_error = E_SSL_DER_ERR_NO_SIGNATURE;

            c_return = 1;
            break;

        default:
            e_error = E_SSL_DER_ERR;
            break;
        }
    }
    return (e_error);
} /* sslCert_decodeCert */

/*============================================================================*/
/*  sslCert_decodeTbsCert													  */
/*============================================================================*/

e_derdRet_t sslCert_decodeTbsCert(s_sslKeyCertInfo_t *ps_certInfo)
{
    s_derdCtx_t s_derdCtx;
    e_derdRet_t e_error = E_SSL_DER_OK;
    int32_t l_temp = 0;
    int8_t c_return = 0;
    e_sslCertDecStep_t e_step = E_SSL_DER_INIT;
    uint8_t c_next = 0;

    assert(ps_certInfo != NULL);
    assert(ps_certInfo->s_octTbsCert.pc_data != NULL);
    assert(ps_certInfo->s_octTbsCert.cwt_len > 0);

    sslDerd_initDecCtx(&s_derdCtx, &ps_certInfo->s_octTbsCert);

    while ((e_error == E_SSL_DER_OK) && (!c_return))
    {
        switch (e_step)
        {
        case E_SSL_DER_INIT:
            c_next = sslDerd_getNextValue(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_UNDEF)
            {
                e_error = E_SSL_DER_ERR_DECODING;
            }

            e_step = E_SSL_DER_GET_VERSION;
            break;

            /*
             * get the certificate version
             */
        case E_SSL_DER_GET_VERSION:
            c_next = sslDerd_getNextValue(&s_derdCtx);

            if (s_derdCtx.c_tag != (SSL_DER_ASN1_CCONTEXTSPEC | 0))
            {
                e_error = sslDerd_getUI32(&s_derdCtx, &(ps_certInfo->l_ver));
                e_step = E_SSL_DER_GET_CERTSERNUM;
            }
            else
            {
                /*
                 * the version number was not present in the DER string
                 * set the default version number v1 = 0
                 */
                ps_certInfo->l_ver = 0;
                ps_certInfo->s_serialN.cwt_len = s_derdCtx.s_octVal.cwt_len;
                ps_certInfo->s_serialN.pc_data = s_derdCtx.s_octVal.pc_data;
                e_step = E_SSL_DER_GET_TBSALGID;
            }
            break;

            /*
             * get the certificate serial number
             */
        case E_SSL_DER_GET_CERTSERNUM:
            c_next = sslDerd_getNextValue(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_INTEGER)
            {
                ps_certInfo->s_serialN.cwt_len = s_derdCtx.s_octVal.cwt_len;
                ps_certInfo->s_serialN.pc_data = s_derdCtx.s_octVal.pc_data;
            }
            e_step = E_SSL_DER_GET_TBSALGID;
            break;

            /*
             *  get TBSCertificate AlgorithmIdentifier and compare it with
             *  the signature AlgorithmIdentifier
             */
        case E_SSL_DER_GET_TBSALGID:
            c_next = sslDerd_getNextValue(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_CSEQUENCE)
            {
                e_error = sslDerd_getSigAlg(&s_derdCtx, &l_temp);
                if (e_error == E_SSL_DER_OK)
                {
                    if (ps_certInfo->l_sigAlgOId != l_temp)
                    {
                        e_error = E_SSL_DER_ERR_DIFSIGALG;
                    }
                    l_temp = 0;
                }
            }
            else
                e_error = E_SSL_DER_ERR_NO_ALGSEQOID;

            e_step = E_SSL_DER_GET_ISSUERNAME;
            break;

            /*
             *  get Issuer Name as OCTET STRING
             */
        case E_SSL_DER_GET_ISSUERNAME:
            c_next = sslDerd_getNextEnd(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_CSEQUENCE)
                ps_certInfo->s_octIssuer = s_derdCtx.s_octDer;
            else
                e_error = E_SSL_DER_ERR_NO_ISSUERNAME;

            e_step = E_SSL_DER_GET_VALIDITY;
            break;

            /*
             *  get Validity as OCTET STRING
             */
        case E_SSL_DER_GET_VALIDITY:
            c_next = sslDerd_getNextValue(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_CSEQUENCE)
            {
                e_error = sslDerd_getValidity(&s_derdCtx,
                        &ps_certInfo->s_validity);
            }
            else
                e_error = E_SSL_DER_ERR_NO_VALIDITYSEQ;

            e_step = E_SSL_DER_GET_SUBJNAME;
            break;

            /*
             *  get Subject name as OCTET STRING
             */
        case E_SSL_DER_GET_SUBJNAME:
            c_next = sslDerd_getNextEnd(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_CSEQUENCE)
                ps_certInfo->s_octSubj = s_derdCtx.s_octDer;
            else
                e_error = E_SSL_DER_ERR_NO_SUBJECTNAME;

            e_step = E_SSL_DER_GET_PUBKEY;
            break;

            /*
             *  get Public key as OCTET STRING
             */
        case E_SSL_DER_GET_PUBKEY:
            c_next = sslDerd_getNextEnd(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_CSEQUENCE)
                ps_certInfo->s_octPubKey = s_derdCtx.s_octDer;
            else
                e_error = E_SSL_DER_ERR_NO_PUBKEYINFO;

            if (s_derdCtx.c_EOS == FALSE)
                e_step = E_SSL_DER_GET_OPTIONAL;
            else
                c_return = 1;
            break;

            /*
             *  Get the optional part of the certificate
             *  It is possible that this is the end of the TBSCertificate!
             */
        case E_SSL_DER_GET_OPTIONAL:
            c_next = sslDerd_getNextEnd(&s_derdCtx);

            if (c_next == SSL_DER_ASN1_UNDEF)
            {
                e_error = E_SSL_DER_ERR_DECODING;
            }
            if ((l_temp >= 3) && (e_error == E_SSL_DER_OK))
            {
                c_return = 1;
            }
            else if (e_error == E_SSL_DER_OK)
            {
                if (s_derdCtx.c_tag == (SSL_DER_ASN1_CCONTEXTSPEC | 1))
                {
                    ps_certInfo->s_octIssuerUId = s_derdCtx.s_octDer;
                    l_temp = 1;
                }
                else if (s_derdCtx.c_tag == (SSL_DER_ASN1_CCONTEXTSPEC | 2))
                {
                    ps_certInfo->s_octSubjUId = s_derdCtx.s_octDer;
                    l_temp = 2;
                }
                else if (s_derdCtx.c_tag == (SSL_DER_ASN1_CCONTEXTSPEC | 3))
                {
                    sslDerd_initDecCtx(&s_derdCtx, &s_derdCtx.s_octDer);

                    if (sslDerd_getNextValue(
                            &s_derdCtx) == SSL_DER_ASN1_CSEQUENCE)
                    {
                        ps_certInfo->s_octExts = s_derdCtx.s_octDer;
                        l_temp = 3;
                    }
                    else
                    {
                        e_error = E_SSL_DER_ERR_NO_CSEQUENCE;
                    }
                }
                else
                    e_error = E_SSL_DER_ERR_WRONGTAG;
            }
            break;

        default:
            e_error = E_SSL_DER_ERR;
            break;
        }
    }

    return (e_error);
} /* sslCert_decodeTbsCert */

/*============================================================================*/
/*  sslCert_initExtens                                             */
/*============================================================================*/
void sslCert_initExtens(s_sslKeyCertExt_t * ps_certExts)
{
    assert(ps_certExts != NULL);

    ps_certExts->s_basicConstr.c_isCa = FALSE;
    ps_certExts->s_basicConstr.l_pathlen = SSL_CERT_PATHLEN_INVALID;

    ps_certExts->s_keyUsage.c_keyCertSign = FALSE;

    ps_certExts->s_extKeyUsage.c_cliAuth = FALSE;

    ps_certExts->s_netscCertType.c_sslCa = FALSE;
    ps_certExts->s_netscCertType.c_sslCli = FALSE;
    ps_certExts->s_netscCertType.c_sslSrv = FALSE;
} /* sslCert_initExtens */

/*============================================================================*/
/*  sslCert_decodeExtens                                                 */
/*============================================================================*/
int sslCert_decodeExtens(s_sslKeyCertInfo_t *ps_certInfo,
        s_sslKeyCertExt_t *ps_certExts)
{
    s_derdCtx_t     s_derdCtx;
    s_derdCtx_t     s_tempCtx;
    s_sslBitStr_t   s_bitStr;
    int32_t         l_return = E_SSL_CERT_OK;
    uint32_t        l_val;

    assert(ps_certInfo != NULL);
    assert(ps_certInfo->s_octExts.pc_data != NULL);
    assert(ps_certInfo->s_octExts.cwt_len > 0);
    assert(ps_certExts != NULL);

    sslDerd_initDecCtx(&s_derdCtx, &ps_certInfo->s_octExts);

    while ((s_derdCtx.c_EOS == FALSE) && ((l_return == E_SSL_CERT_OK) || (l_return == E_SSL_DER_OK)))
    {
        if (sslDerd_getNextValue(&s_derdCtx) != SSL_DER_ASN1_OBJECT)
            continue;

        switch (sslOid_fromDer(s_derdCtx.s_octVal.pc_data, s_derdCtx.s_octVal.cwt_len))
        {
            case SSL_OID_BASIC_CONSTRAINS:
            {
                /*
                 * get Basic Constraints
                 * SEQUENCE {
                 *   OBJECT IDENTIFIER '2 5 29 19'
                 *   [opt. BOOLEAN | FALSE]
                 *   OCTET STRING, encapsulates {
                 *     SEQUENCE {
                 *       BOOLEAN TRUE
                 *       [opt. INTEGER | 0]
                 *       }
                 *     }
                 *   }
                 */
                l_return = sslDerd_getNextValue(&s_derdCtx);
                /*
                 * The OID has already been read, so the next potential element
                 * is a BOOLEAN which indicates if the Basic Constraints are CRITICAL
                 * If this element is contained in the cert, simply step over
                 */
                if (l_return == SSL_DER_ASN1_BOOLEAN)
                {
                    l_return = sslDerd_getNextValue(&s_derdCtx);
                }
                /*
                 * The next element must be an OCTET STRING, containing the
                 * indication if this Cert is a CA
                 */
                if (l_return == SSL_DER_ASN1_OCTET_STRING)
                {
                    sslDerd_initDecCtx(&s_tempCtx, &s_derdCtx.s_octVal);
                    /*
                     * The OCTET STRING must contain a BOOLEAN which indicates
                     * if this cert indentifies a CA
                     */
                    if (sslDerd_getNextValue(&s_tempCtx) != SSL_DER_ASN1_BOOLEAN)
                    {
                        l_return = E_SSL_CERT_ERR_EXT_BC_CA_MISSING;
                        break;
                        /*return E_SSL_CERT_ERR_EXT_BC_CA_MISSING;*/
                    }

                    l_return = sslDerd_getBool(&s_tempCtx, &ps_certExts->s_basicConstr.c_isCa);
                    if (l_return != E_SSL_DER_OK)
                    {
                        l_return = E_SSL_CERT_ERR_EXT_BASIC_CONSTRAINTS;
                        break;
                    }
                    /*
                     * After the CA inidication is possibly the path-length added
                     *
                     * ITU-T X.509 - Ch. 8.4.2.1
                     * "If no pathLenConstraint field appears in any certificate
                     * of a certification path, there is no limit to the allowed
                     * length of the certification path"
                     * This value is later validated again, when this certificate
                     * is verified
                     */
                    if (sslDerd_getNextValue(&s_tempCtx) == SSL_DER_ASN1_INTEGER)
                    {
                        if (sslDerd_getUI32(&s_tempCtx, &l_val) != E_SSL_DER_OK)
                        {
                            l_return = E_SSL_CERT_ERR_EXT_BC_PATHLEN_ERR;
                            break;
                        }
                        if (l_val > INT_MAX)
                        {
                            l_return = E_SSL_CERT_ERR_EXT_BC_PATHLEN_ERR;
                            break;
                        }
                        ps_certExts->s_basicConstr.l_pathlen = (size_t) l_val;
                    }
                    else
                        ps_certExts->s_basicConstr.l_pathlen =
                        SSL_CERT_PATHLEN_INFINITE;
                }
                else
                {
                    l_return = E_SSL_CERT_ERR_EXT_BASIC_CONSTRAINTS;
                    break;
                }
                /*
                 * Forward the "general DER context" over the CSequence
                 * that contained all this content
                 */
                sslDerd_getNextEnd(&s_derdCtx);
                l_return = E_SSL_CERT_OK;
            }
                break;
            case SSL_OID_KEY_USAGE:
            {
                /*
                 * get Key Usage
                 * SEQUENCE {
                 *   OBJECT IDENTIFIER '2 5 29 15'
                 *   OCTET STRING, encapsulates {
                 *     BIT STRING
                 *     }
                 *   }
                 *
                 */
                if (sslDerd_getNextValue(&s_derdCtx) == SSL_DER_ASN1_OCTET_STRING)
                {
                    sslDerd_initDecCtx(&s_tempCtx, &s_derdCtx.s_octVal);
                    if (sslDerd_getBitStr(&s_tempCtx, &s_bitStr) != E_SSL_DER_OK)
                    {
                        l_return = E_SSL_CERT_ERR_EXT_KEYUSAGE;
                        break;
                    }
                    /*
                     * KeyUsage ::= BIT STRING {
                     *  digitalSignature  (0),
                     *  nonRepudiation    (1),
                     *  keyEncipherment   (2),
                     *  dataEncipherment  (3),
                     *  keyAgreement      (4),
                     *  keyCertSign       (5),
                     *  cRLSign           (6),
                     *  encipherOnly      (7),
                     *  decipherOnly      (8) }
                     */
                    if ((s_bitStr.cwt_len == 1)
                            && ((*s_bitStr.pc_bitStr & SSL_DER_ASN1_BITSTR_BIT5) == SSL_DER_ASN1_BITSTR_BIT5))
                        ps_certExts->s_keyUsage.c_keyCertSign = TRUE;
                    else
                        ps_certExts->s_keyUsage.c_keyCertSign = FALSE;
                }
                else
                {
                    l_return = E_SSL_CERT_ERR_EXT_KEYUSAGE;
                    break;
                }

                /*
                 * Forward the "general DER context" over the CSequence
                 * that contained all this content
                 */
                sslDerd_getNextEnd(&s_derdCtx);
                l_return = E_SSL_CERT_OK;
            } /* SSL_OID_KEY_USAGE */
                break;
            case SSL_OID_EXTEND_KEY_USAGE:
            {
                /*
                 * get Extended Key Usage
                 *
                 * SEQUENCE {
                 *   OBJECT IDENTIFIER extKeyUsage (2 5 29 37)
                 *   OCTET STRING, encapsulates {
                 *     SEQUENCE {
                 *       OBJECT IDENTIFIER typeA (1 3 6 1 5 5 7 3 X)
                 *       OBJECT IDENTIFIER typeB (1 3 6 1 5 5 7 3 X)
                 *       }
                 *     }
                 *   }
                 */
                if (sslDerd_getNextValue(&s_derdCtx) == SSL_DER_ASN1_OCTET_STRING)
                {
                    sslDerd_initDecCtx(&s_tempCtx, &s_derdCtx.s_octVal);
                    if (sslDerd_getNextValue(&s_tempCtx) == SSL_DER_ASN1_CSEQUENCE)
                    {
                        while (s_tempCtx.c_EOS != FALSE)
                        {
                            if (sslDerd_getNextValue(&s_tempCtx) == SSL_DER_ASN1_OBJECT)
                            {
                                switch (sslOid_fromDer(s_tempCtx.s_octVal.pc_data, s_tempCtx.s_octVal.cwt_len))
                                {
                                    case SSL_OID_CLIENT_AUTH:
                                        ps_certExts->s_extKeyUsage.c_cliAuth = TRUE;
                                        break;
                                    default:
                                        break;
                                } /* switch */
                            } /* if */
                        } /* while */
                    } /* if */
                    else
                    {
                        l_return = E_SSL_CERT_ERR_EXT_EXTKEYUSAGE;
                        break;
                    }
                } /* if */
                else
                {
                    l_return = E_SSL_CERT_ERR_EXT_EXTKEYUSAGE;
                    break;
                }

                /*
                 * Forward the "general DER context" over the CSequence
                 * that contained all this content
                 */
                sslDerd_getNextEnd(&s_derdCtx);
                l_return = E_SSL_CERT_OK;
            } /* SSL_OID_EXTEND_KEY_USAGE */
                break;
            case SSL_OID_NETSCAPE_CERT_TYPE:
            {
                /*
                 * get Netscape Cert Type
                 * SEQUENCE {
                 *   OBJECT IDENTIFIER '2 16 840 1 113730 1 1'
                 *   OCTET STRING, encapsulates {
                 *     BIT STRING
                 *     }
                 *   }
                 *
                 */
                if (sslDerd_getNextValue(&s_derdCtx) == SSL_DER_ASN1_OCTET_STRING)
                {
                    sslDerd_initDecCtx(&s_tempCtx, &s_derdCtx.s_octVal);
                    if (sslDerd_getBitStr(&s_tempCtx, &s_bitStr) != E_SSL_DER_OK)
                    {
                        l_return = E_SSL_CERT_ERR_EXT_NETSCAPE_CERTTYPE;
                        break;
                    }
                    /*
                     * Simply switch by the length of the BITSTRING to analyse its contents
                     */
                    switch (s_bitStr.cwt_len)
                    {
                        case 8:
                            /* bit-7    Object Signing CA - this cert is certified for issuing certs for Object Signing */
                        case 7:
                            /* bit-6    S/MIME CA - this cert is certified for issuing certs for S/MIME use */
                        case 6:
                            /* bit-5    SSL CA - this cert is certified for issuing certs for SSL use */
                            if ((*s_bitStr.pc_bitStr & SSL_DER_ASN1_BITSTR_BIT5) == SSL_DER_ASN1_BITSTR_BIT5)
                                ps_certExts->s_netscCertType.c_sslCa = TRUE;
                            else
                                ps_certExts->s_netscCertType.c_sslCa = FALSE;
                        case 5:
                            /* bit-4    Reserved - this bit is reserved for future use */
                        case 4:
                            /* bit-3    Object Signing - this cert is certified for signing objects such as Java applets and plugins */
                        case 3:
                            /* bit-2    S/MIME - this cert is certified for use by clients */
                        case 2:
                            /* bit-1    SSL server - this cert is certified for SSL server authentication use */
                            if ((*s_bitStr.pc_bitStr & SSL_DER_ASN1_BITSTR_BIT1) == SSL_DER_ASN1_BITSTR_BIT1)
                                ps_certExts->s_netscCertType.c_sslSrv = TRUE;
                            else
                                ps_certExts->s_netscCertType.c_sslSrv = FALSE;
                        case 1:
                            /* bit-0    SSL client - this cert is certified for SSL client authentication use */
                            if ((*s_bitStr.pc_bitStr & SSL_DER_ASN1_BITSTR_BIT0) == SSL_DER_ASN1_BITSTR_BIT0)
                                ps_certExts->s_netscCertType.c_sslCli = TRUE;
                            else
                                ps_certExts->s_netscCertType.c_sslCli = FALSE;
                            break;
                        default:
                            l_return = E_SSL_CERT_ERR_EXT_NETSCAPE_CERTTYPE;
                            break;
                    } /* switch */
                }
                else
                {
                    l_return = E_SSL_CERT_ERR_EXT_NETSCAPE_CERTTYPE;
                    break;
                }

                if (l_return != E_SSL_CERT_OK)
                {
                    l_return = E_SSL_CERT_ERR;
                    break;
                }

                /*
                 * Forward the "general DER context" over the CSequence
                 * that contained all this content
                 */
                sslDerd_getNextEnd(&s_derdCtx);
                l_return = E_SSL_CERT_OK;
            } /* SSL_OID_NETSCAPE_CERT_TYPE */
                break;
            default:
                /*
                 * do nothing
                 */
                break;
        }
    }

    return (l_return);
} /* sslCert_decodeExtens */

/*============================================================================*/
/*  sslCert_decodeSubjInit                                                    */
/*============================================================================*/
void sslCert_decodeSubjInit(s_sslKeyCertInfo_t *ps_certInfo,
                            s_derdCtx_t *ps_derdCtx)
{
    assert(ps_certInfo != NULL);
    assert(ps_certInfo->s_octSubj.pc_data != NULL);
    assert(ps_certInfo->s_octSubj.cwt_len > 0);
    assert(ps_derdCtx != NULL);

    sslDerd_initDecCtx(ps_derdCtx, &ps_certInfo->s_octSubj);
} /* sslCert_decodeSubjInit */

/*============================================================================*/
/*  sslCert_decodeSubjGetNext                                                 */
/*============================================================================*/
e_sslCertErr_t sslCert_decodeSubjGetNext(s_derdCtx_t        *ps_derdCtx,
                                         s_sslKeyCertSubj_t *ps_certSubj)
{
    e_sslCertErr_t e_res = E_SSL_CERT_OK;

    assert(ps_derdCtx != NULL);
    assert(ps_certSubj != NULL);

    sslCert_subjInit(ps_certSubj);

    /*
     * The structure of the elements in the subject is as follows
     *   thisElement ::= SET {
     *       element-data ::= SEQUENCE {
     *           id-element ::= ASN1 OBJECT
     *           element    ::= CHOICE {
     *               teletexString     TeletexString   (SIZE (1..ub-common-name)),
     *               printableString   PrintableString (SIZE (1..ub-common-name)),
     *               universalString   UniversalString (SIZE (1..ub-common-name)),
     *               utf8String        UTF8String      (SIZE (1..ub-common-name)),
     *               bmpString         BMPString       (SIZE (1..ub-common-name))
     *           }
     *       }
     *   }
     */
    if ((sslDerd_getNextValue(ps_derdCtx) == SSL_DER_ASN1_CSET)
            && (sslDerd_getNextValue(ps_derdCtx) == SSL_DER_ASN1_CSEQUENCE))
    {
        if (sslDerd_getNextValue(ps_derdCtx) == SSL_DER_ASN1_OBJECT)
        {
            int iStringType;
            ps_certSubj->type = sslOid_fromDer(ps_derdCtx->s_octVal.pc_data,
                    ps_derdCtx->s_octVal.cwt_len);
            iStringType = sslDerd_getNextEnd(ps_derdCtx);

            if (SSL_DER_ASN1_IS_STRING(iStringType))
            {
                ps_certSubj->strData.iStringType = iStringType;
                ps_certSubj->strData.pc_data = ps_derdCtx->s_octVal.pc_data;
                ps_certSubj->strData.cwt_len = ps_derdCtx->s_octVal.cwt_len;
            }

            if (ps_derdCtx->c_EOS == FALSE)
            {
                e_res = E_SSL_CERT_MORE_ELEMENTS_AVAILABLE;
            }
        }
        else
        {
            e_res = E_SSL_CERT_ERR_NO_OBJECT;
        }
    }
    else
    {
        e_res = E_SSL_CERT_ERR_STRUCT_FAIL;
    }

    return (e_res);
} /* sslCert_decodeSubjGetNext */

/****************************************************************************
 * Free all dynamic allocatet Memory of a s_sslKeyCertInfo_t * structure.
 ****************************************************************************/
/*============================================================================*/
/*  sslCert_delInfo                                                           */
/*============================================================================*/
void sslCert_delInfo(s_sslKeyCertInfo_t * ps_certInfo)
{
    assert(ps_certInfo != NULL);

} /* sslCert_delInfo */

/*============================================================================*/
/*  ssl_verifyCertSign                                                        */
/*============================================================================*/
/*e_sslCertErr_t ssl_verifyCertSign(s_sslKeyCertInfo_t *ps_certInfo,
        gci_rsaPubKey_t *ps_caPubKey)
*/
e_sslCertErr_t ssl_verifyCertSign(s_sslKeyCertInfo_t *ps_certInfo,
        GciKeyId_t *ps_caPubKey)
{
    int32_t hashAlgo;
    int32_t l_verifyRes;
    uint8_t ac_buf[GCI_MAX_HASHSIZE_BYTES];
    uint32_t ul_bufLen = sizeof(ac_buf);
    e_sslCertErr_t e_ret = E_SSL_CERT_OK;

    GciResult_t err;
    GciCtxId_t hashCtx;
    GciCtxId_t signCtx;

    GciSignConfig_t rsaConf;





    assert(ps_certInfo != NULL);
    assert(ps_certInfo->s_octTbsCert.pc_data != NULL);
    assert(ps_certInfo->s_octTbsCert.cwt_len > 0);
    assert(ps_certInfo->s_sign.pc_bitStr != NULL);
    assert(ps_certInfo->s_sign.cwt_len > 0);
    assert(ps_caPubKey != NULL);

    //OLD-CW: l_hashAlgo = cw_oidIdent2HashIDX(ps_certInfo->l_sigAlgOId);
    switch(ps_certInfo->l_sigAlgOId)
    {
    case SSL_OID_MD5_WITH_RSA_ENC:
    	hashAlgo = GCI_HASH_MD5;
    	break;

    case SSL_OID_SHA1_WITH_RSA_ENC:
    	hashAlgo = GCI_HASH_SHA1;
		break;

    case SSL_OID_SHA256_WITH_RSA_ENC:
    	hashAlgo = GCI_HASH_SHA256;
    	break;

    case SSL_OID_SHA384_WITH_RSA_ENC:
    	hashAlgo = GCI_HASH_SHA384;
    	break;

    case SSL_OID_SHA512_WITH_RSA_ENC:
    	hashAlgo = GCI_HASH_SHA512;
		break;

    default:
    	e_ret = E_SSL_CERT_ERR_INVALID_HASH;
    	break;

    }


    /*OLD-CW: if (cw_hash_memory(l_hashAlgo, ps_certInfo->s_octTbsCert.pc_data,
            ps_certInfo->s_octTbsCert.cwt_len, ac_buf,
            (size_t *) &ul_bufLen) != CW_OK)
    {
        e_ret = E_SSL_CERT_ERR_INVALID_HASH;
    }
*/

    err = gci_hash_new_ctx(hashAlgo, &hashCtx);
    if(err != GCI_OK)
    {
    	//TODO return error state
    }

    err = gci_hash_update(hashCtx, ps_certInfo->s_octTbsCert.pc_data, ps_certInfo->s_octTbsCert.cwt_len);
    if(err != GCI_OK)
    {
    	//TODO return error state
    }

    err = gci_hash_finish(hashCtx, ac_buf,(size_t *) &ul_bufLen);

    if(err != GCI_OK)
    {
    	e_ret = E_SSL_CERT_ERR_INVALID_HASH;
    }


    rsaConf.algo = GCI_SIGN_RSA;
    rsaConf.hash = hashAlgo;
    rsaConf.config.rsa.padding = GCI_PADDING_PKCS1;

    err = gci_sign_verify_new_ctx(&rsaConf, &ps_caPubKey, &signCtx);
    if(err != GCI_OK)
    {
    	//TODO return error state
    }

    err = gci_sign_update(signCtx, ac_buf, ul_bufLen);
    if(err != GCI_OK)
    {
    	//TODO return error state
    }

    err = gci_sign_verify_finish(signCtx, ps_certInfo->s_sign.pc_bitStr, ps_certInfo->s_sign.cwt_len);



    /*OLD-CW: if ((e_ret == E_SSL_CERT_OK)
            && (cw_rsa_hash_verify_ltc(ps_certInfo->s_sign.pc_bitStr,
                    ps_certInfo->s_sign.cwt_len, ac_buf, ul_bufLen, l_hashAlgo,
                    &l_verifyRes, ps_caPubKey) != CW_OK))

    {
    	 e_ret = E_SSL_CERT_ERR_PROCESS_FAILED;
    }

    if (l_verifyRes == 0)
    {
    	 e_ret = E_SSL_CERT_ERR_VERIFICATION_FAILED;
    }

    */
    if(err != GCI_OK)
    {
    	e_ret = E_SSL_CERT_ERR_PROCESS_FAILED;
    }

    if((e_ret != E_SSL_CERT_OK))
    {
    	e_ret = E_SSL_CERT_ERR_VERIFICATION_FAILED;
    }



    return (e_ret);
} /* ssl_verifyCertSign */

/*============================================================================*/
/*  sslCert_prepPubKey                                                        */
/*============================================================================*/
/*e_derdRet_t sslCert_prepPubKey(s_pubKey_t       *ps_pubKeyInfo,
                               s_sslOctetStr_t  *ps_pubKeyStr)
*/
e_derdRet_t sslCert_prepPubKey(GciKey_t       *ps_pubKeyInfo,
                               s_sslOctetStr_t  *ps_pubKeyStr)
{
    s_derdCtx_t s_derdCtx;
    e_derdRet_t e_res = E_SSL_DER_OK;

    assert(ps_pubKeyInfo != NULL);
    assert(ps_pubKeyStr != NULL);

    //OLD-CW: ps_pubKeyInfo->iAlgorithm = SSL_OID_UNDEF;

    if (ps_pubKeyStr->pc_data == NULL)
    {
        e_res = E_SSL_DER_ERR_NO_PUBKEYINFO;
    }
    else
    {
        sslDerd_initDecCtx(&s_derdCtx, ps_pubKeyStr);
        e_res = loc_getRsaPubKeyInfo(&s_derdCtx, ps_pubKeyInfo);
    }

    return (e_res);
} /* sslCert_prepPubKey */

/*============================================================================*/
/*  sslCert_prepPubKey                                                        */
/*============================================================================*/
//OLD-CW: void sslCert_delPubKey(s_pubKey_t * ps_pubKeyInfo)
void sslCert_delPubKey(GciKeyId_t * ps_pubKeyInfo)
{
    assert(ps_pubKeyInfo != NULL);

    //cw_bn_free(ps_pubKeyInfo->pE);
    //cw_bn_free(ps_pubKeyInfo->pM);
}

/* *************************************************************************** */

