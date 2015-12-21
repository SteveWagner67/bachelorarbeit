/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_conf.h                                                 */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*! \file
 *     Main header file of the Embetter SSL implementation.
 *     Everything which needs to be defined and has no other header file yet
 *     is defined temporarily in this file.                                  */
/*                                                                           */
/*  CAUTIONS:                                                                */
/*     Non                                                                   */
/*                                                                           */
/*  LANGUAGE:        ANSI C                 COMPILER:                        */
/*  TARGET SYSTEM:                                                           */
/*                                                                           */
/*****************************************************************************/
/*                                                                           */
/*  MODIFICATION HISTORY:                                                    */
/*                                                                           */
/*  Date        Person        Change                                         */
/*  ====        ======        ======                                         */
/*  06.02-01.03  T. Gillen     Initial version                               */
/*  07.03.03     WAM           Clean up before releasing                     */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*****************************************************************************/

#ifndef    _SSL_CONF_H
#define    _SSL_CONF_H

#ifdef __cplusplus
extern "C"
{
#endif /* begin C prototype in C++ */

/*** Defines ****************************************************************/

/*** Prototypes *************************************************************/

/****************************************************************************/
/* sslConf_seedRand                                                          */
/****************************************************************************/
/*! \brief Customisable function (C-code) which in this case calls
 * CL_RndSetPseudoPool.
 *
 * Acts as an interface between the SSL_serverSM or the SSL_clientSM
 * functions and the lower level asymmetric routines provided by the crypto
 * library.
 *
 * The function allows to use any random generator at discretion.
 *
 * \param destination :
 * \param uiBytes     :
 *
 * \return
 * \sa
 */
/*! PG: Beschreibung anpassen und updaten! */
void sslConf_seedRand(uint8_t *pc_dest, size_t cwt_bytes);

/****************************************************************************/
/* sslConf_rand                                                           */
/****************************************************************************/
/*! \brief Customisable function (C-code) which in this case calls
 * CL_RndGetPseudoRandom.
 *
 * This function allows to use any random generator at discretion.
 *
 * \param destination :
 * \param uiBytes     :
 *
 * \return
 * \sa
 */
/*! PG: Beschreibung updaten! */
void sslConf_rand(uint8_t *destination, size_t uiBytes);

/***************************************************************************
 * Parameters
 * ps_listHead   	Pointer to the start of the list containing the
 * 					certificate chain
 * ps_listTail		Pointer to the end of the list containing the
 * 					certificate chain
 * pc_data      	Pointer to octetstring to hold the result
 * pcwt_dataLen     Pointer to variable holding the length of data
 *             input: maximum length of the data octetstring
 *             output: size of the octetstring
 *
 *
 * Returns
 * E_SSL_OK        Success
 * E_SSL_LEN       Data to long for destination area
 * E_SSL_ERROR     General failure
 *
 *
 * Remark:
 * This function is intended to be modified by the user. This function is
 * called by the SSL_serverSM function to retrieve the server certificate
 * chain, which must be send to the client. Depending on the system resources
 * the chain could be constructed on the fly (using the server certificate
 * chain building functions) or a precomputed chain hold in memory could be
 * copied to the indicated destination.
 *
 **************************************************************************/
e_sslResult_t sslConf_getCertChain(s_sslCertList_t *ps_listHead,
        s_sslCertList_t *ps_listTail, uint8_t *pc_data, size_t *pcwt_dataLen);

/******************************************************************************/
/*! \brief Customisable function (C-code).
 *
 * Provides a ready-to-use certificate request list in the provided octet
 * string.
 *
 * This function is called from inside the SSL_server function and could
 * be adapted by the user. Depending of the system needs, the information
 * can be precalculated or calculated on the fly.
 *
 * \param ps_listHead  : Pointer to head of the CA certificate list
 * \param pc_data      : Pointer to octet string to hold the result
 * \param pcwt_dataLen : Pointer to variable holding the length of data\n
 *                      On calling: maximum length of the data octet string\n
 *                      On return: size of the octet string
 *
 * \return E_SSL_OK    : Success
 *
 * \sa sslCert_initReqList, sslCert_addToReqList
 */
/******************************************************************************/
/*! PG: Parameterbeschreibung und Prototyp kontrollieren und erg�nzen! */
e_sslResult_t sslConf_getCertReqList(s_sslCertList_t *ps_listHead,
        uint8_t *pc_data, size_t *pcwt_dataLen);

/*============================================================================*/
/*!
 \brief  Compare the received CertificateRequest message with a list of CA certificates

 banana banana

 \param ps_caCertList 	Pointer to the list of CA certificates to compare
 \param pc_certReqMsg	The received CertificateRequest message
 \param cwt_msgLen		Length of the received CertificateRequest message

 \return A pointer to the first certificate in the list \ref p_caCertList
 that matches the first one out of the received CertificateRequest message
 \return NULL when there was no certificate in the list \ref p_caCertList
 that matched the proposed ones in the received CertificateRequest message

 */
/*============================================================================*/
s_sslCertList_t * sslConf_cmpCertReqList(s_sslCtx_t* ps_sslCtx,
		s_sslCertList_t *ps_caCertList,
        uint8_t *pc_certReqMsg, size_t cwt_msgLen);

/*! \brief Customisable function (C-code).
 *
 * An approved client certificate is passed to the function, which can extract
 * and process any useful information. The result is an authentication
 * identifier "hooked" to a certain certificate. This identifier is passed to
 * the connection context and can be read at any time by the application.
 *
 * \param ps_sslCtx      : Pointer to the connection context
 * \param ps_cliCertInfo : Pointer to an initialised certificate structure
 *
 * \return
 * FALSE : Certificate refused\n
 * TRUE  : Certificate accepted
 *
 * \sa ssl_getCliAuthID
 */

uint8_t sslConf_certHook(s_sslCtx_t *ps_sslCtx, s_sslKeyCertInfo_t *ps_cliCertInfo);

/*! \brief Customisable function (C-code).
 *
 * Acts as an interface between the SSL_serverSM or the SSL_clientSM
 * functions and the lower level asymmetric routines provided by the crypto
 * library.
 *
 * \param pCtx            : The connection context to be used with the new
 *                          SSL connection
 * \param e_nextAction    : The operation to be performed
 * \param pInputData      : Pointer to the input data octet string
 * \param uiInputDataLen  : Length of InputData in octets
 * \param pOutputData     : Pointer to the output data octet string
 * \param uiOutputDataLen : Length of OutputData in octets\n
 *                          On calling: maximum length\n
 *                          On return: length of outputData in octetx
 *
 * \return
 * E_PENDACT_GEN_WAIT_EVENT : Action will be handled in an other thread\n
 * E_PENDACT_SRV_PKCS1_DECRYPT   : Decrypted result available\n
 * E_PENDACT_SRV_PKCS1_VERIFY    : Signature verify result available\n
 * E_PENDACT_SRV_CERTVERIFY     : Certificate verification result available\n
 * E_PENDACT_SRV_CLICERTCHAIN  : Client certificate chain examined
 *
 * \remarks:
 * This function is intended to be modified by the user. In case of a
 * successful operation, the result is coded in the output data octetstring.
 *
 * \sa cw_rsa_encrypt, cw_pkcs1_v15_decrypt, ssl_verifyHash,
 *          cw_rsa_sign_decode
 */
e_sslPendAct_t sslConf_asymCryptoDisp(s_sslCtx_t * pCtx, int e_nextAction,
        uint8_t *pInputData, size_t uiInputDataLen, uint8_t *pOutputData,
        size_t *uiOutputDataLen);

/*** Global Variables *******************************************************/

/* Your stuff ends here */
#ifdef __cplusplus
} /* extern "C" */
#endif /* end C prototype in C++ */

#endif /* file already included */
