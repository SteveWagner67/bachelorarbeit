/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_certHelper.h                                                 */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*! \file
 *   This module implements the support functions for the handling of an
 *   entire certificate 										             */
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
/*  23.09.14     A. Yushev     Revised version, clean up                     */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*****************************************************************************/

#ifndef    __CERT_HELPER_H
#define    __CERT_HELPER_H

#ifdef __cplusplus
extern "C"
{
#endif /* begin C prototype in C++ */
#include "ssl.h"
#include "ssl_cert.h"

/*** Defines ****************************************************************/

/*** Prototypes *************************************************************/

/*============================================================================*/
/*!

 \brief     Initialise and verify a certificate

 This function is used to initialise and verify certificates

 The parameters p_cert, pCA_rootCert and p_CAlist_head define
 the behaviour of this function.

 When p_cert is equal to pCA_rootCert it is assumed, that the
 given certificate is a self-signed certificate.

 When pCA_rootCert is NULL and p_CAlist_head is NULL it will be
 assumed, that the root of this certificate is not known and the
 s_validity will not be verified.

 When pCA_rootCert is not NULL will the certificate be verified
 against the public key of pCA_rootCert.

 When p_CAlist_head is not NULL will the list be searched for an
 s_octIssuer of this certificate. If one is found will the certificate
 be verified against its public key, otherwise the function will
 fail.

 The two parameters pCA_rootCert and p_CAlist_head are mutually
 exclusive. When pCA_rootCert is not NULL, the list in
 p_CAlist_head is not considered.


 \param     ps_octStrCert        Pointer to an octet string where the certificate in raw binary format can be found
 \param     ps_cert              Pointer to an empty certificate structure
 \param     pcwt_rsaPubKey        Pointer to an initialised public key struct where the public key will be written to
 \param     pc_caSubjName         Pointer to a buffer where the subject of this cert can be stored
 \param     l_caSubjNameLen       Length of the buffer puc_CASubjectName
 \param     ps_caRootCert        Pointer to a CA certificate that can verify this cert
 \param     ps_caListHead        Head to the list where the root of this CA cert can be found

 \return \ref E_SSL_CERT_OK
 \return \ref E_SSL_CERT_BUFFER_NOT_SET
 \return \ref E_SSL_CERT_ERR_DECODING_FAILED
 \return \ref E_SSL_CERT_ERR_NO_CA
 \return \ref E_SSL_CERT_ERR_PATHLENCONSTRAINT
 \return \ref E_SSL_CERT_ERR_BASICCONSTRAINTS
 \return \ref E_SSL_CERT_ERR_NO_ROOT_AVAILABLE
 \return \ref E_SSL_CERT_ERR_PUBLIC_KEY
 \return \ref E_SSL_CERT_ERR_VERIF_FAILED
 \return \ref E_SSL_CERT_ERR_SMALL_BUFFER
 */
/*============================================================================*/
e_sslCertErr_t sslCert_init(s_sslOctetStr_t *ps_octStrCert,
                            s_sslCert_t *ps_cert,
                            gci_rsaPubKey_t *pcwt_rsaPubKey,
                            uint8_t *pc_caSubjName, uint32_t l_caSubjNameLen,
                            s_sslCert_t *ps_caRootCert,
                            s_sslCertList_t *ps_caListHead);

/*============================================================================*/
/*!

 \brief     Free a CA certificate structure

 This function frees all allocted memory of a CA certificate
 structure


 \param     ps_caCert  The CA certificate that should be free'd
 */
/*============================================================================*/
e_sslCertErr_t sslCert_free(s_sslCert_t * ps_caCert);

/*============================================================================*/
/*!

 \brief     Add a certificate to a list of CA certificates

 This function assigns the given parameter pCA_cert to the
 p_CAlist_cert and hangs the entry p_CAlist_cert in the list
 p_CAlist_head.

 The entry will always be entered at the top of the list.

 The return value of this function is always the head of the list.

 \sa SSL_cert_list_remove

 \param     ps_listHead     Pointer to the head of the list
 \param     ps_listElem     Pointer to the element that will be hanged in the list
 \param     ps_caCert       Pointer to the certificate that will be assigned to
 the element that enters the list
 \param     ps_cdbCert      Pointer to a cert_db element that will be assigned to
 the element that enters the list

 \return    s_sslCertList_t* Pointer to the head of the list. This will never be NULL
 */
/*============================================================================*/
s_sslCertList_t * sslCert_addToList(s_sslCertList_t *ps_listHead,
                                    s_sslCertList_t *ps_listElem,
                                    s_sslCert_t *ps_caCert,
                                    s_cdbCert_t *ps_cdbCert);

/*============================================================================*/
/*!

 \brief     Remove a certificate from a list of CA certificates

 This function removes the given parameter pCA_cert from the list
 p_CAlist_head.

 The assigned CA certificate will NOT cleaned! This must be done
 by calling SSL_cert_free()

 The return value of this function is always the head of the list.
 If the return value is NULL, the list is empty.

 \sa SSL_cert_list_add

 \param     ps_head     Pointer to the head of the list
 \param     ps_elem     Pointer to the element that will be hanged in the list

 \return    s_sslCertList_t *    Pointer to the head of the list.
 \return    NULL                  Pointer to the list is empty now
 */
/*============================================================================*/
s_sslCertList_t * sslCert_rmFromList(s_sslCertList_t *ps_head,
                                     s_sslCertList_t *ps_elem);

/*============================================================================*/
/*!

 \brief     Search a certificate in the list by its subject

 This function iterates through the list p_CAlist_head and
 returns the element where the subject of the assigned
 CA certificate equals the given reference poSubject


 \param     ps_caListHead    Pointer to the head of the list
 \param     ps_octSubj       Pointer to the reference OCTETSTRING that will be used
 to find the element in the list

 \return    s_sslCertList_t *     Pointer to the object where the subject
 is equal to the given one
 \return    NULL                  Nothing found in the list
 */
/*============================================================================*/
s_sslCertList_t * sslCert_getBySubject(s_sslCertList_t *ps_caListHead,
                                       s_sslOctetStr_t *ps_octSubj);

/*============================================================================*/
/*!

 \brief     Iterate through the list

 This function iterates through the list p_CAlist_head and
 returns always the next element


 \param     ps_listElem  Pointer to the current element of the list

 \return    ps_sslCertList_t     Pointer to the next element in the list
 \return    NULL                  No more elements in the list
 */
/*============================================================================*/
s_sslCertList_t * sslCert_getNext(s_sslCertList_t *ps_listElem);

/*============================================================================*/
/*!

 \brief     Extracts the subject of a given certificate


 \param     ps_entry   Pointer to a certificate list entry
 \param     pc_dest     Pointer to the memory location where the subject should be saved.
 \param     pcwt_space  [in]   Available size
 [out]  Size written
 When return value is not E_SSL_OK, this will be 0.

 \return    E_SSL_OK     Operation successful.
 \return    E_SSL_LEN    Memory area too small.
 \return    E_SSL_ERROR  Another error occurred.
 */
/*============================================================================*/
e_sslResult_t sslCert_getSubject(s_sslCertList_t *ps_entry, uint8_t *pc_dest,
                                 size_t *pcwt_space);

/*============================================================================*/
/*!

 \brief     Verify the certificate chain


 \param     ps_octInData    Pointer to an octet string containing one or more
 certificates in binary format, usually from a
 SSL/TLS Certificate Handshake message
 \param     pcwt_rsaPubKey   Pointer to a public key structure where the public
 key of the end-point certificate shall be saved.
 \param     ps_caListHead   The head to a list of CA certificates that can verify
 one of the certificates in the chain.

 \return    E_SSL_OK     Operation successful.
 \return    E_SSL_LEN    Memory area too small.
 \return    E_SSL_ERROR  Another error occurred.
 */
/*============================================================================*/
e_sslResult_t sslCert_verifyChain(s_sslOctetStr_t *ps_octInData,
                                  gci_rsaPubKey_t  *pcwt_rsaPubKey,
                                  s_sslCertList_t *ps_caListHead);

/* *************************************************************************/
/* Functions handling entire certificates                                  */
/* *************************************************************************/

/***************************************************************************/
/* sslCert_initChain                                                          */
/***************************************************************************/
/*! \brief Initialises an octet string to hold an entire certificate chain
 * for the SSL-server.
 *
 * \param pc_chain    : Pointer to octet string to hold the entire server
 *                   certificate chain
 * \param cwt_len : Pointer to variable holding the length of chain\n
 *                   On calling: maximum length of the chain octet string\n
 *                   On return: size of the octet string
 *
 * \return    E_SSL_OK    Operation successful.
 * \return    E_SSL_FAIL  Initialisation failed.
 *
 * \sa sslCert_addDataToChain, SSL_getCertificateChain
 */

e_sslResult_t sslCert_initChain(uint8_t * pc_chain, size_t cwt_len);

/***************************************************************************/
/* sslCert_getSpaceInChain                                                */
/***************************************************************************/
/*! \brief Calculates free space in the certificate chain.
 *
 * \param pc_data      : Pointer to certificate chain
 * \param ppc_freeData : Pointer to pointer to the first free space in the chain
 * \param pcwt_freeLen : Pointer to variable holding the length of free space
 * \param cwt_maxLen   : Length of chain
 *
 * \return E_SSL_OK   : Success
 * \sa sslCert_initChain, sslCert_addDataToChain
 */

e_sslResult_t sslCert_getSpaceInChain(uint8_t *pc_data, uint8_t **ppc_freeData,
                                      size_t *pcwt_freeLen, size_t cwt_maxLen);

/***************************************************************************/
/* sslCert_addDataToChain                                                     */
/***************************************************************************/
/*! \brief Adds a DER encoded X.509-certificate to an existing server
 * certification chain.
 *
 * All relevant length-fields are updated and a ready to use chain is provided.
 *
 * \param pc_chain    : Pointer to octet string to hold the entire server
 *                      certificate chain
 * \param pcwt_len    : Pointer to variable holding the length of chain\n
 *                      On calling: maximum length of the chain octet string\n
 *                      On return: size of the octet string
 * \param pc_data     : Pointer to a DER-encoded X.509 certificate
 * \param cwt_dataLen : Size of the certificate
 * \param cwt_maxLen  : Max. size of destination
 * \return
 * E_SSL_OK        : Operation successful\n
 * E_SSL_LEN       : Not enough space in the data octet string\n
 *
 * \sa SSL_initChain, SSL_getCertificateChain
 */

e_sslResult_t sslCert_addDataToChain(uint8_t *pc_chain, size_t *pcwt_len,
                                     uint8_t *pc_data, size_t cwt_dataLen,
                                     size_t cwt_maxLen);

/***************************************************************************/
/* sslCert_initReqList                                                    */
/***************************************************************************/
/*! \brief Initialises an octet string to hold an entire certificate request
 * field (ready-to-use).
 *
 * \param *pc_data      : Pointer to octet string to hold the result
 * \param *pcwt_dataLen : Pointer to variable holding the length of data\n
 *                      On calling: maximum length of the data octet string\n
 *                      On return: size of the octet string
 * \return
 * E_SSL_OK        : Success
 * E_SSL_ERROR     : Failure to initialise the data structure
 *
 * \sa sslCert_addToReqList, sslCert_getCertReqList
 */

e_sslResult_t sslCert_initReqList(uint8_t *pc_data, size_t *pcwt_dataLen);

/****************************************************************************/
/* sslCert_addToReqList                                                    */
/****************************************************************************/
/*! \brief  Adds the Subject-Field from the CA-Certificate to the request list.
 *
 * The length information in the list's header is updated accordingly.
 *
 * \param pc_data       : Pointer to octet string to hold the request
 * \param pcwt_dataLen  : Pointer to a variable holding the length of data\n
 *                        On calling: maximum length of the data octet string\n
 *                        On return: length of the octet string
 * \param pc_cert       : Pointer to a DER-encoded X.509 certificate
 * \param cwt_certLen   : Size of the certificate
 *
 * \return
 * E_SSL_OK    : Operation successful\n
 * E_SSL_ERR   : Not enough space in the data octet string\n
 *
 * \sa ssl_initCertReqList, ssl_getCertReqList
 */

e_sslResult_t sslCert_addToReqList(uint8_t *pc_data, size_t *pcwt_dataLen,
                                   uint8_t *pc_cert, size_t cwt_certLen);

/* *************************************************************************/
/* Certificate Support Functions                                           */
/* *************************************************************************/

/****************************************************************************/
/* sslCert_stripPem                                                            */
/****************************************************************************/
/*! \brief Strips the header and the trailer of a PEM encoded certificate
 * / private key and provides the data field.
 *
 * This function does not copy the data. It sets the data pointer to the start
 * of the base64-encoded data field and determines the length of the field.
 *
 * \param **ppc_base64Data    : Pointer to a pointer to the start of the base64
 *                            encoded data
 * \param *pcwt_base64DataLen : Pointer to a variable holding the size of the
 *                            base64 encoded data
 * \param *pc_pemData         : Pointer to the PEM-data
 * \param cwt_pemLen          : Size of the PEM-data
 *
 * \return
 * E_SSL_OK                 : Success. pBase64Data points to the start of base64 data\n
 * E_SSL_ERR                : Failure
 *
 * \sa SSL_base64Decode
 */

e_sslResult_t sslCert_stripPem(uint8_t **ppc_base64Data,
                               size_t *pcwt_base64DataLen,
                               uint8_t *pc_pemData, size_t cwt_pemLen);

/*!\fn    sslCert_decodeBase64
 * \brief Decodes the data part of a base64 encoded data field.
 *
 * The length of the decoded data is about 75% of the encoded (printable ASCII)
 * data length.\n
 * The removing of the PEM headers and trailers must be done separately.\n
 * Any non-base64 bytes are ignored.\n
 * Returns the actual number of bytes generated.
 *
 * Base-64 encoding represents binary data as printable ASCII characters.
 * Three 8-bit binary bytes are turned into four 6-bit values:
 *
 * BINARY DATA BYTES        [11111111]   [22222222]   [33333333]
 *
 * BASE64 ENCODED BYTES     [111111] [112222]  [222233] [333333]
 *
 * The 6-bit values are represented using the characters "A-Za-z0-9+/".
 *
 * \param *pc_binData      : Pointer to the base64 encoded data
 * \param cwt_binDataLen   : Size of the encoded data block
 * \param *rpc_base64Data  : Pointer to the destination for the decoded data
 * \param cwt_base64DataLen: Maximum size of the decoded data
 *
 * \return
 * 0     : Error occurred (No encoded data)\n
 * pos   : Length of the decoded data
 *
 * \sa sslCert_stripPem
 */
size_t sslCert_decodeBase64(uint8_t *pc_binData, size_t cwt_binDataLen,
                               const char *rpc_base64Data,
                               size_t cwt_base64DataLen);

/*!\fn    sslCert_extractX509Len
 * \brief Extracts the len field of an X509 structure and converts it to an
 * integer.
 */

uint8_t *sslCert_extractX509Len(uint8_t *pc_read, size_t *pcwt_elemLen);

/*!\fn    sslCert_extractX509Elem
 * \brief Extracts an element from a X509 like structure.
 *
 * \param *pc_read     : Pointer to the actual read position in the certificate/
 *                       private key
 * \param *ppcwt_bigNum: Pointer to a memory area to hold a pointer to a BigNum
 *                       structure in to a BigNum-variable
 *
 * \return A pointer to the first character following the element processed.
 */

uint8_t *sslCert_extractX509Elem(uint8_t *pc_read, gci_bigNum_t **ppcwt_bigNum);

/*** Global Variables *******************************************************/

/* Your stuff ends here */
#ifdef __cplusplus
} /* extern "C" */
#endif /* end C prototype in C++ */

#endif /* file already included */
