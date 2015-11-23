/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: wSSL_record.h                                               */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*! \file
 *   This module implements the support functions for the record level
 *   interface (see section 2.2 in User Manual 0.96).                        */
/*                                                                           */
/*  CAUTIONS:                                                                */
/*   Non                                                                     */
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
/*  21.03.03     WAM           Fully revised for release 1                   */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*                                                                           */
/*****************************************************************************/


#ifndef    FILE_SSL_RECORD_H
  #define    FILE_SSL_RECORD_H

#ifdef __cplusplus
extern "C" {
#endif /* begin C prototype in C++ */


/*** Defines ****************************************************************/



/*** Prototypes *************************************************************/

/*============================================================================*/
/*!
    \brief  Check if the version is valid

        this function checks the received version for its minimal and maximal
        constraints that are given by the SSL general context

    \param ps_sslCtx  pointer to current SSL connection context
    \param e_version received version

    \return 0  all went fine
    \return 1  received version is not supported since it is a too late one
    \return -1 received version is not supported because it's a too early one

*/
/*============================================================================*/
int sslRec_fetchCorrectVersion(s_sslCtx_t* ps_sslCtx, e_sslVer_t e_version);

/*============================================================================*/
/*!

   \brief     Check the version of the received record and calculate the record size

   \param     ps_sslCtx          Pointer to the SSL context that should be worked with
   \param     pi_isSSLv2        Pointer to an integer that will contain an indication
                                if the record is of type SSL 2.0. This pointer can be NULL.

   \return    0...16384         The current length of the record in the buffer
   \return    -1                The version did not fit
                                or a SSL 2.0 Record, that is not a Client Hello, has been received
*/
/*============================================================================*/
int sslRec_checkVerCompLen(s_sslCtx_t* ps_sslCtx, int* pi_isSSLv2);

/****************************************************************************/
/* sslRec_getLen                                                        */
/****************************************************************************/
/*! \brief
 * Returns the length of the record provided as argument.
 *
 * The length is calculated from the record header structure including a version check.
 * At least 5 octets are needed. This function is used to provide an entire
 * record to the handling functions.
 *
 * \param *pRecord    : Pointer to record octet string
 * \param uiRecordLen : Length of the record octet string
 *
 * \return
 * 7 .. 16384 : Length of the entire record including the header\n
 * 0          : Failure: Record is invalid or input too short
 */

int  sslRec_getLen(s_sslCtx_t* ps_sslCtx);

int sslRec_getBytesToRead(s_sslCtx_t* ps_sslCtx);

/*** Global Variables *******************************************************/




/* Your stuff ends here */
#ifdef __cplusplus
} /* extern "C" */
#endif /* end C prototype in C++ */


#endif /* file already included */
