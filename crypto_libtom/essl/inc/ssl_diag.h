/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: wssl_diag.c                                                 */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*! \file
 *   This module implements functions which print diagnostics or debug
 *   messages.                                                               */
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
/*  MODIFICATION HISTORY:                                                    */
/*                                                                           */
/*  Date        Person        Change                                         */
/*  ====        ======        ======                                         */
/*  28.03.03     WAM           Initial version                               */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*                                                                           */
/*****************************************************************************/


#ifndef    FILE_SSL_DIAG_H
  #define    FILE_SSL_DIAG_H

#ifdef __cplusplus
extern "C" {
#endif /* begin C prototype in C++ */

#include "ssl.h"
#include "ssl_der.h"

/*** Defines ****************************************************************/
#ifndef DBG_SSL_MAX_DEBUG_STRING_LEN
/*! Size of the internal buffer that is used in sslDiag_printGenericString */
#define DBG_SSL_MAX_DEBUG_STRING_LEN 64
#endif


/* Several Debug Levels */
#define DBG_ALWAYS     0xFFFFFFFF
#define DBG_NEVER      0x00000000
#define DBG_LOW        0x000000FF
#define DBG_MEDIUM     0x0000FF00
#define DBG_HIGH       0x00FF0000
#define DBG_APPL	   0xF0000000


/* Set the level of verbosity */
#define VERBOSE      DBG_NEVER

char* sslDiag_getAssembly(uint8_t assem);
char* sslDiag_getSMState(e_sslSmStatus_t state);
char* sslDiag_getCipherSuite(e_sslCipSpec_t cs);
char* sslDiag_getError(s_sslCtx_t* ctx);
char* sslDiag_getCertHandErr(int err);
char* sslDiag_getCertError(int err);
char* sslDiag_getAlert(e_sslAlertType_t alert);
char* sslDiag_getVersion(e_sslVer_t v);
char* sslDiag_getSigAlg(int id);
char* sslDiag_getExtension(e_tlsExt_t ext);
char* sslDiag_getHashAlg (uint8_t hash);
char* sslDiag_getSignAlg (uint8_t sign);
void sslDiag_printHex(uint8_t *pcData, uint32_t iDataLen);
void sslDiag_printInternals(s_sslGut_t* internal, int details);
//OLD-CW: void sslDiag_printGenericString(s_sslGenStr_t * p_str, rpcw_str_t p_name); const char*
void sslDiag_printGenericString(s_sslGenStr_t * p_str, const char* p_name);
void sslDiag_printSessHsElem(s_sslHsElem_t* elmt, int details);
void sslDiag_printSessKeys(s_sslSecParams_t* keys, int details);
void sslDiag_printSsl(s_sslCtx_t* ctx, int details);
/*** Prototypes *************************************************************/

/****************************************************************************/
/* sslDiag_printMsg()                                                           */
/****************************************************************************/
/*! \brief Printout a message for debugging.
 *
 *  This function prints a textual description given by \<descriptor\>.
 *  The function is only available if the code was compiled with VERBOSE mode
 *  switched on.
 *
 *  \param descriptor  : A textual description
 *  \return None
 */

void sslDiag_printMsg(uint8_t *descriptor);

/****************************************************************************/
/* sslDiag_printHexData()                                                           */
/****************************************************************************/
/*! \brief Printout a binary data field in a human readable form for debugging.
 *
 *  This function prints \<hexLen\> bytes of a binary data field. \<hexData\>
 *  is a pointer to this data and \<descriptor\> is a pointer to a textual
 *  discription of the data which is printed in front of the binary data field.
 *  The function is only available if the code was compiled with VERBOSE mode
 *  switched on.
 *
 *  \param descriptor  : A textual discription of the data
 *  \param pcData      : Pointer to the data to be printed
 *  \param iDataLen    : Length of the data (in bytes) to be printed
 *  \return Nothing
 */

//OLD-CW: void sslDiag_printHexData(rpcw_str_t descriptor, uint8_t *pcData, uint32_t iDataLen); const char*
void sslDiag_printHexData(const char* descriptor, uint8_t *pcData, uint32_t iDataLen);



/****************************************************************************/
/* showDigestStates()                                                     */
/****************************************************************************/
/*! \brief Print the internal state of the message digest algorithms.
 *
 *  The function is only available if the code was compiled with VERBOSE mode
 *  switched on, and is realised as an macro.
 *
 *  \param pSHA1_Ctx  : Pointer to the SHA1 context who's state has to be printed
 *  \param pMD5_Ctx   : Pointer to the MD5 context who's state has to be printed
 *  \return Nothing
 */

//OLD-CW: void sslDiag_printDigestStates(gci_sha1Ctx_t *pSHA1_Ctx, gci_md5Ctx_t *pMD5_Ctx);
void sslDiag_printDigestStates(GciCtxId_t *pSHA1_Ctx, GciCtxId_t *pMD5_Ctx);


/****************************************************************************/
/* DbgPrintDigestStates()                                                     */
/****************************************************************************/
/*! \brief Print the internal state of the message digest algorithms.
 *
 *  The function is only available if the code was compiled with VERBOSE mode
 *  switched on.
 *
 *  \param level      : VERBOSE level to activate the printout
 *  \param pSHA1_Ctx  : Pointer to the SHA1 context who's state has to be printed
 *  \param pMD5_Ctx   : Pointer to the MD5 context who's state has to be printed
 *  \return Nothing
 */


#if VERBOSE
#define DbgPrintDigestStates(level,sha1,md5)  if((level)&VERBOSE)sslDiag_printDigestStates((sha1),(md5));

#else

#define DbgPrintDigestStates(level,sha1,md5)
#endif



/*** Global Variables *******************************************************/




/* Your stuff ends here */
#ifdef __cplusplus
} /* extern "C" */
#endif /* end C prototype in C++ */


#endif /* file already included */
