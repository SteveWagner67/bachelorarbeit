/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_time.c                                                 */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*! \file
 *  This module implements functions for handling time and date.             */
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


#ifndef    FILE_SSL_TIME_H
  #define    FILE_SSL_TIME_H

#ifdef __cplusplus
extern "C" {
#endif /* begin C prototype in C++ */



/*** Defines ****************************************************************/


/*** Prototypes *************************************************************/

/****************************************************************************/
/* unixTime()                                                               */
/****************************************************************************/
/*! \brief Converts a time-/date string to __linux-like time.
 *
 *  This function calculates the elapsed seconds between 1.1.1970, 00:00:00h
 *  and the specified time \<aucTimeString\>. The time must be in the following
 *  format: YYYYMMDDhhmmss. The input value must be NULL terminated. (Frage an
 *  Thomas: warum?)
 *
 *  \param aucTimeString
 *  \return Number of seconds
 */

uint32_t unixTime(uint8_t *aucTimeString);



/*** Global Variables *******************************************************/




/* Your stuff ends here */
#ifdef __cplusplus
} /* extern "C" */
#endif /* end C prototype in C++ */


#endif /* file already included */
