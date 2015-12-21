/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_target.h                                                  */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*! \file
 *   This module implements the target specific functions
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
/*  18.04.03     TG           Initial version                               */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*                                                                           */
/*****************************************************************************/


#ifndef    FILE_SSL_TRG_H
  #define    FILE_SSL_TRG_H

#ifdef __cplusplus
extern "C" {
#endif /* begin C prototype in C++ */

/*============================================================================*/
/*
 * TARGET DEPENDANT HEADERS
 */
#if defined(EMBETTER)
	#include "socket.h"
	#define SSL_INVALID_SOCKET SOC_NOSOCK
#elif defined (_WIN32)
	#include <winsock2.h>
	#define SSL_INVALID_SOCKET INVALID_SOCKET
#elif defined(__linux__)
	#include <netinet/in.h>
	#define INVALID_SOCKET	-1
	#define SSL_INVALID_SOCKET INVALID_SOCKET
#elif defined(__WIZNET__)
	#define INVALID_SOCKET		-1
	#define SSL_INVALID_SOCKET 	INVALID_SOCKET
#endif /* TARGET DEPENDANT HEADERS  */
/*============================================================================*/

/*============================================================================*/
/*!
    \brief  Number of seconds since 01. Jan 1970 (unix like)

        This function returns the number of seconds since the 01. Jan 1970 00:00:00 h

    \return time

*/
/*============================================================================*/
uint32_t fp_getCurTime( void );

/*============================================================================*/
/*!
    \brief  Fetch the IP address assigned to a socket

        This function returns the local IP address that is used by the given TCP socket

    \param socket  the actual socketnumber

    \return IP address of the socket

*/
/*============================================================================*/
uint32_t getCurrentIPaddr(int socket);

/*============================================================================*/
/*!
    \brief  Read from a socket

        This function implements the reading from an emBetter socket

    \param socket  the actual socketnumber
    \param buf     pointer to the buffer where the data read should be saved
    \param count   length of data to read

    \return >0                 returned number is number of bytes successfully read
    \return E_SSL_SOCKET_AGAIN  no data read, call would block
    \return E_SSL_SOCKET_ERROR  operation was not successful, an error occured
    \return E_SSL_SOCKET_CLOSED operation was not successful, socket has been closed

*/
/*============================================================================*/
int sslTarget_read(int socket, void *buf, unsigned int count);

/*============================================================================*/
/*!
    \brief  Write to a socket

        This function implements the writing to an emBetter socket

    \param socket  the actual socketnumber
    \param buf     pointer to the buffer where the data to write is located
    \param count   length of data to write


    return >0                 returned number is number of bytes successfully written
    \return E_SSL_SOCKET_AGAIN  no data written, call would block
    \return E_SSL_SOCKET_ERROR  operation was not successful, an error occured
    \return E_SSL_SOCKET_CLOSED operation was not successful, socket has been closed

*/
/*============================================================================*/
int sslTarget_write(int socket, void *buf, unsigned int count);

/*** Global Variables *******************************************************/




/* Your stuff ends here */
#ifdef __cplusplus
} /* extern "C" */
#endif /* end C prototype in C++ */


#endif /* file already included */
