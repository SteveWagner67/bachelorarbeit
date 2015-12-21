/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_target.c                                                 */
/*                                                                           */
/*  FUNCTIONS:                                                               */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*   This module implements the target (HW, RTOS, etc) specific functions    */
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
/*  18.04.03    T. Gillen     Initial version                               */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                       */
/*                                                                           */
/*****************************************************************************/

#include "crypto_wrap.h"
#include "ssl.h"
#include "ssl_target.h"

/*** Defines ****************************************************************/

/*** Global Variables *******************************************************/

/*** Local Variables ********************************************************/

/*** Forward declarations ***************************************************/

/*** Local Functions ********************************************************/
unsigned int receivedSize(int socket);


/*** Global Functions *******************************************************/

/***************************************************************************
 * fp_getCurTime
 *
 * returns the number of seconds since 1st Jan 1970
 * This time should be get from a realtime clock
 **************************************************************************/
#ifdef BECK_IPC
#include <dos.h>

uint32_t fp_getCurTime()
{

    uint32_t h, min, sec;
    union REGS inregs;
    union REGS outregs;

    inregs.h.ah = 0x2C;
    int86(0x21,&inregs,&outregs);

    h = outregs.h.ch;
    min = outregs.h.cl;
    sec = outregs.h.dh;
    sec += min*60;
    sec += h*3600;

    if ( sec > 1000000000 )
    return ( sec );
    else
    return ( sec + 1050000000 );

}

#endif    /* Beck IPC */

#ifdef _WIN32
#include <time.h>
#include <windows.h>
#include <winsock2.h>

uint32_t fp_getCurTime()
{

    time_t ltime;

    time(&ltime);

    return(ltime);
}

int sslTarget_read(int socket, void *buf, unsigned int count)
{
    int ret;

    ret = recv(socket, buf, count, 0);
    if(ret < 0)
    {
        ret = WSAGetLastError();
        switch(ret)
        {
            case WSAENETDOWN:
            case WSAECONNRESET:
            case WSAENETRESET:
            case WSAESHUTDOWN:
            ret = E_SSL_SOCKET_CLOSED;
            break;
            case WSAEWOULDBLOCK:
            ret = E_SSL_SOCKET_AGAIN;
            break;
            default:
            ret = E_SSL_SOCKET_ERROR;
        }
    }
    else if(ret == 0)
    ret = E_SSL_SOCKET_CLOSED;

    return ret;
}

int sslTarget_write(int socket, void *buf, unsigned int count)
{
    int ret;

    ret = send(socket, buf, count, 0);
    if(ret == SOCKET_ERROR)
    {
        ret = WSAGetLastError();
        switch(ret)
        {
            case WSAENETDOWN:
            case WSAECONNRESET:
            case WSAENETRESET:
            case WSAESHUTDOWN:
            ret = E_SSL_SOCKET_CLOSED;
            break;
            case WSAEWOULDBLOCK:
            ret = E_SSL_SOCKET_AGAIN;
            break;
            default:
            ret = E_SSL_SOCKET_ERROR;
        }
    }

    return ret;
}
#endif

#ifdef __linux__
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

uint32_t fp_getCurTime()
{
    struct timeval s_time;

    gettimeofday(&s_time, NULL);

    return (s_time.tv_sec);
}

int sslTarget_read(int socket, void *buf, unsigned int count)
{
    int ret;
    if ((ret = (recv(socket, buf, count, 0))) < 0)
    {
        switch (errno)
        {
        case ENETDOWN:
        case ECONNRESET:
        case ENETRESET:
        case ESHUTDOWN:
            ret = E_SSL_SOCKET_CLOSED;
            break;
        case EWOULDBLOCK:
            ret = E_SSL_SOCKET_AGAIN;
            break;
        default:
            perror("Failed to read");
            ret = E_SSL_SOCKET_ERROR;
            break;
        }
    }
    else if (ret == 0)
        ret = E_SSL_SOCKET_CLOSED;

    return ret;
}/* sslTarget_read */

int sslTarget_write(int socket, void *buf, unsigned int count)
{
    int ret;

    if ((ret = send(socket, buf, count, 0)) < 0)
    {
        switch (errno)
        {
        case ENETDOWN:
        case ECONNRESET:
        case ENETRESET:
        case ESHUTDOWN:
            ret = E_SSL_SOCKET_CLOSED;
            break;
        case EWOULDBLOCK:
            ret = E_SSL_SOCKET_AGAIN;
            break;
        default:
            perror("Failed to write");
            ret = E_SSL_SOCKET_ERROR;
            break;
        }
    }

    return ret;
} /* sslTarget_write */
#endif /* __linux */

#ifdef __WIZNET__
#include <sys/time.h>
#include <errno.h>
#include "w5100.h"


uint32_t fp_getCurTime()
{
	return HAL_GetTick();
   // return (0);
}

int sslTarget_read(int socket, void *buf, unsigned int count)
{
  int ret = E_SSL_SOCKET_ERROR;
  uint16_t count_min;

  if (IINCHIP_READ(Sn_SR(socket)) == SOCK_ESTABLISHED) {
    count_min = getSn_RX_RSR(socket);
    if (count_min < count)
    {
      count = (unsigned int)count_min;
    }

    ret = recv(socket, buf, count);
    if (ret <= 0) {
      ret = E_SSL_SOCKET_AGAIN;
    }
  } else {
    ret = E_SSL_SOCKET_CLOSED;
  }

  return ret;

}/* sslTarget_read */


int sslTarget_write(int socket, void *buf, unsigned int count)
{
    int ret;

    if ((ret = send(socket, buf, count, 0)) < 0)
    {
        switch (errno)
        {
        case ENETDOWN:
        case ECONNRESET:
        case ENETRESET:
        case ESHUTDOWN:
            ret = E_SSL_SOCKET_CLOSED;
            break;
        case EWOULDBLOCK:
            ret = E_SSL_SOCKET_AGAIN;
            break;
        default:
            perror("Failed to write");
            ret = E_SSL_SOCKET_ERROR;
            break;
        }
    }

    return ret;
} /* sslTarget_write */
#endif /* __WIZNET__ */

#ifdef NET_OS
#include <tx_api.h>

uint32_t fp_getCurTime()
{
    uint32_t ltime;

    ltime = tx_get_time();

    if ( ltime > 1000000000L )
    return ( ltime );
    else
    return ( ltime + 1050000000L );
}

#endif

#ifdef EMBETTER
#include "socket.h"

uint32_t fp_getCurTime(void)
{
    uint32_t time = 42;
    /*
     * the emBetter TCP/IP Stack provides per default
     * no function where the time can be read from, so we
     * return a dummy value
     */
    return(time);
}

uint32_t getCurrentIPaddr(int socket)
{
    uint32_t ip;
    soc_get_info(SOC_INF_SOC_ADDR, socket, &ip);
    return ip;
}

int sslTarget_read(int socket, void *buf, unsigned int count)
{
    int retVal;
    uint16_t readRet;

    /*
     * read from the specified socket
     */
    readRet = soc_read((uint8_t)socket, (uint8_t*)buf, (uint16_t)count);

    /*
     * check the returnvalue..
     * if it's bigger than 0 it has been something read
     * if it's equal to zero, there was either an error or no data available
     */
    if(readRet > 0)
    {
        retVal = readRet;
    }
    else
    {
        if(soc_errno[socket] != ERR_SOC_OK)
        {
            if(soc_errno[socket] == ERR_SOC_AGAIN)
            {
                /*
                 * It was no data available
                 */
                retVal = E_SSL_SOCKET_AGAIN;
            }
            else if(soc_errno[socket] < ERR_SOC_ECL_SEVERE)
            {
                /*
                 * There was a severe error
                 */
                retVal = E_SSL_SOCKET_ERROR;
            }
            else if((soc_errno[socket] == ERR_SOC_CLOSING)
                    || (soc_errno[socket] == ERR_SOC_CONNRESET)
                    || (soc_errno[socket] == ERR_SOC_NOTCONN))
            {
                /*
                 * The socket is closed or closing atm, could be error but could be a shutdown as well
                 */
                retVal = E_SSL_SOCKET_CLOSED;
            }
            else
            {
                retVal = E_SSL_SOCKET_AGAIN;
            }
        } /* if(soc_errno != ERR_SOC_OK) */
        else
        {
            retVal = E_SSL_SOCKET_AGAIN;
        }
    }/* if(readRet == 0)  */

    return retVal;
} /* sslTarget_read() */

int sslTarget_write(int socket, void *buf, unsigned int count)
{
    int retVal;
    uint16_t writeRet;

    retVal = E_SSL_SOCKET_AGAIN;

    writeRet = soc_write(socket, buf, count);

    if(writeRet > 0)
    {
        retVal = writeRet;
    }
    else
    {
        if(soc_errno[socket] != ERR_SOC_OK)
        {
            if(soc_errno[socket] == ERR_SOC_AGAIN)
            {
                retVal = E_SSL_SOCKET_AGAIN;
            }
            else if(soc_errno[socket] < ERR_SOC_ECL_SEVERE)
            {
                retVal = E_SSL_SOCKET_ERROR;
            }
            else if(soc_errno[socket] == ERR_SOC_NOBUFS)
            {
                retVal = E_SSL_SOCKET_AGAIN;
            }
            else if((soc_errno[socket] == ERR_SOC_CLOSING)
                    || (soc_errno[socket] == ERR_SOC_CONNRESET)
                    || (soc_errno[socket] == ERR_SOC_NOTCONN))
            {
                retVal = E_SSL_SOCKET_CLOSED;
            }
            else
            {
                retVal = E_SSL_SOCKET_AGAIN;
            }
        } /* if(soc_errno[socket] != ERR_SOC_OK) */
    } /* if(iBytesTransfered == 0) */

    return retVal;
} /* sslTarget_write() */
#endif

