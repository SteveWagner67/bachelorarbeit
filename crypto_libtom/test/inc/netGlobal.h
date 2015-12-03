#ifndef NET_GLOBAL_H
#define NET_GLOBAL_H

#ifndef __DECL__NET_GLOBAL_H__
#define __DECL__NET_GLOBAL_H__  extern
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef WIN32
#include <sys/param.h>
#elif __linux
#include <endian.h>
#endif

/*============================================================================*/
/*! \file   netGlobal.h

    \author ??? by STZ-EDN, Loerrach, Germany, http://www.embetter.de

    \brief  This file contains general network settings

    \version $Version$
*/
/*============================================================================*/

/*==============================================================================
                           SYSTEM STRUCTURES AND OTHER TYPEDEFS
==============================================================================*/


/*==============================================================================
                                BASIC CONSTANTS
==============================================================================*/
#undef  FALSE
#undef  TRUE
#define FALSE                   0
#define TRUE                    1

/*==============================================================================
                     *********************************
                     ***     emBetter  settings    ***
                     *********************************

 In this section the user can modify specific options of the emBetter software
   suite. Options are grouped so that the most important or most likely to be
                           changed options are first.

For most options TRUE or FALSE is required. For some blocks of options only one
   option can be TRUE at a time, the rest has to remain FALSE (e.g. CPU type)

 ===============================================================================*/

                    /***************************************
                    *     Target hardware selection      *
                    ***************************************/

/* Use memcpy() from the standard library */
#define MEMCPY(a,b,c) 		            memcpy(a,b,c)
#undef EMBETTER_DMA

              /***************************************************
              *                 PHY selection                    *
              * The PHY selection should be done automatically   *
              * according to the selected target platform.       *
              * The target platform selection is taken out of    *
              * system.h or done by hand in the section above.   *
              ***************************************************/

                    /***************************************
                    *           Miscellaneous              *
                    ***************************************/

#define EMBETTER_LATEST_VERSION "$LatestVersion$"

/* Use checksum function in socket.c */
#define IN_CHECKSUM(a,b,c)            in_checksum (a, b, c)



                    /***************************************
                    *     General network settings         *
                    ***************************************/

/*!
 * Fixed IP address: used for the initialisation of the IP interface with
 * the static IP address. Note that a second IP interface exists with a
 * dynamically allocated IP address, if PROT_AUTOIP and/or PROT_DHCP is enabled.
 */
#define MYIP_LAN_1           192UL
#define MYIP_LAN_2           168UL
#define MYIP_LAN_3            40UL
#define MYIP_LAN_4             3UL

/*!
 * Maximum Ethernet frame length. Note, that Windows 7 requires at least 536 bytes long
 * TCP data. Therefore set it no lower than 590 bytes.
 */
#define SUBMASK_1            255UL
#define SUBMASK_2            255UL
#define SUBMASK_3            255UL
#define SUBMASK_4              0UL



                    /****************************************
                     *      Buffer sizes (very important)   *
                     *                                      *
                     * The following settings will affect   *
                     * the use of RAM for emBetter. Please  *
                     * specify the buffers according to the *
                     * estimated demands                    *
                     ***************************************/
/*!
     \brief  Number of buffers to store outgoing TCP segments

             The number of buffers to store outgoing TCP segments
             and incoming TCP or UDP data.
             The memory requirement depends on the length of
             one packet on interface level as well as of some
             control bytes on TCP level. The size of one buffer
             element can be displayed when compiling with the
             option DBG_EMB_INFO TRUE
*/
#define SOC_NUM_BUF                10


                    /****************************************
                     *          Socket settings             *
                     ***************************************/

/* The maximum number of sockets allowed */
#define SOC_NUM_SOCKS               10
#define SOC_MAXBUF_SOC_OUT          3
#define SOC_MAXBUF_SOC_IN           3


                    /****************************************
                     *     Terminal program settings        *
                     ***************************************/



                    /****************************************
                     *           Debug information          *
                     *                                      *
                     * Debug information are sent to a      *
                     * terminal. All protocols provide of   *
                     * debug output. Please select which    *
                     * protocol to debug.                   *
                     ***************************************/

#define LOGGER_LEVEL			3

/* Welcome screen with important emBetter settings */
#define DBG_SSL_PROTO_MODULE    TRUE

#define DBG_SOC_INFO          	TRUE

#define DBG_TIMEOUT				TRUE

#define DBG_SSL_CERT_MODULE		TRUE

#define DBG_CERT_DB_MODULE		TRUE

#define DBG_SSL_OSAL_CACHE		TRUE

#define DBG_SSL_CW_MODULE		TRUE

#define DBG_SSL_SOCKET			TRUE

#define DBG_SSL_SRVSOCKET		TRUE

#define DBG_SSL_CERTHANDLER		TRUE

#define DBG_SSL_CONF			TRUE

#define DBG_SSL_DERD			TRUE

#define DBG_SSL_DIAG			TRUE

#define DBG_SSL_OID				TRUE

#define DBG_SSL_RECORD			TRUE

#define DBG_SSL_KEY_MANAG		TRUE

#define DBG_DEMO_SSLCLI_MODULE  TRUE

#define DBG_DEMO_SSLSRV_MODULE  TRUE

/*==============================================================================
                   SYSTEM STRUCTURES AND OTHER TYPEDEFS
==============================================================================*/

#define TOMLIB_CRYPTO		TRUE
/*==============================================================================
                     MACRO DEFINITIONS (do not change)
==============================================================================*/
#ifdef __linux
    #if __BYTE_ORDER__ == __BIG_ENDIAN
        #define __USER_BIG_ENDIAN TRUE
    #elif __BYTE_ORDER__ == __LITTLE_ENDIAN
        #define __USER_LITTLE_ENDIAN TRUE
    #endif /* __BYTE_ORDER */
#elif _WIN32
    #if BYTE_ORDER == LITTLE_ENDIAN
        #define __USER_LITTLE_ENDIAN TRUE
    #elif BYTE_ORDER == BIG_ENDIAN
        #define __USER_BIG_ENDIAN TRUE
    #endif /* __BYTE_ORDER */
#elif __arm__
    #define __USER_LITTLE_ENDIAN TRUE
#endif /* __linux or WIN32 */
/* Prefix string for all debug output */
#define DBG_STRING "\r\n%s, %d: "


#define EBTTR_ASSERT_VOID_NDEBUG(expr) if (!(expr)) return

#define EBTTR_ASSERT_VOID_DEBUG(expr) \
  do { \
    if (!(expr)) \
    { \
     EBTTR_DBG_PRINTF(DBG_STRING "Error: Expression " #expr " is false", DBG_FILE_NAME, __LINE__); \
     return; \
    } \
  } while(0)

#define EBTTR_ASSERT_RET_NDEBUG(expr, r) if (!(expr)) return (r)

#define EBTTR_ASSERT_RET_DEBUG(expr, r) \
  do { \
    if (!(expr)) \
    { \
     EBTTR_DBG_PRINTF(DBG_STRING "Error: Expression " #expr " is false", DBG_FILE_NAME, __LINE__); \
     return (r); \
    } \
  } while(0)

#define LONG_IPV4_TO_DDDD(a) *((uint8_t*)&a + 0), *((uint8_t*)&a + 1), *((uint8_t*)&a + 2), *((uint8_t*)&a + 3)


/*==============================================================================
                    FUNCTION PROTOTYPES OF THE MAIN MODULE
==============================================================================*/


/*
 * The main() shall not be defined in embetter_main.c
 */
#define EMBETTER_NO_MAIN

/*============================================================================*/
#endif  /* NET_GLOBAL_H */

