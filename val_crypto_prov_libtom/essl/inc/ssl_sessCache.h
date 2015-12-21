/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_sessCache.h                                                */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*! \file
 *   This module implements the session cache database. The cache DB stores
 *   the security attributes of the sessions which are resumable (see
 *   section 2.6 in the User Manual 0.96).
 *
 *   The cache is organized as a LRU-Buffer (Least Recently Used). Every
 *   entry in the DB has an LRU-Counter value. Each DB query decrements the
 *   counter of every entry by one. A counter value of 0 indicates an unused
 *   entry. A cache hit sets the counter to the maximal possible value.
 *
 *
 *  CAUTIONS:\n
 *   As the session cache is a central resource, only one access at a time
 *   is allowed. Multiple access from independent threads leads to errors. A
 *   serialisation mechanism must be established, if more than one task has
 *   access to the session cache.\n
 *   The protection method depends on the system architecture.               */
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
/*  20.03.03     WAM           Initial version                               */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*****************************************************************************/

#ifndef    FILE_OSAL_CACHE_H
#define    FILE_OSAL_CACHE_H

#ifdef __cplusplus
extern "C"
{
#endif /* begin C prototype in C++ */

#include "ssl.h"

/*** Defines ****************************************************************/

typedef enum E_SSL_SESSCACHE_ERR_CODES
{
    E_SSL_SESSCACHE_OK = E_SSL_OK, E_SSL_SESSCACHE_FAIL = E_SSL_ERROR,

    E_SSL_SESSCACHE_HIT, E_SSL_SESSCACHE_MISS
} e_sslSesCacheErr_t;

/*** Prototypes *************************************************************/
/*! \brief The data from the current connection is used to create a new entry in
 * the session database to allow new connections for session resumption.
 *
 * The session identifier will be taken from the connection context.
 *
 * If an entry with the same identifier is found, then the entry is
 * refreshed (means LRU counter will be set to maximum value).\n
 * If no matching entry is found, then an empty slot is used.\n
 * If no empty slot is available, the least recently used slot
 * is used. Previous content is lost.
 *
 * \param ps_sessCache : Pointer to the connection context
 *
 * \return Nothing
 *
 **************************************************************************/
/*! PG: Gesamte Beschreibung kontrollieren und anpassen! */
e_sslSesCacheErr_t sslSesCache_addEntry(s_sslSessCache_t *ps_sessCache,
        s_sslSessElem_t *ps_newSessElem, uint32_t l_toutInMS);

/*! \brief Search in the session database for an entry with a matching sessionId and
 * use the session parameters to establish a new connection.
 *
 * If a matching entry is found, the sessionId and the corresponding
 * master-secret is restored in the connection context. The LRU-counter of
 * this entry is set to the maximum value.
 *
 * \param ps_sessCache   :
 * \param ps_sessElem :
 * \return
 * 0: No matching entry found\n
 * 1: Matching entry
 * \sa
 */
/*! PG: Beschreibung kontrollieren und updaten! */
e_sslSesCacheErr_t sslSesCache_getElem(s_sslSessCache_t *ps_sessCache,
        s_sslSessElem_t *ps_sessElem);

e_sslSesCacheErr_t sslSesCache_findElem(s_sslSessCache_t *ps_sessCache,
        s_sslSessElem_t *pSessionElement);

e_sslSesCacheErr_t sslSesCache_getById(s_sslSessCache_t *ps_sessCache,
        l_sslSess_t l_id);

l_sslSess_t sslSesCache_getNewSessId(s_sslSessCache_t *ps_sessCache);

/*! \brief Destroys the content of the session context database and marks it
 * for later reuse.
 *
 * If a matching entry is found, the session-ID and the corresponding
 * master secret is cleared.
 *
 * \param ps_sessCache :
 * \param pucSessionID  :
 *
 * \return
 * 0: No matching entry found\n
 * 1: Matching entry found
 *
 * \sa
 */
/*! PG: Beschreibung kontrollieren und updaten! */
e_sslSesCacheErr_t sslSesCache_delEntry(s_sslSessCache_t *ps_sessCache,
        uint8_t *pucSessionID);

/*** Global Variables *******************************************************/

/* Your stuff ends here */
#ifdef __cplusplus
} /* extern "C" */
#endif /* end C prototype in C++ */

#endif /* file already included */
