/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_sesCache.c                                                */
/*                                                                           */
/*  FUNCTIONS:                                                               */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*   This module implements the session cache database. The cache DB stores  */
/*   the security attributes of the sessions which are resumable (see        */
/*   section 2.6 in the User Manual 0.96)                                    */
/*                                                                           */
/*   The cache is organized as a LRU-Buffer (Least Recently Used). Every     */
/*   entry in the DB has an LRU-Counter value. Each DB query decrements the  */
/*   counter of every entry by one. A counter value of 0 indicates an unused */
/*   entry. A cache hit sets the counter to the maximal possible value.      */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  CAUTIONS:                                                                */
/*   As the session cache is a central resource, only one access at a time   */
/*   is allowed. Multiple access from independent threads leads to errors. A */
/*   serialisation mechanism must be established, if more than one task has  */
/*   access to the session cache.                                            */
/*   The protection method depends on the system architecture.               */
/*                                                                           */
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
/*  2002-2003    T. Gillen     Initial version                               */
/*  05.03.03     WAM           First version after splitting into several    */
/*                             files                                         */
/*  20.03.03     WAM           Fully revised for release 1                   */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*****************************************************************************/

#ifdef BECK_IPC
#include <dos.h>
#endif

#include <stdio.h>
#include "crypto_wrap.h"
#include "ssl.h"
#include "ssl_target.h"
#include "ssl_sessCache.h"
#include "ssl_diag.h"

/*** Defines ****************************************************************/

#define FREE_CACHE_ENTRY       0  /* Value of the LRU counter if the entry   */
/* is free */

#define LRU_CNT_MAX_VALUE  65535  /* A cache hit will set the LRU counter to */
/* this value */

#define SESSION_LIFETIME    3600  /* Maximum live time of a session. Session */
/* resumption is possible within this time */

#define NUM_CACHE_DB_ENTRIES  SSL_SESSION_CACHE_SIZE

#define	LOGGER_ENABLE		DBG_SSL_OSAL_CACHE
#include "logger.h"

/*** Global Variables *******************************************************/

/*** Forward declarations ***************************************************/

static void _rmUnusedEntries(s_sslSessCache_t *ps_sessCache);

static uint32_t _resetCache(s_tot2_Tmr_t* p_tmr, void* p_ctx);

static s_sslSessCache_t* _getEntryById(s_sslSessCache_t *ps_sessCache,
        l_sslSess_t identifier, uint8_t onlyActiveEntries);
/*** Local Functions ********************************************************/

static void _rmUnusedEntries(s_sslSessCache_t *ps_sessCache)
{
    int i = 0;

    s_sslSessCache_t *pCache;

    assert(ps_sessCache != NULL);

    pCache = ps_sessCache;

    for (i = 0; i < NUM_CACHE_DB_ENTRIES; i++)
    {
        /* Check if this is an unused entry */
        if (pCache[i].i_lruCounter == FREE_CACHE_ENTRY)
        {
            /* reset the timer before it will been overwritten */
            tot2_resetTmr(&pCache[i].s_sessTimeout);
            /* Clear the entire cache entry */
            CW_MEMSET(&pCache[i], 0x00, sizeof(s_sslSessCache_t));
            LOG2_INFO("Session Cache Element @ %p has been erased", &pCache[i]);
        }
    }
}

static uint32_t _resetCache(s_tot2_Tmr_t* p_tmr, void* p_ctx)
{
    CW_MEMSET(p_ctx, 0x00, sizeof(s_sslSessCache_t));
    LOG2_INFO("Session Cache Element @ %p has " "been hit by reset timer", p_ctx);
    return 0;
}

static s_sslSessCache_t* _getEntryById(s_sslSessCache_t *ps_sessCache,
        l_sslSess_t identifier, uint8_t onlyActiveEntries)
{
    int i;
    for (i = 0; i < NUM_CACHE_DB_ENTRIES; i++)
    {
        /* Check only the active entries */
        if ((onlyActiveEntries == FALSE)
                || (ps_sessCache[i].i_lruCounter > FREE_CACHE_ENTRY))
        {
            if (identifier == ps_sessCache[i].s_sessElem.s_desc)
            {
                return &ps_sessCache[i];
            }
        }
    }
    return NULL;
} /* _getEntryById() */

/*** Global Functions *******************************************************/

/*==============================================================================
 sslConf_asymCryptoDisp()
 ==============================================================================*/
e_sslSesCacheErr_t sslSesCache_addEntry(s_sslSessCache_t *ps_sessCache,
        s_sslSessElem_t *ps_newSessElem, uint32_t l_toutInMS)
{
    uint16_t i_lruValue;
    e_sslSesCacheErr_t e_ret = E_SSL_SESSCACHE_MISS;
    int32_t i;
    int32_t l_freeEntry; /* 	Index of an free or the least
     recently used entry */
    int32_t l_cacheHit; /* 	Index of the matching entry
     (match prevents a new entry) */
    uint8_t cmpArray[MSSEC_SIZE] = { 0 };
    s_sslSessCache_t *ps_sslSessCache;

    assert(ps_sessCache != NULL);
    assert(ps_newSessElem != NULL);

    l_freeEntry = NUM_CACHE_DB_ENTRIES - 1; /* Ensure a valid element */
    l_cacheHit = NUM_CACHE_DB_ENTRIES;
    i_lruValue = LRU_CNT_MAX_VALUE;

    for (i = 0; i < NUM_CACHE_DB_ENTRIES; i++)
    {
        /* Decrement the non-zero lru-counters of all entrys to realize the    */
        /* LRU-Mechanism */
        if (ps_sessCache[i].i_lruCounter != FREE_CACHE_ENTRY)
        {
            ps_sessCache[i].i_lruCounter--;

            /* This entry is also a candidate for an update */
            if (CW_MEMCMP(ps_sessCache[i].s_sessElem.ac_id, ps_newSessElem->ac_id,
            SESSID_SIZE) == 0)
            {
                l_cacheHit = i;
            }
        }

        /* Search for the oldest entry i.e. the smallest LRU-Counter value */
        if (ps_sessCache[i].i_lruCounter < i_lruValue)
        {
            i_lruValue = ps_sessCache[i].i_lruCounter;
            l_freeEntry = i;
        }
    }

    /* Check if we have a cache hit */
    if (l_cacheHit < NUM_CACHE_DB_ENTRIES)
    {
        /* Because we had a cache hit, set the counter to the max value */
        ps_sessCache[l_cacheHit].i_lruCounter = LRU_CNT_MAX_VALUE;

        tot2_retriggerTmrMs(&ps_sessCache[l_cacheHit].s_sessTimeout,
                l_toutInMS);

        e_ret = E_SSL_SESSCACHE_HIT;
    }
    else
    {
        /* There was no cache hit. Thus overwrite the oldest cache entry */
        ps_sslSessCache = &ps_sessCache[l_freeEntry];

        if (CW_MEMCMP(ps_sslSessCache->s_sessElem.ac_id, cmpArray, SESSID_SIZE)
                != 0)
        {
            LOG2_RAW("\nreplace Session ID");
            LOG2_HEX(ps_sslSessCache->s_sessElem.ac_id, SESSID_SIZE);
            LOG2_RAW("\nby this Session ID");
            LOG2_HEX(ps_newSessElem->ac_id, SESSID_SIZE);
        }
        if (CW_MEMCMP(ps_sslSessCache->s_sessElem.ac_msSec, cmpArray,
                MSSEC_SIZE) != 0)
        {
            LOG2_RAW("\nreplace MasterSecret");
            LOG2_HEX(ps_sslSessCache->s_sessElem.ac_msSec, MSSEC_SIZE);
            LOG2_RAW("\nby this MasterSecret");
            LOG2_HEX(ps_newSessElem->ac_msSec, MSSEC_SIZE);
        }

        /* For optimisation: use CW_MEMCOPY to copy the SESSION_ELEMENT     */
        /* struct from ps_sslSessElem to pCache[freeEntry] */
        CW_MEMCOPY(ps_sslSessCache->s_sessElem.ac_id,
                ps_newSessElem->ac_id, SESSID_SIZE);

        CW_MEMCOPY(ps_sslSessCache->s_sessElem.ac_msSec,
                ps_newSessElem->ac_msSec, MSSEC_SIZE);

        ps_sslSessCache->s_sessElem.l_authId = ps_newSessElem->l_authId;

        ps_sslSessCache->s_sessElem.e_lastUsedVer = ps_newSessElem->e_lastUsedVer;

        ps_sslSessCache->i_lruCounter = LRU_CNT_MAX_VALUE;

        ps_sslSessCache->s_sessElem.s_desc = ps_newSessElem->s_desc;

        ps_sslSessCache->s_sessElem.s_signAlg.c_hash = ps_newSessElem->s_signAlg.c_hash;

        ps_sslSessCache->s_sessElem.s_signAlg.c_sign = ps_newSessElem->s_signAlg.c_sign;

        tot2_initTmr(&ps_sslSessCache->s_sessTimeout);

        tot2_setTmrMs(&ps_sslSessCache->s_sessTimeout, l_toutInMS, _resetCache,
                ps_sslSessCache);

        TOT2_SET_DESCRIPTION(&ps_sslSessCache->s_sessTimeout,
                "OSAL Cache Session Expiry Timer");

        e_ret = E_SSL_SESSCACHE_MISS;

    }
    return (e_ret);
}/* sslSesCache_addEntry() */

/*==============================================================================
 sslSesCache_getElem()
 ==============================================================================*/
e_sslSesCacheErr_t sslSesCache_getElem(s_sslSessCache_t *ps_sessCache,s_sslSessElem_t *ps_sessElem)
{
    uint8_t i = 0;
    e_sslSesCacheErr_t e_ret = E_SSL_SESSCACHE_MISS;

    assert(ps_sessCache != NULL);
    assert(ps_sessElem != NULL);

    for (i = 0; i < NUM_CACHE_DB_ENTRIES; i++)
    {
        /* Check only active entrys */
        if (ps_sessCache[i].i_lruCounter > FREE_CACHE_ENTRY)
        {
            if (CW_MEMCMP(ps_sessElem->ac_id, ps_sessCache[i].s_sessElem.ac_id,
            SESSID_SIZE) == 0)
            {
                /* We have a cache hit. Set the counter to the max value */
                ps_sessCache[i].i_lruCounter = LRU_CNT_MAX_VALUE;

                /* Isn't it useless to copy the SessionID? At this stage they */
                /* are equal anyway. */
                CW_MEMCOPY(ps_sessElem->ac_id,
                        ps_sessCache[i].s_sessElem.ac_id, SESSID_SIZE);

                CW_MEMCOPY(ps_sessElem->ac_msSec,
                        ps_sessCache[i].s_sessElem.ac_msSec, MSSEC_SIZE);

                ps_sessElem->l_authId = ps_sessCache[i].s_sessElem.l_authId;

                ps_sessElem->e_lastUsedVer = ps_sessCache[i].s_sessElem.e_lastUsedVer;

                ps_sessElem->s_desc = ps_sessCache[i].s_sessElem.s_desc;

                ps_sessElem->s_signAlg.c_hash = ps_sessCache[i].s_sessElem.s_signAlg.c_hash;

                ps_sessElem->s_signAlg.c_sign = ps_sessCache[i].s_sessElem.s_signAlg.c_sign;

                /* Having found a valid cache entry, we have time to do some  */
                /* garbage collection in the cache, i.e. clean all unused     */
                /* cache entries. */
                _rmUnusedEntries(ps_sessCache);

                e_ret = E_SSL_SESSCACHE_HIT;
                break;
            }
        }
    }

    return (e_ret);
}/* sslSesCache_getElem() */

/*==============================================================================
 sslSesCache_findElem()
 ==============================================================================*/
e_sslSesCacheErr_t sslSesCache_findElem(s_sslSessCache_t *ps_sessCache,
        s_sslSessElem_t *ps_sessElem)
{
    e_sslSesCacheErr_t e_ret = E_SSL_SESSCACHE_MISS;
    s_sslSessCache_t *ps_entry = NULL;

    assert(ps_sessCache != NULL);
    assert(ps_sessElem != NULL);

    ps_entry = _getEntryById(ps_sessCache, ps_sessElem->s_desc, TRUE);

    if (ps_entry != NULL)
    {
        /* We have a cache hit. Set the counter to the max value */
        ps_entry->i_lruCounter = LRU_CNT_MAX_VALUE;

        /* Isn't it useless to copy the SessionID? At this stage they */
        /* are equal anyway. */
        CW_MEMCOPY(ps_sessElem->ac_id,ps_entry->s_sessElem.ac_id,SESSID_SIZE);

        CW_MEMCOPY(ps_sessElem->ac_msSec,ps_entry->s_sessElem.ac_msSec, MSSEC_SIZE);

        ps_sessElem->l_authId = ps_entry->s_sessElem.l_authId;

        ps_sessElem->e_lastUsedVer = ps_entry->s_sessElem.e_lastUsedVer;

        ps_sessElem->s_signAlg.c_hash = ps_entry->s_sessElem.s_signAlg.c_hash;

        ps_sessElem->s_signAlg.c_sign = ps_entry->s_sessElem.s_signAlg.c_sign;

        /* Having found a valid cache entry, we have time to do some  */
        /* garbage collection in the cache, i.e. clean all unused     */
        /* cache entries. */
        _rmUnusedEntries(ps_sessCache);

        e_ret = E_SSL_SESSCACHE_HIT;
    }

    return (e_ret);
} /* sslSesCache_findElem() */

/*==============================================================================
 sslSesCache_getById()
 ==============================================================================*/
e_sslSesCacheErr_t sslSesCache_getById(s_sslSessCache_t *ps_sessCache,
        l_sslSess_t l_id)
{
    e_sslSesCacheErr_t e_ret;
    assert(ps_sessCache != NULL);

    if (_getEntryById(ps_sessCache, l_id, TRUE) != NULL)
        e_ret = E_SSL_SESSCACHE_HIT;
    else
        e_ret = E_SSL_SESSCACHE_MISS;

    return (e_ret);
} /* sslSesCache_getById() */

/*==============================================================================
 sslSesCache_getNewSessId()
 ==============================================================================*/
l_sslSess_t sslSesCache_getNewSessId(s_sslSessCache_t *ps_sessCache)
{
    l_sslSess_t l_id;

    assert(ps_sessCache != NULL);

    /*
     * Generate a unique identifier
     */
    do
    {
        cw_prng_read((uint8_t*) &l_id, sizeof(l_id));
        /*
         * Loop until the PRNG generates a valid session and the
         * generated session can't be found in the session cache
         */
    } while ((l_id == SSL_INVALID_SESSION )
            || (_getEntryById(ps_sessCache, l_id, FALSE) != NULL));

    return l_id;
} /* sslSesCache_getNewSessId() */

/*==============================================================================
 sslSesCache_delEntry()
 ==============================================================================*/
e_sslSesCacheErr_t sslSesCache_delEntry(s_sslSessCache_t *ps_sessCache,
        uint8_t *pc_sessID)
{

    uint8_t i = 0;
    e_sslSesCacheErr_t e_ret = E_SSL_SESSCACHE_MISS;

    assert(ps_sessCache != NULL);
    assert(pc_sessID != NULL);

    for (i = 0; i < NUM_CACHE_DB_ENTRIES; i++)
    {
        /* Check only the active entries */
        if (ps_sessCache[i].i_lruCounter > FREE_CACHE_ENTRY)
        {
            if (CW_MEMCMP(pc_sessID, ps_sessCache[i].s_sessElem.ac_id,
            SESSID_SIZE) == 0)
            {
                /* first reset the timer */
                tot2_resetTmr(&ps_sessCache[i].s_sessTimeout);
                /* Clear the entire DB entry: ID, mastersecret, i_lruCounter, ... */
                CW_MEMSET(&ps_sessCache[i], 0x00, sizeof(s_sslSessCache_t));

                e_ret = E_SSL_SESSCACHE_HIT;
                break;
            }
        }
    }

    return (e_ret);
}/* sslSesCache_delEntry */

