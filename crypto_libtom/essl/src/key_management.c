/*============================================================================*/
/*! \file   key_management.c

 \author � by STZEDN, Loerrach, Germany, http://www.stzedn.de

 \brief  Implementation of the key management for DH Ephemeral Keys

 \version  $Version$

 */
/*============================================================================*/

/*==============================================================================
 INCLUDE FILES
 =============================================================================*/
#define __DECL_KEY_MANAGEMENT_H__
#include "key_management.h"


/*==============================================================================
 MACROS
 =============================================================================*/
#define	LOGGER_ENABLE		DBG_SSL_KEY_MANAG
#include "logger.h"
/*==============================================================================
 ENUMS
 =============================================================================*/

/*==============================================================================
 STRUCTURES AND OTHER TYPEDEFS
 =============================================================================*/
typedef struct s_dheKey
{
    /*! The key we manage with this module */
    //OLD-CW: gci_dhKey_t cwt_dheKey;
	GciKeyId_t cwt_dheKey;
    /*! Indicates the number of times this key has been used */
    int32_t l_count;
    /*! Indicates the number of times this key is currently in use */
    int32_t l_inUse;
    /*! Indicates if the key has been successfully initialised */
    uint8_t b_isValid;
} s_kmDheKey_t;
/*==============================================================================
 LOCAL VARIABLE DECLARATIONS
 =============================================================================*/
static s_kmDheKey_t gst_dheKey =
{
{ 0 }, 0, 0, 0 };
/*==============================================================================
 LOCAL CONSTANTS
 =============================================================================*/

/*==============================================================================
 LOCAL FUNCTION PROTOTYPES
 =============================================================================*/

/*==============================================================================
 LOCAL FUNCTIONS
 =============================================================================*/

/*==============================================================================
 API FUNCTIONS
 =============================================================================*/

/*============================================================================*/
/*  km_dhe_init()                                                             */
/*============================================================================*/
//OLD-CW: int km_dhe_init(void)
en_gciResult_t km_dhe_init()
{
    en_gciResult_t err;

    GciCtxId_t dhCtx;
    st_gciDhConfig_t dhConf;

    uint8_t a_allocDhDomainParam[GCI_BUFFER_MAX_SIZE];
    uint8_t	a_allocDhParamG[GCI_BUFFER_MAX_SIZE/2] = {8, 78};
    uint8_t a_allocDhParamP[GCI_BUFFER_MAX_SIZE/2];

    //OLD-CW: cw_dh_free(&gst_dheKey.cwt_dheKey);

    gst_dheKey.b_isValid = FALSE;

    gst_dheKey.l_count = 0;

    gst_dheKey.l_inUse = 0;


    dhConf.type = en_gciDhType_Dh;


    //fix the domain parameter inside
    err = gciDhNewCtx(&dhConf, &dhCtx);
    if(err != en_gciResult_Ok)
    {
    	//TODO return error state
    }

    err = gciDhGenKey(dhCtx, &gst_dheKey.cwt_dheKey);

    //if ((i_ret = cw_dhe_makeKey(&gst_dheKey.cwt_dheKey)) == CW_OK)
    if(err == en_gciResult_Ok)
    {
        gst_dheKey.b_isValid = TRUE;
    }
    else
    {
        //OLD-CW: LOG1_ERR("cw_dhe_makeKey() error: %s", cw_error2string(i_ret));
    	LOG1_ERR("Error by creating DH keys");
#if LOGGER_LEVEL > 1
        //OLD-CW: cw_mem_printUsage();
#endif
    }


    //Release the context
    err = gciCtxRelease(dhCtx);
    if(err != en_gciResult_Ok)
    {
    	//TODO Return error from state
    }

    return err;
} /* km_dhe_init() */

/*============================================================================*/
/*  km_dhe_getKey()                                                           */
/*============================================================================*/
// OLD-CW: gci_dhKey_t* km_dhe_getKey(void)
en_gciResult_t km_dhe_getKey(GciKeyId_t* dhKeyID)
{
    en_gciResult_t err = en_gciResult_Ok;

    LOG_INFO("km_dhe_getKey() Valid: %i, Count: %i, inUse: %i",
            gst_dheKey.b_isValid, gst_dheKey.l_count, gst_dheKey.l_inUse);

    /*! check if the key is initialized  */
    if (gst_dheKey.b_isValid)
    {
        /* we reused too often? */
        if (gst_dheKey.l_count > SSL_KM_DHE_MAX_REUSE)
        {
            /* is the key still in use? */
            if (gst_dheKey.l_inUse == 0)
            {
                /* no, so we can renew the key */
                if (km_dhe_init() == en_gciResult_Ok)
                {
                    gst_dheKey.l_count++;
                    gst_dheKey.l_inUse++;
                    dhKeyID = &gst_dheKey.cwt_dheKey;

                } /* if(km_dhe_init() == CW_OK) */


                else
                {
                	//TODO return error from state
                }

            } /* if(l_inUse == 0) */

            else
            {
            	//TODO return error from state
            }

        } /* if(l_count > SSL_KM_DHE_MAX_REUSE) */
        else
        {
            gst_dheKey.l_count++;
            gst_dheKey.l_inUse++;
            dhKeyID = &gst_dheKey.cwt_dheKey;
        }

    } /* if(gst_dheKey.b_isValid) */
    else
    {
        if (km_dhe_init() == en_gciResult_Ok)
        {
            gst_dheKey.l_count++;
            gst_dheKey.l_inUse++;
            dhKeyID = &gst_dheKey.cwt_dheKey;
        } /* if(km_dhe_init() == CW_OK) */

        else
        {
        	//TODO return error from state
        }
    }

    return err;
} /* km_dhe_getKey() */

/*============================================================================*/
/*  km_dhe_releaseKey()                                                       */
/*============================================================================*/
void km_dhe_releaseKey(void)
{
    LOG_INFO("km_dhe_releaseKey() Valid: %i, Count: %i, inUse: %i",
            gst_dheKey.b_isValid, gst_dheKey.l_count, gst_dheKey.l_inUse);
    gst_dheKey.l_inUse--;
} /* km_dhe_releaseKey() */
