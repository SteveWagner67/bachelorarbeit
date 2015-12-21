#ifdef __cplusplus
extern "C" {
#endif
/*============================================================================*/
/*!
    \file   timeout.c

    \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

    \brief  Utility functions for timings and delay generation.

            There are two different timer functions defined in this file:
             - Older timer functions with prefix tot_
             - New timer functions with prefix tot2_

            The newer timer functions provide a better API to the programmer.
            Functions with the prefix tot_ should are deprecated.

            In order for the timers to work properly the following must be
            considered:
             - A ISR or other mean of periodic function call must call the
               function tot_tick() to update a local counter. In an OS
               environment this can be called out of a OS timer or a seperate
               task.
             - To check for events the function tot_handleEvents() must also
               be called periodically. This function is to be called out of the
               main application and calls the timer callback functions for
               event generations.

             Even though in certain environments sophisticated timer functions
             exist these functions in this file do provide a platform
             independant API.

             Two debugging options are available:
               - DBG_TIMEOUT: To get debug output when a timer is set and when it
                              expires
               - DBG_TIMEOUT_INFO: To compile the function tot2_dumpTimeout()
                                   along with the sources that allows to
                                   dump the list of active timers using the
                                   debug output.

  \version  4.2.0
*/
/*============================================================================*/

/*==============================================================================
                             INCLUDE FILES
==============================================================================*/
#include  "netGlobal.h"
#include  <string.h>
#include  "timeout.h"
#include <sys/time.h>
#include <time.h>


/*==============================================================================
                             LOCAL CONSTANTS
==============================================================================*/

/*==============================================================================
                    LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==============================================================================*/

/*==============================================================================
                             LOCAL MACROS
==============================================================================*/

#ifndef EBTTR_DBG_PRINTF
#include <stdio.h>
/*! Use regular printf functions for debugging output */
#define EBTTR_DBG_PRINTF printf
#endif

/*! Checks if a is less than b */
#define TMR_LT(a,b)  (((a)-(b))&0x80000000)

/*! Checks if a is less or equal than b */
#define TMR_LEQ(a,b) (!TMR_GT(a,b))

/*! Checks if a is greater than b */
#define TMR_GT(a,b)  TMR_LT(b,a)

/*! Checks if a is greater or equal than b */
#define TMR_GEQ(a,b) (!TMR_LT(a,b))

#ifndef DBG_FILE_NAME
/*! File name of this module for debug messages */
#define DBG_FILE_NAME "timeout.c"
#endif

/*==============================================================================
                            LOCAL VARIABLES
==============================================================================*/

/*! Storage for timer list values */
static struct
{
  /*! First timer in the timer chain */
  s_tot2_Tmr_t* p_tmrFirst;

  /*! This is a tick counter, incremented at every timer tick in the ISR */
  /*! uint32_t l_tickCnt; */

  uint32_t (*_get_time)(void);

  /*! Ticks per second of the hardware driver  */
  uint16_t i_ticksPerSec;
}gst_tmr;

/*==============================================================================
                        LOCAL FUNCTION PROTOTYPES
==============================================================================*/
static s_tot2_Tmr_t*  getTmrRefNext   (s_tot2_Tmr_t* p_tmr);
static int             checkTmrInList  (s_tot2_Tmr_t* p_tmr);
static	uint32_t 	   tot2_getTime(void);
/*==============================================================================
                             LOCAL FUNCTIONS
==============================================================================*/

/*============================================================================*/
/*!
   \brief   Checks the list of timers and finds a timer that has the specified
            timer set as "next" reference.

   \param   p_tmr The timer to verify
   \return  A timer that has the timers reference in it's "next" field
   \return  NULL if no reference could be found
*/
/*============================================================================*/
static s_tot2_Tmr_t* getTmrRefNext (s_tot2_Tmr_t* p_tmr)
{
  s_tot2_Tmr_t* p_returnTmr;

  p_returnTmr = gst_tmr.p_tmrFirst;

  /*
   * Check each timer in the list
   */
  while(p_returnTmr && (p_returnTmr->p_tmrNext != p_tmr))
    p_returnTmr = p_returnTmr->p_tmrNext;

  return p_returnTmr;
} /* getTmrRefNext() */

/*============================================================================*/
/*!
   \brief   Checks if a timer is in the list

            Checks if the specified timer is referenced by a timer in the list.
            This is the case if the timer is active.

   \param   p_tmr The timer to verify

   \return  0: the timer is not part of the list
   \return  1: the timer is in the list
*/
/*============================================================================*/
static int checkTmrInList (s_tot2_Tmr_t* p_tmr)
{
  int i_return = 0;

  /*
   * Check if there is a timer that references this timer
   */
  if (!getTmrRefNext(p_tmr))
   {
     /*
      * If there is no timer that references this timer it can only be that this
      * is the first timer in the list
      */
     if (gst_tmr.p_tmrFirst == p_tmr)
      {
         /*
          * This is apparently the first timer so in this case we can return
          * with TRUE
          */
         i_return = 1;
      } /* if */
   }
  else
    i_return = 1;

  return i_return;
} /* checkTmrInList() */

/*==============================================================================
                             GLOBAL FUNCTIONS
==============================================================================*/

/*============================================================================*/
/*  tot_init()                                                                */
/*============================================================================*/
void tot_init (void)
{
  gst_tmr.p_tmrFirst = NULL;
  gst_tmr.i_ticksPerSec = 0;
  gst_tmr._get_time = tot2_getTime;
} /* tot_init */

/*============================================================================*/
/*  tot_handleEvents()                                                        */
/*============================================================================*/
void tot_handleEvents (void)
{

  #if DBG_TIMEOUT
  if (gst_tmr.i_ticksPerSec == 0)
    EBTTR_DBG_PRINTF(DBG_STRING " Warning! timeout module not initialized! Timers do not work!", __FILE__, __LINE__);
  #endif

  if (gst_tmr.p_tmrFirst)
  {
    /*
     * Check if the first timer in the list expired
     */
    if (TMR_GEQ(gst_tmr._get_time(), gst_tmr.p_tmrFirst->l_ticks))
    {
      #if DBG_TIMEOUT
      const char* p_desc;
      #endif

      /*
       * Store the currently expired timer in a local variable so that
       * the timer list can be updated already but we can still call the
       * callback function
       */
      s_tot2_Tmr_t* p_tmr = gst_tmr.p_tmrFirst;

      /*
       * Set the timer to expired
       */
      p_tmr->e_tmrState = TOT_EXPIRED;

      /*
       * Update the list of timers. Next timer is going to be the first in
       * the list. Check if it was not the last in the list
       */
      gst_tmr.p_tmrFirst = p_tmr->p_tmrNext;
      if (gst_tmr.p_tmrFirst)
        gst_tmr.p_tmrFirst->p_tmrPrev = NULL;

      #if DBG_TIMEOUT
      if (p_tmr->p_desc)
        p_desc = p_tmr->p_desc;
      else
        p_desc = "";
      #endif

      /*
       * If the currently expired timer requires a callback function
       * then call it
       */
      if (p_tmr->fp_Callback)
      {
        uint32_t l_newTimer;
        fp_tot2_Callback_t p_function;

        p_function = (fp_tot2_Callback_t)p_tmr->fp_Callback;

        /*
         * Call the callback function for this timer
         */
        l_newTimer = p_function(p_tmr, p_tmr->p_cbCtx);

        /*
         * If the callback function returns a value > 0 then the timeout
         * needs to be retriggered
         */
        if (l_newTimer)
        {
          #if DBG_TIMEOUT_DUMP
          const char* p_description = p_tmr->p_desc;
          #endif

          tot2_setTmrTicks(p_tmr, l_newTimer, (fp_tot2_Callback_t)p_tmr->fp_Callback, p_tmr->p_cbCtx);

          TOT2_SET_DESCRIPTION(p_tmr, p_description);

          #if DBG_TIMEOUT
          EBTTR_DBG_PRINTF(DBG_STRING " timer @%p \"%s\" retriggered with %d ticks", DBG_FILE_NAME, __LINE__, p_tmr, p_desc, l_newTimer);
          #endif
        }
        #if DBG_TIMEOUT
        else
        {
          EBTTR_DBG_PRINTF(DBG_STRING " timer @%p \"%s\" expired, callback called", DBG_FILE_NAME, __LINE__, p_tmr, p_desc);
        } /* if ... else */
        #endif
      }
      else
      {
        #if DBG_TIMEOUT
        EBTTR_DBG_PRINTF(DBG_STRING " timer @%p \"%s\" expired without callback", DBG_FILE_NAME, __LINE__, p_tmr, p_desc);
        #endif
      } /* if ... else */
    } /* if */
  } /* if */
} /* tot_handleEvents() */

/*============================================================================*/
/*  tot_delay()                                                               */
/*============================================================================*/
void tot_delay (uint32_t u32_ticksToWait)
{
	  uint32_t u32_delay;
	  uint8_t	stop_delay = 0;

	  u32_delay = gst_tmr._get_time() + u32_ticksToWait;

	  while (!stop_delay) {
		  if (gst_tmr._get_time() >= u32_delay)
			  stop_delay = 1;
	  }

} /* tot_delay() */

/*============================================================================*/
/*  tot2_setTmrTicks()                                                        */
/*============================================================================*/
void tot2_setTmrTicks (s_tot2_Tmr_t*      p_tmr,
                       uint32_t              l_ticks,
                       fp_tot2_Callback_t  p_cbFunc,
                       void*               p_cbCtx)
{

  /*
   * Check if the timer is not NULL
   */
  if (p_tmr)
  {
      /*
       * Check if this timer is already in the list of timers. Then we must
       * reset it first
       */
      if (checkTmrInList(p_tmr))
       {
          tot2_resetTmr(p_tmr);
          #if DBG_TIMEOUT
          EBTTR_DBG_PRINTF(DBG_STRING " running timer reset before setting it to a new value", DBG_FILE_NAME, __LINE__);
          #endif
       } /* if */

      /*
       * Calculate the time that this timer is going to expire based on the
       * current tick count
       */
      p_tmr->l_ticks = gst_tmr._get_time() + l_ticks;

      /*
       * Set it to the state running
       */
      p_tmr->e_tmrState = TOT_RUNNING;

      /*
       * Initialize the description pointer to null
       */
      p_tmr->p_desc = NULL;

      /*
       * Set the callback function and the context pointer
       */
      p_tmr->fp_Callback = p_cbFunc;
      p_tmr->p_cbCtx     = p_cbCtx;

      /*
       * Initialize some values
       */
      p_tmr->p_tmrNext = NULL;
      p_tmr->p_tmrPrev = NULL;

      /*
       * Now hook the timer into the list
       * The following cases have to be considered:
       *   - There is currently no timer set
       *   - The timer is going to expire as first timer, thus register it at the
       *     first position in the list
       *   - The timer expires in the middle of the list of other timers
       *   - The timer expires after all other timers expired, add it to the end
       *     of the list
       */
      if (gst_tmr.p_tmrFirst)
       {
         /*
          * It is not the first timer so we need to walk through the list to find
          * the position in the list to hook this timer in.
          * We must stop at the end of the list in order to be able to attach
          * the timer to the list.
          */
         s_tot2_Tmr_t* p_tmrList = gst_tmr.p_tmrFirst;

         do
          {
            if (TMR_LT(p_tmr->l_ticks, p_tmrList->l_ticks))
              break;
            else
             {
               if (p_tmrList->p_tmrNext)
                 p_tmrList = p_tmrList->p_tmrNext;
             }
          } while (p_tmrList->p_tmrNext != NULL);

         /*
          * Check if we are at the last position or in the middle of the
          * list
          */
         if ((p_tmrList->p_tmrNext != NULL) || (TMR_LT(p_tmr->l_ticks, p_tmrList->l_ticks)))
          {
            /*
             * Retrieve the previous timer of the current timer
             * We need to adjust its "next" field if it is not the first timer
             * in the list
             */
            s_tot2_Tmr_t* p_tmrCurrPrev = p_tmrList->p_tmrPrev;

            /*
             * The reference to the "next" timer of the new timer must be set to the
             * currently found timer
             */
            p_tmrList->p_tmrPrev = p_tmr;

            /*
             * The reference of the currently set timer must be set
             */
            p_tmr->p_tmrNext = p_tmrList;
            p_tmr->p_tmrPrev = p_tmrCurrPrev;

            if (p_tmrCurrPrev == NULL)
            {
              /*
               * If the previous timer is set to null then this means that we are
               * at the beginning of the list
               */
              gst_tmr.p_tmrFirst = p_tmr;

              #if DBG_TIMEOUT
              EBTTR_DBG_PRINTF(DBG_STRING " timer added at the beginning of the list", DBG_FILE_NAME, __LINE__);
              #endif
            }
           else
            {
              /*
               * The reference of the previous timer must be set to our current
               * timer
               */
              p_tmrCurrPrev->p_tmrNext = p_tmr;

              #if DBG_TIMEOUT
              EBTTR_DBG_PRINTF(DBG_STRING " timer added in the middle of the list", DBG_FILE_NAME, __LINE__);
              #endif
            } /* if ... else */
          }
         else
          {
            /*
             * We reached the end of the list
             * therefore we just need to add our timer to the list at the end
             */
            p_tmr->p_tmrNext     = NULL;
            p_tmr->p_tmrPrev     = p_tmrList;
            p_tmrList->p_tmrNext = p_tmr;

            #if DBG_TIMEOUT
            EBTTR_DBG_PRINTF(DBG_STRING " timer added to the end of the list", DBG_FILE_NAME, __LINE__);
            #endif
          } /* if ... else */
      }
     else
      {
         /*
          * This is the very first timer to register
          */
         gst_tmr.p_tmrFirst = p_tmr;
         p_tmr->p_tmrNext       = NULL;
         p_tmr->p_tmrPrev       = NULL;

         #if DBG_TIMEOUT
         EBTTR_DBG_PRINTF(DBG_STRING " first timer set", DBG_FILE_NAME, __LINE__);
         #endif
      } /* if ... else */
  }
 else
  {
     #if DBG_TIMEOUT
     EBTTR_DBG_PRINTF(DBG_STRING " Failed to set timer since pointer to variable is NULL!", DBG_FILE_NAME, __LINE__);
     #endif
  }
} /* tot2_setTmrTicks() */

/*============================================================================*/
/*  tot2_setTmrMs()                                                           */
/*============================================================================*/
void tot2_setTmrMs (s_tot2_Tmr_t*      p_tmr,
                    uint32_t              l_ms,
                    fp_tot2_Callback_t  p_cbFunc,
                    void*               p_cbCtx)
{
  /*
   * Set the timer based on the system ticks
   */
  tot2_setTmrTicks (p_tmr, tot2_msToTicks(l_ms), p_cbFunc, p_cbCtx);

} /* tot2_setTmrMs() */

/*============================================================================*/
/*  tot2_retriggerTmrTicks()                                                  */
/*============================================================================*/
void tot2_retriggerTmrTicks (s_tot2_Tmr_t*  p_tmr,
                             uint32_t          l_ticks)
{
  fp_tot2_Callback_t p_cbFunc = (fp_tot2_Callback_t)p_tmr->fp_Callback;
  void*              p_cbCtx  = p_tmr->p_cbCtx;

#if DBG_TIMEOUT_DUMP
  const char*        p_desc   = p_tmr->p_desc;
#endif

  /*
   * Set the new timeout by calling the setting function with the previous
   * parameters. Note that the function tot2_setTmrTicks() handles a timer
   * correctly even if it is an active timer
   */
  tot2_setTmrTicks (p_tmr, l_ticks, p_cbFunc, p_cbCtx);

  TOT2_SET_DESCRIPTION(p_tmr, p_desc);

} /* tot2_retriggerTmrTicks() */


/*============================================================================*/
/*  tot2_retriggerTmrMs()                                                     */
/*============================================================================*/
void tot2_retriggerTmrMs (s_tot2_Tmr_t*      p_tmr,
                          uint32_t              l_ms)
{
  tot2_retriggerTmrTicks(p_tmr, tot2_msToTicks(l_ms));
} /* tot2_retriggerTmrMs() */


/*============================================================================*/
/*  tot2_resetTmr()                                                           */
/*============================================================================*/
void  tot2_resetTmr (s_tot2_Tmr_t* p_tmr)
{
  /*
   * Check that the timer is not NULL!
   */
  if (p_tmr)
   {
     /*
      * Remove the timer of the list if only it is running
      */
     if (p_tmr->e_tmrState == TOT_RUNNING)
      {
         /*
          * Get the reference in this timer to the previous and the next timer
          */
         s_tot2_Tmr_t* p_tmrPrev;
         s_tot2_Tmr_t* p_tmrNext;

         p_tmrPrev = p_tmr->p_tmrPrev;
         p_tmrNext = p_tmr->p_tmrNext;

         /*
          * If the pointer in the previous field is set then adjust the pointer
          * of this timer to the new timer in the list.
          * If the pointer to the previous timer is NULL then this is the first
          * pointer in the list. Therefore set the first pointer in the global
          * structure to the next pointer
          */
         if (p_tmrPrev)
          {
            p_tmrPrev->p_tmrNext = p_tmrNext;
          }
         else
          {
            gst_tmr.p_tmrFirst = p_tmrNext;
          } /* if ... else */

         /*
          * Set the pointer to the previous timer in the timer next. If there is
          * no next element, then skip this step since it was the last timer in the
          * list
          */
         if (p_tmrNext)
         {
           p_tmrNext->p_tmrPrev = p_tmrPrev;
         } /* if */
      } /* if */
     /*
      * Reset the fields in the current timer
      */
     p_tmr->e_tmrState = TOT_NOEXIST;

   } /* if */
} /* tot2_resetTmr() */

/*============================================================================*/
/*  tot2_initTmr()                                                           */
/*============================================================================*/
void  tot2_initTmr (s_tot2_Tmr_t* p_tmr)
{
  if (p_tmr)
   {

     /*
      * Check if there is a reference in the list of timers so that we don't
      * reset a running timer to NULL and therefore destroy and mess with the
      * linked list of timers
      */
     if (checkTmrInList(p_tmr))
      {
        #if DBG_TIMEOUT
        EBTTR_DBG_PRINTF(DBG_STRING " the timer to initialize is referenced by a timer, reset the timer", DBG_FILE_NAME, __LINE__);
        #endif

        tot2_resetTmr(p_tmr);
      }
     else
      {
         /*
          * Reset the entire timer variable to 0
          */
         (void) memset(p_tmr, 0, sizeof(s_tot2_Tmr_t));

         /*
          * Set the flag of the timer to "expired"
          */
         p_tmr->e_tmrState = TOT_EXPIRED;
      } /* if ... else */
   }
} /* tot2_initTmr() */

/*============================================================================*/
/*  tot2_getStatusTicks()                                                     */
/*============================================================================*/
uint32_t tot2_getStatusTicks (const s_tot2_Tmr_t* p_tmr)
{
  uint32_t l_return = 0;
  if (p_tmr)
   {
     if (p_tmr->e_tmrState == TOT_RUNNING)
      {
        /*
         * Check if the timer has not expired yet
         */
        if (TMR_LT(gst_tmr._get_time(), p_tmr->l_ticks))
         {
            /*
             * Check for a possible wrap around of the timer
             */
            if (p_tmr->l_ticks > gst_tmr._get_time())
              l_return = p_tmr->l_ticks - gst_tmr._get_time();
            else
              l_return = gst_tmr._get_time() - p_tmr->l_ticks;
        } /* if */
      } /* if */
   } /* if */
  return l_return;
} /* tot2_getStatusTicks() */

/*============================================================================*/
/*  tot2_getStatusMs()                                                        */
/*============================================================================*/
uint32_t tot2_getStatusMs (const s_tot2_Tmr_t* p_tmr)
{
  return tot2_ticksToMs(tot2_getStatusTicks(p_tmr));
} /* tot2_getStatusTicks() */

/*============================================================================*/
/*  tot2_getStatus()                                                        */
/*============================================================================*/
E_TOT_STATE tot2_getStatus (const s_tot2_Tmr_t* p_tmr)
{
  if ((p_tmr->e_tmrState == TOT_RUNNING) && TMR_LT(gst_tmr._get_time(), p_tmr->l_ticks))
    return TOT_RUNNING;
  else
    return TOT_EXPIRED;
} /* tot2_getStatus() */

/*============================================================================*/
/*  tot2_setDescription()                                                     */
/*============================================================================*/
void tot2_setDescription (s_tot2_Tmr_t* p_tmr, const char* p_desc)
{
  if (p_tmr)
    p_tmr->p_desc = p_desc;
} /* tot2_setDescription() */

/*============================================================================*/
/*  tot2_getTicksPerSec()                                                     */
/*============================================================================*/
uint16_t tot2_getTicksPerSec (void)
{
  return gst_tmr.i_ticksPerSec;
} /* tot_getTicksPerSec() */

/*============================================================================*/
/*  tot2_setTicksPerSec()                                                     */
/*============================================================================*/
uint16_t tot2_setTicksPerSec (uint16_t us_ticks)
{
  uint16_t us_return = gst_tmr.i_ticksPerSec;

  gst_tmr.i_ticksPerSec = us_ticks;

  return us_return;
} /* tot_getTicksPerSec() */

/*============================================================================*/
/*  tot2_getSysTicks()                                                        */
/*============================================================================*/
uint32_t tot2_getSysTicks (void)
{
  return gst_tmr._get_time();
} /* tot2_getSysTicks() */

/*============================================================================*/
/*  tot2_msToTicks()                                                          */
/*============================================================================*/
uint32_t tot2_msToTicks (uint32_t l_ms)
{
  /*
   * Compute the ticks based on the milli-seconds
   */
  uint32_t l_return;

  /*
   * Check here if the timeout module has been initialized yet
   * If it has been initialized, calculate the tick count of the given msecs
   * If not, return 0 instead.
   */
  if(gst_tmr.i_ticksPerSec > 0)
   {
        /*
         * In order to prevent an overflow and to retain precision of the timers
         * a decision must be made how the calculation from ms to ticks is done
         */
        if(gst_tmr.i_ticksPerSec < 1000)
         {
            /*
             * Prevent the overflow of multiplication of l_ms * 1000
             *
             *                  l_ms
             *  l_return = ---------------
             *                  1000
             *               -----------
             *               ticksPerSec
             *
             * Which is the same as (l_ms * ticksPerSec) / 1000
             *
             * This prevents the overflow in the calculation l_ms * ticksPerSec
             * and prevents a resulting 0 when l_ms < 1000
             *
             */

            l_return = (l_ms / (1000 / (uint32_t)gst_tmr.i_ticksPerSec));
         }
        else
         {
            /*
             * Milliseconds when timer time base >=1000 are calculated as follows
             *
             *                      ticksPerSec
             *  l_return = l_ms *  --------------
             *                         1000
             *
             */

            l_return = l_ms * ((uint32_t)gst_tmr.i_ticksPerSec / 1000);
         }

        /*
         * Check for the condition when the return value was calculated as 0. Two
         * cases must be distinguished:
         *  1) if the time base in gst_tmr.i_ticksPerSec is greater than 1ms, then
         *     an operation might result in 0 for timer periods < 1/i_ticksPerSec. In
         *     this case this function returns 1
         *  2) If l_ms is set to 0, of course this function might return 0.
         */
        if ((l_return == 0) && l_ms)
            l_return = 1;
   }
  else
   {
        /*
         * The timeout module has not been initialized, so return 0
         */
        l_return = 0;
   }

  return l_return;
} /* tot2_msToTicks() */

/*============================================================================*/
/*  tot2_ticksToMs()                                                          */
/*============================================================================*/
uint32_t tot2_ticksToMs (uint32_t l_ticks)
{
  uint32_t l_return;

  /*
   * Check if the timeout module has been initialized
   */
  if (gst_tmr.i_ticksPerSec)
   {
      /*
       * If the timer interval is higher than 1ms, then multiply the number of
       * ticks, otherwise use the divisor.
       */
      if (gst_tmr.i_ticksPerSec < 1000)
      {
        uint32_t l_multiplyWith = 1000 / gst_tmr.i_ticksPerSec;

        l_return = l_ticks * l_multiplyWith;

      }
      else
      {
          uint32_t l_divisior = tot2_msToTicks(1);
          l_return = (l_ticks / l_divisior);
      } /* if ... else */
   }
  else
   {
      /*
       * The timeout module is not initialized, so return 0
       */
      l_return = 0;
   }

  return l_return;

} /* tot2_ticksToMs() */

/*============================================================================*/
/*  tot2_ticksToExpire()                                                      */
/*============================================================================*/
uint32_t tot2_ticksToExpire (uint32_t l_timeTicks)
{
  /*
   * Check if the given time ticks is in the future, then calculate the
   * difference until the given time
   */
  if (TMR_GT(l_timeTicks, tot2_getSysTicks()))
    return TMR_GT(l_timeTicks, tot2_getSysTicks());
  else
    return 0;
} /* tot2_ticksToExpire() */

#if DBG_TIMEOUT || DBG_TIMEOUT_INFO
/*============================================================================*/
/*!
   \brief   Dumps the currently active timers

            This function dumps the currently active timers and the
            descriptions using EBTTR_DBG_PRINTF()
*/
/*============================================================================*/
void tot2_dumpTimeout (void)
{
  s_tot2_Tmr_t* p_tmr;

  EBTTR_DBG_PRINTF("\r\n");
  EBTTR_DBG_PRINTF("********************************************************************************\r\n");
  EBTTR_DBG_PRINTF("                             Settings for timeouts\r\n");
  EBTTR_DBG_PRINTF("********************************************************************************\r\n");
  EBTTR_DBG_PRINTF("Timebase in number of ticks per second: %d\r\n", tot2_getTicksPerSec());
  EBTTR_DBG_PRINTF("Current tick cnt:                       %d\r\n", gst_tmr._get_time());
  EBTTR_DBG_PRINTF("\r\n");
  EBTTR_DBG_PRINTF("********************************************************************************\r\n");
  EBTTR_DBG_PRINTF("                        List of active timeouts (tot2_xx)\r\n");
  EBTTR_DBG_PRINTF("********************************************************************************\r\n");
  EBTTR_DBG_PRINTF("Timer @    | Due in/ticks | Due in / ms | Description\r\n");
  EBTTR_DBG_PRINTF("-----------+--------------|-------------+---------------------------------------\r\n");

  p_tmr = gst_tmr.p_tmrFirst;

  if (p_tmr)
   {
      while (p_tmr)
       {
         const char* p_desc = p_tmr->p_desc;

         if (!p_desc)
           p_desc = "No description";

         EBTTR_DBG_PRINTF("0x%08x | %10d   | %10d  | %s\r\n", (unsigned int)p_tmr, tot2_getStatusTicks(p_tmr), tot2_getStatusMs(p_tmr), p_desc);

         if (tot2_getStatusTicks(p_tmr) == 0)
           EBTTR_DBG_PRINTF("  --> Warning: Timer is expired but still in the list! tot_handleEvents() \r\n               needs to be called to remove it from the list.\r\n");

         p_tmr = p_tmr->p_tmrNext;
       } /* while */
   }
  else
   {
     EBTTR_DBG_PRINTF("Currently no active timers set\r\n");
   } /* if ... else */
} /* tot2_dumpTimeout() */

uint32_t tot2_getTime(void)
{
	struct timeval  tv;
	gettimeofday(&tv, NULL);

	uint32_t time_in_micros = 1000000 * tv.tv_sec + tv.tv_usec;

	return time_in_micros;
}


char * tot2_getStrTime(void) {
	time_t raw_time;
	time(&raw_time);
	return ctime(&raw_time);
}
#endif

#ifdef __cplusplus
}
#endif
