#ifndef TIMEOUT_H
#define TIMEOUT_H
/*============================================================================*/
/*!
    \file   timeout.h

    \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

    \brief  Utility functions for timings and delay generation.

            There are two different timer functions defined in this file:
             - Older timer functions with prefix tot_
             - New timer functions with prefix tot2_

            The newer timer functions provide a better API to the programmer.
            Functions with the prefix tot_ are deprecated.

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
               - DBG_TIMEOUT: To get printf's when a timer is set and when it
                              expires
               - DBG_TIMEOUT_INFO: To compile the function tot2_dumpTimeout()
                                   along with the sources that allows to
                                   dump the list of active timers using printf.

  \version  4.1.0
*/
/*============================================================================*/

/*=============================================================================
                              INCLUDE FILES
 =============================================================================*/
#include "netGlobal.h"


/*=============================================================================
                                 MACROS
 =============================================================================*/
/* Defines that tot2_xxx() functions are available */
#define TOT2_TIMEOUTS


#ifndef TOT_NUM_TIMEOUTS
/*!
 * Number of available timers for old timer functions. Set to 0 by default
 * that old timeouts are not available since no longer used anymore
 */
#define TOT_NUM_TIMEOUTS 0
#endif

#ifndef DBG_TIMEOUT_INFO
/* Enable the function tot2_dumpTimeout() */
#define DBG_TIMEOUT_INFO FALSE
#endif

#ifndef DBG_TIMEOUT
/* Enable debug information */
#define DBG_TIMEOUT FALSE
#endif

/* This macro is TRUE when the debugging options allow the dump of timers */
#define DBG_TIMEOUT_DUMP (DBG_TIMEOUT_INFO || DBG_TIMEOUT)

#if DBG_TIMEOUT_DUMP
/*!
 * Call the function to set descriptions since the debugging options are
 * enabled
 */
#define TOT2_SET_DESCRIPTION(tmr, str) tot2_setDescription(tmr, str)
#else
/* Do not set a description */
#define TOT2_SET_DESCRIPTION(tmr,str)
#endif

/*=============================================================================
                                  ENUMS
 =============================================================================*/
/*!
 *  \brief State of timers
 */
typedef enum totState
{
	/* The timer is running */
	TOT_RUNNING = 1,
	/* The timer expired */
	TOT_EXPIRED,
	/* Only for tot_...() functions, the timer does not exist */
	TOT_NOEXIST,
	/* Only for tot_...() functions, timer index too high */
	TOT_UNALLOW
} E_TOT_STATE;

/*=============================================================================
                        STRUCTURES AND OTHER TYPEDEFS
 =============================================================================*/

/*!
 * Type of the timer structture
 * \sa ST_TOT2_TMR
 */
typedef struct ST_TOT2_TMR s_tot2_Tmr_t;

/*!
 * Function pointer to a call-back function for a timer event
 *
 * @param p_tmr Pointer to the timer that fired this event
 * @param p_ctx Pointer to the context that was passed when setting the timer
 *              using tot2_setTmrTicks() or tot2_setTmrMs()
 *
 * @return 0 if the timer does not have to be called anymore
 * @return >0 A value in timer ticks for the timer to be started again. If the
 *            timer should be re-triggered in a certain time in ms, then the
 *            function tot2_msToTicks() must be used to convert ms in ticks.
 */
typedef uint32_t (*fp_tot2_Callback_t)(s_tot2_Tmr_t* p_tmr, void* p_ctx);

/*!
 * Structure of a timer
 */
struct ST_TOT2_TMR
{
  /*!
   * Current state of the timer
   * If the timer was not yet initialized this field has an undefined value
   */
  E_TOT_STATE e_tmrState;

  /*!
   * The number of ticks after this timer expires
   * This is an absolute value calculated from the actual timer tick on
   * to the end of the delay
   */
  uint32_t l_ticks;

  /*! Previous timer in chain */
  s_tot2_Tmr_t* p_tmrPrev;
  /*! Next timer in chain */
  s_tot2_Tmr_t* p_tmrNext;

  /*!
   * Callback function pointer. If set to a function this function will be
   * called when the timeout expires. If set to NULL, then the function
   * is not being called and the timer is most likely to be polled
   */
  fp_tot2_Callback_t fp_Callback;

  /*!
   * Context of the callback function
   * This is a pointer that can be used by the callback function at its
   * use
   */
  void* p_cbCtx;

  /*!
   * For debugging purposes a description can be set. This field is not
   * required
   */
  const char* p_desc;
};


/*==============================================================================
                          FUNCTION PROTOTYPES
==============================================================================*/

/*============================================================================*/
/*!
   \brief   Callback function from the hardware timer

            This function is given to the hardware driver as call back function
            for the timer events.

*/
/*============================================================================*/
void tot_tick (void);

/*============================================================================*/
/*!
   \brief   Initialisation of the timeout module

            This function calls the initialisation of a hardware timer and
            initializes all timeouts as provided.
            The hardware initialisation must return the number of ticks per
            second as an event counter in order to work with the absolute
            timer values.
*/
/*============================================================================*/
void  tot_init (void);

#if TOT_NUM_TIMEOUTS
/*============================================================================*/
/*!
   \brief   Setting up a timeout

   \param   pFunction Callback function to call when the timeout expires
   \param   uiTicks   Number of ticks after that the timeout expires

   \return  The handle of the timeout

   \deprecated Use functions tot2_xxx() instead
*/
/*============================================================================*/
uint8_t tot_setTimeout (void (*pFunction)(void), uint16_t uiTicks);

/*============================================================================*/
/*!
   \brief   Deactivates a timeout before the event has occured

   \param   ucTimeoutNr Handle of the timeout

   \deprecated Use functions tot2_xxx() instead
*/
/*============================================================================*/
void  tot_resetTimeout (uint8_t ucTimeoutNr);

/*============================================================================*/
/*!
   \brief   Returns the status of a specified timeout.

   \param   cHandle Handle of the timeout

   \return TOT_RUNNING : the timer hasn't expired yet
   \return TOT_NOEXIST : the timer has expired or has never been set before
   \return TOT_EXPIRED : timeout is expired
   \return TOT_UNALLOW : timeout number too big (unallowed)

   \deprecated Use functions tot2_xxx() instead
*/
/*============================================================================*/
uint8_t tot_getStatus (uint8_t cHandle);
#endif /* TOT_NUM_TIMEOUTS */

/*============================================================================*/
/*!
   \brief   This function calls the event functions from expired timers

            This function must be called as often as possible in order to
            handle the timers most accurately.

            Note that this function handles both, the deprecated timers as well
            as the new timer functions.
*/
/*============================================================================*/
void  tot_handleEvents (void);

/*============================================================================*/
/*!
   \brief   Waits for a specified number of timer ticks.

            This function blocks and waits until the specified number of ticks
            expired.
            This function is mainly used during initialisation.

   \param   u32_ticksToWait 	Number of timer ticks to wait.
*/
/*============================================================================*/
void  tot_delay (uint32_t u32_ticksToWait);

/*============================================================================*/
/*!
   \brief   Set a timer based on the number of timer ticks

            This function sets a timer based on the number of ticks of the timer
            interval. Note that on different platforms the timer interval might
            differ.
            See also tot_getTicksPerSec() and tot2_setTmrMs().

            This function adds the given timer to the list of timer at the
            position after the timer that expires before the given timer.

            If this function is being applied to a running timer, then the
            timer is being first reset and started again.

   \param   p_tmr Pointer to a timer variable. This timer must reside in a static
                  memory location.

   \param   l_ticks  Delay in system ticks. See tot_getTicksPerSec().

   \param   p_cbFunc Callback function pointer. If a function needs to be called
                     once the timeout expired then this function need to get
                     called. If this pointer is set to NULL then no function
                     is called and it is assumed, that the timer is used in
                     polled manner.
   \param   p_cbCtx  Pointer to a context variable, passed when calling a
                     callback function. Can be set to NULL when no callback
                     is being used.
*/
/*============================================================================*/
void  tot2_setTmrTicks (s_tot2_Tmr_t*      p_tmr,
                        uint32_t              l_ticks,
                        fp_tot2_Callback_t  p_cbFunc,
                        void*               p_cbCtx);

/*============================================================================*/
/*!
   \brief   Set a timer based on a timer interval in milliseconds.

            This function sets a timer based on an interval in milliseconds.
            It is intended to be platform independent.
            If the timebase (from hardware) has not the required resolution
            the timer interval is set at least to 1 hardware tick. Otherwise
            the timer ticks are rounded to a lower value.

            If this function is being applied to a running timer, then the
            timer is being first reset and started again.

   \param   p_tmr Pointer to a timer variable. This timer must reside in a static
                  memory location.

   \param   l_ms  Delay in milliseconds. If the timer resolution is less than
                  the required value the timeout is being rounded down. For
                  example, if a timer needs to be set with 5ms but the timer
                  resolution is 100 ticks / second (10ms) then the timer is
                  is still set to expire after 10ms. See tot_getTicksPerSec().

   \param   p_cbFunc Callback function pointer. If a function needs to be called
                     once the timeout expired then this function need to get
                     called. If this pointer is set to NULL then no function
                     is called and it is assumed, that the timer is used in
                     polled manner.
   \param   p_cbCtx  Pointer to a context variable, passed when calling a
                     callback function. Can be set to NULL when no callback
                     is being used.

   \sa tot2_setTmrTicks(), tot_getTicksPerSec()
*/
/*============================================================================*/
void  tot2_setTmrMs (s_tot2_Tmr_t*      p_tmr,
                     uint32_t              l_ms,
                     fp_tot2_Callback_t  p_cbFunc,
                     void*               p_cbCtx);



/*============================================================================*/
/*!
   \brief   Initialize a variable as a timer

            This function resets a timer variable. If the timer variable is
            already contained in the list then it is being removed first.
            To reset running timers normally the function tot2_resetTmr() is
            used.

   \param   p_tmr Pointer to a timer variable. This timer must reside in a static
                  memory location.
*/
/*============================================================================*/
void  tot2_initTmr(s_tot2_Tmr_t* p_tmr);

/*============================================================================*/
/*!
   \brief   Remove a running timer from the list

            Remove a running timer from the list of timers. It is being checked
            if the timer is running and then it is being removed from the list
            of timers. If the timer is not running then it is only be marked
            as TOT_NOEXIST.

   \param   p_tmr Pointer to a timer variable. This timer must reside in a static
                  memory location.
*/
/*============================================================================*/
void  tot2_resetTmr(s_tot2_Tmr_t* p_tmr);

/*============================================================================*/
/*!
   \brief   Retrigger a timer with a new value in number of ticks

            This function might be used to retrigger a running or an expired
            timer with a new timer value in number of ticks.

   \param   p_tmr   Pointer to a timer variable. This timer must reside in a
                    static memory location.
   \param   l_ticks Number of ticks after that the timer has to expire. See
                    also tot2_getTicksPerSec()
*/
/*============================================================================*/
void tot2_retriggerTmrTicks (s_tot2_Tmr_t*  p_tmr,
                             uint32_t          l_ticks);

/*============================================================================*/
/*!
   \brief   Retrigger a timer with a new value in milliseconds

            This function might be used to retrigger a running or an expired
            timer with a new timer value in number of milliseconds.

   \param   p_tmr  Pointer to a timer variable. This timer must reside in a
                   static memory location.
   \param   l_ms   Delay in milliseconds for the timer to expire. The delay is
                   calculated from the current time + l_ms.
*/
/*============================================================================*/
void tot2_retriggerTmrMs (s_tot2_Tmr_t*  p_tmr,
                          uint32_t          l_ms);

/*============================================================================*/
/*!
   \brief   Get the status of a timer as number of remaining ticks

            If the timer is still running this function returns the number
            of ticks before the timer expires. This function might be used
            to poll the timer.
            If the timer expired then this function returns 0.

            The behaviour of this function is undefined if the timer that
            the pointer p_tmr points to has not been initialized with
            tot2_setTmrTicks() or tot2_setTmrMs().

   \param   p_tmr Pointer to a timer variable. This timer must reside in a static
                  memory location.

   \return  The number of ticks until the specified timer expires. If the
            timer already expired this function returns 0
*/
/*============================================================================*/
uint32_t  tot2_getStatusTicks (const s_tot2_Tmr_t* p_tmr);

/*============================================================================*/
/*!
   \brief   Get the status of a timer as number of milliseconds before it
            expires.

            If the timer is still running this function returns the number
            of milliseconds before the timer expires. This function might be used
            to poll the timer.
            If the timer expired then this function returns 0.

            The behaviour of this function is undefined if the timer that
            the pointer p_tmr points to has not been initialized with
            tot2_setTmrTicks() or tot2_setTmrMs().

   \param   p_tmr Pointer to a timer variable. This timer must reside in a static
                  memory location.

   \return  The number of ticks until the specified timer expires. If the
            timer already expired this function returns 0

   \sa      tot2_getStatusTicks()
*/
/*============================================================================*/
uint32_t tot2_getStatusMs (const s_tot2_Tmr_t* p_tmr);

/*============================================================================*/
/*!
   \brief   Returns the state of a timer

            This function returns the status of the timer. It works similar
            to the functions tot2_getStatusMs() or tot2_getStatusTicks() with
            the difference that it does not calculate the remaining time for
            the timer to expire.
            In many cases this function is sufficient to check a timer and is
            especially on low performance platforms a faster function to
            check the state of the timer.

   \param   p_tmr Pointer to a timer variable. This timer must reside in a
                  static memory location.

   \return  TOT_RUNNING  The timer has not expired yet
   \return  TOT_EXPIRED  The timer expired

   \sa      tot2_getStatusTicks(), tot2_getStatusMs()
*/
/*============================================================================*/
E_TOT_STATE tot2_getStatus (const s_tot2_Tmr_t* p_tmr);

/*============================================================================*/
/*!
   \brief   Returns the number of ticks for a given value of milliseconds

            This function might be especially useful for calculating the number
            of ticks when returning from a callback routine to retrigger a
            timer.

            If the base timer is smaller than the time requested, e.g. the
            base timer tick is 10ms and the timeout of 5ms needs to be
            converted, then this function returns at least 1.

    \param  l_ms Time in milliseconds

    \return Number of timer events (ticks) for a given time in milliseconds
            based on the ticks per seconds from the timer interrupt.

    \sa     tot2_getTicksPerSec()
*/
/*============================================================================*/
uint32_t tot2_msToTicks (uint32_t l_ms);

/*============================================================================*/
/*!
   \brief   Calculates milliseconds based on the number of ticks

            This function converts a number of system ticks into milliseconds.
            It can be used e.g. to calculate the remaining time until a
            timer expires.

    \param  l_ticks Number of ticks

    \return Number of milliseconds until the timeout expires.

    \sa     tot2_msToTicks()
*/
/*============================================================================*/
uint32_t tot2_ticksToMs (uint32_t l_ticks);

/*============================================================================*/
/*!
   \brief   Set the description field of a timer

            This function might be useful for debugging. A pointer to a
            description can be set. The timer must be a pointer different
            to NULL.

   \param   p_tmr  The timer
   \param   p_desc A pointer to a description
*/
/*============================================================================*/
void tot2_setDescription (s_tot2_Tmr_t* p_tmr, const char* p_desc);

/*============================================================================*/
/*!
   \brief   Returns the number of ticks per second of the hardware platform

            This function returns the number of ticks per second that the
            hardware timer provides.

    \return Number of timer events (ticks) per second as the time base for
            timers.

    \sa     tot2_setTicksPerSec()
*/
/*============================================================================*/
uint16_t tot2_getTicksPerSec (void);

/*============================================================================*/
/*!
   \brief   Sets the number of ticks per second of the hardware platform

            This function sets the number of ticks per second that the
            hardware timer provides.

    \return Number of timer events (ticks) per second that was set before

    \sa     tot2_getTicksPerSec()
*/
/*============================================================================*/
uint16_t tot2_setTicksPerSec (uint16_t us_ticks);

/*============================================================================*/
/*!
   \brief   Returns the counter value of the timebase.

            This function returns the number of ticks since the timer module
            was initialized. The timer overflow occurs after 2^32 timer ticks
            which is for a tot2_getTicksPerSec() == 1000 after 49 days. After
            that the counter restarts at 0.

    \return Number of timer ticks since the initialisation of this module
*/
/*============================================================================*/
uint32_t tot2_getSysTicks (void);

/*============================================================================*/
/*!
   \brief   Utility function to check a given value against the current
            system tick counter.

            A typical example is, if in a function no timer can be used but
            a loop might must time out. Then this function can be used to
            check for the condition that the given time expired.

\code
            // System tick value when the time expired
            uint32_t l_ticksToExpire = tot2_getSysTicks();

            // Compute the expiration time
            l_ticksToExpire += tot2_msToTicks(TIME_TO_EXPIRE_IN_MS);

            do
             {
               ... loop ...
             }while(tot2_ticksToExpire(l_ticksToExpire))
\endcode

    \param  l_timeTicks The tick-count to check against the current system
                        tick counter.

    \return If l_timeTicks is greater than the current system ticks, this
            function returns the number of ticks that are left until the system
            tick counter reaches the value of l_timeTicks.
    \return 0 if the system tick counter is equal or greater than l_timeTicks.

    \sa     tot2_getSysTicks()
*/
/*============================================================================*/
uint32_t tot2_ticksToExpire (uint32_t l_timeTicks);

#if DBG_TIMEOUT || DBG_TIMEOUT_INFO
void tot2_dumpTimeout(void);
#endif

/*============================================================================*/
#endif  /* TIMEOUT_H */

