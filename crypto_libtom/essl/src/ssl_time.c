/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_time.c                                                 */
/*                                                                           */
/*  FUNCTIONS:                                                               */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*   This module implements functions for handling time and date.            */
/*                                                                           */
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
/*  MODIFICATION HISTORY: (Optional for DSEE files)                          */
/*                                                                           */
/*  Date        Person        Change                                         */
/*  ====        ======        ======                                         */
/*  28.03.03     WAM           Initial version                               */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*****************************************************************************/

#include "crypto_wrap.h"
#include "ssl_time.h"

/*** Defines ****************************************************************/

/*** Global Variables *******************************************************/

/*** Local Variables ********************************************************/

/* Table with days till the indicated month */
static const uint16_t uiDaysInYear[] =
{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

/*** Forward declarations ***************************************************/

/* static size_t daysFromStart(size_t year,
 size_t month,
 size_t day);
 */

/*** Local Functions ********************************************************/

/****************************************************************************/
/* daysFromOrigin()                                                          */
/****************************************************************************/
/*! \brief Calculates number of days since 1.1.1970.
 *
 *  This function calculates the number of days between the specified date
 *  and the 1. January 1970. Leap years are supported.
 *
 *  \param year
 *  \param month
 *  \param day
 *  \return Number of days since 1.1.1970
 */
/* *********************************************************************** */

static size_t daysFromOrigin(size_t year, size_t month, size_t day)
{
    size_t years;
    size_t days;
    size_t leaps;

#if 0
    /* Years since the origin */
    years= year - 1970;

    //sj watch out for real calculation of a leap year
    /*
     *  If ((Jahreszahl Mod 4) == 0
     *      And (Jahreszahl Mod 100) != 0)
     *      Or (Jahreszahl Mod 400) == 0
     *     Schaltjahr = True
     *  Else
     *     Schaltjahr = False
     */
    /* sj so this isn't really correct ;) */
    /* Leap years since origin, 1970 wasn't a leap year */
    leaps= (years + 1) / 4;
#endif
    leaps = 0;

    for (years = 1970; years <= year; years++)
        if (((years % 4 == 0) && (years % 100 != 0)) || (years % 400 == 0))
            leaps++;

    years = year - 1970;

    days = uiDaysInYear[month - 1] + years * 365 + leaps + day - 1;

    /* Is the actual year a leap year and is month not Jan or Feb */
    if ((month > 2)
            && (((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0)))
    {
        days++;
    }

    return (days);
}

/*** Global Functions *******************************************************/

/****************************************************************************/
/* unixTime()                                                               */
/****************************************************************************/
uint32_t unixTime(uint8_t *aucTimeString)
{
    /* aucTimeString is C-like string (terminated by \0) */
    uint32_t uiSeconds;
    uint16_t uiYear;
    uint8_t uiMonth;
    uint8_t uiDay;

    /* WAMs DevNote: is there a problem because of little/big endian */
    /* TG: String is not endian sensitive */
    uiYear = (aucTimeString[0] & 0x0F) * 1000 + (aucTimeString[1] & 0x0F) * 100
            + (aucTimeString[2] & 0x0F) * 10 + (aucTimeString[3] & 0x0F);

    uiMonth = (aucTimeString[4] & 0x0F) * 10 + (aucTimeString[5] & 0x0F);

    uiDay = (aucTimeString[6] & 0x0F) * 10 + (aucTimeString[7] & 0x0F);

    uiSeconds = 86400L * daysFromOrigin(uiYear, uiMonth, uiDay);

    uiSeconds += 36000L * (aucTimeString[8] & 0x0F) + /* Tens of hours */
    3600L * (aucTimeString[9] & 0x0F) + /* hours */
    600L * (aucTimeString[10] & 0x0F) + /* Tens of minutes */
    60L * (aucTimeString[11] & 0x0F); /* minutes */

    if (aucTimeString[12] == '\0')
    /* No seconds field present */
    {
        return (uiSeconds);
    }

    uiSeconds += 10L * (aucTimeString[12] & 0x0F) + /* Tens of seconds */
    (aucTimeString[13] & 0x0F); /* seconds */

    return (uiSeconds);
}

