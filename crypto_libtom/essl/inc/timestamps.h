/*============================================================================*/
/**
 * \file    timestamps.h
 *
 * \author  Kofi
 *
 * \brief   Timestamps for performance measurements
 *
 */
/*============================================================================*/

/*============================================================================*/

/*============================================================================*/
/*                                INCLUDES                                    */
/*============================================================================*/
#ifndef TIMESTAMPS_H_
#define TIMESTAMPS_H_


/*============================================================================*/
/*                          FUNCTION PROTOTYPES                               */
/*============================================================================*/

/*============================================================================*/
/**
 * \brief   Get the timestamp for a specific tag
 *
 * @param   Tag - USER defined tags
 *
 */
/*============================================================================*/
void timeStamp(uint8_t tag);


/*============================================================================*/
/**
 * \brief   Transmit timestamps to console or a file
 *
 *          This function is used to transmit all computed timestamps to console
 *          or a file
 *
 *@param    None
 */
/*============================================================================*/
void transmitStamps(void);


/*============================================================================*/
/**
 * \brief      Transmit timestamps byte by byte
 *
 *             This function is used to transmit timestamps byte by byte
 *
 * @param      byte - byte to be transmmitted
 *
 */
/*============================================================================*/
void txHexByte(uint8_t byte);


#endif /* TIMESTAMPS_H_ */
