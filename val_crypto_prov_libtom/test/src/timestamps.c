/*
#include "tls_main.h"
#include "stm32f4xx_hal.h"
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "timestamps.h"


/*
TIM_TypeDef* uctimer2 = TIM2_BASE;

#define __HAL_TIM_GetCounter(__HANDLE__) ((__HANDLE__)->Instance->CNT)
*/
/*
static unsigned int nStamps = 0;
static uint32_t stamps[128];

static const uint8_t hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
*/

/* Compute timestamps and tags */
void timeStamp(uint8_t tag) {
}

/* Transmit all computed timestams  */
 void transmitStamps(void) {
}

/* Transmit timestamp byte by byte */
void txHexByte(uint8_t byte) {
}