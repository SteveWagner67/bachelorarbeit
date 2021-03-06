#ifndef __KEY_MANAGEMENT_H__
#define __KEY_MANAGEMENT_H__
#ifndef __DECL_KEY_MANAGEMENT_H__
#define __DECL_KEY_MANAGEMENT_H__ extern
#endif

/*============================================================================*/
/*! \file   key_management.h

 \author � by STZEDN, Loerrach, Germany, http://www.stzedn.de

 \brief  Declaration of API function of the key management module

 Currently are only DHE keys supported

 \version  $Version$

 */
/*============================================================================*/

/*==============================================================================
 INCLUDE FILES
 ==============================================================================*/
#include "ssl.h"
#include "string.h"
/*==============================================================================
 MACROS
 ==============================================================================*/

#ifndef SSL_KM_DHE_MAX_REUSE
//! Default Maximum number of times a key will be reused
#define SSL_KM_DHE_MAX_REUSE 15
#endif

/*==============================================================================
 ENUMS
 ==============================================================================*/

/*==============================================================================
 STRUCTURES AND OTHER TYPEDEFS
 ==============================================================================*/

/*==============================================================================
 GLOBAL VARIABLE DECLARATIONS
 ==============================================================================*/

/*==============================================================================
 FUNCTION PROTOTYPES OF THE API
 ==============================================================================*/

/*============================================================================*/
/*!

 \brief     release the formerly reserved dhe key

 */
/*============================================================================*/
void km_dhe_releaseKey(void);

/*============================================================================*/
/*!

 \brief     Watch out if there's a dhe key available


 \return    a pointer to the dhe key or NULL if the key's expired


 */
/*============================================================================*/
//OLD-CW: gci_dhKey_t* km_dhe_getKey(void);
en_gciResult_t km_dhe_getKey(GciKeyId_t* dhKeyID);

/*============================================================================*/
/*!

 \brief     Init the dhe key management and generate a new dhe private keypair


 \return    TRUE  everything's OK
 \return    FALSE generation of dhe privatekey failed


 */
/*============================================================================*/
//OLD-CW: int km_dhe_init(void);
en_gciResult_t km_dhe_init();

/*============================================================================*/
#endif /* __KEY_MANAGEMENT_H__ */
