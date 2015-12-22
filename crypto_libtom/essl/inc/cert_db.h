#ifndef _CERT_DB_H_
#define _CERT_DB_H_
/*============================================================================*/
/*!
 \file   cert_db.h

 \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  API definitions for certificate manager

 \version  $Version$

 */
/*=============================================================================
 INCLUDE FILES
 ============================================================================*/
#include "stdint.h"
#include "stdlib.h"
#include "assert.h"
/*==============================================================================
 CONSTANTS
 ==============================================================================*/
#ifndef SSL_CDB_MAX_BUFFSIZE
/*! maximum size of the internal working buffer */
#if (SSL_RSA_MAX_KEY_SIZE < 2560)
/* minimum 2560 Bytes due to certificates that can be large */
#define SSL_CDB_MAX_BUFFSIZE      2560
#else
/* when the keysize grows, the buffer has to grow as well */
#define SSL_CDB_MAX_BUFFSIZE      GCI_RSA_MAX_KEY_SIZE
#endif
#endif

/*==============================================================================
 MACROS
 ==============================================================================*/
#ifndef SSL_USE_EFS
/*! Define to true if the EFS file system wrapper is available and
 *  should be used
 */
#define SSL_USE_EFS    FALSE
#endif

/*==============================================================================
 STRUCTURES AND OTHER TYPEDEFS
 ==============================================================================*/

typedef enum E_CDB_MEM_LOCATION
{
    /*! Not clear where it is located... */
    CDB_MEM_UNKNOWN,
    /*! Data is located in EFS */
    CDB_MEM_EFS,
    /*! Data is located in a static variable in linear memory */
    CDB_MEM_LINEAR

} e_cdbMemLoc_t;

typedef enum E_CDB_FORMAT_STATE
{
    /*! Not clear what format it got... */
    CDB_STATE_IS_UNKNOWN,
    /*! Certificate in BASE64 encoded Format without PEM headers */
    CDB_STATE_IS_ASCII,
    /*! Certificate in natural PEM Format */
    CDB_STATE_IS_PEM,

} e_cdbFState_t;

typedef struct
{
    /*! indicates whether the file is located in EFS or linear memory */
    e_cdbMemLoc_t e_memloc;
    /*! indicates the format of the data */
    e_cdbFState_t e_fstate;
    /*! length indicator used in case of e_fstate = CDB_IS_BIN
     *  or e_memloc = CDB_MEM_LINEAR
     */
    int i_length;

    union
    {
        /*! e_memloc = CDB_MEM_LINEAR */
        const char* pc_linear;
        /*! e_memloc = CDB_MEM_EFS */
        const char* pc_fName;
    } filepointer;

} s_cdbCert_t;

/*==============================================================================
 GLOBAL VARIABLES
 ==============================================================================*/

/*==============================================================================
 FUNCTION PROTOTYPES OF THE API
 ==============================================================================*/

/*============================================================================*/
/*!
 \brief   read a certificate

 This function reads the requested certificate from the appropriate
 location to the destinationbuffer.
 The output will always be base64 decoded, binary data

 \param   pcdbt_cert      Pointer to a certificate structure

 \param   pc_dest         Pointer to the destination to save the data

 \param   pcwt_len        In: Maximum size of reserved memory
 Out: Length of requested data

 \return  TRUE            Operation successful
 \return  FALSE           Operation failed

 */
/*============================================================================*/
int cdb_read(s_cdbCert_t* pcdbt_cert, uint8_t* pc_dest, size_t* pcwt_len);

/*============================================================================*/
/*!
 \brief   read a certificate to internal buffer

 This function reads the requested certificate from the appropriate
 location to an internal buffer and returns a pointer to the location of
 the read certificate. The requested certificate will be Base64 decoded
 and is available as binary data.
 After usage of the read data, the buffer has to be freed' by calling
 cdb_free()

 \param   pcdbt_cert      Pointer to a certificate structure

 \param   pcwt_len        In:  don't care
 Out: Length of requested data

 \return  Pointer to the memory where the data can be read from
 \return  NULL on error!

 */
/*============================================================================*/
uint8_t* cdb_read2buf(s_cdbCert_t* pcdbt_cert, size_t* pcwt_len);

/*============================================================================*/
/*!
 \brief   free's the buffered memory

 erases the memory in the workingbuffer

 */
/*============================================================================*/
void cdb_free(void);

/*============================================================================*/
/*!
 \brief   free's the buffered memory

 resets only the workingbuffer length paramater but has the same effect
 as cdb_free without the costs of securely overwriting the data.
 Use this function carefully -> better use cdb_free
 This function doesn't destroy security critical data in the buffer!

 */
/*============================================================================*/
void cdb_drop(void);

#if SSL_USE_EFS
/*============================================================================*/
/*!
 \brief   This function initialises a PEM file

 This function strips off PEM headers/footers, \\r and \\n, Base64Decodes
 the whole thing and saves the result in the same filedescriptor

 \param   pcdbt_cert      Pointer to a certificate structure

 \param   pc_fileName     Pointer to the filename that should be read

 \return  TRUE            Operation successful
 \return  FALSE           Operation failed

 */
/*============================================================================*/
int cdb_initPEM_EFS(s_cdbCert_t* pcdbt_cert, const char* pc_fileName);

/*============================================================================*/
/*!
 \brief   This function initialises a cert located in EFS

 Initialisation of a certificate, located into EFS.
 Base64 encoded OpenSSL Certificate without the headers.
 Remember that it must not contain \\r, \\n or PEM headers/footers !

 \param   pcdbt_cert      Pointer to a certificate structure

 \param   pc_fileName     Pointer to the filename that should be read

 \return  TRUE            Operation successful
 \return  FALSE           Operation failed

 */
/*============================================================================*/
int cdb_initCert_EFS(s_cdbCert_t* pcdbt_cert, const char* pc_fileName);
#endif /* #if SSL_USE_EFS */

/*============================================================================*/
/*!
 \brief   This function initialises a cert located in linear memory

 Initialisation of a certificate, located into linear(static) memory.
 Base64 encoded OpenSSL Certificate without the headers

 \param   cdbt_cert       Pointer to a certificate structure

 \param   pc_cert         Pointer to linear memory where the cert can be read from

 \return  TRUE            Operation successful
 \return  FALSE           Operation failed

 */
/*============================================================================*/
int cdb_initCert_linear(s_cdbCert_t* cdbt_cert, const char* pc_cert);

#endif /*!_CERT_DB_H_ */
