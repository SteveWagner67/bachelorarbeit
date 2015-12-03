/*================================================================================================*/
/*!
 \file   cert_db.c

 \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

 \brief  Certificate wrapper API

 \version  $Version$
 */

#include "cert_db.h"
#include "ssl_certHelper.h"
#if SSL_USE_EFS
#include "efs.h"
#endif
/*=============================================================================
 LOCAL CONSTANTS
 =============================================================================*/

/*=============================================================================
 LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
 =============================================================================*/

/*=============================================================================
 LOCAL DEFINES
 =============================================================================*/
#define	LOGGER_ENABLE		DBG_CERT_DB_MODULE
#include "logger.h"

/*=============================================================================
 LOCAL MACROS
 =============================================================================*/

#define IS_BASE64(x) \
        ((x > '.') && (x < ':'))  \
     || ((x > '@') && (x < '['))  \
     || ((x > '`') && (x < '{')) \
     || (x == '+') || (x == '=')

/*=============================================================================
 LOCAL VARIABLES
 =============================================================================*/
static uint8_t workingBuffer[SSL_CDB_MAX_BUFFSIZE];
static size_t workingBufLen;

/*==============================================================================
 LOCAL FUNCTION PROTOTYPES
 ==============================================================================*/

#if SSL_USE_EFS
static int cdb_readStripPEM(uint8_t* pc_dest, size_t* pcwt_destLen, const char* pc_fileName);
static int cdb_readCert(uint8_t* pc_dest, size_t* pcwt_destLen, const char* pc_fileName);
#endif /* SSL_USE_EFS */
static void cdb_erase(size_t cwt_length);

/*==============================================================================
 LOCAL FUNCTIONS
 ==============================================================================*/
#if SSL_USE_EFS
/*============================================================================*/
/*!
 \brief   Read a PEM file from the filesystem

 This function reads a PEM file from the emBetter File System (EFS).
 Its features are to remove the leading and trailing PEM stuff like
 "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN CERTIFICATE-----" and all its
 variations and END versions.
 It removes CarriageReturns and LineFeeds as well

 When calling this function watch out to reserve enough memory in advance.

 \param   pc_dest         Pointer to the destination where to save the read
 file. Needed Memory has to be allocated before.

 \param   pcwt_destLen    In: Maximum reserved Memory
 Out: Used Memory when certificate has been read

 \param   pc_fileName     The name and path of the file that has to be read

 \return  TRUE            Everything went fine

 \return  FALSE           An error occured. Possible reasons are:
 FileOpen wasn't successful -> pcwt_destLen = 0
 Buffer is completely filled -> pcwt_destLen = Maxlen

 */
/*============================================================================*/
static int cdb_readStripPEM(uint8_t* pc_dest, size_t* pcwt_destLen, const char* pc_fileName)
{
    td_efs_FILE* p_filedesc;
    int i_readData, retVal;
    unsigned char uc_readData, uc_pem_state;
    size_t cwt_realLen;
    uc_pem_state = 0;
    cwt_realLen = 0;
    retVal = FALSE;
    /*!
     * open the file and get the filedescriptor
     */
    if((p_filedesc = efs_fopen(pc_fileName, "r")) == NULL)
    {
#if DBG_SSL
        SSL_DBG_PRINTF(SSL_DBG_STRING " %s could not be opened", DBG_FILE_NAME, __LINE__, NULL, pc_fileName);
#endif
    }
    else
    {

        /*!
         * read the file from the filesystem to the linear memory and remove
         * PEM headers/footers, CarriageReturn and LineFeed
         */
        while(cwt_realLen < *pcwt_destLen)
        {
            if((i_readData = efs_fgetc(p_filedesc)) != EFS_EOF)
            {
                uc_readData = (unsigned char)i_readData;
                /*
                 * check for CR and LF, and if found don't copy it
                 */
                if((uc_readData == 0x0A) || (uc_readData == 0x0D))
                continue;
                /*
                 * check for header/footer of PEM Files "-----BEGIN/END BLAH-----"
                 */
                else if(uc_readData == '-')
                {
                    /* set uc_pem_state to indicate when to jump out,
                     * and for identification of possible BOF's
                     * set to 1 on first run - "-----BEGIN BLAH-----"
                     * set to 2 on second run - "-----END BLAH-----" - to indicate that the
                     * whole file has been read, also if the buffer has been completely
                     * filled what could mean dataloss as well
                     */
                    if(uc_pem_state++)
                    break;
                    //jump over leading '-'
                    do
                    {
                        i_readData = efs_fgetc(p_filedesc);
                        uc_readData = (unsigned char)i_readData;
                    }while(uc_readData == '-');
                    //jump over text
                    do
                    {
                        i_readData = efs_fgetc(p_filedesc);
                        uc_readData = (unsigned char)i_readData;
                    }while(uc_readData != '-');
                    //jump over trailing '-'
                    do
                    {
                        i_readData = efs_fgetc(p_filedesc);
                        uc_readData = (unsigned char)i_readData;
                    }while(uc_readData == '-');

                    if(IS_BASE64(uc_readData))
                    {
                        *(pc_dest + cwt_realLen) = uc_readData;
                        cwt_realLen++;
                    }

                }
                /*
                 * a base64 encoded letter was found so copy it
                 */
                else if(IS_BASE64(uc_readData))
                {
                    *(pc_dest + cwt_realLen) = uc_readData;
                    cwt_realLen++;
                }
#if DBG_SSL > 1
                else
                {
                    SSL_DBG_PRINTF(SSL_DBG_STRING " Non-BASE64 Char: %c", DBG_FILE_NAME, __LINE__, NULL, uc_readData);
                }
#endif
            } /* if(i_readData != EOF) */
            else
            {
#if DBG_SSL > 1
                SSL_DBG_PRINTF(SSL_DBG_STRING " EOF hit", DBG_FILE_NAME, __LINE__, NULL);
#endif
                retVal = TRUE;
                break;
            }

        } /* while */
        // buffer is full?
        if(cwt_realLen == *pcwt_destLen)
        {
#if DBG_SSL > 1
            SSL_DBG_PRINTF(SSL_DBG_STRING " Buffer has been completely filled!", DBG_FILE_NAME, __LINE__, NULL);
#endif
            if((i_readData = efs_fgetc(p_filedesc)) == EFS_EOF)
            {
                retVal = TRUE;
            }
        }
        if(uc_pem_state == 2)
        {
            retVal = TRUE;
        }
        //! try to close the file
        if(efs_fclose(p_filedesc) != 0)
        {
#if DBG_SSL
            SSL_DBG_PRINTF(SSL_DBG_STRING " %s could not be closed", DBG_FILE_NAME, __LINE__, NULL, pc_fileName);
#endif
        }
    }/* efs_fopen != NULL */

    *pcwt_destLen = cwt_realLen;

    return retVal;
}

/*============================================================================*/
/*!
 \brief   reads the whole file into the buffer

 This function tries to read the whole file, given as argument, into the
 given buffer of size *pcwt_destLen.

 \param   pc_dest         Pointer to the destination to save the requested data

 \param   pcwt_destLen    In:  Maximum size of reserved memory
 Out: Length of requested data

 \param   pc_fileName     Name of the file that should be read

 \return  TRUE            successful
 \return  FALSE           not successful

 */
/*============================================================================*/
static int cdb_readCert(uint8_t* pc_dest, size_t* pcwt_destLen, const char* pc_fileName)
{
    td_efs_FILE* p_filedesc;
    int i_readData, retVal;
    size_t cwt_realLen;

    retVal = FALSE;
    cwt_realLen = 0;

    if((p_filedesc = efs_fopen(pc_fileName, "r")) == NULL)
    {
#if DBG_SSL
        SSL_DBG_PRINTF(SSL_DBG_STRING " %s could not be opened", DBG_FILE_NAME, __LINE__, NULL, pc_fileName);
#endif
    }
    else
    {
        /*!
         * read the file from the filesystem to the linear memory
         */
        while(cwt_realLen < *pcwt_destLen)
        {
            if((i_readData = efs_fgetc(p_filedesc)) != EFS_EOF)
            {
                *(pc_dest + cwt_realLen) = (unsigned char)i_readData;
                cwt_realLen++;
            } /* if(i_readData != EOF) */
            else
            {
#if DBG_SSL > 1
                SSL_DBG_PRINTF(SSL_DBG_STRING " EOF hit", DBG_FILE_NAME, __LINE__, NULL);
#endif
                retVal = TRUE;
                break;
            }

        } /* while */
        // buffer is full?
        if(cwt_realLen == *pcwt_destLen)
        {
#if DBG_SSL > 1
            SSL_DBG_PRINTF(SSL_DBG_STRING " Buffer has been completely filled!", DBG_FILE_NAME, __LINE__, NULL);
#endif
            if((i_readData = efs_fgetc(p_filedesc)) == EFS_EOF)
            {
                retVal = TRUE;
            }

        }
        //! try to close the file
        if(efs_fclose(p_filedesc) != 0)
        {
#if DBG_SSL
            SSL_DBG_PRINTF(SSL_DBG_STRING " %s could not be closed", DBG_FILE_NAME, __LINE__, NULL, pc_fileName);
#endif
        }
    }/* efs_fopen != NULL */

    *pcwt_destLen = cwt_realLen;

    return retVal;
}
#endif /* #if SSL_USE_EFS */
/*============================================================================*/
/*!
 \brief   erase's the buffered memory

 erases the workingbuffer. if lengthargument is bigger that 0 it erases
 only the given length, otherwise it erases the whole workingbuffer

 \param   cwt_length      Optional length that should be freed'

 \return  TRUE            successful
 \return  FALSE           not successful

 */
/*============================================================================*/
static void cdb_erase(size_t cwt_length)
{
	GciResult_t err;


    if (cwt_length && (cwt_length < sizeof(workingBuffer)))
    {
        //OLD-CW: cw_prng_read(workingBuffer, cwt_length);
        err = gci_rng_gen(cwt_length, workingBuffer);
        if(err != GCI_OK)
        {
        	//TODO return error state
        }
    }
    else
    {
        //OLD-CW: cw_prng_read(workingBuffer, sizeof(workingBuffer));
        err = gci_rng_gen(sizeof(workingBuffer), workingBuffer);
        if(err != GCI_OK)
        {
        	//TODO return error state
        }
    }

    workingBufLen = 0;
}

/*=============================================================================
 API FUNCTIONS
 =============================================================================*/

/*==============================================================================
 int cdb_read(s_cdbCert_t* pcdbt_cert, uint8_t* pc_dest, size_t* pcwt_len)
 - read a certificate
 ==============================================================================*/
int cdb_read(s_cdbCert_t* pcdbt_cert, uint8_t* pc_dest, size_t* pcwt_len)
{
    assert(pcdbt_cert != NULL);
    assert(pc_dest != NULL);
    assert(pcwt_len != NULL);

    int retVal = FALSE;

    switch (pcdbt_cert->e_fstate)
    {
    case CDB_STATE_IS_ASCII:
        if (pcdbt_cert->e_memloc == CDB_MEM_EFS)
        {
#if SSL_USE_EFS
            size_t cwt_realLen;
            cwt_realLen = *pcwt_len;
            if(cdb_readCert(pc_dest, &cwt_realLen, pcdbt_cert->filepointer.pc_fName))
            {

                *pcwt_len = sslCert_decodeBase64(pc_dest, *pcwt_len, (const char*)pc_dest, cwt_realLen);
                if(*pcwt_len)
                retVal = TRUE;

            }
#else
            LOG_ERR("EFS not available");
#endif
        }
        else if (pcdbt_cert->e_memloc == CDB_MEM_LINEAR)
        {
            *pcwt_len = sslCert_decodeBase64(pc_dest, *pcwt_len,
                    pcdbt_cert->filepointer.pc_linear, pcdbt_cert->i_length);
            if (*pcwt_len)
                retVal = TRUE;
        }
        else
        {
            LOG_ERR("Input of not supported type");
        }
        break;
    case CDB_STATE_IS_PEM:
        if (pcdbt_cert->e_memloc == CDB_MEM_EFS)
        {
#if SSL_USE_EFS
            size_t cwt_realLen;
            cwt_realLen = *pcwt_len;
            if(cdb_readStripPEM(pc_dest, &cwt_realLen, pcdbt_cert->filepointer.pc_fName))
            {
                *pcwt_len = sslCert_decodeBase64(pc_dest, *pcwt_len, (const char*)pc_dest, cwt_realLen);
                if(*pcwt_len)
                retVal = TRUE;
            }
#else
            LOG_ERR("EFS not available");
#endif
        }
        else
        {
            LOG_ERR("Input of not supported type");
        }

        break;
    default:
        LOG1_INFO("Default case");
        break;
    }

    return retVal;
}
/*==============================================================================
 uint8_t* cdb_read2buf(s_cdbCert_t* pcdbt_cert, size_t* pcwt_len)
 - This function reads the b64 decoded certificate into an internal buffer
 ==============================================================================*/
uint8_t* cdb_read2buf(s_cdbCert_t* pcdbt_cert, size_t* pcwt_len)
{
    uint8_t* retVal;
    size_t cwt_bufSize;

    retVal = NULL;
    cwt_bufSize = sizeof(workingBuffer);
    if (cdb_read(pcdbt_cert, workingBuffer, &cwt_bufSize))
    {
        retVal = workingBuffer;
        workingBufLen = cwt_bufSize;
        *pcwt_len = cwt_bufSize;
    }

    return retVal;

}
/*==============================================================================
 void cdb_free(void)
 - erases the memory in the workingbuffer
 ==============================================================================*/
void cdb_free(void)
{
    cdb_erase(workingBufLen);
}

/*==============================================================================
 void cdb_drop(void)
 - pseudo-free's the workingbuffer
 ==============================================================================*/
void cdb_drop(void)
{
    workingBufLen = 0;
}
#if SSL_USE_EFS
/*==============================================================================
 int cdb_initPEM_EFS(s_cdbCert_t* pcdbt_cert, const char* pc_fileName)
 - This function initialises a PEM file located in EFS
 ==============================================================================*/
int cdb_initPEM_EFS(s_cdbCert_t* pcdbt_cert, const char* pc_fileName)
{
    assert(pcdbt_cert != NULL);
    assert(pc_fileName != NULL);

    size_t cwt_bufLen;
    int retVal;
    cwt_bufLen = sizeof(workingBuffer);
    retVal = FALSE;

    //! read the PEM file from efs, strip PEM stuff and write to workbuffer
    if(cdb_readStripPEM(workingBuffer, &cwt_bufLen, pc_fileName) == TRUE)
    {
        // set default values
        pcdbt_cert->e_fstate = CDB_STATE_IS_PEM;
        pcdbt_cert->e_memloc = CDB_MEM_EFS;
        pcdbt_cert->filepointer.pc_fName = pc_fileName;
        pcdbt_cert->i_length = workingBufLen = cwt_bufLen;
        retVal = TRUE;
    }
    else
    {
        LOG_ERR("cdb_readStripPEM not successful on %s", pc_fileName);
    }

    (void)cdb_free();

    return retVal;
}

/*==============================================================================
 int cdb_initCert_EFS(s_cdbCert_t* pcdbt_cert, const char* pc_fileName)
 - This function initialises a cert located in EFS
 ==============================================================================*/
int cdb_initCert_EFS(s_cdbCert_t* pcdbt_cert, const char* pc_fileName)
{
    assert(pcdbt_cert != NULL);
    assert(pc_fileName != NULL);

    size_t cwt_bufLen;
    int retVal;

    cwt_bufLen = sizeof(workingBuffer);
    retVal = FALSE;

    pcdbt_cert->e_memloc = CDB_MEM_EFS;
    pcdbt_cert->e_fstate = CDB_STATE_IS_ASCII;

    if(cdb_readCert(workingBuffer, &cwt_bufLen, pc_fileName))
    {
        retVal = TRUE;
    }
    else
    {
        LOG_ERR("cdb_readStripPEM not successful on %s", pc_fileName);
    }

    (void)cdb_free();

    return retVal;
}
#endif /* #if SSL_USE_EFS */
/*==============================================================================
 int cdb_initCert_linear(s_cdbCert_t* pcdbt_cert, const char* pc_cert)
 - This function initialises a cert located in linear memory
 ==============================================================================*/
int cdb_initCert_linear(s_cdbCert_t* pcdbt_cert, const char* pc_cert)
{
    assert(pcdbt_cert != NULL);
    assert(pc_cert != NULL);

    pcdbt_cert->e_memloc = CDB_MEM_LINEAR;
    pcdbt_cert->e_fstate = CDB_STATE_IS_ASCII;
    pcdbt_cert->filepointer.pc_linear = pc_cert;
    pcdbt_cert->i_length = strlen(pc_cert);
    return TRUE;
}

