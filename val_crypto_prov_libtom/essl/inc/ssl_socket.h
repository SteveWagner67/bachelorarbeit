#ifndef _SSL_SOCKET_H_
#define _SSL_SOCKET_H_
/*============================================================================*/
/*!
    \file   ssl_socket.h

    \author � by STZ-EDN, Loerrach, Germany, http://www.embetter.de

    \brief  This is the API Reference for the usage of the SSL module

  \version  $Version$

*/
/*==============================================================================
                                 INCLUDE FILES
==============================================================================*/
#include "ssl.h"
#include "ssl_conf.h"
/*==============================================================================
                                   CONSTANTS
==============================================================================*/


/*==============================================================================
                                    MACROS
==============================================================================*/


/*==============================================================================
                         STRUCTURES AND OTHER TYPEDEFS
==============================================================================*/


/*==============================================================================
                               GLOBAL VARIABLES
==============================================================================*/


/*==============================================================================
                        FUNCTION PROTOTYPES OF THE API
==============================================================================*/
/*============================================================================*/
/*!
    \brief  Initialize the SSL Module, independent of General Contexts and so on

        Resets the whole Module by calling sslSoc_killall()
        and every socket is set to state E_SSL_SOCKET_UNUSED

*/
/*============================================================================*/
void SSL_init(void);

/*============================================================================*/
/*!
    \brief  Initialize SSL General Context

        Resets the whole General Context to the default values

    \param SSLctx pointer to current SSL general context
    \param Keytype is the type of key used for authentification (RSA/ECDSA)

*/
/*============================================================================*/

void sslSoc_initSett(s_sslSett_t* ps_sslSett, e_sslKeyType_t keyType);
/*============================================================================*/
/*!
    \brief  Free SSL General Context

        Cleans up the whole SSL general context and free's all allocated memory

    \param SSLctx pointer to current SSL general context

*/
/*============================================================================*/
void sslSoc_freeSett(s_sslSett_t* ps_sslSett);

/*============================================================================*/
/*!
    \brief  Set the read and write functionpointer for the generic socket interface

        This function sets the functionpointers for the read and write routine
        of the socket interface that is intended to be used.
        Example implementation are available for the emBetter TCP/IP stack and
        Windows Sockets(winsock2).
        Please consider wssl_trg.c/h for these examples.

    \param SSLctx pointer to SSL general context
    \param read   pointer to the readfunction
    \param write  pointer to the writefunction

*/
/*============================================================================*/
void sslSoc_setReadWrite(s_sslSett_t* ps_sslSett, fp_ssl_readHandler read, fp_ssl_writeHandler write);

/*============================================================================*/
/*!
    \brief  Set the functionpointer to read the current time of day

        This function sets the functionpointer for the routine that should
        return the current time of day, that is needed for verification of
        the received certificates.
        Example implementations are available for multiple platforms.
        Please consider wssl_trg.c/h for these examples.
        NB: This MUST be done before using the general SSL context!
        If the verification should be passed over,
        what is a deep security hole,
        call this function with the parameter getTime set to 0.
        It is assumed that the return value of the function is in the format
        of the __linux time.

    \param SSLctx   pointer to SSL general context
    \param getTime  pointer to the function

*/
/*============================================================================*/
void sslSoc_setTimeFunc(s_sslSett_t* ps_sslSett, fp_ssl_getCurrentTime getTime);

/*============================================================================*/
/*!
    \brief  Sets the default Client Authentication Behavior

        This sets the default Client Authentication behavior of a SSL socket
        that will be derived from this SSL General Context

        The following levels can be set:
        behavior is depending on role(client or server)

        \b E_SSL_NO_AUTH

            - \c Client: There won't be sent a certificate even if one exists
                         and a CertificateRequest has been received

            - \c Server: The CertificateRequest won't be sent

        \b E_SSL_SHOULD_AUTH

            - \c Client: If we receive a CertificateRequest
                         we will send our Certificate and the CertificateVerify

            - \c Server: The CertificateRequest will be sent and if the client
                         sends his certificate the further handshake handling
                         for client authentication will be processed.
                         If the client sends no certificate the handshake will
                         go on without client authentication.

        \b E_SSL_MUST_AUTH

            - \c Client: If we receive a CertificateRequest
                         we will send our Certificate and the CertificateVerify.
                         If we do not receive a CertificateRequest the handshake
                         will be cancelled.

            - \c Server: The CertificateRequest will be sent and if the client
                         doesn't send his certificate the handshake will be canceled.

        \b E_SSL_MUST_VERF_SRVCERT

            - \c Client: This enables verification of the Certificate that
                         has been sent by the server.

            - \c Server: No change in behaviour.

        \b E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_NO_AUTH

            - \c Combination of \ref E_SSL_NO_AUTH and \ref E_SSL_MUST_VERF_SRVCERT

        \b E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_SHOULD_AUTH

            - \c Combination of \ref E_SSL_SHOULD_AUTH and \ref E_SSL_MUST_VERF_SRVCERT

        \b E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_MUST_AUTH

            - \c Combination of \ref E_SSL_MUST_AUTH and \ref E_SSL_MUST_VERF_SRVCERT


    \param SSLctx  pointer to current SSL general context
    \param e_level effective authentication level

*/
/*============================================================================*/
void sslSoc_setAuthLvl(s_sslSett_t* ps_sslSett, e_sslAuthLevel_t e_level);

/*============================================================================*/
/*!
    \brief  Sets version constraints

        This function sets the minimal required and maximal allowed versions
        supported by an SSL Context. Every derived SSL socket will check for
        these constraints excepting when an explicit version has been
        associated by sslSoc_setCtxVer(s, v);

        Default initialized values can be set in wssl.h
        see:
        - \c SSL_MIN_SSL_TLS_VERSION
        - \c SSL_MAX_SSL_TLS_VERSION

        The following Versions are supported at the moment:

          - \b E_SSL_3_0   - SSL Version 3.0 communication

          - \b E_TLS_1_0   - TLS Version 1.0 communication, identifying as SSL 3.1

          - \b E_TLS_1_1   - TLS Version 1.1 communication, identifying as SSL 3.2

          - \b E_VER_DCARE - If only one constraint is desired,
                           please set the second constraint to \c E_VER_DCARE
                           e.g. <tt>sslSoc_setVer(&ctx, E_TLS_1_0, E_VER_DCARE);</tt>

        For future releases planned:

          - \b E_TLS_1_2 - TLS Version 1.2 communication
                         see http://www.ietf.org/html.charters/tls-charter.html
                         for more information on this standard in draft

    \param SSLctx pointer to current SSL general context
    \param min The minimal version that has to be used
    \param max The maximal version that should be supported

*/
/*============================================================================*/
void sslSoc_setVer(s_sslSett_t* ps_sslSett, e_sslVer_t min, e_sslVer_t max);

/*============================================================================*/
/*!
    \brief  Set the default behavior when a communication partner tries to start a renegotiation

        This enables/disables the default behavior when in a SSL socket that
        has been derived from this general context receives the request to
        renegotiate session parameters.

        \sa sslSoc_setCtxReneg

    \param SSLctx Pointer to current SSL general context
    \param enable To enable renegotiation set this flag to TRUE, otherwise to FALSE

    \return Returns the value that was set before

*/
/*============================================================================*/
uint8_t sslSoc_setReneg(s_sslSett_t* ps_sslSett, uint8_t enable);

/*============================================================================*/
/*!
    \brief  Set the Session Timeout of a cached Session

        This sets the session timeout of a session that has been cached for
        session resumption.
        After this time, the session will be erased from the session cache.

    \param SSLctx pointer to current SSL general context
    \param ui_timeoutInSeconds space of time (in seconds) when session resumption should be possible

*/
/*============================================================================*/
void sslSoc_setSessTimeout(s_sslSett_t* ps_sslSett, uint32_t ui_timeoutInSeconds);

/*============================================================================*/
/*!
    \brief  Assign a former initialised CA certificate list

        This function sets the parameter p_list_head as CA certificate list
        that contains all CA certificates which are 'trusted' and allowed
        to authenticate peers.

        \sa sslCert_addToList

    \param SSLctx pointer to current SSL general context
    \param p_list_head head of the CA certificate list

*/
/*============================================================================*/
void sslSoc_setCaCertList(s_sslSett_t* ps_sslSett, s_sslCertList_t *p_list_head);

/*============================================================================*/
/*!
    \brief  Fetch the head of the Client CA certificate list

        This function returns the head of the CA certificate list.

    \param SSLctx pointer to current SSL general context

    \return     head of the CA certificate list
    \return     NULL if the CA certificate list is empty/not initialised

*/
/*============================================================================*/
s_sslCertList_t * sslSoc_getCaCertList(s_sslSett_t* ps_sslSett);

/*============================================================================*/
/*!
    \brief  Assign a former initialized client certificate chain

        This function sets the parameter p_list_head as certificate chain
        which shall contain one certificate and should contain all CA certificates
        that are required for a peer to verify the certificate.

        This list must be in the following form:
            cert->SubCAx->...->SubCA1->RootCA

        \sa sslCert_addToList

    \param SSLctx pointer to current SSL general context
    \param p_list_head Start of the certificate chain

*/
/*============================================================================*/
void sslSoc_setCertChainList(s_sslSett_t* ps_sslSett, s_sslCertList_t * p_list_head);

/*============================================================================*/
/*!
    \brief  Fetch the head of the certificate chain

        This function returns the head of the certificate chain

        \sa sslSoc_setCertChainList

    \param SSLctx pointer to current SSL general context

    \return     head of the certificate chain
    \return     NULL if the certificate chain is empty/not initialised

*/
/*============================================================================*/
s_sslCertList_t * sslSoc_getCertChainList(s_sslSett_t* ps_sslSett);

/*============================================================================*/
/*!
    \brief  Import the RSA private key

        This function reads the private key out of the cert_db and initialises
        the internal RSA private key. It is assumed that this key belongs to the
        certificate that can be found in the certificate chain.

        \sa sslSoc_setCertChainList

    \param SSLctx pointer to current SSL connection context
    \param pcdt_privKey The private key

    \return E_SSL_OK on success
    \return E_SSL_ERROR on fail

*/
/*============================================================================*/
int sslSoc_setRsaPrivKey(s_sslSett_t* ps_sslSett, s_cdbCert_t* pcdt_privKey);


/*==============================================================================*/
/*!
    \brief  Import the ECC private key

        This function reads the private key out of the cert_db and initialises
        the internal ECC private key. It is assumed that this key belongs to the
        certificate that can be found in the certificate chain.

        \sa sslSoc_setCertChainList

    \param SSLctx pointer to current SSL connection context
    \param pcdt_privKey The private key

    \return E_SSL_OK on success
    \return E_SSL_ERROR on fail
*/
/*==============================================================================*/
int sslSoc_setECCPrivKey(s_sslSett_t* ps_sslSett, s_cdbCert_t* pcdt_privKey);


/*============================================================================*/
/*!
    \brief  Returns the authentication level

        this function reads the authentication level that has been reached
        when client authentication was successful.
        The level of each client that should be authenticated must be implemented
        in wssl_conf.c:sslConf_certHook().
        In this function are also some example implementations of clients.

    \param SSLsocket pointer to current SSL connection context

    \return The level that has been reached in the client authentication

*/
/*============================================================================*/
uint32_t sslSoc_getCtxAuthLvl(s_sslCtx_t* SSLsocket);

/*============================================================================*/
/*!
    \brief  Sets the cipherspecs that are allowed to be used
    	TODO vpy: update list with supported cipher suites

        this is a function with a variable number of arguments.
        the chain of arguments has to be finished with 'NULL'
        Possible arguments are:

             - TLS_RSA_WITH_RC4_128_MD5
             - TLS_RSA_WITH_RC4_128_SHA
             - TLS_RSA_WITH_3DES_EDE_CBC_SHA
             - TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
             - TLS_RSA_WITH_AES_128_CBC_SHA
             - TLS_RSA_WITH_AES_128_CBC_SHA256
             - TLS_DHE_RSA_WITH_AES_128_CBC_SHA
             - TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
             - TLS_RSA_WITH_AES_256_CBC_SHA
             - TLS_RSA_WITH_AES_256_CBC_SHA256
             - TLS_DHE_RSA_WITH_AES_256_CBC_SHA
             - TLS_DHE_RSA_WITH_AES_256_CBC_SHA256

        NB: The sequence of the given parameters must be in the preferred
            order (favorite choice first)

    \param SSLsocket pointer to current SSL connection context
    \param wt_ciph a variable argumentlist that MUST be finished by NULL

*/
/*============================================================================*/
void sslSoc_setCtxCipSpecs(s_sslCtx_t* SSLsocket, e_sslCipSpec_t wt_ciph, ...);

/*============================================================================*/
/*!
    \brief  Sets the ciphersuites that are allowed to be used
		TODO vpy: update list with supported cipher suites
        this is a function similar to this one of OpenSSL
        no excuses are allowed despite these defined ciphersuites
        Possible arguments are these macros seperated by ":":

             - TLS_RSA_WITH_RC4_128_MD5_NAME
             - TLS_RSA_WITH_RC4_128_SHA_NAME
             - TLS_RSA_WITH_3DES_EDE_CBC_SHA_NAME
             - TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA_NAME
             - TLS_RSA_WITH_AES_128_CBC_SHA_NAME
             - TLS_RSA_WITH_AES_128_CBC_SHA256_NAME
             - TLS_DHE_RSA_WITH_AES_128_CBC_SHA_NAME
             - TLS_DHE_RSA_WITH_AES_128_CBC_SHA256_NAME
             - TLS_RSA_WITH_AES_256_CBC_SHA_NAME
             - TLS_RSA_WITH_AES_256_CBC_SHA256_NAME
             - TLS_DHE_RSA_WITH_AES_256_CBC_SHA_NAME
             - TLS_DHE_RSA_WITH_AES_256_CBC_SHA256_NAME

        or its string representatives seperated by ':'

             - "TLS_RSA_WITH_RC4_128_MD5"
             - "TLS_RSA_WITH_RC4_128_SHA"
             - "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
             - "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
             - "TLS_RSA_WITH_AES_128_CBC_SHA256"
             - "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
             - "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
             - "TLS_RSA_WITH_AES_256_CBC_SHA"
             - "TLS_RSA_WITH_AES_256_CBC_SHA256"
             - "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
             - "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"

        NB: The list of the given parameters must be in the preferred
            order (favorite choice first)

    \code
sslSoc_setCtxCipList(p_ssl, TLS_RSA_WITH_AES_256_CBC_SHA_NAME":"TLS_RSA_WITH_AES_128_CBC_SHA_NAME);
    \endcode
    \code
sslSoc_setCtxCipList(p_ssl, "TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA");
    \endcode

    \param SSLsocket pointer to current SSL connection context
    \param str a string of ciphersuites, each ciphersuite seperated by a ':'

    \return x number of ciphersuites set
    \return 0 on complete failure

*/
/*============================================================================*/
int sslSoc_setCtxCipList(s_sslCtx_t *SSLsocket, const char *str);

/*============================================================================*/
/*!
    \brief  Sets the flush limit to write

        This method sets the maximum transmit unit of the plaintext in a SSL
        record. Once the buffersize has reached this limit will the data
        automatically be signed, encrypted and sent out.

        NB: When giving a MTU limit of 1000 bytes there can be added
            up to 276 bytes from the padding and MAC, what is depending on
            the used SSL/TLS version and ciphersuite.

        If it is desired to force a SSL socket to be sent out but the datasize
        is fluctuating use \c sslSoc_flush(s)

    \param SSLsocket pointer to current SSL connection context
    \param l_mtu the limit from where on the socket has to be flushed
*/
/*============================================================================*/
void sslSoc_setCtxMtu(s_sslCtx_t* SSLsocket, uint32_t l_mtu);

/*============================================================================*/
/*!
    \brief  Sets the verification level

        This function sets the verification behavior relating to
        Client Authentication.

        see sslSoc_sett_set_ClientAuth_behavior() for details

    \param SSLsocket pointer to current SSL connection context
    \param level the verification level of the SSL socket, concerning client authentication
*/
/*============================================================================*/
void sslSoc_setCtxVerif(s_sslCtx_t* SSLsocket, e_sslAuthLevel_t level);

/*============================================================================*/
/*!
    \brief  Sets the version constraint

        This function sets the necessarily used SSL/TLS Version per SSL socket.
        No exception is possible. If a minimal Version number is desired and
        higher versions shall be supported, this has to be done by usage of
        sslSoc_setVer(s, l, h);

        For supported versions see description of sslSoc_setVer()

    \param SSLsocket pointer to current SSL connection context
    \param version the version that MUST be used in the handshake
*/
/*============================================================================*/
void sslSoc_setCtxVer(s_sslCtx_t* SSLsocket, e_sslVer_t version);

/*============================================================================*/
/*!
    \brief  Set the behavior when a communication partner tries to start a renegotiation

        This allows/denies renegotiation if a communication partner tries to do so.

    \param SSLsocket Pointer to current SSL connection context
    \param enable    To enable renegotiation set this flag to TRUE, otherwise to FALSE

    \return Returns the value that was set before

*/
/*============================================================================*/
uint8_t sslSoc_setCtxReneg(s_sslCtx_t* SSLsocket, uint8_t enable);

/*============================================================================*/
/*!
    \brief  Assign a session identifier to a SSL connection context

        This function sets the session identifier for a specific SSL connection
        context. This is only required for SSL client applications, since SSL
        server applications search valid session automatically.

        \sa sslSoc_getCtxSess()

    \param SSLsocket Pointer to current SSL connection context
    \param s_desc    The identifier for a cached session that
                                can be used for session resumption

    \return E_SSL_OK     The provided s_desc was found in the session cache
    \return E_SSL_ERROR  The provided s_desc was not found in the session cache

*/
/*============================================================================*/
e_sslResult_t sslSoc_setCtxSess(s_sslCtx_t* SSLsocket, l_sslSess_t s_desc);

/*============================================================================*/
/*!
    \brief  Returns the session identifier of a SSL connection context

        \sa sslSoc_setCtxSess()

    \param SSLsocket Pointer to current SSL connection context

    \return Returns the session identifier of the given SSL connection context.

*/
/*============================================================================*/
l_sslSess_t sslSoc_getCtxSess(s_sslCtx_t* SSLsocket);


/*============================================================================*/
/*!
    \brief  Clear all SSL parameters!

        Clears all SSL contexts, session caches and handshake buffers

    \return E_SSL_OK     everything successful removed :)

*/
/*============================================================================*/
e_sslResult_t sslSoc_killall(void);

/*============================================================================*/
/*!
    \brief  Shutdown current SSL connection

        Initiates the closure of a SSL connection. If the closure has been
        initiated before by the communication party it will immediately return
        \c E_SSL_OK
        If the closure must be initiated is the behavior dependant on the
        macro \c SSL_WAIT_FOR_SHUTDOWN that is explained in \c wssl.h

    \param SSLsocket pointer to current SSL connection context

    \return E_SSL_ERROR  shutdown was canceled due to an error
    \return E_SSL_AGAIN  shutdown was not successful, please call again
    \return E_SSL_OK     shutdown was successful

*/
/*============================================================================*/
int sslSoc_shutdown(s_sslCtx_t * SSLsocket);

/*============================================================================*/
/*!
    \brief  Links a network connection (e.g. a socket) to a new created SSL connection context object

    \param SSLsocket pointer to current SSL connection context
    \param fd socket to link to the given SSL connection context


    \return E_SSL_OK  operation successful

*/
/*============================================================================*/
int sslSoc_setCtxFd(s_sslCtx_t * SSLsocket, int fd);

/*============================================================================*/
/*!
    \brief  Checks if a new SSL socket can be provided

        Searches for a free entry in the SSL_ConnectionCtx array. In case a free
        entry has been found it ensures that the necessary settings from the
        general context are copied and the pointer to the SSL socket would be
        returned.

    \param psSslGeneralCtx pointer to general SSL connection index

    \return pointer to an available SSL socket context
    \return NULL no new SSL socket can be provided

*/
/*============================================================================*/
s_sslCtx_t * sslSoc_new ( s_sslSett_t * psSslGeneralCtx );

/*============================================================================*/
/*!
    \brief  Destroys all sensitive information of a connection context and frees the context.

            This function is used to delete all security related information and
            to free the connection context after an SSL connection was closed.

    \param SSLsocket pointer to current SSL connection context

    \return E_SSL_OK Operation was successful

*/
/*============================================================================*/
int sslSoc_free ( s_sslCtx_t * SSLsocket );

/*============================================================================*/
/*!
    \brief  Returns the size of immediately available decrypted data

            Returns the number of bytes which are available in the plain text
            buffer for immediate read (bytes are delivered out of buffer,
            no blocking occurs)

    \param SSLsocket pointer to current SSL connection context


    \return >0 operation was successful, the number returned is the number of bytes available
                in buffer
    \return  0 no data available

*/
/*============================================================================*/
int sslSoc_pending(s_sslCtx_t  * SSLsocket );

/*============================================================================*/
/*!
    \brief  Read action. Depending on Socket layer interface state

        Delivers data from plain text buffer (PTB)
        Interacts with the networklayer if required
        Gets data from network to build SSL record, if full SSL record aquired:
            Check and decrypt SSL-Record and store result in PTB

    \param SSLsocket pointer to current SSL connection context
    \param pcReadBuffer pointer to the buffer to read from
    \param iReadBufferLen length of pcReadBuffer

    \return >0 operation was successful, the number returned is the number of
               bytes read from the SSL socket
    \return E_SSL_AGAIN no data read
    \return E_SSL_WANT_WRITE operation was not successful, socket must be flushed before
    \return E_SSL_ERROR operation was not successful, an error occurred

*/
/*============================================================================*/
int sslSoc_read (s_sslCtx_t * SSLsocket, char * pcReadBuffer, int iReadBufferLen );

/*============================================================================*/
/*!
    \brief  Write action. Depending on Socket layer interface state:

            Writes data to the plaintext buffer
            If maximum tranmit unit has been hit it signs and encrypts the SSL record
            When an encrypted SSL record is available it sends the data over the
            generic socket interface

    \param SSLsocket pointer to current SSL connection context
    \param pcWriteBuffer pointer to the plain text buffer
    \param iWriteBufferLen length of pcWriteBuffer

    \return >0 operation was successful, the number returned is the number of bytes
                written to the SSL socket
    \return E_SSL_AGAIN operation was not successful, please call again
    \return E_SSL_WANT_AGAIN operation was not successful, socket can be read only
    \return E_SSL_ERROR operation was not successful, an error occurred

*/
/*============================================================================*/
int sslSoc_write (s_sslCtx_t * SSLsocket, const char * pcWriteBuffer, int iWriteBufferLen );

/*============================================================================*/
/*!
    \brief  Flushing SSL Socket

            It forces a SSL record to be completed
            All data in the plaintext buffer will be signed and encrypted
            and sent out over the generic socket interface

    \param SSLsocket pointer to current SSL connection context

    \return E_SSL_OK     operation was successful
    \return E_SSL_AGAIN  operation was not successful, socket is still processing
    \return E_SSL_ERROR  socket has to be closed

*/
/*============================================================================*/
int sslSoc_flush (s_sslCtx_t * SSLsocket);

/*============================================================================*/
/*!
    \brief  wait for a SSL client to perform a SSL handshake

            sslSoc_accept() waits for a SSL client to perform the SSL handshake.
            The underlying reliable communication channel must already have
            been established and assigned to the SSLsocket.

    \param SSLsocket pointer to current SSL connection context

    \return E_SSL_OK    The SSL handshake was successfully completed, a SSL connection has been established.
    \return E_SSL_AGAIN operation was not completed, please call again
    \return E_SSL_ERROR operation was not successful, an error occurred

*/
/*============================================================================*/
int sslSoc_accept (s_sslCtx_t * SSLsocket );

/*============================================================================*/
/*!
    \brief  perform the SSL handshake

            sslSoc_connect() initiates the Handshake by sending a ClientHello
            The underlying reliable communication channel must already have
            been established and assigned to the SSLsocket.

    \param SSLsocket pointer to current SSL connection context


    \return E_SSL_OK    The SSL handshake was successfully completed, a SSL connection has been established.
    \return E_SSL_AGAIN operation was not completed, please call again
    \return E_SSL_ERROR operation was not successful, an error occurred, underlying communication channel has to be closed

*/
/*========================================================================== */
int sslSoc_connect (s_sslCtx_t * SSLsocket);

/*============================================================================*/
/*!
    \fn     int sslSoc_procRec (s_ssl_t * SSLsocket)

    \brief  network specific function used to process an entire record received

        	The result of the operation is placed in the buffer, and the buffer
        	action is set to the corresponding value(SEND BUFFER TO NETWORK,...)

    \param  SSLsocket  the SSL connection context we're in


    \return  0 record processing was successful
    \return else a problem occurred

*/
/*============================================================================*/
int sslSoc_procRec (s_sslCtx_t * SSLsocket);
/*============================================================================*/
/*!
    \fn     int sslSoc_io (s_ssl_t * SSLsocket )

    \brief  network stack specific input / output action with the network layer

        Depending on the actual SLI socket state the SLI socket buffer is
        filled out from the network or the buffer content is written
        to the network.
        This is an internal service function used by the API functions


    \param  SSLsocket  the SSL connection context we're in


    \return <0 an error occurred
    \return  0 socket is in idle mode
    \return >0 number of bytes transferred
*/
/*============================================================================*/
int32_t sslSoc_io (s_sslCtx_t * SSLsocket );

#endif /*_SSL_SOCKET_H_ */
