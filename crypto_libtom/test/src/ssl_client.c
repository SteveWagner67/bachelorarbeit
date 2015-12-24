/*
 ============================================================================
 Name        : ssl_simpleClient.c
 Author      : Artem Yushev (artem.yushev@hs-offenburg.de)
 Version     :
 Copyright   :
 Description :
 ============================================================================
 */
#include <stdio.h>
#include "ssl_client.h"
#include "netGlobal.h"
#include "errno.h"

/* Socket Libraries */
#include <unistd.h>
#include <fcntl.h>
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#elif __linux
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* EmBetter SSL Includes */
#include "ssl.h"
#include "ssl_socket.h"
#include "ssl_target.h"
#include "ssl_diag.h"
//#include "crypto_wrap.h"

//#include "crypto_iface.h"

#include "crypto_tomcrypt.h"

#include "cert_db.h"
#include "ssl_certHelper.h"
#include "key_management.h"
#include "logger.h"

#define	LOGGER_ENABLE DBG_SSL_CW_MODULE



/*==================================================================================================
                          LOCAL TYPEDEFS (STRUCTURES, UNIONS, ENUMS)
==================================================================================================*/
/* States of the client SSL terminal */
enum en_ssl_client_state
{
  SSL_CLIENT_INITIALISATION = 0,
  SSL_CLIENT_INIT,
  SSL_CLIENT_SOC_CONNECT,
  SSL_CLIENT_CONNECT,
  SSL_CLIENT_READ,
  SSL_CLIENT_WRITE,
  SSL_CLIENT_FLUSH,
  SSL_CLIENT_CLOSING,
  SSL_CLIENT_CLOSING_ERR,
  SSL_CLIENT_CLOSE,
  SSL_CLIENT_CLOSE_ERR,
  SSL_CLIENT_CLEANUP,
  SSL_CLIENT_IDLE
};

/*==================================================================================================
                                        LOCAL MACROS
==================================================================================================*/

/* SSL_CLIENT 1 activates SSL
 * SSL_CLIENT 0 will use unsecured TCP/IP */
#define SSL_CLIENT 1

/* If we want to profile our program we need to call exit after
 * one successful connection */
#define PROFILING 0

/* Here you can define the IP to connect to */
#define SSL_SERVER_IP "141.79.66.226"

/* Here you can define the port to connect to */
#define SSL_SERVER_PORT 1338

#define HTTPS_REQ      TRUE

#define 	DEBUG_MODULE	DBG_SOC_INFO

/*==================================================================================================
                                      SSL VARIABLES
==================================================================================================*/
/* Structure that holds the basic SSL_Information */
static s_sslSett_t s_sslCtx;

/* pointer to the assigned SSL context */
static s_sslCtx_t* ps_sslCtx;

#define SSL_CLIENTCA_SUBJECT_LEN	512
typedef uint8_t t_subjectArray[SSL_CLIENTCA_SUBJECT_LEN];

typedef struct s_clientCertificate
{
  const char* name;
  const char* cert;
  const char* private_key;
} s_cliCert_t;

#define SSL_CLIENT_CERTS_NUM      	4
#define SSL_CLIENT_CA_CERTS_NUM    	4

/* Memory for the client certificates' cert_db entries */
static s_cdbCert_t client_cdb_certs[SSL_CLIENT_CERTS_NUM];
static s_sslCertList_t client_cert_list[SSL_CLIENT_CERTS_NUM];

/* Allocate the CA certificate structs */
static s_sslCert_t as_caCert[SSL_CLIENT_CA_CERTS_NUM];
/* Allocate a list element for every CA certificate */
static s_sslCertList_t s_caCertList[SSL_CLIENT_CA_CERTS_NUM];
/* Allocate storage for the Client Ca Subject, needed for Client Certificate Request */
static t_subjectArray ClientCaSubject[SSL_CLIENT_CA_CERTS_NUM];


/*==================================================================================================
                                      GLOBAL VARIABLES
==================================================================================================*/
/* Client state */
static enum en_ssl_client_state i_state = SSL_CLIENT_INITIALISATION;

/* Reading buffer */
static char c_readBuf[SSL_TLS_MAX_PLAINTEXTLEN];
static char c_writeBuffer[SSL_WRITE_BLOCK_LEN];
static uint32_t l_bytesWrite;

#ifdef _WIN32
WSADATA wsa;
SOCKET socket_descriptor;
struct sockaddr_in server;
#elif __linux
int socket_descriptor;
struct sockaddr_in server;
#endif



static int l_bytes = 0;

/* pointer to file to receive via HTTP(S) */
static FILE * fp;


int init_client_CA_certs(char ** ppc_CAcerts);

/*=================================================================================================*/
/*!
 * int ssl_client_entry()
 *
 * Brief: Implements a non blocking terminal program.
 *
 *        This implementation can be taken as a reference for emBetter SSL socket programming.
 *        It implements a state machine that does all the handling from initialisation
 *        to communication.
*/
/*=================================================================================================*/
E_CLIENT_FSM_RESULT ssl_client_entry(SSL_CLIENT_PARS parameters) {

	char * pc_filename_remote	= parameters.pc_filename_remote;
	char * pc_filename_local	= parameters.pc_filename_local;
	char * pc_ciphersuites		= parameters.pc_ciphersuites;
	uint16_t u_port				= parameters.u_port;
	struct in_addr ip_addr		= parameters.ip_addr;
	e_sslVer_t versmin			= parameters.versmin;
	e_sslVer_t versmax			= parameters.versmax;
	char *	key					= parameters.key;
	char **	certs				= parameters.ppc_certs;
	char ** ppc_CAcerts			= parameters.ppc_CAcerts;
	e_sslAuthLevel_t authlevel	= parameters.authlevel;


	int err;

	en_gciResult_t gci_err;

	st_gciKey_t rsaPriv = {.type = en_gciKeyType_RsaPriv};
	/* Check the state of the client */
	switch (i_state)
	{
		case SSL_CLIENT_INITIALISATION:

			/* initialize file pointer */
			fp = NULL;

			/* Create a socket */
#ifdef _WIN32
			int32_t i_res;
			/*! Initialize Winsock */
			i_res = WSAStartup(MAKEWORD(2,2), &wsa);
			if (i_res != 0) {
				printf("WSAStartup failed with error: %d\n", i_res);
				return E_CLIENT_FSM_ERROR;
			}

			if ((socket_descriptor = socket(AF_INET , SOCK_STREAM , 0 )) < 0) {
				LOG_ERR("socket failed %s" , strerror(errno));
			}
			u_long	l_mode = 1;
			ioctlsocket(socket_descriptor, FIONBIO, &l_mode);
#elif __linux
			if ((socket_descriptor = socket(AF_INET , SOCK_STREAM , 0 )) < 0) {
				LOG_ERR("socket failed %s" , strerror(errno));
			}
			fcntl(socket_descriptor, F_SETFL, O_NONBLOCK);
#endif



			LOG_OK("Socket created");

/*============================================================================*/
/*
 * General SSL Initialisation
 */
/*============================================================================*/
			/* Initialises the SSL module */
			SSL_init();

			/* Initialises the crypto */
			//OLD-CW: cw_crypto_init();
			//TODO sw - where to become the user name + password ??
			gci_err = gciInit(NULL, 0, NULL, 0);
			if(gci_err != en_gciResult_Ok)
			{
				//TODO return error state
			}

			//		{
			//			/*
			//			 * Use some "random" bytes to init the PRNG
			//			 */
			//			uint8_t c_rand[] = { 0x42, 0x72, 0x75, 0x63, 0x65, 0x20, 0x53, 0x63, 0x68, //TODO sw - this step in gci_init
			//					0x6E, 0x65, 0x69, 0x65, 0x72, 0x21, 0x0D, 0x0A, 0x00 };
			//			cw_prng_init(c_rand, sizeof(c_rand));
			//		}

			/*
			 * Initialisation of keymanager for DHE and DHE private key generation
			 */
			gci_err = km_dhe_init();
			if(gci_err != en_gciResult_Ok)
			{
				//TODO return error state
			}

/*============================================================================*/
/*
 * Initialization of the SSL settings for the demonstration SSL context
 */
/*============================================================================*/
			/* Initialises the SSL context */
			sslSoc_initSett(&s_sslCtx, E_SSL_SIGN_ECDSA); //TODO vpy ECDSA: change

/*============================================================================*/
/*
 * Initialization of the general SSL settings
 */
/*============================================================================*/
			/*
			 * Init the time-function pointer implicit to NULL, this will disable
			 * checking of the validity of the used certificates
			 * (To enable 'getCurrentTime' function should be used)
			 */
			sslSoc_setTimeFunc(&s_sslCtx, NULL);

			/* Initialize client CA certificates */
			if (ppc_CAcerts != NULL) {
				init_client_CA_certs(ppc_CAcerts);
			}

			/* ===== Initialize Server Certificates and private key ===== */

			s_cdbCert_t cdb_tmp;
			s_sslCertList_t * list_head = sslSoc_getCertChainList(&s_sslCtx);

			if (certs != NULL) {
				int i = 0;
				while (certs[i] != NULL) {
					/*
					printf("certs[%i] = '%s'\n", i, certs[i]);
					*/
					cdb_initCert_linear(&client_cdb_certs[i], certs[i]);
					list_head = sslCert_addToList(list_head,
							&client_cert_list[i], NULL, &client_cdb_certs[i]);
					i++;
				}
			}

			sslSoc_setCertChainList (&s_sslCtx, list_head);

			if (key != NULL) {
				cdb_initCert_linear(&cdb_tmp, key);

				if (sslSoc_setRsaPrivKey(&s_sslCtx, &cdb_tmp) != E_SSL_OK) {
					printf(DBG_STRING "Import of private key failed", __FILE__, __LINE__);
					return (E_CLIENT_FSM_ERROR);
				}
			}

//			else
//			{
//			    //TODO sw - put the key in a rsa priv key and get an ID
//			    //rsaPriv.un_key.keyRsaPriv.
//			}

			/* Setting up the SSL version */
			sslSoc_setVer(&s_sslCtx, versmin, versmax);

			sslSoc_setSessTimeout(&s_sslCtx, 600);

			sslSoc_setReadWrite(&s_sslCtx, sslTarget_read, sslTarget_write);

			sslSoc_setAuthLvl(&s_sslCtx, authlevel);

			//OLD-CW: cw_prng_read((uint8_t *)c_writeBuffer, sizeof(c_writeBuffer));

			gci_err = gciRngGen(sizeof(c_writeBuffer), (uint8_t *)c_writeBuffer);
			if(gci_err != en_gciResult_Ok)
			{
				//TODO error state
			}

			/* After the initialisation the client state is now initialized */
			i_state = SSL_CLIENT_INIT;
			break;
			/* SSL_CLIENT_INITIALISATION */

		case SSL_CLIENT_INIT:
		{
#ifdef _WIN32
			/* Sets the server IP address, family and port */
			server.sin_addr.s_addr = ip_addr.s_addr;
			server.sin_family = AF_INET;
			server.sin_port = htons(u_port);
#elif __linux
			/* Sets the server IP address, family and port */
			server.sin_addr = ip_addr;
			server.sin_family = AF_INET;
			server.sin_port = htons(u_port);
#endif

			/* After binding the address and port the client state is now connecting */
			i_state = SSL_CLIENT_SOC_CONNECT;
			break;
			/* SSL_CLIENT_INIT */
		}
		case SSL_CLIENT_SOC_CONNECT:
#ifdef _WIN32
			err = connect(socket_descriptor, (struct sockaddr *)&server , sizeof(server));
	        if (err < INVALID_SOCKET) {
	            LOG_ERR("socket failed with error: %ld\n", WSAGetLastError());
	            WSACleanup();
	            return E_CLIENT_FSM_ERROR;
	        }
#elif __linux
			err = connect(socket_descriptor , (struct sockaddr *)&server , sizeof(server));
			if ((err < 0) && (errno != EINPROGRESS))
			{
				perror("connect");
				return E_CLIENT_FSM_ERROR;
			}
#endif
			/* Connects to the server (Simple SSL/TLS Server) */

			puts("Connected.");

			/* Checks if a SSL context is available */
			ps_sslCtx = sslSoc_new ( &s_sslCtx );
			if (ps_sslCtx == NULL)
			{
				/* Not available */
				i_state = SSL_CLIENT_CLOSE;
			}
			else
			{
				/* Sets the socket number into the SSL socket context */
				sslSoc_setCtxFd(ps_sslCtx, socket_descriptor);

				/* set supported ciphersuites if list is provided */
				if (strlen(pc_ciphersuites) > 0) {
					sslSoc_setCtxCipList(ps_sslCtx, pc_ciphersuites);
				}

				i_state = SSL_CLIENT_CONNECT;
			} /* if ... else */

			break;
			/* SSL_CLIENT_SOC_CONNECT */

		case SSL_CLIENT_CONNECT:

			/* Performs a SSL handshake */
			switch (sslSoc_connect(ps_sslCtx)) {
			case E_SSL_AGAIN:
				break;
			case E_SSL_OK:
				/* print some connection specifics */
				printf("\n>INFO::Ciphers: RX = 0x%.4X, TX = 0x%.4X\n",
						ps_sslCtx->s_sslGut.e_rxCipSpec,
						ps_sslCtx->s_sslGut.e_txCipSpec);
				printf("\n>INFO::Version: 0x%.4X\n", ps_sslCtx->e_ver);

				i_state = SSL_CLIENT_WRITE;
				break;
			case E_SSL_ERROR:
				i_state = SSL_CLIENT_CLOSE_ERR;
				break;
			default:
				i_state = SSL_CLIENT_CLOSE;
				break;
			} /* switch */

			break; /* case SSL_CLIENT_CONNECT */

		case SSL_CLIENT_WRITE:

			/* prepare HTTP GET command */
			l_bytesWrite = sprintf(c_writeBuffer,
					"GET /%s HTTP/1.1\r\n\r\n", pc_filename_remote);

			printf("GET /%s HTTP/1.1\r\n\r\n", pc_filename_remote);

			/* send HTTP GET command to peer */
			l_bytes += sslSoc_write(ps_sslCtx, c_writeBuffer, l_bytesWrite);
			if (l_bytes > 0) {
				i_state = SSL_CLIENT_FLUSH;
				l_bytes = 0;
			}

			break; /* case SSL_CLIENT_WRITE */

	    case SSL_CLIENT_READ: {

	    	/* read data from peer to a buffer */
	    	l_bytes = sslSoc_read(ps_sslCtx, c_readBuf, sizeof(c_readBuf));

	    	if (l_bytes > 0) {

	    		char * pc_buf = c_readBuf;

	    		/* expect HTTP response if file to write not is yet open */
	    		if (fp == NULL && (strncmp(c_readBuf, "HTTP/1.0 200", 12) == 0
	    				|| strncmp(c_readBuf, "HTTP/1.1 200", 12) == 0)) {

	    			/* find beginning of content (strstr assumes a terminating '\0'
	    			 * in c_readBuf which might not be there!!) */
	    			char * pc_content = strstr(c_readBuf, "\r\n\r\n");

	    			if (pc_content != NULL) {
		    			/* open file */
	    				fp = fopen(pc_filename_local, "wb");

	    				/* move to beginning of content */
	    	    		pc_buf = pc_content + 4 * sizeof(char);
	    	    		l_bytes -= (pc_buf - c_readBuf) / sizeof(char);
	    			}
	    		}

	    		if (fp != NULL) {
		    		/* write to file if is already open */
	    			fwrite(pc_buf, 1, l_bytes, fp);
	    		}

	    		l_bytes = 0;

	    	} else if (l_bytes < 0) {
	    		/* an error occurred */
	    		i_state = SSL_CLIENT_CLOSING_ERR;
	    	}
	    }
	    break; /* case SSL_CLIENT_READ */

		case SSL_CLIENT_FLUSH: {

	    	switch(sslSoc_flush(ps_sslCtx)) {
				case E_SSL_OK:
					i_state = SSL_CLIENT_READ;
					break;
				case E_SSL_AGAIN:
				break;
				case E_SSL_ERROR:
				default: i_state = SSL_CLIENT_CLOSING;
				break;
			}
		}
		break; /* case SSL_CLIENT_FLUSH */

		case SSL_CLIENT_CLOSING:
		case SSL_CLIENT_CLOSING_ERR:

	    	if (sslSoc_shutdown(ps_sslCtx)) {
				i_state = (i_state == SSL_CLIENT_CLOSING_ERR) ? SSL_CLIENT_CLOSE_ERR : SSL_CLIENT_CLOSE;
			}

	    	break; /* case SSL_CLIENT_CLOSING, SSL_CLIENT_CLOSING_ERR */

		case SSL_CLIENT_CLOSE:
		case SSL_CLIENT_CLOSE_ERR:

			/* Closes the socket */
			close(socket_descriptor);

			/* close file */
			if (fp != NULL) {
				fclose(fp);
				fp = NULL;
			}

			return (i_state == SSL_CLIENT_CLOSE_ERR) ? E_CLIENT_FSM_ERROR : E_CLIENT_FSM_DONE;

			break; /* case SSL_CLIENT_CLOSE */

		case SSL_CLIENT_CLEANUP:
			break;

		case SSL_CLIENT_IDLE:
			return E_CLIENT_FSM_AGAIN;
			break;

		default:
			break;
	} /* switch */

	/* client FSM would like to be re-entered again */
	return E_CLIENT_FSM_AGAIN;
}



int init_client_CA_certs(char ** ppc_CAcerts) {

	/* pointer to current CA certificate */
	char * pc_CAcert;
	/* index of current CA certificate in ppc_CAcerts array */
	int i = 0;

	e_sslCertErr_t c_ret = 0;

	en_gciResult_t err;

	/* loop over CA certificates in ppc_CAcerts (assuming it is NULL-terminated) */
	while (i < SSL_CLIENT_CA_CERTS_NUM && (pc_CAcert = ppc_CAcerts[i]) != NULL) {

		/*printf("> Initializing CAcert[%d] = '\033[01;32m%s\033[00;00m'\n", i, pc_CAcert);*/

		/* Get pointer to a list of CA certificates */
		s_sslCertList_t * ps_listHead = sslSoc_getCaCertList(&s_sslCtx);

		/* Initialize cdb_certificate with a given pure CA Certificate */
		s_cdbCert_t s_cdbCert;
		cdb_initCert_linear(&s_cdbCert, pc_CAcert);

		/* Init the pointer to the "root CA" of the selected certificate */
		s_sslCert_t * ps_rootCaCert = (i == 0) ? &as_caCert[0] : &as_caCert[i - 1];

		s_sslOctetStr_t so_caCert;
		size_t sz_bufLen;


		/* Try to init the CA certificate */
		so_caCert.pc_data = cdb_read2buf(&s_cdbCert, &sz_bufLen);
		if (so_caCert.pc_data == NULL) {
			printf("\033[01;31mERROR: Failed to read certificate %d\033[00;00m\n", i);
		} else {
			/* Everything is ok, so assign length of successfully read cert */
			so_caCert.cwt_len = sz_bufLen;

			/* Give pointer to a public key to generate a new one */

			//OLD-CW: cw_rsa_publickey_init(&as_caCert[i].gci_caPubKey);


			c_ret = sslCert_init(	&so_caCert,
					&as_caCert[i],
					&as_caCert[i].gci_caPubKey,
					(uint8_t*)&ClientCaSubject[i],
					SSL_SUBJECT_STORAGE_SIZE,
					ps_rootCaCert, NULL);

			/* Check here if init was OK and we've not to tried
			 * init the Sub-Sub-Sub CA cert which must fail */
			if (c_ret == E_SSL_CERT_OK) {

				/* Shrink the memory of the initialised public key to save memory */
				//OLD-CW: cw_rsa_publickey_shrink(&as_caCert[i].gci_caPubKey);
				ps_listHead = sslCert_addToList(ps_listHead,
						&s_caCertList[i],
						&as_caCert[i],
						NULL);
				sslSoc_setCaCertList(&s_sslCtx, ps_listHead);
				c_ret = 0;
			} else {
				printf("\033[01;31mERROR: Failed to import certificate %d\033[00;00m\n", i);

				LOG_ERR("At import of certificate %i occurred error: %s (%d)", i,
						sslDiag_getCertError(c_ret), (uint32_t)c_ret);
				if ((i == (SSL_CLIENT_CA_CERTS_NUM - 1))
						&& (c_ret == E_SSL_CERT_ERR_PATHLENCONSTRAINT)) {
					LOG_ERR("CA in the chain defined a maximal path length");
				}

				//OLD-CW: cw_rsa_publickey_free(&as_caCert[i].gci_caPubKey);

				err = gciKeyDelete(&as_caCert[i].gci_caPubKey);
				if(err != en_gciResult_Ok)
				{
					//TODO return error state
				}

				c_ret = -1;
			} /* if ... else */

			cdb_free();
		}

		i++;
	}

	return c_ret;
}
