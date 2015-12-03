/*
 * ssl_simpleClient.h
 *
 *  Created on: 14.11.2013
 *      Author: Naksit
 */

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#elif __linux
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "netGlobal.h"
#include "ssl.h"

#ifndef SSL_SIMPLECLIENT_H_
#define SSL_SIMPLECLIENT_H_

/* return values for client FSM */
typedef enum {
	/* the client FSM would like to be re-entered again */
	E_CLIENT_FSM_AGAIN = 0,
	/* the client FSM is done */
	E_CLIENT_FSM_DONE = 1,
	/* an error occurred */
	E_CLIENT_FSM_ERROR = -1
} E_CLIENT_FSM_RESULT;


typedef struct {
	char *				pc_filename_remote;
	char *				pc_filename_local;
	char *				pc_ciphersuites;
	uint16_t			u_port;
	struct in_addr		ip_addr;
	e_sslVer_t		    versmin;
	e_sslVer_t		    versmax;
	e_sslKeyType_t		keyType;	//type of the key provided by user
	char *				key;
	char *				keyParameters;	//parameters of the key provided by user (EC params,...)
	char **				ppc_certs;
	char **				ppc_CAcerts;
	e_sslAuthLevel_t	authlevel;
} SSL_CLIENT_PARS;



/*==================================================================================================
                                     EXTERN VARIABLES
==================================================================================================*/

extern const char ClientCaCertificate[];
extern const char ClientCertificate[];
extern const char ClientPrivateKey[];
extern const char ServerCaCertificate[];
extern const char ServerCertificate[];
extern const char ServerPrivateKey[];
/*==================================================================================================
                                   FUNCTION PROTOTYPES
==================================================================================================*/

E_CLIENT_FSM_RESULT ssl_client_entry(SSL_CLIENT_PARS parameters);

#endif /* SSL_SIMPLECLIENT_H_ */
