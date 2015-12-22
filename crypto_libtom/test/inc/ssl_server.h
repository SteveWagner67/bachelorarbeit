/*
 * ssl_simpleServer.h
 *
 *  Created on: 18.11.2013
 *      Author: Naksit
 */

#include "netGlobal.h"
#include "ssl.h"

#ifndef SSL_SIMPLESERVER_H_
#define SSL_SIMPLESERVER_H_


/* return values for server FSM */
typedef enum {
	/* the server FSM would like to be re-entered again */
	E_SERVER_FSM_AGAIN = 0,
	/* the server FSM is done */
	E_SERVER_FSM_DONE = 1,
	/* an error occured */
	E_SERVER_FSM_ERROR = -1
} E_SERVER_FSM_RESULT;

typedef struct {
	uint8_t				echo;
	char *				pc_filename;
	char *				pc_ciphersuites;
	uint16_t			u_port;
	e_sslVer_t			versmin;
	e_sslVer_t			versmax;
	e_sslKeyType_t		keyType;	//type of the key provided by user
	char *				key;
	char *				keyParameters;	//parameters of the key provided by user (EC params,...)
	char **				ppc_certs;
	char **				ppc_CAcerts;
	e_sslAuthLevel_t	authlevel;
} SSL_SERVER_PARS;


/*==================================================================================================
                                     EXTERN VARIABLES
==================================================================================================*/

extern const char ClientCaCertificate[];
extern const char ServerCaCertificate[];
extern const char ServerCertificate[];
extern const char ServerPrivateKey[];

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

E_SERVER_FSM_RESULT ssl_server_entry(SSL_SERVER_PARS parameters);
void ssl_server_reset(void);
void ssl_server_start(void);


#endif /* SSL_SIMPLESERVER_H_ */
