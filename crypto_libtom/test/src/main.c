/*	This is a test wrapper programm for embetter_ssl.
 *
 *  Created on 2014-09-04 by Andreas Walz (template taken from
 *  Naksit Anantalapochai)
 */

#define _GNU_SOURCE

/* ===== standard C headers ===== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/time.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#elif __linux
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* ===== application specific headers ===== */
#include "netGlobal.h"
#include "ssl_client.h"
#include "ssl_server.h"a
#include "timeout.h"
#include "tools.h"


/* ===== forward declarations ===== */
int test_run_client(SSL_CLIENT_PARS parameters);
int test_run_server(SSL_SERVER_PARS parameters, int i_n_connections);
char* str_null_to_empty(char * pc_input);
void assign_optarg(char **, char *);

char * read_pem_file_(char * pc_filename, char ** ppc_type, char* pc_keyParameters, e_sslKeyType_t* p_keyType);

int read_pem_files(char ** ppc_buffer, int i_N_max);
void print_string_tokens(char ** pc_tokens, int i_N);
int tokenize_string(char * pc_input, char ** ppc_tokens, int i_N_max);


/* conversion between protocol version enumeration and string identifier */
int version_string_to_enum(char * version, e_sslVer_t * p_version);
char * version_enum_to_string(e_sslVer_t version);

/* conversion between authentication level enumeration and string identifier */
int authlevel_string_to_enum(char * pc_authlevel, e_sslAuthLevel_t * p_authlevel);
char * authlevel_enum_to_string(e_sslAuthLevel_t p_authleveln);


/* what is this for?? */
char * logger_get_time(void) {
	time_t raw_time;
	time(&raw_time);
	return ctime(&raw_time);
}


/*! ===========================================================================
 * int main()
 *
 * Brief: Main function
 *
 * Command line arguments:
 *
 *   --certs <cert1>[:<cert2>[:<cert3>]]
 *
 *     Certificate(s) to be transmitted for authentication (certificates will
 *     be transmitted with the last certificate in the list first)
 *
 *
 *
 *
 * ============================================================================
 */


#define Otest 0

#if !Otest
int main(int argc , char *argv[])
{
	if (argc < 2)
	{
		puts("ssl_test: A command-line wrapper for emBetterSSL"
				" client and server implementation\n");

		puts("Usage: ./ssl_test ROLE [OPTIONS]\n");

		puts("ROLE refers to either of:");
		puts("  server: running server");
		puts("  client: running client");
		puts("  echo:   running server in echo mode (echos any data received)\n");

		puts("OPTIONS refer to either of:");
		puts("  --ip:           IP address of the server to connect to "
				"[client mode only]");
		puts("  --port:         TCP port to listen at or to connect to");
		puts("  --in:           Filename of file to offer for HTTP download "
				"(server mode) or filename of file to request via HTTP (client "
				"mode)");
		puts("  --out:          Filename of file to write downloaded file to "
				"[client mode only]");
		puts("  --ciphersuites: Colon (:) separated list of cipher suites to be "
				"offered/supported");
		puts("  --versmin:      Minimum SSL/TLS version offered/accepted");
		puts("  --versmax:      Maximum SSL/TLS version offered/accepted");
		puts("  --key:          Private key file (PEM) for server (server mode) "
				"or client (client authentication in client mode)");
		puts("  --certs:        Colon separated list of certificate files (PEM) "
				"used for authentication");
		puts("  --CAcerts:      Colon separated list of CA certificate files "
				"(PEM) used to verify the peer's certificate(s)");
		puts("  --authlevel:    Level auf authentication");
		puts("  --nconnections: Number of connections the server accepts before "
				"terminating (-1: run until error occurs, -2: run forever) "
				"[server mode only]\n");

		puts("Supported cipher suites are:");
		puts("  TLS_RSA_WITH_RC4_128_MD5");
		puts("  TLS_RSA_WITH_RC4_128_SHA");
		puts("  TLS_RSA_WITH_3DES_EDE_CBC_SHA");
		puts("  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
		puts("  TLS_RSA_WITH_AES_128_CBC_SHA");
		puts("  TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
		puts("  TLS_RSA_WITH_AES_256_CBC_SHA");
		puts("  TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
		puts("  TLS_RSA_WITH_AES_128_CBC_SHA256 (with tls1_2 option)");
		puts("  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (with tls1_2 option)");
		puts("  TLS_RSA_WITH_AES_256_CBC_SHA256 (with tls1_2 option)");
		puts("  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (with tls1_2 option)");
		//begin vpy
		puts("* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (with tls1_2 option)");
		puts("* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (with tls1_2 option)");
		puts("* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (with tls1_2 option)");
		puts("* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (with tls1_2 option)");
		puts("* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (with tls1_2 option)");
		puts("* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (with tls1_2 option)\n");
		//end vpy
		puts("Supported SSL/TLS versions are:");
		puts("  ssl3:   SSL v3.0");
		puts("  tls1:   TLS v1.0");
		puts("  tls1_1: TLS v1.1");
		puts("  tls1_2: TLS v1.2\n"); //vpy

		puts("Possible authentication levels:");
		puts("  E_SSL_NO_AUTH:           No client authentication");
		puts("  E_SSL_SHOULD_AUTH:       Request client authentication but "
				"continue if invalid");
		puts("  E_SSL_MUST_AUTH:         Request client authentication and "
				"abort if invalid");
		puts("  E_SSL_MUST_VERF_SRVCERT: Let client verify server certificate(s)");
		puts("  E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_NO_AUTH:     combination of "
				"E_SSL_MUST_VERF_SRVCERT and E_SSL_NO_AUTH");
		puts("  E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_SHOULD_AUTH: combination of "
				"E_SSL_MUST_VERF_SRVCERT and E_SSL_SHOULD_AUTH");
		puts("  E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_MUST_AUTH:   combination of "
				"E_SSL_MUST_VERF_SRVCERT and E_SSL_MUST_AUTH");
		exit(0);
	}


	/* ===== parameters to be set via options and arguments ===== */

	/* the role of the peer (either 'client', 'server', or 'echo' */
	char * pc_role = 0;

	/* list of supported ciphersuites (separated by a colon ':') */
	char * pc_ciphersuites = NULL;

	/* input and output file names */
	char * pc_in	= NULL;
	char * pc_out	= NULL;

	/* authentication level: argument passed after
	 * "--authlevel" option (default: E_SSL_NO_AUTH) */
	e_sslAuthLevel_t authlevel = E_SSL_NO_AUTH;

	/* IP address the client connects to (default: 127.0.0.1) */
	struct in_addr ip_addr;
#ifdef _WIN32
	ip_addr.s_addr = inet_addr("127.0.0.1");
#elif __linux
	inet_aton("127.0.0.1", &ip_addr);
#endif

	/* TCP port the client connects to (default: 1338) */
	uint16_t u_port	= 1338;

	/* minimum and maximum protocol version to be supported */
	e_sslVer_t versmin	= SSL_MIN_SSL_TLS_VERSION;
	e_sslVer_t versmax	= SSL_MAX_SSL_TLS_VERSION;

	/* files for keys and certificates (PEM format) */
	char * pc_file_key		= NULL;
	char * pc_file_certs	= NULL;
	char * pc_file_CAcerts	= NULL;

	/* the number of connections to accept before
	 * exiting (-1 representing an infinite number) */
	int i_n_connections = -1;

	/* ========== */

	/* pointer temporary character string variables */
	char * pc_tmp	= 0;
	char * pc_tmp2	= 0;

	/* prevent getopt_long from displaying error messages itself */
	opterr = 0;
	/* the first option is the role (e.g. 'client'),
	 * so let getopt_long ignore that part */
	optind = 1;

	/* define options and arguments accepted here */
	static struct option long_options[] =
	{
			{"ip",				required_argument, 0, 0},
			{"port",			required_argument, 0, 0},
			{"in",				required_argument, 0, 0},
			{"out",				required_argument, 0, 0},
			{"ciphersuites",	required_argument, 0, 0},
			{"versmin",			required_argument, 0, 0},
			{"versmax",			required_argument, 0, 0},
			{"key",				required_argument, 0, 0},
			{"certs",			required_argument, 0, 0},
			{"CAcerts",			required_argument, 0, 0},
			{"authlevel",		required_argument, 0, 0},
			{"nconnections",	required_argument, 0, 0},
			{0, 0, 0, 0}
	};


	/* ===== parse options (and arguments) ===== */

	/* gets a value =! 0 in case an error occured
	 * (will also be the exit code of the programm) */
	int errcode = 0;

	if (argc >= 2)
	{
		/* assign role from first argument */
		assign_optarg(&pc_role, argv[1]);
	}

	else
	{
		printf("No role defined. Stopping!\n");
		/* some value != 0 to indicate an error */
		errcode = 1;
	}

	int c = 0;
	while (c >= 0 && errcode == 0) {

		/* parse next option */
		int option_index = 0;
		c = getopt_long (argc, argv, "", long_options, &option_index);

		if (c >= 0) {
			switch (option_index) {
			case 0: /* ip */
				assign_optarg(&pc_tmp, optarg);
				/* convert input string defining the ip to in_addr_t */
#ifdef _WIN32
				if ((ip_addr.s_addr = inet_addr(pc_tmp)) == 0) {
#elif __linux
					if (inet_aton(pc_tmp, &ip_addr) == 0) {
#endif
						/* some value != 0 to indicate an error */
						errcode = 1;
					}
					free(pc_tmp);
					pc_tmp = NULL;
					break;

			case 1: /* port */
				assign_optarg(&pc_tmp, optarg);
				/* convert input string defining the port to integer */
				u_port = atoi(pc_tmp);
				pc_tmp2 = realloc(pc_tmp2, 10);
				sprintf(pc_tmp2, "%d", u_port);
				if (strcmp(pc_tmp, pc_tmp2) != 0) {
					/* some value != 0 to indicate an error */
					errcode = 1;
				}
				free(pc_tmp);
				free(pc_tmp2);
				pc_tmp2 = NULL;
				pc_tmp = NULL;
				break;

			case 2: /* in */
				assign_optarg(&pc_in, optarg);
				break;

			case 3: /* out */
				assign_optarg(&pc_out, optarg);
				break;

			case 4: /* ciphersuites */
				assign_optarg(&pc_ciphersuites, optarg);
				break;

			case 5: /* versmin */
				assign_optarg(&pc_tmp, optarg);
				if (version_string_to_enum(pc_tmp, &versmin) != 0) {
					/* unknown protocol version */
					errcode = 1;
					printf("\033[01;31mERROR: Unknown protocol version '%s'."
							" Stopping!\033[00;00m\n", pc_tmp);
				}
				free(pc_tmp);
				pc_tmp = NULL;
				break;

			case 6: /* versmax */
				assign_optarg(&pc_tmp, optarg);
				if (version_string_to_enum(pc_tmp, &versmax) != 0) {
					/* unknown protocol version */
					errcode = 1;
					printf("\033[01;31mERROR: Unknown protocol version '%s'."
							" Stopping!\033[00;00m\n", pc_tmp);
				}
				free(pc_tmp);
				pc_tmp = NULL;
				break;

			case 7: /* key */
				assign_optarg(&pc_file_key, optarg);
				break;

			case 8: /* certs */
				assign_optarg(&pc_file_certs, optarg);
				break;

			case 9: /* CAcerts */
				assign_optarg(&pc_file_CAcerts, optarg);
				break;

			case 10: /* authlevel */
				assign_optarg(&pc_tmp, optarg);
				if (authlevel_string_to_enum(pc_tmp, &authlevel) != 0) {
					/* unknown authentication level */
					errcode = 1;
					printf("\033[01;31mERROR: Unknown authentication level '%s'."
							" Stopping!\033[00;00m\n", pc_tmp);
				}
				free(pc_tmp);
				pc_tmp = NULL;
				break;

			case 11: /* nconnections */
				assign_optarg(&pc_tmp, optarg);
				/* convert input string defining the number of connections to integer */
				i_n_connections = atoi(pc_tmp);
				pc_tmp2 = realloc(pc_tmp2, 10);
				sprintf(pc_tmp2, "%d", i_n_connections);
				if (strcmp(pc_tmp, pc_tmp2) != 0) {
					/* some value != 0 to indicate an error */
					errcode = 1;
				}
				free(pc_tmp);
				free(pc_tmp2);
				pc_tmp2 = NULL;
				pc_tmp = NULL;
				break;
				}
			}
		}

		/* print parameter */
		printf("in           = '%s'\n", pc_in);
		printf("out          = '%s'\n", pc_out);
		printf("ip           = '%s'\n", inet_ntoa(ip_addr));
		printf("port         = %d\n", u_port);
		printf("ciphersuites = '%s'\n", pc_ciphersuites);
		printf("versmin      = '%s'\n", version_enum_to_string(versmin));
		printf("versmax      = '%s'\n", version_enum_to_string(versmax));
		printf("key          = '%s'\n", pc_file_key);
		printf("certs        = '%s'\n", pc_file_certs);
		printf("CAcerts      = '%s'\n", pc_file_CAcerts);
		printf("authlevel    = '%s'\n", authlevel_enum_to_string(authlevel));
		printf("nconnections = %d\n", i_n_connections);

		pc_ciphersuites = str_null_to_empty(pc_ciphersuites);


		if (errcode == 0) {

			/* ===== parse file name lists for certificates and CA certificates ===== */

			char ** ppc_certs = malloc(10 * sizeof(char*));
			char ** ppc_CAcerts = malloc(10 * sizeof(char*));

			int i_N_certs = tokenize_string(pc_file_certs, ppc_certs, 10);
			int i_N_CAcerts = tokenize_string(pc_file_CAcerts, ppc_CAcerts, 10);

			if (read_pem_files(ppc_certs, i_N_certs) < 0) {
				puts("\033[01;31mERROR: Failed to read certificates"
						" (--certs). Ignoring...\033[00;00m");
				/* TODO: also need to free memory!! */
				ppc_certs = NULL;
			}
			if (read_pem_files(ppc_CAcerts, i_N_CAcerts) < 0) {
				puts("\033[01;31mERROR: Failed to read CA certificates"
						" (--CAcerts). Ignoring...\033[00;00m");
				/* TODO: also need to free memory!! */
				ppc_CAcerts = NULL;
			}

			/* initialize timeout timer? */
			tot_init();

			if (strcmp(pc_role, "client") == 0) {

				/* client parameter */
				SSL_CLIENT_PARS parameters;
				parameters.pc_filename_remote	= pc_in;
				parameters.pc_filename_local	= pc_out;
				parameters.pc_ciphersuites		= pc_ciphersuites;
				parameters.u_port				= u_port;
				parameters.ip_addr				= ip_addr;
				parameters.versmin 				= versmin;
				parameters.versmax 				= versmin;
				parameters.key 					= NULL;
				parameters.keyType				= E_SSL_KEY_UNDEFINED;
				parameters.keyParameters		= malloc(20*sizeof(char));
				parameters.ppc_certs 			= ppc_certs;
				parameters.ppc_CAcerts 			= ppc_CAcerts;
				parameters.authlevel			= authlevel;

				if (pc_file_key != NULL) {
					parameters.key = read_pem_file_(pc_file_key, NULL, parameters.keyParameters, &(parameters.keyType));
				}

				puts("Acting as CLIENT");

				/* start client */
				errcode = test_run_client(parameters);


			} else if (strcmp(pc_role, "server") == 0 || strcmp(pc_role, "echo") == 0) {

				/* server parameter */
				SSL_SERVER_PARS parameters;
				parameters.pc_filename 		= pc_in;
				parameters.pc_ciphersuites	= pc_ciphersuites;
				parameters.u_port 			= u_port;
				parameters.versmin 			= versmin;
				parameters.versmax 			= versmax;
				parameters.key 				= NULL;
				parameters.keyType			= E_SSL_KEY_UNDEFINED;
				parameters.keyParameters	= malloc(200*sizeof(char)); //TODO vpy: check if 200 bytes are enough for all EC parameter
				parameters.ppc_certs 		= ppc_certs;
				parameters.ppc_CAcerts 		= ppc_CAcerts;
				parameters.authlevel		= authlevel;

				if (pc_file_key != NULL) {
					parameters.key = read_pem_file_(pc_file_key, NULL, parameters.keyParameters, &(parameters.keyType));
				}

				if (strcmp(pc_role, "echo") == 0) {
					parameters.echo = 1;
					puts("Acting as Echo SERVER");
				} else {
					parameters.echo = 0;
					puts("Acting as SERVER");
				}

				/* start server */
				errcode = test_run_server(parameters, i_n_connections);

			} else {
				printf("ERROR: Unknown role '%s'. Stopping!\n", pc_role);
				errcode = 1;
			}

			free(ppc_certs);
			free(ppc_CAcerts);
		} else {
			printf("ERROR: An error occurred while parsing input options. Stopping!\n");
			errcode = 1;
		}


		free(pc_in);
		free(pc_out);
		free(pc_role);
		free(pc_ciphersuites);


		/* return the error code which is 0 if no error occurred */
		return errcode;
	}


	int test_run_client(SSL_CLIENT_PARS parameters) {
		puts("CLIENT started");

		/* run client */
		E_CLIENT_FSM_RESULT client_result;
		do {
			client_result = ssl_client_entry(parameters);
		} while (client_result == E_CLIENT_FSM_AGAIN);

		printf("CLIENT stopped ");
		if (client_result == E_CLIENT_FSM_ERROR) {
			printf("with errors\n");
		} else {
			printf("without errors\n");
		}

		return (client_result == E_CLIENT_FSM_ERROR) ? 1 : 0;
	}


	int test_run_server(SSL_SERVER_PARS parameters, int i_n_connections) {
		ssl_server_start();
		if (parameters.echo != 0) {
			puts("Echo SERVER started");
		} else {
			puts("SERVER started");
		}

		if (i_n_connections == -2) {
			puts("Please note: Going to relaunch server infinite times");
		}

		/* run server in normal mode */
		E_SERVER_FSM_RESULT server_result;
		do {
			server_result = ssl_server_entry(parameters);
			if (server_result == E_SERVER_FSM_DONE && i_n_connections > 0) {
				i_n_connections--;
			}
		} while ((i_n_connections != 0 && (server_result == E_SERVER_FSM_AGAIN ||
				server_result == E_SERVER_FSM_DONE)) || i_n_connections == -2);

		if (parameters.echo != 0) {
			printf("Echo SERVER stopped ");
		} else {
			printf("SERVER stopped ");
		}
		if (server_result == E_SERVER_FSM_ERROR) {
			printf("with errors\n");
		} else {
			printf("without errors\n");
		}

		return (server_result == E_SERVER_FSM_ERROR) ? 1 : 0;
	}


	char * str_null_to_empty(char * pc_input) {
		if (pc_input == NULL) {
			return "";
		} else {
			return pc_input;
		}
	}


	void assign_optarg(char ** pc_par, char * pc_optarg) {
		int length = (pc_optarg != NULL) ? strlen(pc_optarg) : 0;
		if (length > 0) {
			if (*pc_par == NULL) {
				*pc_par = (char*)malloc(length + 1);
			}
			strncpy(*pc_par, pc_optarg, length + 1);
		}
	}


	int version_string_to_enum(char * version, e_sslVer_t * p_version) {

		/* a value != 0 indicates an unknown authentication level input string */
		int b_fail = 0;

		if (strcmp(version, "ssl3") == 0) {
			*p_version = E_SSL_3_0;
		} else if (strcmp(version, "tls1") == 0) {
			*p_version = E_TLS_1_0;
		} else if (strcmp(version, "tls1_1") == 0) {
			*p_version = E_TLS_1_1;
		} else if (strcmp(version, "tls1_2") == 0) {
			*p_version = E_TLS_1_2;
		} else {
			/* unknown protocol version */
			b_fail = 1;
		}

		/* return 0 if successful */
		return b_fail;
	}


	char * version_enum_to_string(e_sslVer_t version) {
		char * ret = "<unknown>";
		switch (version) {
		case E_SSL_3_0:
			ret = "ssl3";
			break;
		case E_TLS_1_0:
			ret = "tls1";
			break;
		case E_TLS_1_1:
			ret = "tls1_1";
			break;
		case E_TLS_1_2:
			ret = "tls1_2";
			break;
		case E_VER_DCARE:
			ret = "dont_care";
			break;
		}
		return ret;
	}


	int authlevel_string_to_enum(char * pc_authlevel, e_sslAuthLevel_t * p_authlevel) {

		/* a value != 0 indicates an unknown authentication level input string */
		int b_fail = 0;

		if (strcmp(pc_authlevel, "E_SSL_NO_AUTH") == 0) {
			*p_authlevel = E_SSL_NO_AUTH;
		} else if (strcmp(pc_authlevel, "E_SSL_SHOULD_AUTH") == 0) {
			*p_authlevel = E_SSL_SHOULD_AUTH;
		} else if (strcmp(pc_authlevel, "E_SSL_MUST_AUTH") == 0) {
			*p_authlevel = E_SSL_MUST_AUTH;
		} else if (strcmp(pc_authlevel, "E_SSL_MUST_VERF_SRVCERT") == 0) {
			*p_authlevel = E_SSL_MUST_VERF_SRVCERT;
		} else if (strcmp(pc_authlevel, "E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_NO_AUTH") == 0) {
			*p_authlevel = E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_NO_AUTH;
		} else if (strcmp(pc_authlevel, "E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_SHOULD_AUTH") == 0) {
			*p_authlevel = E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_SHOULD_AUTH;
		} else if (strcmp(pc_authlevel, "E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_MUST_AUTH") == 0) {
			*p_authlevel = E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_MUST_AUTH;
		} else {
			/* unknown authentication level */
			b_fail = 1;
		}

		/* return 0 if successful */
		return b_fail;
	}

	char * authlevel_enum_to_string(e_sslAuthLevel_t p_authleveln) {

		char * ret = "<unknown>";
		switch (p_authleveln) {
		case E_SSL_NO_AUTH:
			ret = "E_SSL_NO_AUTH";
			break;
		case E_SSL_SHOULD_AUTH:
			ret = "E_SSL_SHOULD_AUTH";
			break;
		case E_SSL_MUST_AUTH:
			ret = "E_SSL_MUST_AUTH";
			break;
		case E_SSL_MUST_VERF_SRVCERT:
			ret = "E_SSL_MUST_VERF_SRVCERT";
			break;
		case E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_NO_AUTH:
			ret = "E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_NO_AUTH";
			break;
		case E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_SHOULD_AUTH:
			ret = "E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_SHOULD_AUTH";
			break;
		case E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_MUST_AUTH:
			ret = "E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_MUST_AUTH";
			break;
		}
		return ret;
	}


	int read_pem_files(char ** ppc_buffer, int i_N_max) {

		int i = 0;
		while (i >= 0 && i < i_N_max && ppc_buffer[i] != NULL) {
			char * pc_filename = ppc_buffer[i];

			char * pc_buf = read_pem_file_(pc_filename, NULL, NULL, NULL);

			if (pc_buf != NULL) {
				/* replace pointer to filename string by pointer to file contents */
				ppc_buffer[i] = pc_buf;
				i++;
			} else {
				i = -1;
			}

		}

		return i;
	}


	char * read_pem_file_(char * pc_filename, char ** ppc_type, char* pc_keyParameters, e_sslKeyType_t* p_keyType) {

		/* open PEM file */
		FILE * fp = fopen(pc_filename, "r");

		/* pointer to output stream */
		char * pc_out = NULL;

		/* length of file */
		int i_len = 0;

		/* determine length of file */
		if (fp != NULL) {
			while (fgetc(fp) != EOF) {
				i_len++;
			}
			rewind(fp);
		}

		if (i_len > 0) {
			/* allocate memory to store file (including terminating '\0') */
			char * pc_input = (char*)malloc((i_len + 1) * sizeof(char));

			/* read from file and add terminating '\0' */
			fread(pc_input, sizeof(char), i_len, fp);
			pc_input[i_len] = '\0';

			/* a temporary pointer */
			char * pc_tmp;
			/* pointer to current position in input stream */
			char * pc_in_pos = pc_input;

			//Temp pointer to help to find the key/cert
			char * pc_in_pos_tmp;

			/* to be safe allocate as much memory as input needs */
			pc_out = malloc(i_len * sizeof(char));
			/* pointer to current position in output stream */
			char * pc_out_pos = pc_out;

			//if a BEGIN EC PARAMETERS is present, we have an EC key
			if((pc_in_pos_tmp = strstr(pc_in_pos, "-BEGIN EC PARAMETERS")) != NULL)
			{
				assert(pc_keyParameters!=NULL);
				assert(p_keyType!=NULL);

				//Store the type of key
				*p_keyType = E_SSL_KEY_EC;

				//Store the EC Parameters
				//*pc_keyParameters = ...

				pc_tmp = strstr(pc_in_pos_tmp+sizeof(char), "-");

				/* scan for end of BEGIN marker */
				while (*pc_tmp == '-') {
					pc_tmp++;
				}

				//Loop until begin of end marker (-----END xxxxx-----)
				while (*pc_tmp != '-') {
					/* only include BASE64 characters */
					if ((pc_tmp[0] >= 'a' 	&& *pc_tmp <= 'z')   ||
							(*pc_tmp >= 'A' && *pc_tmp <= 'Z') ||
							(*pc_tmp >= '0' && *pc_tmp <= '9') ||
							*pc_tmp == '/' || *pc_tmp == '+'  || *pc_tmp == '=')
					{
						*pc_keyParameters = *pc_tmp;
						pc_keyParameters++;
					}
					pc_tmp++;
				}

				*pc_keyParameters = '\0';

				//Go to the beginning of the key
				pc_in_pos = strstr(pc_in_pos, "-BEGIN EC PRIVATE KEY");
			}

			//if a BEGIN EC PRIVATE KEY is present, we have a EC private key
			else if((pc_in_pos_tmp = strstr(pc_in_pos, "-BEGIN EC PRIVATE KEY")) != NULL)
			{
				assert(pc_keyParameters!=NULL);
				assert(p_keyType!=NULL);

				//Store the type of key
				*p_keyType = E_SSL_KEY_EC;

				//Go to beginning of the key
				pc_in_pos = strstr(pc_in_pos, "-BEGIN EC PRIVATE KEY");
			}

			//if a BEGIN RSA PRIVATE KEY is present, we have a RSA private key
			else if((pc_in_pos_tmp = strstr(pc_in_pos, "-BEGIN RSA PRIVATE KEY")) != NULL)
			{
				assert(pc_keyParameters!=NULL);
				assert(p_keyType!=NULL);

				//Store the type of key
				*p_keyType = E_SSL_KEY_RSA;

				//Go to beginning of the key
				pc_in_pos = strstr(pc_in_pos, "-BEGIN RSA PRIVATE KEY");
			}
			else
			{
				if(p_keyType!=NULL)
				{
					//We are reading a certificate or something else
					*p_keyType = E_SSL_KEY_UNDEFINED;
				}
				pc_in_pos = strstr(pc_in_pos, "-BEGIN ");
			}
			//end vpy
			pc_tmp = strstr(pc_in_pos + sizeof(char), "-");
			if (ppc_type != NULL) {
				memcpy(*ppc_type, pc_in_pos + 7 * sizeof(char),
						pc_tmp - pc_in_pos - 7 * sizeof(char));
			}
			pc_in_pos = pc_tmp;

			/* scan for end of BEGIN marker */
			while (pc_in_pos[0] == '-') {
				pc_in_pos = &(pc_in_pos[1]);
			}

			/* read up to END marker */
			while (pc_in_pos[0] != '-') {
				/* only include BASE64 characters */
				if ((pc_in_pos[0] >= 'a' && pc_in_pos[0] <= 'z') ||
						(pc_in_pos[0] >= 'A' && pc_in_pos[0] <= 'Z') ||
						(pc_in_pos[0] >= '0' && pc_in_pos[0] <= '9') ||
						pc_in_pos[0] == '/' || pc_in_pos[0] == '+' || pc_in_pos[0] == '=') {
					pc_out_pos[0] = pc_in_pos[0];
					pc_out_pos = &(pc_out_pos[1]);
				}
				pc_in_pos = &(pc_in_pos[1]);
			}

			pc_out_pos[0] = '\0';

			/* free memory again */
			free(pc_input);
		}

		/* close file */
		if (fp != NULL) {
			fclose(fp);
		}

		return pc_out;
	}


	void print_string_tokens(char ** pc_tokens, int i_N) {

		if (pc_tokens != NULL) {
			int i;
			for (i = 0; i < i_N; i++) {
				if (pc_tokens[i] != NULL) {
					printf("%d: '%s'\n", i, pc_tokens[i]);
				}
			}
		}
	}


	int tokenize_string(char * pc_input, char ** ppc_tokens, int i_N_max) {

		/* the return value of this function: will
		 * be the number of extracted string tokens */
		int i_N = 0;

		if (pc_input != NULL) {
			/* output buffer: the buffer holding the string tokens */
			char * pc_buf = malloc(sizeof(char) * (strlen(pc_input) + 1));
			/* pointer to current position in output buffer */
			char * pc_buf_pos = pc_buf;
			/* end of buffer */
			char * pc_buf_end = pc_buf + sizeof(char) * strlen(pc_input);

			strcpy(pc_buf, pc_input);

			while (pc_buf_pos < pc_buf_end && i_N < i_N_max) {
				char * pc_next = strchr(pc_buf_pos, ':');
				if (pc_next != NULL) {
					/* replace separation character by string termination character '\0' */
					*pc_next = '\0';
					/*  */
					ppc_tokens[i_N++] = pc_buf_pos;
					pc_buf_pos = pc_next + sizeof(char);
				} else {
					ppc_tokens[i_N++] = pc_buf_pos;
					pc_buf_pos += sizeof(char) * (strlen(pc_buf_pos) + 1);
				}
			}
		}

		if (i_N < i_N_max) {
			/* terminate the array of pointers with a NULL pointer */
			ppc_tokens[i_N] = NULL;
		}

		return i_N;
	}

#else

#define testOther 0
	int main(int argc , char *argv[])
	{

#if testOther
		GciCtxConfig_t p[10];
		int i=0;

		p[4].data.sign.config.cmac.iv = (uint8_t*)malloc(sizeof(uint8_t));

		if(NULL != p[4].data.sign.config.cmac.iv)
		{
			puts("Done.");
		}

		else
		{
			puts("Error.");
		}

		uint8_t array[5];
		array[0]=1;
		array[1]=2;
		array[2]=3;
		array[3]=4;
		array[4]=5;

		uint8_t* test;


		printf("\r\nfor copy without malloc:");
		for(i=0;i<5;i++)
		{
			printf("%d", test[i]);
		}

		test = (uint8_t*)malloc(sizeof(*test)*5);


		printf("\r\nfor copy with malloc:");
		for(i=0;i<5;i++)
		{
			printf("%d", test[i]);
		}

		memcpy(test, array, sizeof(array));
		printf("\r\nafter copy:");
		for(i=0;i<5;i++)
		{
			printf("%d", test[i]);
		}

		free(test);
		printf("\r\nafter free memory:");
		for(i=0;i<5;i++)
		{
			printf("%d", test[i]);
		}

		memcpy(test, array, sizeof(array));
		printf("\r\nmemcopy after free memory:");
		for(i=0;i<5;i++)
		{
			printf("%d", test[i]+1);
		}

		/*	free(test);
	printf("\r\nafter free memory:");
	for(i=0;i<5;i++)
	{
		printf("%d", test[i]);
	}
		 */
		printf("\r\n");


#else

		//Used for test



#endif
		return 0;
	}

#endif
