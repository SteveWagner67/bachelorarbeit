//SSL-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

 
#define FAIL    -1
 
int OpenConnection(const char* hostname, int port) {

    int sd;
    struct sockaddr_in addr;
 
    struct in_addr ip_addr;
	inet_aton(hostname, &ip_addr);

    sd = socket(PF_INET, SOCK_STREAM, 0);
	/*fcntl(sd, F_SETFL, O_NONBLOCK);*/

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = ip_addr;

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 &&
            (errno != EINPROGRESS)) {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
 
SSL_CTX* InitCTX(void) {

    const SSL_METHOD* method;
    SSL_CTX* ctx;
 
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}



int http_get(SSL * p_ssl, char * pc_filename) {

    char buf[1024];
    int bytes;
    FILE * fp = NULL;

    char * msg = "GET / HTTP/1.1\r\n\r\n";
    SSL_write(p_ssl, msg, strlen(msg));

    while ((bytes = SSL_read(p_ssl, buf, sizeof(buf))) > 0) {

        buf[bytes] = 0;
        char * pc_buf = buf;

	    if (fp == NULL && (strncmp(buf, "HTTP/1.0 200", 12) == 0
			    || strncmp(buf, "HTTP/1.1 200", 12) == 0)) {

		    /* find beginning of content */
		    char * pc_start = strstr(buf, "\r\n\r\n");

		    if (pc_start != NULL) {
			    /* open file */
			    fp = fopen(pc_filename, "w");

			    /* move to beginning of content */
        		pc_buf = pc_start + 4 * sizeof(char);
        		bytes -= (pc_buf - buf) / sizeof(char);
		    }
	    }

	    if (fp != NULL) {
		    /* write to file if is already open */
		    fwrite(pc_buf, 1, bytes, fp);
	    }
    }

    if (fp != NULL) {
        fclose(fp);
    }

    return 0;
}


 
int main(int count, char *strings[]) {

    const unsigned int N = 20;

    SSL_CTX *ctx;
    int server;
    SSL* ssl[N];
    
    char *hostname, *portnum;
 
    if (count == 1) {
        hostname = "127.0.0.1";
        portnum = "4433";
    } else if (count == 3) {
        hostname = strings[1];
        portnum = strings[2];
    } else {
        printf("usage: %s [<hostname> <portnum>]\n", strings[0]);
        exit(0);
    }

    SSL_library_init();
 
    ctx = InitCTX();

    int i;
    for (i = 0; i < N; i++) {

        printf("==> Running iteration i = %d\n", i);

        ssl[i] = SSL_new(ctx);

        server = OpenConnection(hostname, atoi(portnum));
        SSL_set_fd(ssl[i], server);

        if (SSL_connect(ssl[i]) != -1) {
            
            char * pc_filename = malloc(100);
            sprintf(pc_filename, "testfile_i%d.out", i);

            http_get(ssl[i], pc_filename);

            free(pc_filename);
            

            SSL_shutdown(ssl[i]);

            SSL_free(ssl[i]);

        } else {
            puts("Cannot connect");
        }

        close(server);

        /* wait for a second */
        if (i < N) {
            sleep(1);
        }
    }
    /*
    for (i = 0; i < N; i++) {
        SSL_free(ssl[i]);
    }
    */
    SSL_CTX_free(ctx);

    return 0;
}
