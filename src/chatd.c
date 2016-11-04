/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

// Constants:
#define MAX_MESSAGE_LENGTH 1024

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <glib.h>
#include <glib/gprintf.h>

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
             (_addr1->sin_family != _addr2->sin_family));

    if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return -1;
    } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return 1;
    } else if (_addr1->sin_port < _addr2->sin_port) {
        return -1;
    } else if (_addr1->sin_port > _addr2->sin_port) {
        return 1;
    }
    return 0;
}

/* This can be used to build instances of GTree that index on
   the file descriptor of a connection. */
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data)
{
     return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}

int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_in server, client;

    if (argc != 2) {
         fprintf(stderr, "Usage: %s <port>\n", argv[0]);
         exit(EXIT_FAILURE);
    }

    const int server_port = strtol(argv[1], NULL, 10);

    gchar message[MAX_MESSAGE_LENGTH];

    /* Create and bind a TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    /* Network functions need arguments in network byte order instead of
       host byte order. The macros htonl, htons convert the values. */
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = server_port;
    bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

    /* Before the server can accept messages, it has to listen to the
       welcome port. A backlog of six connections is allowed. */
    listen(sockfd, 6);

    gchar *crt_path = g_strconcat("fd.crt", NULL);
    gchar *pkey_path = g_strconcat("root-ca/private/rsa-public.key", NULL);

     /* Initialize OpenSSL */
    SSL_library_init(); /* load encryption & hash algorithms for SSL */
    SSL_load_error_strings(); /* load the error strings for good error reporting */

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_server_method());
    /* Load server certificate into the SSL context */
    if (SSL_CTX_use_certificate_file(ssl_ctx, crt_path, SSL_FILETYPE_ASN1) <= 0) { 
        perror("SSL_CTX_use_certificate_file()");
        exit(EXIT_FAILURE);
    }
    /* Load the server private-key into the SSL context */
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, pkey_path, SSL_FILETYPE_ASN1) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file()");
        exit(EXIT_FAILURE);
    }

     /* Receive and handle messages. */
    for(;;) {
        //Accepting a TCP connection, connfd is a handle dedicated to this connection.
        socklen_t len = (socklen_t) sizeof(client);
        int connfd = accept(sockfd, (struct sockaddr *) &client, &len);
        SSL_set_fd(cSSL, newsockfd );

        /* Receive from connfd, not sockfd. */
        ssize_t n = recv(connfd, message, sizeof(message) - 1, 0);
        message[n] = '\0';

        for(unsigned int i = 0; i < n; i++) g_printf("%hhx ", message[i]);
        g_printf("\n");
    }

    exit(EXIT_SUCCESS);
}
