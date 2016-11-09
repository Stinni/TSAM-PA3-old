
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* GLib headers */
#include <glib.h>
#include <glib/gprintf.h>

/* Logger header */
#include "logger.h"

// Constants:
#define MAX_MESSAGE_LENGTH    1025
#define MAX_NUMBER_OF_CLIENTS   30

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

    if(_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return -1;
    } else if(_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return 1;
    } else if(_addr1->sin_port < _addr2->sin_port) {
        return -1;
    } else if(_addr1->sin_port > _addr2->sin_port) {
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

int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(sd, (struct sockaddr*) &addr, (socklen_t) sizeof(addr)) != 0)
    {
        perror("Can't bind port");
        exit(EXIT_FAILURE);
    }
    if(listen(sd, 6) != 0 ) // A backlog of 6 connections is allowed
    {
        perror("Can't configure listening port");
        exit(EXIT_FAILURE);
    }
    return sd;
}

SSL_CTX* InitServerCTX()
{
    SSL_CTX *ctx;

    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */
    SSL_load_error_strings(); /* load the error strings for good error reporting */
    ctx = SSL_CTX_new(TLSv1_server_method()); /* create new context from method */
    if(!ctx)
    {
        perror("SSL_CTX_new(TLSv1_server_method())");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* file)
{
    /* Load server certificate into the SSL context */
    if(SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM) <= 0) { 
        perror("SSL_CTX_use_certificate_file()");
        exit(EXIT_FAILURE);
    }

    /* Load the server private-key into the SSL context */
    if(SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file()");
        exit(EXIT_FAILURE);
    }

    /* verify private key */
    if(!SSL_CTX_check_private_key(ctx)) {
        perror("Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    if(argc != 2) {
         fprintf(stderr, "Usage: %s <port>\n", argv[0]);
         exit(EXIT_FAILURE);
    }

    /* Initialize OpenSSL */
    SSL_library_init(); /* load encryption & hash algorithms for SSL */
    SSL_CTX *ssl_ctx = InitServerCTX();

    //char filePath[17] = "./src/server.pem\0"; // gamla cert og key
    char filePath[17] = "./src/mycert.pem\0"; // útbjó nýtt samkv. simplecodings demo
    LoadCertificates(ssl_ctx, filePath); /* load certs */
    SSL *ssl = SSL_new(ssl_ctx);

    /* Create and bind a TCP socket */
    int server_port = strtol(argv[1], NULL, 10);
    int server = OpenListener(server_port);

    //set of socket descriptors
    fd_set readfds;

    int new_socket, activity, bytes, sd, max_sd;
    int client_socket[MAX_NUMBER_OF_CLIENTS];
    struct sockaddr_in client;
    socklen_t len = (socklen_t) sizeof(client); 

    //initialise all client_socket[] to 0 so not checked
    for(int i = 0; i < MAX_NUMBER_OF_CLIENTS; i++) {
        client_socket[i] = 0;
    }

    //GTree *map = g_tree_new(fd_cmp);

    char message[MAX_MESSAGE_LENGTH];
    bzero(&message, sizeof(message));

     /* Receive and handle messages. */
    for(;;) {
        //clear the socket set
        FD_ZERO(&readfds);
        //add master socket to set
        FD_SET(server, &readfds);
        max_sd = server;

        //add child sockets to set
        for(int i = 0; i < MAX_NUMBER_OF_CLIENTS; i++) 
        {
            //socket descriptor
            sd = client_socket[i];
            //if valid socket descriptor then add to read list
            if(sd > 0) {
                FD_SET(sd, &readfds);
            }
            //highest file descriptor number, need it for the select function
            if(sd > max_sd) {
                max_sd = sd;
            }
        }

        //wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if((activity < 0) && (errno!=EINTR))
        {
            perror("select()");
        }

        //If something happened on the server socket , then its an incoming connection
        if(FD_ISSET(server, &readfds)) 
        {
            if((new_socket = accept(server, (struct sockaddr *) &client, &len)) < 0)
            {
                perror("accept()");
                exit(EXIT_FAILURE);
            }

            //add new socket to array of sockets
            for(int i = 0; i < MAX_NUMBER_OF_CLIENTS; i++) 
            {
                //if position is empty
                if(client_socket[i] == 0)
                {
                    client_socket[i] = new_socket;
                    break;
                }
            }

            SSL_set_fd(ssl, new_socket);

            /* do SSL-protocol accept */
            if(SSL_accept(ssl) < 0)
            {
                perror("SSL_accept()");
            }
            else
            {
                gchar *clientIP = g_strdup_printf("%s", inet_ntoa(client.sin_addr));
                gchar *clientPort = g_strdup_printf("%i", (int)ntohs(client.sin_port));
                logConnected(clientIP, clientPort);
                g_free(clientPort);
                g_free(clientIP);
                //char msg[36] = "This message is from the SSL server\0";
                //SSL_write(ssl, msg, sizeof(msg)); /* send msg */
            }
        }

        //else its some IO operation on some other socket :)
        for(int i = 0; i < MAX_NUMBER_OF_CLIENTS; i++) 
        {
            sd = client_socket[i];

            if(FD_ISSET(sd, &readfds))
            {
                SSL_set_fd(ssl, sd);
                //Check if it was for closing , and also read the incoming message
                if((bytes = SSL_read(ssl, message, sizeof(message) - 1)) == 0)
                {
                    //Somebody disconnected , get his details and log
                    getpeername(sd, (struct sockaddr*)&client , &len);
                    gchar *clientIP = g_strdup_printf("%s", inet_ntoa(client.sin_addr));
                    gchar *clientPort = g_strdup_printf("%i", (int)ntohs(client.sin_port));
                    logDisconnected(clientIP, clientPort);
                    g_free(clientPort);
                    g_free(clientIP);

                    //Close the socket and mark as 0 in list for reuse
                    close(sd);
                    client_socket[i] = 0;
                }
                else // Work with incoming messages here!
                {
                    message[bytes] = 0;
                    printf("Client msg: \"%s\"\n", message);
                    fflush(stdout);
                }
            }
        }
    }

    SSL_free(ssl);            /* release SSL state */
    close(server);
    SSL_CTX_free(ssl_ctx);
    exit(EXIT_SUCCESS);
}
