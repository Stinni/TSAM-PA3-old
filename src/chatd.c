
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

/* GLib header */
#include <glib.h>

/* Logger header */
#include "logger.h"

/* Constants */
#define MAX_NUMBER_OF_CONNECTIONS  256
#define MAX_MESSAGE_LENGTH        1025

/* A struct to keep info about each client */
typedef struct {
    char username[64];
    char password[48];
    char chatroom[64];
    int sock;
    SSL* ssl;
    char ip[64];
    char port[8];
} ClientInfo;

/* Global variables */
#define CERT_FILE_PATH "./src/mycert.pem"
#define WELCOME_MSG    "Welcome to the chat server. Please start by logging in.\n"
ClientInfo*   clientInfo;
static GTree* usersTree;
static GTree* chatroomsTree;
static int    max_sd;
GString*      allUsers;
GString*      allRooms;

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
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data) {
     return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}

/* This is used to go through the usersTree and create a list of
   all the users as a string so it can be sent back to a client. */
gboolean getAllUsersAsString(gpointer G_GNUC_UNUSED key, gpointer value, gpointer G_GNUC_UNUSED data) {
    /* make the string that contains info about all users */
    ClientInfo *tmp = (ClientInfo*) value;

    allUsers = g_string_append(allUsers, "\nUsername: ");
    allUsers = g_string_append(allUsers, tmp->username);
    allUsers = g_string_append(allUsers, "\nIP: ");
    allUsers = g_string_append(allUsers, tmp->ip);
    allUsers = g_string_append(allUsers, "\nPort: ");
    allUsers = g_string_append(allUsers, tmp->port);
    allUsers = g_string_append(allUsers, "\nChatroom: ");
    allUsers = g_string_append(allUsers, tmp->chatroom);
    allUsers = g_string_append(allUsers, "\n");
    return FALSE;
}

gboolean getAllChatroomsAsString(gpointer key, gpointer G_GNUC_UNUSED value, gpointer G_GNUC_UNUSED data) {
    allRooms = g_string_append(allRooms, key);
    allRooms = g_string_append(allRooms, "\n");
    return FALSE;
}

gboolean set_readfds(gpointer G_GNUC_UNUSED key, gpointer value, gpointer data) {
    ClientInfo* tmp = (ClientInfo*) value;
    fd_set *readfds = (fd_set*) data;
    FD_SET(tmp->sock, readfds);
    if(tmp->sock > max_sd) {
        max_sd = tmp->sock;
    }
    return 0;
}

gboolean checkClients(gpointer key, gpointer value, gpointer data) {
    int bytes;
    char message[MAX_MESSAGE_LENGTH];
    memset(&message, 0, sizeof(message));

    /* Get the client info from the tree */
    ClientInfo* tmp = (ClientInfo*) value;
    fd_set *readfds = (fd_set*) data;

    if(FD_ISSET(tmp->sock, readfds))
    {
        //Check if it was for closing, and also read the incoming message
        if((bytes = SSL_read(tmp->ssl, message, sizeof(message) - 1)) > 0)
        {
            // Work with incoming messages here!
            message[bytes] = 0;
            printf("Client msg: \"%s\"\n", message);
            char msg[36] = "This message is from the SSL server\n";
            SSL_write(tmp->ssl, msg, sizeof(msg)); /* send msg */
        }
        else if(bytes == 0)
        {
            // Somebody disconnected , get his details and log
            // TODO: Make the client send a message when disconnecting and log it then
            struct sockaddr_in client;
            socklen_t len = (socklen_t) sizeof(client); 
            memset(&client, 0, sizeof(client));
            if(getpeername(tmp->sock, (struct sockaddr*)&client, &len) != 0) {
                perror("getpeername()");
            } else {
                gchar *clientIP = g_strdup_printf("%s", inet_ntoa(client.sin_addr));
                gchar *clientPort = g_strdup_printf("%i", (int)ntohs(client.sin_port));
                logDisconnected(clientIP, clientPort);
                g_free(clientPort);
                g_free(clientIP);
                // Close the socket, free the ssl and remove from the tree
                close(tmp->sock);
                SSL_free(tmp->ssl);            /* release SSL state */
                g_tree_remove(usersTree, key);
            }
        }
        else
        {
            int err = SSL_get_error(tmp->ssl, bytes);
            switch(err)
            {
                case SSL_ERROR_SSL:
                {
                    // no real error, just try again...
                    printf("SSL_ERROR_SSL");
                    break;
                }
                case SSL_ERROR_NONE:
                {
                    // no real error, just try again...
                    printf("SSL_ERROR_NONE");
                    break;
                }
                case SSL_ERROR_ZERO_RETURN: 
                {
                    /* This shouldn't happen since we already check if bytes == 0 */
                    printf("SSL_ERROR_ZERO_RETURN");
                    break;
                }
                case SSL_ERROR_WANT_READ: 
                {
                    // no data available right now, wait a few seconds in case new data arrives...
                    printf("SSL_ERROR_WANT_READ");
                    /*FD_ZERO(&fds);
                    FD_SET(sd, &fds);

                    struct timeval *timeout;
                    memset(&timeout, 0, sizeof(struct timeval));
                    timeout.tv_sec = 5;
                    timeout.tv_nsec = 0;

                    err = select(sock+1, &fds, NULL, NULL, &timeout);
                    if (err > 0)
                        continue; // more data to read...

                    if (err == 0) {
                        // timeout...
                    } else {
                        // error...
                    }*/

                    break;
                }
                case SSL_ERROR_WANT_WRITE: 
                {
                    // socket not writable right now, wait a few seconds and try again...
                    perror("SSL_ERROR_WANT_WRITE");

                    /*FD_ZERO(&fds);
                    FD_SET(sd, &fds);

                    timeout.tv_sec = 5;
                    timeou.tv_nsec = 0;

                    err = select(sd+1, NULL, &fds, NULL, &timeout);
                    if (err > 0)
                        continue; // can write more data now...

                    if (err == 0) {
                        // timeout...
                    } else {
                        // error...
                    }*/

                    break;
                }
                default:
                {
                    printf("error %i:%i\n", bytes, err); 
                    break;
                }
            }
        }
    }
    return FALSE;
}

int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(sd, (struct sockaddr*) &addr, (socklen_t) sizeof(addr)) != 0)
    {
        perror("Can't bind port");
        exit(EXIT_FAILURE);
    }
    if(listen(sd, MAX_NUMBER_OF_CONNECTIONS) != 0 ) // A backlog of MAX_NUMBER_OF_CONNECTIONS connections is allowed
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
    ctx = SSL_CTX_new(SSLv23_server_method()); /* create new context from method */
    if(!ctx)
    {
        perror("SSL_CTX_new(SSLv23_server_method())");
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

    LoadCertificates(ssl_ctx, CERT_FILE_PATH); /* load certs */

    /* Create and bind a TCP socket */
    int server_port = strtol(argv[1], NULL, 10);
    int server = OpenListener(server_port);

    //set of socket descriptors
    fd_set readfds;

    int new_socket;
    struct sockaddr_in client;
    socklen_t len = (socklen_t) sizeof(client); 

    usersTree     = g_tree_new((GCompareFunc) fd_cmp);
    chatroomsTree = g_tree_new((GCompareFunc) strcmp);

     /* Receive and handle messages. */
    for(;;) {
        // clear the socket set and add server socket to set
        FD_ZERO(&readfds);
        FD_SET(server, &readfds);
        max_sd = server;

        //add child sockets to set
        g_tree_foreach(usersTree, set_readfds, &readfds);

        //wait for an activity on one of the sockets, timeout is NULL, so wait indefinitely
        if((select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) && (errno!=EINTR))
        {
            perror("select()");
            exit(EXIT_FAILURE);
        }

        // If something happened on the server socket, then its an incoming connection
        // TODO: Check if it makes sense to create a special function for this part
        if(FD_ISSET(server, &readfds)) 
        {
            memset(&client, 0, sizeof(client));
            if((new_socket = accept(server, (struct sockaddr *) &client, &len)) < 0)
            {
                perror("accept()");
                exit(EXIT_FAILURE);
            }

            SSL *ssl = SSL_new(ssl_ctx);
            if(ssl == NULL) {
                perror("SSL_new()");
                exit(EXIT_FAILURE);
            }
            SSL_set_fd(ssl, new_socket);

            /* do SSL-protocol accept */
            if(SSL_accept(ssl) < 0)
            {
                perror("SSL_accept()");
                exit(EXIT_FAILURE);
            }
            else
            {
                clientInfo = g_new0(ClientInfo, 1);
                clientInfo->ssl = ssl;
                clientInfo->sock = new_socket;
                //strcpy(clientInfo->username, "Anonymous");
                //strcpy(clientInfo->chatroom, "public");
                strcpy(clientInfo->ip, inet_ntoa(client.sin_addr));
                sprintf(clientInfo->port, "%d", ntohs(client.sin_port));

                /* Logging that a client has connected to the server */
                gchar *clientIP = g_strdup_printf("%s", inet_ntoa(client.sin_addr));
                gchar *clientPort = g_strdup_printf("%i", (int)ntohs(client.sin_port));
                logConnected(clientIP, clientPort);
                g_free(clientPort);
                g_free(clientIP);

                /* The user is added to the tree with the sockaddr as key and 
                 * the client Info as value */
                int *key = g_new0(int, 1);
                memcpy(key, &new_socket, sizeof(int));
                g_tree_insert(usersTree, key, clientInfo);

                /* add the user to the room public */
                /*GSList* roomList = g_tree_lookup(chatroomsTree, "public");
                roomList = g_slist_prepend(roomList, clientInfo);
                g_tree_insert(chatroomsTree, "public", roomList);*/

                /* Send a welcome message to the new client */
                if(SSL_write(ssl, WELCOME_MSG, strlen(WELCOME_MSG)) < 0)
                {
                    perror("SSL_write()");
                    exit(EXIT_FAILURE);
                }
            }
        }

        // else its some IO operation on some other socket :)
        // We iterate through all clients and check if there is data to be
        // recieved. checkClients() function is used for that.
        g_tree_foreach(usersTree, checkClients, &readfds);
    }

    g_tree_destroy(chatroomsTree);
    g_tree_destroy(usersTree);
    close(server);
    SSL_CTX_free(ssl_ctx);
    exit(EXIT_SUCCESS);
}
