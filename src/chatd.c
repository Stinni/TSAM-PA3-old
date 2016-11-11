// SSL Chat Server & Client - Programming Assignment 3 for Computer Networking
// University of Reykjavík, autumn 2016
// Students: Ágúst Aðalsteinsson & Kristinn Heiðar Freysteinsson
// Usernames: agust11 & kristinnf13

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
#include <signal.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* GLib header */
#include <glib.h>

/* Logger header */
#include "logger.h"

/* Constants */
#define MAX_NUMBER_OF_CONNECTIONS  1024
#define MAX_MESSAGE_LENGTH         1025

#define CERT_FILE_PATH "./src/server.pem"
#define WELCOME_MSG    "Welcome to the chat server. Please start by logging in."

/* PROTOCOL prefixes
 * These are the prefixes of the message that the server recieves from and sends to the client
 */
#define REQ_GAME  "REQUEST_GAME"
#define REQ_SAY   "REQUEST_SAYY"
#define REQ_ROLL  "REQUEST_ROLL"
#define REQ_JOIN  "REQUEST_JOIN"
#define REQ_USER  "REQUEST_USER"
#define REQ_LIST  "REQUEST_LIST"
#define REQ_WHO   "REQUEST_WHOO"
#define RESP_GAME "RESPONSE_GAME"
#define RESP_SAY  "RESPONSE_SAYY"
#define RESP_ROLL "RESPONSE_ROLL"
#define RESP_JOIN "RESPONSE_JOIN"
#define RESP_USER "RESPONSE_USER"
#define RESP_LIST "RESPONSE_LIST"
#define RESP_WHO  "RESPONSE_WHOO"

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
ClientInfo*   clientInfo;
static GTree* usersTree;
static GTree* chatroomsTree;
static int    max_sd;

/* sigint_handler - The chat server can be gracefully terminated :) */
void sigint_handler(int G_GNUC_UNUSED sig)
{
    // Do cleanup and terminate the program!
    // TODO: Implement
    write(STDOUT_FILENO, "\nBye...\n", 8);
    exit(EXIT_SUCCESS);
}

/* This can be used to build instances of GTree that index on
   the file descriptor of a connection. */
static gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data) {
     return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}

/* This is used to go through the usersTree and create a list of
   all the users as a string so it can be sent back to a client. */
static gboolean getAllUsersAsString(gpointer G_GNUC_UNUSED key, gpointer value, gpointer data) {
    ClientInfo *tmp = (ClientInfo*) value;
    GString *allUsers = (GString*) data;

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

/* This is used to go through the chatroomsTree and create a list of
   all the chatrooms as a string so it can be sent back to a client. */
static gboolean getAllChatroomsAsString(gpointer key, gpointer G_GNUC_UNUSED value, gpointer data) {
    char *chatroom = (char*) key;
    GString *allRooms = (GString*) data;

    allRooms = g_string_append(allRooms, chatroom);
    allRooms = g_string_append(allRooms, "\n");
    return FALSE;
}

static gboolean set_readfds(gpointer G_GNUC_UNUSED key, gpointer value, gpointer data) {
    ClientInfo* tmp = (ClientInfo*) value;
    fd_set *readfds = (fd_set*) data;

    FD_SET(tmp->sock, readfds);
    if(tmp->sock > max_sd) {
        max_sd = tmp->sock;
    }
    return FALSE;
}

static gboolean findUser(gpointer G_GNUC_UNUSED key, gpointer value, gpointer data) {
    ClientInfo* tmp = (ClientInfo*) value;
    char *username = (char*) data;

    if(g_strcmp0(tmp->username, username) == 0) {
        printf("User found!\n");
    }

    return FALSE;
}

static void sendToUser(gpointer data, gpointer user_data) {
    ClientInfo* tmp = (ClientInfo*)data;
    char* message = user_data;

    SSL_write(tmp->ssl, message, strlen(message));
}

gboolean checkClients(gpointer key, gpointer value, gpointer data) {
    /* Get the client info from the tree */
    ClientInfo* tmp = (ClientInfo*) value;
    fd_set *readfds = (fd_set*) data;

    if(FD_ISSET(tmp->sock, readfds))
    {
        int bytes;
        char message[MAX_MESSAGE_LENGTH];
        memset(&message, 0, sizeof(message));

        //Check if it was for closing, and also read the incoming message
        if((bytes = SSL_read(tmp->ssl, message, sizeof(message) - 1)) > 0)
        {
            // Work with incoming messages here!
            message[bytes] = 0;
            if(g_str_has_prefix(message, REQ_USER))
            {
                gchar **msgSplit = g_strsplit_set(message, " ", 4); // split incoming message into 4 parts
                if(strlen(msgSplit[1]) > 0 && strlen(msgSplit[2]) > 0) { // we want the message to include a password!
                    strcpy(tmp->username, msgSplit[1]);
                    strcpy(tmp->password, msgSplit[2]);
                    gchar *msgString = g_strconcat(RESP_USER, " Username has been changed to ", msgSplit[1], "!\n", NULL);
                    if(SSL_write(tmp->ssl, msgString, strlen(msgString)) < 0) {
                        perror("SSL_write()");
                    }
                    g_free(msgString);
                }
                else
                {
                    logError("Client tried to change username without including either name or password");
                }
                g_strfreev(msgSplit);
            }
            else if(g_str_has_prefix(message, REQ_JOIN))
            {
                gchar **msgSplit = g_strsplit_set(message, " ", 3); // split incoming message into 3 parts
                if(strlen(msgSplit[1]) > 0) { // If only the req string is sent, the second token/string will be empty
                    gchar *room = g_strdup_printf("%s", msgSplit[1]);

                    /* first we remove the user from the current chatroom */
                    GSList *currentList = g_tree_lookup(chatroomsTree, tmp->chatroom);
                    currentList = g_slist_remove(currentList, tmp);
                    g_tree_replace(chatroomsTree, tmp->chatroom, currentList);

                    /* and then we add the user to the new chatroom */
                    GSList *userList = g_tree_lookup(chatroomsTree, room);
                    userList = g_slist_prepend(userList, tmp);
                    g_tree_replace(chatroomsTree, room, userList);
                    strcpy(tmp->chatroom, room);

                    /* Send a welcome message to chatroom */ 
                    gchar *msgString = g_strconcat(RESP_JOIN, " Welcome to the chat room ", room, "!\n", NULL);
                    if(SSL_write(tmp->ssl, msgString, strlen(msgString)) < 0) {
                        perror("SSL_write()");
                    }
                    g_free(msgString);
                }
                else
                {
                    logError("Client tried to join chatroom without including the chatroom");
                }
                g_strfreev(msgSplit);
            }
            else if(g_str_has_prefix(message, REQ_LIST))
            {
                GString *allRooms = g_string_new(RESP_LIST);
                allRooms = g_string_append(allRooms, " \nChatrooms:\n");
                g_tree_foreach(chatroomsTree, getAllChatroomsAsString, allRooms);

                if(SSL_write(tmp->ssl, allRooms->str, strlen(allRooms->str)) < 0) {
                    perror("SSL_write()");
                }
                g_string_free(allRooms, 1);
            }
            else if(g_str_has_prefix(message, REQ_SAY))
            {
                gchar **msgSplit = g_strsplit_set(message, " ", 3); // split incoming message into 3 parts
                if(strlen(msgSplit[1]) > 0 && strlen(msgSplit[2]) > 0) { // If only the req string is sent, or the
                    // req string along with a username but no message, we'll ignore this
                    gchar *reciever = g_strdup_printf("%s", msgSplit[1]);

                    g_tree_foreach(usersTree, findUser, reciever);

                    g_free(reciever);
                }
                else
                {
                    logError("Client tried to send private message without including either reciever and/or message");
                }
                g_strfreev(msgSplit);
            }
            else if(g_str_has_prefix(message, REQ_WHO))
            {
                GString *allUsers = g_string_new(RESP_WHO);
                allUsers = g_string_append(allUsers, "\n");
                g_tree_foreach(usersTree, getAllUsersAsString, allUsers);

                if(SSL_write(tmp->ssl, allUsers->str, strlen(allUsers->str)) < 0) {
                    perror("SSL_write()");
                }
                g_string_free(allUsers, 1);
            }
            else if(g_str_has_prefix(message, REQ_GAME))
            {
                printf("Client sent a \"REQ_GAME\" request.\n");
            }
            else if(g_str_has_prefix(message, REQ_ROLL))
            {
                printf("Client sent a \"REQ_ROLL\" request.\n");
            }
            else
            {
                /* Message should be sent to everyone in the same chatroom as the sender */
                GSList *currentList = g_tree_lookup(chatroomsTree, tmp->chatroom);
                gchar *msg = g_strconcat(tmp->username, " says: ", message, NULL);
                g_slist_foreach(currentList, sendToUser, msg);
                g_free(msg);
            }
        }
        else if(bytes == 0)
        {
            // Somebody disconnected , get his details and log
            gchar *clientIP = g_strdup_printf("%s", tmp->ip);
            gchar *clientPort = g_strdup_printf("%s", tmp->port);
            logDisconnected(clientIP, clientPort);
            g_free(clientPort);
            g_free(clientIP);

            /* Remove the user from the current chatroom */
            GSList *currentList = g_tree_lookup(chatroomsTree, tmp->chatroom);
            currentList = g_slist_remove(currentList, tmp);
            g_tree_replace(chatroomsTree, tmp->chatroom, currentList);

            // Close the socket, free the ssl and remove from the tree
            close(tmp->sock);
            SSL_free(tmp->ssl);            /* release SSL state */
            g_tree_remove(usersTree, key);
        }
        else /* Some error occurred */
        {
            int err = SSL_get_error(tmp->ssl, bytes);
            switch(err)
            {
                case SSL_ERROR_NONE:
                    logError("SSL_ERROR_NONE");
                    break;
                case SSL_ERROR_SSL:
                    logError("SSL_ERROR_SSL");
                    break;
                case SSL_ERROR_WANT_READ: 
                    logError("SSL_ERROR_WANT_READ");
                    break;
                case SSL_ERROR_WANT_WRITE: 
                    logError("SSL_ERROR_WANT_WRITE");
                    break;
                case SSL_ERROR_SYSCALL:
                    logError("SSL_ERROR_SYSCALL");
                    break;
                case SSL_ERROR_ZERO_RETURN: 
                    /* This shouldn't happen since we already check if bytes == 0 */
                    logError("SSL_ERROR_ZERO_RETURN");
                    break;
                default:
                    logError("SSL_ERROR"); 
                    break;
            }
        }
        memset(&message, 0, sizeof(message));
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

    /* Set the signal handler. */
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;           /* Restart interrupted reads */
    sa.sa_handler = sigint_handler;
    if(sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction()");
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
    g_tree_insert(chatroomsTree, "Lobby", NULL);

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
                strcpy(clientInfo->chatroom, "Lobby");
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

                /* add the user to the Lobby chatroom */
                GSList* roomList = g_tree_lookup(chatroomsTree, "Lobby");
                roomList = g_slist_prepend(roomList, clientInfo);
                g_tree_replace(chatroomsTree, "Lobby", roomList);

                /* Send a welcome message to the new client */
                if(SSL_write(ssl, WELCOME_MSG, strlen(WELCOME_MSG)) < 0)
                {
                    perror("SSL_write()");
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
