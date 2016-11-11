// SSL Chat Server & Client - Programming Assignment 3 for Computer Networking
// University of Reykjavík, autumn 2016
// Students: Ágúst Aðalsteinsson & Kristinn Heiðar Freysteinsson
// Usernames: agust11 & kristinnf13

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* GLib header */
#include <glib.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

/* For getpasswd function */
//#include "getpasswd.c"

/* Constants */
#define MAX_MESSAGE_LENTH 1025
/*CLIENT MESSAGES */
#define REQ_GAME "REQUEST_GAME"
#define REQ_SAY  "REQUEST_SAYY"
#define REQ_ROLL "REQUEST_ROLL"
#define REQ_JOIN "REQUEST_JOIN"
#define REQ_USER "REQUEST_USER"
#define REQ_LIST "REQUEST_LIST"
#define REQ_WHO  "REQUEST_WHOO"

/* SERVER RESPONSES */

#define RESP_GAME "RESPONSE_GAME"
#define RESP_SAY  "RESPONSE_SAYY"
#define RESP_ROLL "RESPONSE_ROLL"
#define RESP_JOIN "RESPONSE_JOIN"
#define RESP_USER "RESPONSE_USER"
#define RESP_LIST "RESPONSE_LIST"
#define RESP_WHO  "RESPONSE_WHOO"
/* This variable holds a file descriptor of a pipe on which we send a
 * number if a signal is received. */
 static int exitfd[2];

/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. The
   signal number is sent through a self pipe to notify the main loop
   of the received signal. This avoids a race condition in select. */
void signal_handler(int signum)
{
    int _errno = errno;
    if (write(exitfd[1], &signum, sizeof(signum)) == -1 && errno != EAGAIN) {
        abort();
    }
    fsync(exitfd[1]);
    errno = _errno;
}


static void initialize_exitfd(void)
{
    /* Establish the self pipe for signal handling. */
    if (pipe(exitfd) == -1) {
        perror("pipe()");
        exit(EXIT_FAILURE);
    }

    /* Make read and write ends of pipe nonblocking */
    int flags;
    flags = fcntl(exitfd[0], F_GETFL);
    if (flags == -1) {
        perror("fcntl-F_GETFL");
        exit(EXIT_FAILURE);
    }
    flags |= O_NONBLOCK;                /* Make read end nonblocking */
    if (fcntl(exitfd[0], F_SETFL, flags) == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }

    flags = fcntl(exitfd[1], F_GETFL);
    if (flags == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }
    flags |= O_NONBLOCK;                /* Make write end nonblocking */
    if (fcntl(exitfd[1], F_SETFL, flags) == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }

    /* Set the signal handler. */
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;           /* Restart interrupted reads()s */
    sa.sa_handler = signal_handler;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
static int server_fd;
static SSL *server_ssl;

/* This variable is to access the SSL context. It's only global so it
 * can be used to free it when shutting down the client.
 */
static SSL_CTX *ctx;

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static gchar *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static gchar *prompt;

void Message_From_Server()
{
    char message[MAX_MESSAGE_LENTH];
    memset(&message, 0, sizeof(message));
    int bytes = SSL_read(server_ssl, message, sizeof(message) - 1); /* get request */
    if (bytes > 0)
    {
        message[bytes] = 0;
        int i = 13;
        if(strncmp("RESPONSE", message, 8) == 0) {
            if(strncmp(RESP_GAME, message, i) == 0){
                /*TO DO */
                return;
            }
            if(strncmp(RESP_ROLL, message, i) == 0){
                /*TO DO */
                return;
            }
            if(strncmp(RESP_USER, message, i) == 0){
                /*TO DO */
                return;
            }
            /* PRIVATE MESSAGES */ 
            if(strncmp(RESP_SAY, message, i) == 0){
                gchar *echo = g_strdup_printf("%s", &(message[i+1]));
                printf("Private message from -> %s\n", echo);
                fflush(stdout);
                g_free(echo);
                rl_redisplay();
                return;
            }
            else {
                gchar *echo = g_strdup_printf("%s", &(message[i+1]));
                printf("%s\n", echo);
                fflush(stdout);
                g_free(echo);
                rl_redisplay();
            }
        
       }
       else /*Chatroom messages */
       {
            printf("%s\n", message);
            fflush(stdout);
       }
    }
    else if(bytes == 0)
    {
        SSL_free(server_ssl);
        SSL_CTX_free(ctx);        /* release context */
        printf("The server terminated the connection!\n");
        fflush(stdout);
        exit(EXIT_SUCCESS);
    }
    else
    {
        perror("SSL_read()"); //server not responding to query
    }
}
char* create_message_to_server(char *REQ, char *message)
{
    char *messageToServer = malloc(strlen(REQ) + strlen(message) + 2);
    strcpy(messageToServer, REQ); //copy the REQUEST_GAME to 
    strcat(messageToServer, " "); //Add a space between the request and the username
    strcat(messageToServer, message); // add the username and message to the message to the server..

    return messageToServer;
}
char* create_prompt(char *first, char *last)
{
    char *new_prompt = malloc(strlen(first) + strlen(last) + 4);
    strcpy(new_prompt, first); //copy the REQUEST_GAME to 
    strcat(new_prompt, "@"); //Add a space between the request and the username
    strcat(new_prompt, last); // add the username and message to the message to the server..
    strcat(new_prompt, "> "); //Add a space between the request and the username

    return new_prompt;
}
/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line)
{
    if (NULL == line) {
        rl_callback_handler_remove();
        signal_handler(SIGTERM);
        return;
    }
    if (strlen(line) > 0) {
        add_history(line);
    }
    if ((strncmp("/bye", line, 4) == 0) ||
        (strncmp("/quit", line, 5) == 0) ||
        (strncmp("/exit", line, 5) == 0)) {
        rl_callback_handler_remove();
        signal_handler(SIGTERM);
        return;
    }
    if (strncmp("/game", line, 5) == 0) {
        /* Skip whitespace */
        int i = 5;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /game username\n", 29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        char *username = strdup(&(line[i]));
        SSL_write(server_ssl, create_message_to_server(REQ_GAME, username), 256); /* send list request */
        /* Start game */
        return;
    }
    if (g_str_has_prefix(line, "/join")) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if(line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        if(user == NULL) {
            write(STDOUT_FILENO, "You have to log in first. Use /user to do so\n", 45);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }

        g_free(chatroom);
        chatroom = g_strdup_printf("%s", &(line[i]));
        /* Process and send this information to the server. */
        gchar *msg = g_strconcat(REQ_JOIN, " ", chatroom, NULL);
        SSL_write(server_ssl, msg, strlen(msg)); /* send join request */
        g_free(msg);

        g_free(prompt);
        prompt = g_strconcat(user, "@", chatroom, "> ", NULL);
        rl_set_prompt(prompt);
        rl_redisplay();
        return;
    }
    if (strncmp("/list", line, 5) == 0) {
        /* Query all available chat rooms */
        SSL_write(server_ssl, REQ_LIST, sizeof(REQ_LIST)); /* send list request */
        return;
    }
    if (strncmp("/roll", line, 5) == 0) {
        /* roll dice and declare winner. */
        return;
    }
    if(g_str_has_prefix(line, "/say")) {
        /* Skip whitespace */
        gchar **lineSplit = g_strsplit_set(line, " ", 3);

        if(lineSplit[1] == NULL || lineSplit[2] == NULL) {
            write(STDOUT_FILENO, "Usage: /say username message\n", 29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }

        /* Send private message to receiver. */
        gchar *msg = g_strconcat(REQ_SAY, " ", lineSplit[1], " ", lineSplit[2],  NULL);
        SSL_write(server_ssl, msg, strlen(msg)); /* send say request */
        g_free(msg);
        g_strfreev(lineSplit);
        return;
    }
    if (strncmp("/user", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /user username\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        user = strdup(&(line[i]));
        char passwd[48];
        getpasswd("Password: ", passwd, 48);
        /* Process and send this information to the server. */
        g_free(prompt);
        prompt = create_prompt(user, chatroom);
        rl_set_prompt(prompt);
        char *usernameAndPasswd = create_message_to_server(user, passwd);
        char *msg = create_message_to_server(REQ_USER, usernameAndPasswd);
        SSL_write(server_ssl, msg, strlen(msg)); /* send list request */
        free(usernameAndPasswd);
        free(msg);
        //Here we would have put ssl_read to check for errors or success.
        return;
    }
    if (strncmp("/who", line, 4) == 0) {
        /* Query all available users */
        SSL_write(server_ssl, REQ_WHO, sizeof(REQ_WHO)); /* send list request */
        return;
    }

    SSL_write(server_ssl, line, strlen(line)); /* Sent the input to the server. */
    rl_redisplay();
}

static void InitCTX()
{
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    ctx = SSL_CTX_new(SSLv23_client_method());   /* Create new context */
    if (ctx == NULL)
    {
        perror("SSL_CTX_new(SSLv23_client_method())");
        exit(EXIT_FAILURE);
    }
}

static int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if(!inet_aton(hostname, &addr.sin_addr)) {
        perror(hostname);
        exit(EXIT_FAILURE);
    }

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror(hostname);
        exit(EXIT_FAILURE);
    }
    return sd;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
         fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
         exit(EXIT_FAILURE);
    }

    char *hostname, *port;

    initialize_exitfd();

    /* Initialize OpenSSL */
    SSL_library_init();
    hostname = argv[1];
    port = argv[2];

    InitCTX();
    server_fd = OpenConnection(hostname, atoi(port));

    /* TODO:
     * We may want to use a certificate file if we self sign the
     * certificates using SSL_use_certificate_file(). If available,
     * a private key can be loaded using
     * SSL_CTX_use_PrivateKey_file(). The use of private keys with
     * a server side key data base can be used to authenticate the
     * client.
     */
    server_ssl = SSL_new(ctx);

    /* Use the socket for the SSL connection. */
    SSL_set_fd(server_ssl, server_fd);

    /* Set up secure connection to the chatd server. */
    if (SSL_connect(server_ssl) < 0) {
        perror("SSL_connect()");
        SSL_free(server_ssl);
        close(server_fd);         /* close socket */
        SSL_CTX_free(ctx);        /* release context */
        exit(EXIT_FAILURE);
    }

    chatroom = g_strdup_printf("%s", "Lobby"); // The Lobby is always the chatroom you start in

    /* Read characters from the keyboard while waiting for input.
     */
    prompt = g_strdup_printf("%s", "anon@Lobby> ");
    rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
    for (;;) {
        fd_set rfds;
        struct timeval timeout;

        /* You must change this. Keep exitfd[0] in the read set to
           receive the message from the signal handler. Otherwise,
           the chat client can break in terrible ways. */
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(exitfd[0], &rfds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_SET(server_fd, &rfds);
        int r = select(server_fd + 1, &rfds, NULL, NULL, &timeout);
        
        if (r < 0) {
            if (errno == EINTR) {
                /* This should either retry the call or
                   exit the loop, depending on whether we
                   received a SIGTERM. */
                continue;
            }
            /* Not interrupted, maybe nothing we can do? */
            perror("select()");
            break;
        }
        if (r == 0) {
            //write(STDOUT_FILENO, "No message?\n", 12);
            //fsync(STDOUT_FILENO);
            /* Whenever you print out a message, call this
               to reprint the current input line. */
            rl_redisplay();
            
            continue;
        }
        if (FD_ISSET(exitfd[0], &rfds)) {
        /* We received a signal. */
            int signum;
            for (;;) {
                if (read(exitfd[0], &signum, sizeof(signum)) == -1) {
                    if ((errno = EAGAIN)) {
                        break;
                    } else {
                        perror("read()");
                        exit(EXIT_FAILURE);
                    }
                }
            }
            if (signum == SIGINT) {
            /* Don't do anything. */
            } else if (signum == SIGTERM) {
                /* Clean-up and exit. */
                close(server_fd);         /* close socket */
                SSL_free(server_ssl);
                SSL_CTX_free(ctx);        /* release context */
                exit(EXIT_SUCCESS);
            }
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            rl_callback_read_char();
        }
        if (FD_ISSET(server_fd, &rfds)) {
            /* Handle messages from the server here! */
            Message_From_Server();
        }

        rl_redisplay();
    }

    return 0;
}
