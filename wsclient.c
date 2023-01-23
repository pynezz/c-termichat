#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netdb.h>

// #include <libwebsockets.h>
#include "wsclient.h"

#define MAXLINE 4096
#define SA struct sockaddr
#define SERVER_PORT 80


int err_n_no_exit(const char *fmt, ...) { // ... means that the function takes a variable number of arguments
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    return 1;
}


int main(int argc, char **argv) {
    int sockfd, n;
    char recvline[MAXLINE + 1];

    struct sockaddr_in servaddr;

    if (argc != 2) {
        err_n_no_exit("usage: %s <IPaddress>", argv[0]);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("socket error");
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);

    // IF_NET means that the IP address is in network byte order (big endian), which is used by the internet
    if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0) {
        printf("inet_pton error for %s", argv[1]);
        return -1;
    }

    if (connect(sockfd, (SA *) &servaddr, sizeof(servaddr)) < 0) {
        printf("connect error");
        return -1;
    }

    while ((n = read(sockfd, recvline, MAXLINE)) > 0) {
        recvline[n] = 0;
        if (fputs(recvline, stdout) == EOF) {
            printf("fputs error");
            return -1;
        }
    }

    if (n < 0) {
        printf("read error");
        return -1;
    }

    return 0;

}



// STRUCTS

// struct lws_context_creation_info info;
// struct lws_client_connect_info i;
// struct lws_context *context;
// struct lws *wsi;
// struct lws_protocols protocols[] = {
//     {
//         "my-protocol",
//         callback_function,
//         0,
//         0,
//     },
//     { NULL, NULL, 0, 0 } /* terminator */
// };

// // FUNCTIONS

// int callback_function(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
//     switch (reason) {
//         case LWS_CALLBACK_CLIENT_ESTABLISHED:
//             printf("Connection established with server");
//             break;
//         case LWS_CALLBACK_CLIENT_RECEIVE:
//             printf("Received message from server: %s", in);
//             break;
//         case LWS_CALLBACK_CLIENT_WRITEABLE:
//             printf("Sending message to server");
//             break;
//         default:
//             break;
//     }
//     return 0;
// }

// int wsclient_init() {
//     // Init OpenSSL
//     OpenSSL_add_all_algorithms();
//     ERR_load_BIO_strings();
//     ERR_load_crypto_strings();
//     SSL_load_error_strings();

//     // Init libwebsockets
//     lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
//     memset(&info, 0, sizeof info);
//     info.port = CONTEXT_PORT_NO_LISTEN;
//     info.protocols = protocols;
//     info.gid = -1;
//     info.uid = -1;
//     info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

//     context = lws_create_context(&info);
//     if (context == NULL) {
//         printf("Error creating libwebsockets context");
//         return -1;
//     }

//     wsi = lws_client_connect_via_info(&info);
//     if (wsi == NULL) {
//         printf("Error connecting to server");
//         return -1;
//     }
    
//     while (1) {
//         lws_service(context, 50);
//     }

//     lws_context_destroy(context);

//     return 0;
// }