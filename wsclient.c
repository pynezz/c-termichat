#include <libwebsockets.h>
#include "wsclient.h"


// STRUCTS

struct lws_context_creation_info info;
struct lws_context *context;
struct lws *wsi;
struct lws_protocols protocols[] = {
    {
        "my-protocol",
        callback_function,
        0,
        0,
    },
    { NULL, NULL, 0, 0 } /* terminator */
};

// FUNCTIONS

int callback_function(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("Connection established with server");
            break;
        case LWS_CALLBACK_CLIENT_RECEIVE:
            printf("Received message from server: %s", in);
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            printf("Sending message to server");
            break;
        default:
            break;
    }
    return 0;
}

int wsclient_init() {
    // Init OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    // Init libwebsockets
    lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
    memset(&info, 0, sizeof info);
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    context = lws_create_context(&info);
    if (context == NULL) {
        printf("Error creating libwebsockets context");
        return -1;
    }

    wsi = lws_client_connect(context, "localhost", 8080, 0, "/", "localhost", "localhost", protocols[0].name, -1);
    if (wsi == NULL) {
        printf("Error connecting to server");
        return -1;
    }

    while (1) {
        lws_service(context, 50);
    }

    lws_context_destroy(context);

    return 0;
}