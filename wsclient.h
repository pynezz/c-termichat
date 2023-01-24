#ifndef wsclient
#define wsclient

int wsclient_init(int argc, char **argv);
int wsclient_send(char *msg);
int wsclient_close(void);


#endif