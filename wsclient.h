#ifndef wsclient
#define wsclient

int wsclient_init(void);
int wsclient_send(char *msg);
int wsclient_close(void);


#endif