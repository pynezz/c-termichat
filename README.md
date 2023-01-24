# c-termichat

*WIP*

## A Secure* chat application client written in C

Termichat is a WIP hobby / self-study project for expanding my knowledge in C beyond the school classes.

### Idea
The idea is to have a chat application working in the terminal to better live up to the image our prof 
painted by saying every Linux user operates mainly in the terminal. Unfortunately Discord does not work in the terminal.
This application aims to fix the issue of having to use a resource intensive GUI for chatting, 
and by reinventing the wheel, I will hopefully learn something along the way. 

### Stack
 - Websockets (libwebsockets)
 - OpenSSL (asymmetric encryption)

---

## Notes

In `wsclient.c`, `lws_protocols`:

- The first field of the structure is the protocol name, which is a string that should match the protocol name used by the server.
- The second field is a callback function that will be called when a message is received for this protocol.
- The third field is the size of the per-session data that will be allocated for each connection.
- The fourth field is the maximum size of a message that can be received for this protocol.

You can have multiple protocols in the array, and the server will use the protocol specified by the client when connecting.

It's important to notice that the callback_example is a function that you should define and implement according to your needs, this function is going to handle the incoming messages according to the protocol.

---


\* *I hope*
