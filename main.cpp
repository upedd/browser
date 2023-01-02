#include <iostream>
#include <sys/socket.h>
#include "socket.h"
int main() {
    Socket socket ( Socket::createConnection(SOCK_STREAM, "www.example.com", 80) );
    socket.sendString("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n");
    std::cout << socket.receiveString();
    return 0;
}
