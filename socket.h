#ifndef BROWSER_SOCKET_H
#define BROWSER_SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cerrno>
#include <unistd.h>
#include <string_view>

// #TODO windows support
// #TODO implement rest of the api

/**
 * Wrapper for system sockets with utility functions.
 * Inspired by python's socket api (https://docs.python.org/3/library/socket.html)
 */
class Socket {
public:
    // #TODO check other implementations
    static constexpr int DEFAULT_MAX_BUFFER_SIZE = 1024;

    class Error : public std::runtime_error {
    public:
        explicit Error(const char *error) : std::runtime_error(error) {};
    };

    explicit Socket(int family, int type, int protocol = 0);

    // disable copying
    Socket(const Socket &socket) = delete;

    Socket &operator=(const Socket &) = delete;

    // move constructor
    Socket(Socket &&socket) noexcept: mIsOpen(socket.mIsOpen), mFileDescriptor(socket.mFileDescriptor),
                                      mType(socket.mType), mFamily(socket.mFamily) {
        socket.mFileDescriptor = -1;
        socket.mIsOpen = false;
    };

    void connectSocket(addrinfo *address) const;

    void sendString(std::string_view string) const;

    void sendBytes(const void *data, size_t length, int flags = 0) const;

    template<typename T>
    std::vector<T> receive(int maxBufferSize = DEFAULT_MAX_BUFFER_SIZE);

    std::string receiveString(int maxBufferSize = DEFAULT_MAX_BUFFER_SIZE);

    void closeSocket();

    ~Socket();

    // #TODO change address info to platform independent type
    static addrinfo *
    getAddressInfo(std::string_view address, std::string_view port, int family = 0, int type = 0, int protocol = 0,
                   int flags = 0);

    static Socket createConnection(int type, std::string_view address, int port);

    static Socket createConnection(int type, std::string_view address, std::string_view port);

private:
    bool mIsOpen = true;
    int mFileDescriptor;
    int mFamily;
    int mType;
};

#endif //BROWSER_SOCKET_H
