#include <string>
#include <vector>
#include "socket.h"
// here or in header?
#include "cerrno"
int errno;

Socket::Socket(int family, int type, int protocol) {
    mFileDescriptor = socket(family, type, protocol);
    if (mFileDescriptor == -1) {
        throw Socket::Error(strerror(errno));
    }
    mFamily = family;
    mType = type;
}

void Socket::sendString(std::string_view string) const {
    sendBytes(string.data(), string.length());
}

void Socket::sendBytes(const void *data, size_t length, int flags) const {
    int64_t bytesSend = send(mFileDescriptor, data, length, flags);
    if (bytesSend == -1) {
        throw Socket::Error(strerror(errno));
    }
    // handle partial sends
}

template<typename T>
std::vector<T> Socket::receive(int maxBufferSize) {
    // #TODO flags?
    T buffer[maxBufferSize];
    std::vector<T> result;
    int64_t bytesReceived;
    do {
        // reset buffer to zeros
        std::fill(buffer, buffer + maxBufferSize, 0);
        bytesReceived = recv(mFileDescriptor, buffer, maxBufferSize, 0);
        if (bytesReceived == -1) {
            // maybe we can return partial results instead of throwing errors.
            throw Socket::Error(strerror(errno));
        }
        // refactor?
        if (bytesReceived > 0) {
            result.insert(result.end(), &buffer[0], buffer + bytesReceived);
        }
    } while (bytesReceived > 0);
    return result;
}

std::string Socket::receiveString(int maxBufferSize) {
    // performance?
    std::vector<char> response = receive<char>(maxBufferSize);
    std::string string (response.begin(), response.end());
    return string;
}

void Socket::closeSocket() {
    // #TODO check for error
    if (mIsOpen) {
        close(mFileDescriptor);
        mIsOpen = false;
    }
}

Socket::~Socket() {
    closeSocket();
}

addrinfo* Socket::getAddressInfo(std::string_view address, std::string_view port, int family, int type, int protocol, int flags) {
    addrinfo hints{flags, // flags
                   family, // family
                   type, // type
                   protocol, // protocol, using 0 to automatically get protocol for type
                   0, // address length
                   nullptr, // canon name
                   nullptr, // address
                   nullptr // next
    };
    addrinfo *response;

    int status = getaddrinfo(address.data(), port.data(), &hints, &response);
    if (status != 0) {
        throw Socket::Error(gai_strerror(status));
    }

    return response;
}

void Socket::connectSocket(addrinfo *address) const {
    int status = connect(mFileDescriptor, address->ai_addr, address->ai_addrlen);
    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }
}

Socket Socket::createConnection(int type, std::string_view address, int port) {
    return createConnection(type, address, std::to_string(port));
}

Socket Socket::createConnection(int type, std::string_view address, std::string_view port) {
    addrinfo* response = getAddressInfo(address, port, AF_UNSPEC, type);
    // iterate over linked list of address and connect to the first one we can.
    addrinfo* current;
    for (current = response; current != nullptr; current = current->ai_next) {
        try {
            Socket currentSocket (current->ai_family, current->ai_socktype, current->ai_protocol);
            currentSocket.connectSocket(current);
            // no errors thrown mean we got a connection
            return currentSocket;
        } catch (const Socket::Error& error) {
            // connection failed -> debug log?
        }
    }
    throw Socket::Error("Couldn't create a connection!");
    // free address?
}


