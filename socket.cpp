#include <string>
#include <vector>
#include "socket.h"
// here or in header?
#include "cerrno"
int errno;

Socket::Socket(int family, int type, int protocol) {
    mFileDescriptor = platform_socket(family, type, protocol);
    if (mFileDescriptor == -1) {
        throw Socket::Error(strerror(errno));
    }
    mFamily = family;
    mType = type;
    mProtocol = protocol;
}

void Socket::close() {
    // #TODO check for error
    if (mIsOpen) {
        platform_close(mFileDescriptor);
        mIsOpen = false;
    }
}

Socket::~Socket() {
    close();
}

std::vector<Socket::AddressInformation> Socket::getAddressInfo(std::string_view address, std::string_view port, int family, int type, int protocol, int flags) {
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

    int status = platform_getaddrinfo(address.data(), port.data(), &hints, &response);
    if (status != 0) {
        throw Socket::Error(gai_strerror(status));
    }

    std::vector<AddressInformation> addresses;

    // iterate over linked list of address and convert them into our platform independent type
    addrinfo* current;
    for (current = response; current != nullptr; current = current->ai_next) {
        addresses.emplace_back(current);
    }

    return addresses;
}

void Socket::connect(const Socket::Address& address) const {
    sockaddr* sockAddr = address.getPlatform();
    int status = platform_connect(mFileDescriptor, sockAddr, sockAddr->sa_len);
    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }
}

Socket Socket::createConnection(int type, std::string_view address, int port) {
    return createConnection(type, address, std::to_string(port));
}

Socket Socket::createConnection(int type, std::string_view address, std::string_view port) {
    auto response = getAddressInfo(address, port, AF_UNSPEC, type);
    for (auto& addressInformation : response) {
        try {
            Socket currentSocket (
                    addressInformation.getFamily(),
                    addressInformation.getType(),
                    addressInformation.getProtocol()
                    );
            currentSocket.connect(addressInformation.getAddress());
            // no errors thrown mean we got a connection
            return currentSocket;
        } catch (const Socket::Error& error) {
            // connection failed -> debug log?
        }
    }
    throw Socket::Error("Couldn't create a connection!");
    // free address?
}

void Socket::bind(const Socket::Address &address) const {
    sockaddr* sockAddr = address.getPlatform();
    int status = platform_bind(mFileDescriptor, sockAddr, sockAddr->sa_len);
    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }
}

void Socket::listen(int maxBacklog) const {
    int status = platform_listen(mFileDescriptor, maxBacklog);

    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }
}

std::pair<Socket, Socket::Address> Socket::accept() const {
    Socket::Address address;
    sockaddr* sockAddr = address.getPlatform();
    socklen_t sockAddrSize = sizeof(*sockAddr);
    int socketFileDescriptor = platform_accept(mFileDescriptor, sockAddr, &sockAddrSize);

    if (socketFileDescriptor == -1) {
        throw Socket::Error(strerror(errno));
    }

    Socket newSocket (socketFileDescriptor, mFamily, mType, mProtocol);

    return {std::move(newSocket), std::move(address)};
}

Socket
Socket::createServer(std::string_view address, std::string_view port, int family, int type, bool reusePort,
                     bool dualStackIpv6) {
    // #TODO dual stack

    auto addresses = Socket::getAddressInfo(address, port, family, type, 0, AI_PASSIVE);

    for (auto& addressInfo : addresses) {
        try {
            Socket socket {addressInfo.getFamily(), addressInfo.getType(), addressInfo.getProtocol()};

            if (reusePort) {
                socket.setOption(SO_REUSEADDR, 1);
            }

            socket.bind(addressInfo.getAddress());
            // no errors mean we got successfully bound socket
            return socket;
        } catch (const Socket::Error& error) {
            // debug log?
        }
    }

    throw Socket::Error("Failed to bind");
}

