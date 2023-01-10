#ifndef BROWSER_SOCKET_H
#define BROWSER_SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <string_view>
#include <stdexcept>
#include <vector>
#include <ranges>
#include <utility>

// #TODO is it correct?
#include "cerrno"

int errno;

// #TODO windows support
// #TODO implement rest of the api
// #TODO auto conversion to network ints and vice versa

// type aliasing functions to avoid conflicts with member functions
static constexpr auto platform_send = send;
static constexpr auto platform_socket = socket;
static constexpr auto platform_connect = connect;
static constexpr auto platform_recv = recv;
static constexpr auto platform_close = close;
static constexpr auto platform_getaddrinfo = getaddrinfo;
static constexpr auto platform_bind = bind;
static constexpr auto platform_listen = listen;
static constexpr auto platform_accept = accept;
static constexpr auto platform_setsockopt = setsockopt;
static constexpr auto platform_getsockopt = getsockopt;

/**
 * Wrapper for system sockets with utility functions.
 * Inspired by python's socket api (https://docs.python.org/3/library/socket.html)
 */
class Socket {
public:

    // maybe separate to owning and not owning address?
    class Address {
    public:
        explicit Address(sockaddr *sockAddr) : mSockAddr(sockAddr), owner(false) {};

        Address() {
            owner = true;
            mSockAddr = new sockaddr();
        }

        // disable copying
        Address(const Address &addressInformation) = delete;

        Address &operator=(const Address &) = delete;

        // move constructor
        Address(Address &&address) noexcept: mSockAddr(address.mSockAddr), owner(address.owner) {
            address.owner = false;
        }

        ~Address() {
            if (owner) {
                delete mSockAddr;
            }
        };

        std::string toString() {
            // #TODO refactor
            // only callable for inet addresses
            // change size depending on family?
            if (mSockAddr->sa_family == AF_INET6) {
                char result[INET6_ADDRSTRLEN];
                inet_ntop(mSockAddr->sa_family, mSockAddr, result, INET6_ADDRSTRLEN);
                return {result};
            } else if (mSockAddr->sa_family == AF_INET) {
                char result[INET_ADDRSTRLEN];
                inet_ntop(mSockAddr->sa_family, mSockAddr, result, INET_ADDRSTRLEN);
                return {result};
            } else {
                // throw
            }
        }

        [[nodiscard]] sockaddr *getPlatform() const {
            return mSockAddr;
        }

    private:
        sockaddr *mSockAddr;
        // is this object responsible for deleting sock addr?
        bool owner;
    };

    class AddressInformation {

    public:
        explicit AddressInformation(addrinfo *addrInfo) : mAddrInfo(addrInfo), mAddress(addrInfo->ai_addr) {};

        // disable copying
        AddressInformation(const AddressInformation &addressInformation) = delete;

        AddressInformation &operator=(const AddressInformation &) = delete;

        // move constructor
        AddressInformation(AddressInformation &&addressInformation) noexcept: mAddrInfo(addressInformation.mAddrInfo),
                                                                              mAddress(std::move(
                                                                                      addressInformation.mAddress)) {
            addressInformation.mAddrInfo = nullptr;
        }

        ~AddressInformation() {
            if (mAddrInfo) {
                // #TODO why?
                mAddrInfo->ai_next = nullptr;
                freeaddrinfo(mAddrInfo);
            }
        }

        [[nodiscard]] int getFamily() const {
            return mAddrInfo->ai_family;
        }

        [[nodiscard]] int getType() const {
            return mAddrInfo->ai_socktype;
        }

        [[nodiscard]] int getProtocol() const {
            return mAddrInfo->ai_protocol;
        }

        [[nodiscard]] const char *getCanonicalName() const {
            return mAddrInfo->ai_canonname;
        }

        [[nodiscard]] const Address &getAddress() const {
            return mAddress;
        }

    private:
        addrinfo *mAddrInfo;
        Address mAddress;
    };

    class Error : public std::runtime_error {
    public:
        explicit Error(const char *error) : std::runtime_error(error) {};
    };


    // #TODO check other implementations
    static constexpr std::size_t DEFAULT_MAX_BUFFER_SIZE = 1024;

    // temp fix protocol should be defaulted to 0
    Socket(int fileDescriptor, int family, int type, int protocol) : mFileDescriptor(fileDescriptor), mFamily(family),
                                                                     mType(type), mProtocol(protocol) {};

    Socket(int family, int type, int protocol);

    // Disable copying
    Socket(const Socket &socket) = delete;
    Socket &operator=(const Socket &) = delete;

    // Enable moving
    Socket(Socket &&socket) noexcept: mIsOpen(std::exchange(socket.mIsOpen, false)),
                                      mFileDescriptor(std::exchange(socket.mFileDescriptor, -1)),
                                      mType(socket.mType), mFamily(socket.mFamily),
                                      mProtocol(socket.mProtocol) {};

    ~Socket();

    /*
     * [Section] Standard Socket Functions
     */

    void bind(const Socket::Address &address) const;

    void connect(const Socket::Address &address) const;

    // default max backlog?
    void listen(int maxBacklog = 128) const;

    [[nodiscard]] std::pair<Socket, Socket::Address> accept() const;

    template<class T>
    requires std::ranges::sized_range<T>
    int64_t send(T &&range, int flags = 0) const;

    template<typename T, std::size_t BUFFER_SIZE = DEFAULT_MAX_BUFFER_SIZE>
    std::pair<std::array<T, BUFFER_SIZE>, int64_t> receive();

    void close();

    template<typename T>
    void setOption(int option, T value);

    // #TODO get option

    static std::vector<AddressInformation>
    getAddressInfo(std::string_view address, std::string_view port, int family = 0, int type = 0, int protocol = 0,
                   int flags = 0);

    /*
     * [Section] Utility Functions
     */

    template<class T>
    requires std::ranges::sized_range<T>
    void sendAll(T &&range, int flags = 0) const;

    template<typename T, std::size_t BUFFER_SIZE = DEFAULT_MAX_BUFFER_SIZE>
    std::vector<T> receiveAll();

    template<std::size_t BUFFER_SIZE = DEFAULT_MAX_BUFFER_SIZE>
    std::string receiveAllAsString();

    static Socket createConnection(int type, std::string_view address, int port);

    static Socket createConnection(int type, std::string_view address, std::string_view port);

    static Socket
    createServer(std::string_view address, std::string_view port, int family = AF_INET, int type = SOCK_STREAM,
                 bool reusePort = false, bool dualStackIpv6 = false);

private:
    bool mIsOpen = true;
    int mFileDescriptor;
    int mFamily;
    int mType;
    int mProtocol;
};

inline Socket::Socket(int family, int type, int protocol) {
    mFileDescriptor = platform_socket(family, type, protocol);
    if (mFileDescriptor == -1) {
        throw Socket::Error(strerror(errno));
    }
    mFamily = family;
    mType = type;
    mProtocol = protocol;
}

inline Socket::~Socket() {
    close();
}

inline void Socket::bind(const Socket::Address &address) const {
    sockaddr *sockAddr = address.getPlatform();
    int status = platform_bind(mFileDescriptor, sockAddr, sockAddr->sa_len);
    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }
}

inline void Socket::connect(const Socket::Address &address) const {
    sockaddr *sockAddr = address.getPlatform();
    int status = platform_connect(mFileDescriptor, sockAddr, sockAddr->sa_len);
    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }
}

inline void Socket::listen(int maxBacklog) const {
    int status = platform_listen(mFileDescriptor, maxBacklog);

    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }
}

inline std::pair<Socket, Socket::Address> Socket::accept() const {
    Socket::Address address;
    sockaddr *sockAddr = address.getPlatform();
    socklen_t sockAddrSize = sizeof(*sockAddr);
    int socketFileDescriptor = platform_accept(mFileDescriptor, sockAddr, &sockAddrSize);

    if (socketFileDescriptor == -1) {
        throw Socket::Error(strerror(errno));
    }

    Socket newSocket(socketFileDescriptor, mFamily, mType, mProtocol);

    return {std::move(newSocket), std::move(address)};
}

template<class T>
requires std::ranges::sized_range<T>
inline int64_t Socket::send(T &&range, int flags) const {
    int64_t bytesSend = platform_send(mFileDescriptor, std::ranges::data(range), std::ranges::size(range), flags);
    if (bytesSend == -1) {
        throw Socket::Error(strerror(errno));
    }
    return bytesSend;
}

template<typename T, std::size_t BUFFER_SIZE>
inline std::pair<std::array<T, BUFFER_SIZE>, int64_t> Socket::receive() {
    // #TODO flags?
    std::array<T, BUFFER_SIZE> buffer{};
    // #FIXME BUFFER_SIZE is dependant on type
    int64_t bytesReceived = platform_recv(mFileDescriptor, buffer.data(), BUFFER_SIZE, 0);
    if (bytesReceived == -1) {
        throw Socket::Error(strerror(errno));
    }
    return std::make_pair(buffer, bytesReceived);
}

inline void Socket::close() {
    // #TODO check for error
    if (mIsOpen) {
        platform_close(mFileDescriptor);
        mIsOpen = false;
    }
}

template<typename T>
inline void Socket::setOption(int option, T value) {
    int status = platform_setsockopt(mFileDescriptor, SOL_SOCKET, option, &value, sizeof(T));
    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }
}

inline std::vector<Socket::AddressInformation>
Socket::getAddressInfo(std::string_view address, std::string_view port, int family, int type, int protocol, int flags) {
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
    addrinfo *current;
    for (current = response; current != nullptr; current = current->ai_next) {
        addresses.emplace_back(current);
    }

    return addresses;
}

template<class T>
requires std::ranges::sized_range<T>
inline void Socket::sendAll(T &&range, int flags) const {
    int64_t total = 0;
    int64_t left = std::ranges::size(range);
    while (total < left) {
        // this should probably work?
        int64_t bytesSent = send(std::ranges::subrange(std::ranges::begin(range) + total, std::ranges::end(range)),
                                 flags);
        total += bytesSent;
        left -= bytesSent;
    }
}

template<typename T, std::size_t BUFFER_SIZE>
inline std::vector<T> Socket::receiveAll() {
    std::vector<T> result;
    while (true) {
        auto [buffer, bytesReceived] = receive<T, BUFFER_SIZE>();
        if (bytesReceived > 0) {
            result.insert(result.end(), buffer.begin(), buffer.begin() + bytesReceived);
        } else {
            break;
        }
    }
    return result;
}

template<std::size_t BUFFER_SIZE>
inline std::string Socket::receiveAllAsString() {
    auto response = receiveAll<char, BUFFER_SIZE>();
    return {response.begin(), response.end()};
}

inline Socket Socket::createConnection(int type, std::string_view address, int port) {
    return createConnection(type, address, std::to_string(port));
}

inline Socket Socket::createConnection(int type, std::string_view address, std::string_view port) {
    auto response = getAddressInfo(address, port, AF_UNSPEC, type);
    for (auto &addressInformation: response) {
        try {
            Socket currentSocket(
                    addressInformation.getFamily(),
                    addressInformation.getType(),
                    addressInformation.getProtocol()
            );
            currentSocket.connect(addressInformation.getAddress());
            // no errors thrown mean we got a connection
            return currentSocket;
        } catch (const Socket::Error &error) {
            // connection failed -> debug log?
        }
    }
    throw Socket::Error("Couldn't create a connection!");
    // free address?
}

inline Socket
Socket::createServer(std::string_view address, std::string_view port, int family, int type, bool reusePort,
                     bool dualStackIpv6) {
    // #TODO dual stack

    auto addresses = Socket::getAddressInfo(address, port, family, type, 0, AI_PASSIVE);

    for (auto &addressInfo: addresses) {
        try {
            Socket socket{addressInfo.getFamily(), addressInfo.getType(), addressInfo.getProtocol()};

            if (reusePort) {
                socket.setOption(SO_REUSEADDR, 1);
            }

            socket.bind(addressInfo.getAddress());
            // no errors mean we got successfully bound socket
            return socket;
        } catch (const Socket::Error &error) {
            // debug log?
        }
    }

    throw Socket::Error("Failed to bind");
}

#endif //BROWSER_SOCKET_H
