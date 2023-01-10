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

// #TODO windows support
// #TODO implement rest of the api
// #TODO auto conversion to network ints and vice versa

// #FIXME errno

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
        Address(const Address& addressInformation) = delete;
        Address& operator=(const Address &) = delete;

        // move constructor
        Address(Address &&address) noexcept : mSockAddr(address.mSockAddr), owner(address.owner) {
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

        [[nodiscard]] sockaddr* getPlatform() const {
            return mSockAddr;
        }
    private:
        sockaddr* mSockAddr;
        // is this object responsible for deleting sock addr?
        bool owner;
    };

    class AddressInformation {

    public:
        explicit AddressInformation(addrinfo* addrInfo) : mAddrInfo(addrInfo), mAddress(addrInfo->ai_addr) {};

        // disable copying
        AddressInformation(const AddressInformation& addressInformation) = delete;
        AddressInformation& operator=(const AddressInformation &) = delete;

        // move constructor
        AddressInformation(AddressInformation &&addressInformation) noexcept : mAddrInfo(addressInformation.mAddrInfo),
                                                                               mAddress(std::move(addressInformation.mAddress)) {
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

        [[nodiscard]] const char* getCanonicalName() const {
            return mAddrInfo->ai_canonname;
        }

        [[nodiscard]] const Address &getAddress() const {
            return mAddress;
        }

    private:
        addrinfo* mAddrInfo;
        Address mAddress;
    };

    // #TODO check other implementations
    static constexpr std::size_t DEFAULT_MAX_BUFFER_SIZE = 1024;

    class Error : public std::runtime_error {
    public:
        explicit Error(const char *error) : std::runtime_error(error) {};
    };

    // temp fix protocol should be defaulted to 0
    Socket(int fileDescriptor, int family, int type, int protocol) : mFileDescriptor(fileDescriptor), mFamily(family), mType(type), mProtocol(protocol) {};
    Socket(int family, int type, int protocol);

    // disable copying
    Socket(const Socket &socket) = delete;

    Socket &operator=(const Socket &) = delete;

    // move constructor
    Socket(Socket &&socket) noexcept: mIsOpen(socket.mIsOpen), mFileDescriptor(socket.mFileDescriptor),
                                      mType(socket.mType), mFamily(socket.mFamily), mProtocol(socket.mProtocol) {
        socket.mFileDescriptor = -1;
        socket.mIsOpen = false;
    };

    void connect(const Socket::Address& address) const;

    void bind(const Socket::Address& address) const;

    void listen(int maxBacklog = 128) const;

    [[nodiscard]] std::pair<Socket, Socket::Address> accept() const;

    template<typename T>
    void setOption(int option, T value) {
        int status = platform_setsockopt(mFileDescriptor, SOL_SOCKET, option, &value, sizeof(T));
        if (status == -1) {
            throw Socket::Error(strerror(errno));
        }
    }

    // #TODO get option

    // #TODO why this needs to be here?
    template <class T> requires std::ranges::sized_range<T>
    int64_t send(T&& range, int flags = 0) const {
        int64_t bytesSend = platform_send(mFileDescriptor, std::ranges::data(range), std::ranges::size(range), flags);
        if (bytesSend == -1) {
            throw Socket::Error(strerror(errno));
        }
        return bytesSend;
    };

    /**
     * Utility function. Sends all the data from given range
     * @tparam T
     * @param range
     * @param flags
     */
    template <class T> requires std::ranges::sized_range<T>
    void sendAll(T&& range, int flags = 0) const {
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

    template<typename T, std::size_t BUFFER_SIZE = DEFAULT_MAX_BUFFER_SIZE>
    std::pair<std::array<T, BUFFER_SIZE>, int64_t> receive() {
        // #TODO flags?
        std::array<T, BUFFER_SIZE> buffer {};
        // #FIXME BUFFER_SIZE is dependant on type
        int64_t bytesReceived = platform_recv(mFileDescriptor, buffer.data(), BUFFER_SIZE, 0);
        if (bytesReceived == -1) {
            throw Socket::Error(strerror(errno));
        }
        return std::make_pair(buffer, bytesReceived);
    }

    template<typename T, std::size_t BUFFER_SIZE = DEFAULT_MAX_BUFFER_SIZE>
    std::vector<T> receiveAll() {
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

    template <std::size_t BUFFER_SIZE = DEFAULT_MAX_BUFFER_SIZE>
    std::string receiveAllAsString() {
        auto response = receiveAll<char, BUFFER_SIZE>();
        return {response.begin(), response.end()};
    };

    void close();

    ~Socket();

    static std::vector<AddressInformation>
    getAddressInfo(std::string_view address, std::string_view port, int family = 0, int type = 0, int protocol = 0,
                   int flags = 0);

    static Socket createConnection(int type, std::string_view address, int port);

    static Socket createConnection(int type, std::string_view address, std::string_view port);

    // default value for backlog?
    static Socket createServer(std::string_view address, std::string_view port, int family = AF_INET, int type = SOCK_STREAM, bool reusePort = false, bool dualStackIpv6 = false);

private:
    bool mIsOpen = true;
    int mFileDescriptor;
    int mFamily;
    int mType;
    int mProtocol;
};

#endif //BROWSER_SOCKET_H
