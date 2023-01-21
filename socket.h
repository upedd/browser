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
#include <utility>
#include <vector>
#include <ranges>
#include <utility>
#include <variant>

// #TODO is it correct?
#include "cerrno"

int errno;

// #TODO windows support
// #TODO support for msghdr?

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
static constexpr auto platform_getnameinfo = getnameinfo;
static constexpr auto platform_getpeername = getpeername;
static constexpr auto platform_ntop = inet_ntop;
static constexpr auto platform_pton = inet_pton;
static constexpr auto platform_recvfrom = recvfrom;
static constexpr auto platform_sendto = sendto;

/**
 * Wrapper for system sockets with utility functions.
 * Inspired by python's socket api (https://docs.python.org/3/library/socket.html)
 */
class Socket {
public:
    class Address {
    public:
        explicit Address(sockaddr *sockAddr) : storage(reinterpret_cast<sockaddr_storage *>(sockAddr)),
                                               mIsOwning(false) {};

        Address(int family, std::string_view address) : Address(family) {
            int status = 0;
            std::variant<sockaddr_in *, sockaddr_in6 *> inetAddress = getAsInternet();
            // we have to support both ipv4 and ipv6 variants
            if (sockaddr_in **ipv4 = std::get_if<sockaddr_in *>(&inetAddress)) {
                status = platform_pton(family, address.data(), &(*ipv4)->sin_addr);
            } else if (sockaddr_in6 **ipv6 = std::get_if<sockaddr_in6 *>(&inetAddress)) {
                status = platform_pton(family, address.data(), &(*ipv6)->sin6_addr);
            }
            if (status == -1) {
                throw Socket::Error(strerror(errno));
            }
        }

        explicit Address(int family) : Address() {
            storage->ss_family = family;
        }

        Address() {
            mIsOwning = true;
            storage = new sockaddr_storage();
        }

        // disable copying
        Address(const Address &addressInformation) = delete;

        Address &operator=(const Address &) = delete;

        // move constructor
        Address(Address &&address) noexcept: storage(std::exchange(address.storage, nullptr)),
                                             mIsOwning(std::exchange(address.mIsOwning, false)) {}

        ~Address() {
            if (isOwning() && storage) {
                delete storage;
            }
        };

        std::string toString() {
            char result[INET6_ADDRSTRLEN];

            std::variant<sockaddr_in *, sockaddr_in6 *> inetAddress = getAsInternet();
            if (sockaddr_in **ipv4 = std::get_if<sockaddr_in *>(&inetAddress)) {
                inet_ntop(AF_INET, &(*ipv4)->sin_addr, result, INET6_ADDRSTRLEN);
            } else if (sockaddr_in6 **ipv6 = std::get_if<sockaddr_in6 *>(&inetAddress)) {
                inet_ntop(AF_INET6, &(*ipv6)->sin6_addr, result, INET6_ADDRSTRLEN);
            }

            return {result};
        }

        [[nodiscard]] sockaddr_storage *getSockStorage() const {
            return storage;
        }

        [[nodiscard]] sockaddr *get_ptr() const {
            return reinterpret_cast<sockaddr *>(storage);
        }

        [[nodiscard]] uint8_t get_size() const {
            return storage->ss_len;
        }

        std::variant<sockaddr_in *, sockaddr_in6 *> getAsInternet() {
            if (storage->ss_family == AF_INET) {
                return reinterpret_cast<sockaddr_in *>(storage);
            } else if (storage->ss_family == AF_INET6) {
                return reinterpret_cast<sockaddr_in6 *>(storage);
            }
            throw Socket::Error(
                    "Can't get an address as a internet address pointer for family other than AF_INET or AF_INET6");
        }

        [[nodiscard]] bool isOwning() const {
            return mIsOwning;
        }

    private:
        sockaddr_storage *storage;
        // determines if this is object is responsible for deleting mSockAddr
        bool mIsOwning;
    };

    /**
     * Wrapper around addrinfo pointer.
     * Stores information about only one address info, and not linked list of addresses like addrinfo struct.
     * Is responsible for deleting pointer to that address.
     */
    class AddressInformation {

    public:
        explicit AddressInformation(addrinfo *addrInfo) : mAddrInfo(addrInfo), mAddress(addrInfo->ai_addr) {};

        // disable copying
        AddressInformation(const AddressInformation &addressInformation) = delete;

        AddressInformation &operator=(const AddressInformation &) = delete;

        // move constructor
        AddressInformation(AddressInformation &&addressInformation) noexcept: mAddrInfo(
                std::exchange(addressInformation.mAddrInfo, nullptr)),
                                                                              mAddress(std::move(
                                                                                      addressInformation.mAddress)) {}

        ~AddressInformation() {
            if (mAddrInfo) {
                // we want to delete only our object and not entire linked list of objects.
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
    Socket(Socket &&socket) noexcept: mFileDescriptor(std::exchange(socket.mFileDescriptor, -1)),
                                      mType(socket.mType), mFamily(socket.mFamily),
                                      mProtocol(socket.mProtocol) {};

    ~Socket();

    void bind(const Socket::Address &address) const;

    void connect(const Socket::Address &address) const;

    // default max backlog?
    void listen(int maxBacklog = 10) const;

    [[nodiscard]] std::pair<Socket, Socket::Address> accept() const;

    template<typename T>
    requires std::ranges::sized_range<T>
    int64_t send(const T &range, int flags = 0) const;

    template<typename T>
    requires std::ranges::sized_range<T>
    int64_t send_to(const Socket::Address &address, const T &range, int flags = 0) const;

    template<typename T>
    requires std::ranges::sized_range<T>
    void send_all(const T &range, int flags = 0) const;

    template<typename T>
    requires std::ranges::sized_range<T>
    void send_all_to(const Socket::Address &address, const T &range, int flags = 0) const;

    template<typename T>
    std::vector<T> receive(int buffer_size = DEFAULT_MAX_BUFFER_SIZE, int flags = 0) const;

    template<typename T, size_t size>
    int64_t receive_into(const std::array<T, size> &buffer, int flags) const;

    template<typename T>
    std::pair<Address, std::vector<T>> receive_from(int buffer_size = DEFAULT_MAX_BUFFER_SIZE, int flags = 0) const;

    template<typename T, size_t size>
    std::pair<Address, int64_t> receive_from_into(const std::array<T, size> &buffer, int flags) const;

    template<typename T>
    std::vector<T> receive_to_end(int buffer_size = DEFAULT_MAX_BUFFER_SIZE, int flags = 0) const;

    template<typename T>
    std::pair<Address, std::vector<T>>
    receive_to_end_from(int buffer_size = DEFAULT_MAX_BUFFER_SIZE, int flags = 0) const;

    void close();

    template<typename T>
    void setOption(int option, T value);

    [[nodiscard]] Socket::Address getPeerName() const;

    // #TODO get option

    static std::vector<AddressInformation>
    getAddressInfo(std::string_view address, std::string_view port, int family = 0, int type = 0, int protocol = 0,
                   int flags = 0);

    class NameInfo {
    public:
        NameInfo(std::string mHost, std::string mService) : mHost(std::move(mHost)), mService(std::move(mService)) {}

        // it this needed?
        NameInfo(NameInfo &&nameInfo) noexcept: mHost(nameInfo.mHost), mService(nameInfo.mService) {};

        const std::string mHost;
        const std::string mService;
    };

    static NameInfo getNameInfo(const Socket::Address &address, int flags = 0);

    static Socket createConnection(int type, std::string_view address, int port);

    static Socket createConnection(int type, std::string_view address, std::string_view port);

    static Socket
    createServer(std::string_view address, std::string_view port, int family = AF_INET, int type = SOCK_STREAM,
                 bool reusePort = false, bool dualStackIpv6 = false);

private:
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
    sockaddr *sockAddr = address.get_ptr();
    int status = platform_bind(mFileDescriptor, sockAddr, sockAddr->sa_len);
    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }
}

inline void Socket::connect(const Socket::Address &address) const {
    sockaddr *sockAddr = address.get_ptr();
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
    sockaddr *sockAddr = address.get_ptr();
    // we get and pass size of a sockaddr_storage type instead of sockaddr
    // as the sockaddr is stored as sockaddr_storage in Socket::Address
    // and to support properly storing ipv6 which requires more storage
    // we need to tell platform_accept we have space for a larger object
    socklen_t sockStorageSize = sizeof(sockaddr_storage);
    int socketFileDescriptor = platform_accept(mFileDescriptor, sockAddr, &sockStorageSize);

    if (socketFileDescriptor == -1) {
        throw Socket::Error(strerror(errno));
    }

    Socket newSocket(socketFileDescriptor, mFamily, mType, mProtocol);

    return {std::move(newSocket), std::move(address)};
}

template<typename T>
requires std::ranges::sized_range<T>
int64_t Socket::send(const T &range, int flags) const {
    auto data = std::ranges::data(range);
    uint32_t data_size = std::ranges::size(range);

    int bytesSent = platform_send(mFileDescriptor, data, data_size, flags);
    if (bytesSent == -1) {
        throw Socket::Error(strerror(errno));
    }
    return bytesSent;
}

template<typename T>
requires std::ranges::sized_range<T>
int64_t Socket::send_to(const Socket::Address &address, const T &range, int flags) const {
    auto data = std::ranges::data(range);
    uint32_t data_size = std::ranges::size(range);

    int bytes_sent = platform_sendto(mFileDescriptor, data, data_size, flags, address.get_ptr(), address.get_size());
    if (bytes_sent == -1) {
        throw Socket::Error(strerror(errno));
    }
    return bytes_sent;
}


template<typename T>
requires std::ranges::sized_range<T>
void Socket::send_all(const T &range, int flags) const {
    auto begin_iter = std::ranges::begin(range);
    auto end_iter = std::ranges::end(range);

    int64_t total_bytes_sent = 0;
    int64_t bytes_left = std::ranges::size(range);

    while (total_bytes_sent < bytes_left) {
        int64_t bytes_sent = send(std::ranges::subrange(begin_iter + total_bytes_sent, end_iter), flags);
        total_bytes_sent += bytes_sent;
        bytes_left -= bytes_sent;
    }
}

template<typename T>
requires std::ranges::sized_range<T>
void Socket::send_all_to(const Socket::Address &address, const T &range, int flags) const {
    auto begin_iter = std::ranges::begin(range);
    auto end_iter = std::ranges::end(range);

    int64_t total_bytes_sent = 0;
    int64_t bytes_left = std::ranges::size(range);

    while (total_bytes_sent < bytes_left) {
        int64_t bytes_sent = send_to(address, std::ranges::subrange(begin_iter + total_bytes_sent, end_iter), flags);
        total_bytes_sent += bytes_sent;
        bytes_left -= bytes_sent;
    }
}

template<typename T>
std::vector<T> Socket::receive(int buffer_size, int flags) const {
    std::vector<T> buffer{};
    buffer.resize(buffer_size);

    size_t buffer_size_in_bytes = buffer_size * sizeof(T);
    int bytes_received = platform_recv(mFileDescriptor, buffer.data(), buffer_size_in_bytes, flags);

    if (bytes_received == -1) {
        throw Socket::Error(strerror(errno));
    }

    // shrink buffer vector to only fit elements we received
    size_t num_of_elements_received = bytes_received / sizeof(T);
    buffer.resize(num_of_elements_received);
    return buffer;
}


template<typename T, size_t size>
int64_t Socket::receive_into(const std::array<T, size> &buffer, int flags) const {
    constexpr size_t buffer_size_in_bytes = size * sizeof(T);
    int bytes_received = platform_recv(mFileDescriptor, buffer.data(), buffer_size_in_bytes, flags);
    if (bytes_received == -1) {
        throw Socket::Error(strerror(errno));
    }
    // return num of elements we received
    return bytes_received / sizeof(T);
}

template<typename T>
std::pair<Socket::Address, std::vector<T>> Socket::receive_from(int buffer_size, int flags) const {
    Address address {};
    std::vector<T> buffer{};
    buffer.resize(buffer_size);

    size_t buffer_size_in_bytes = buffer_size * sizeof(T);
    // sockaddr_storage instead of sockaddr so we can receive ipv6 addresses
    socklen_t sock_length = sizeof(sockaddr_storage);

    int bytes_received = platform_recvfrom(mFileDescriptor, buffer.data(), buffer_size_in_bytes, flags, address.get_ptr(), &sock_length);

    if (bytes_received == -1) {
        throw Socket::Error(strerror(errno));
    }

    // shrink buffer vector to only fit elements we received
    size_t num_of_elements_received = bytes_received / sizeof(T);
    buffer.resize(num_of_elements_received);

    return std::make_pair(std::move(address), std::move(buffer));
}


template<typename T, size_t size>
std::pair<Socket::Address, int64_t> Socket::receive_from_into(const std::array<T, size> &buffer, int flags) const {
    constexpr size_t buffer_size_in_bytes = size * sizeof(T);

    Socket::Address address {};
    // sockaddr_storage instead of sockaddr so we can receive ipv6 addresses
    socklen_t sock_length = sizeof(sockaddr_storage);

    int bytes_received = platform_recv_from(mFileDescriptor, buffer.data(), buffer_size_in_bytes, flags, address.get_ptr(), &sock_length);
    if (bytes_received == -1) {
        throw Socket::Error(strerror(errno));
    }

    size_t num_of_elements_received = bytes_received / sizeof(T);

    return std::make_pair(std::move(address), num_of_elements_received);
}

template<typename T>
std::vector<T> Socket::receive_to_end(int buffer_size, int flags) const {
    std::vector<T> result_buffer;
    while (true) {
        auto buffer = receive<T>(buffer_size, flags);
        // we receive until we get an empty buffer which means there so more data to read
        if (buffer.size() > 0) {
            result_buffer.insert(result_buffer.end(), buffer.begin(), buffer.end());
        } else {
            break;
        }
    }
    return result_buffer;
}

template<typename T>
std::pair<Socket::Address, std::vector<T>> Socket::receive_to_end_from(int buffer_size, int flags) const {
    std::vector<T> result_buffer;
    Socket::Address last_address;
    while (true) {
        auto [buffer, address] = receive<T>(buffer_size, flags);
        // we receive until we get an empty buffer which means there so more data to read
        if (buffer.size() > 0) {
            result_buffer.insert(result_buffer.end(), buffer.begin(), buffer.end());
            // we will return the last address we got data from
            last_address = address;
        } else {
            break;
        }
    }

    return std::make_pair(std::move(last_address), std::move(result_buffer));
}

inline void Socket::close() {
    // #TODO check for error
    if (mFileDescriptor != -1) {
        platform_close(mFileDescriptor);
        mFileDescriptor = -1;
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

inline Socket::NameInfo Socket::getNameInfo(const Socket::Address &address, int flags) {
    char host[1024];
    char service[20];
    sockaddr *addr = address.get_ptr();

    int status = platform_getnameinfo(addr, sizeof(*addr), host, sizeof(host), service, sizeof(service), flags);
    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }

    return {host, service};
}

inline Socket::Address Socket::getPeerName() const {
    Socket::Address address{};
    sockaddr *addr = address.get_ptr();
    socklen_t addrSize = sizeof(*addr);
    int status = platform_getpeername(mFileDescriptor, addr, &addrSize);
    if (status == -1) {
        throw Socket::Error(strerror(errno));
    }

    return address;
}



#endif //BROWSER_SOCKET_H
