#ifndef BROWSER_SOCKET_H
#define BROWSER_SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef USE_EXPECTED_POLYFILL
#include "include/expected.hpp"

// workaround!
namespace std {
    using namespace tl; // NOLINT(cert-dcl58-cpp)
}
#else

#include <expected>

#endif

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
#include <memory>
#include <system_error>

#include "cerrno"

int errno;

// #TODO windows support
// #TODO support for msghdr?
// #TODO addresses error handling

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
static constexpr auto platform_getsockname = getsockname;
static constexpr auto platform_shutdown = shutdown;

/**
 * Wrapper for system sockets with utility functions.
 * Inspired by python's socket api (https://docs.python.org/3/library/socket.html)
 */
class Socket {
public:
    class Address;

    class InternetAddress;

    class InternetAddressV4;

    class InternetAddressV6;

    // #TODO more getters and setters for internet addresses.

    class Address {
    public:
        Address() : storage_(new sockaddr_storage), is_owner_(true) {};

        explicit Address(sockaddr_storage *storage, bool transfer_ownership = false) : storage_(storage), is_owner_(
                transfer_ownership) {};

        explicit Address(sockaddr *storage, bool transfer_ownership = false) : Address(
                reinterpret_cast<sockaddr_storage *>(storage), transfer_ownership) {};

        // #TODO copying
        Address(const Address &address) = delete;

        Address &operator=(const Address &) = delete;

        Address(Address &&address) noexcept: storage_(std::exchange(address.storage_, nullptr)),
                                             is_owner_(std::exchange(address.is_owner_, false)) {}

        [[nodiscard]] sockaddr *get_ptr() const {
            return reinterpret_cast<sockaddr *>(storage_);
        }

        [[nodiscard]] inline constexpr static size_t get_size() noexcept {
            return sizeof(sockaddr_storage);
        }

        [[nodiscard]] socklen_t get_ptr_length() const {
            return storage_->ss_len;
        }

        [[nodiscard]] uint8_t get_family() const {
            return storage_->ss_family;
        }

        [[nodiscard]] std::unique_ptr<InternetAddress> get_as_inet() const {
            if (get_family() == AF_INET) {
                return get_as_v4();
            } else if (get_family() == AF_INET6) {
                return get_as_v6();
            }
            return {};
        };

        [[nodiscard]] std::unique_ptr<InternetAddressV4> get_as_v4() const {
            if (get_family() == AF_INET) {
                return std::make_unique<InternetAddressV4>(storage_);
            }
            return {};
        };

        [[nodiscard]] std::unique_ptr<InternetAddressV6> get_as_v6() const {
            if (get_family() == AF_INET6) {
                return std::make_unique<InternetAddressV6>(storage_);
            }
            return {};
        };

        ~Address() {
            if (is_owner_) {
                delete storage_;
            }
        }

    private:
        sockaddr_storage *storage_;
        bool is_owner_;
    };

    class InternetAddress : public Address {
    public:
        using Address::Address;

        virtual std::string get_as_string() = 0;

        virtual ~InternetAddress() = default;
    };

    class InternetAddressV4 : public InternetAddress {
    public:
        using InternetAddress::InternetAddress;

        InternetAddressV4(std::string_view address, uint16_t port) : InternetAddress() {
            sockaddr_in *inet_ptr = get_inet_ptr();
            inet_ptr->sin_port = port;
            int status = platform_pton(AF_INET, address.data(), &inet_ptr->sin_addr);

            if (status == -1) {
                throw Socket::Error(errno, std::system_category());
            }
        }

        std::string get_as_string() override {
            char buffer[INET_ADDRSTRLEN];
            platform_ntop(AF_INET, &get_inet_ptr()->sin_addr, buffer, INET_ADDRSTRLEN);
            return {buffer};
        }

        [[nodiscard]] sockaddr_in *get_inet_ptr() const {
            return reinterpret_cast<sockaddr_in *>(get_ptr());
        }
    };

    class InternetAddressV6 : public InternetAddress {
    public:
        using InternetAddress::InternetAddress;

        InternetAddressV6(std::string_view address, uint16_t port) : InternetAddress() {
            sockaddr_in6 *inet6_ptr = get_inet6_ptr();
            inet6_ptr->sin6_port = port;
            int status = platform_pton(AF_INET6, address.data(), &inet6_ptr->sin6_addr);

            if (status == -1) {
                throw Socket::Error(errno, std::system_category());
            }
        }

        std::string get_as_string() override {
            char buffer[INET6_ADDRSTRLEN];
            platform_ntop(AF_INET6, &get_inet6_ptr()->sin6_addr, buffer, INET6_ADDRSTRLEN);
            return {buffer};
        }

        [[nodiscard]] sockaddr_in6 *get_inet6_ptr() const {
            return reinterpret_cast<sockaddr_in6 *>(get_ptr());
        }
    };

    enum class Family {
        UNSPECIFIED = AF_UNSPEC,
        IPV4 = AF_INET,
        IPV6 = AF_INET6,
    };

    enum class Type {
        STREAM = SOCK_STREAM,
        DGRAM = SOCK_DGRAM
    };

    enum class Protocol {
        AUTO = 0,
        TCP = IPPROTO_TCP,
        UDP = IPPROTO_UDP
    };

    /**
     * Wrapper around addrinfo pointer.
     * Stores information about only one address info, and not linked list of addresses like addrinfo struct.
     * Is responsible for deleting pointer to that address.
     */
    class AddressInformation {

    public:
        explicit AddressInformation(addrinfo *address_info) noexcept : address_info_(address_info), address_(address_info->ai_addr) {};

        // disable copying
        AddressInformation(const AddressInformation&_) = delete;

        AddressInformation &operator=(const AddressInformation &) = delete;

        // move constructor
        AddressInformation(AddressInformation &&addressInformation) noexcept:
            address_info_(std::exchange(addressInformation.address_info_, nullptr)),
            address_(std::move(addressInformation.address_)) {}

        ~AddressInformation() {
            if (address_info_) {
                // we want to delete only our object and not entire linked list of objects.
                address_info_->ai_next = nullptr;
                freeaddrinfo(address_info_);
            }
        }

        [[nodiscard]] inline Socket::Family get_family() const noexcept {
            return Socket::Family { address_info_->ai_family };
        }

        [[nodiscard]] inline Socket::Type get_type() const noexcept {
            return Socket::Type { address_info_->ai_socktype };
        }

        [[nodiscard]] inline Socket::Protocol get_protocol() const noexcept {
            return Socket::Protocol { address_info_->ai_protocol };
        }

        [[nodiscard]] inline std::string_view get_canonical_name() const noexcept {
            return address_info_->ai_canonname;
        }

        [[nodiscard]] inline const Address& get_address() const noexcept {
            return address_;
        }

    private:
        addrinfo *address_info_;
        Address address_;
    };

    class Error : public std::system_error {
    public:
        using std::system_error::system_error;
    };

    // #TODO check other implementations
    static constexpr std::size_t DEFAULT_MAX_BUFFER_SIZE = 1024;

    // temp fix protocol should be defaulted to 0
    Socket(int file_descriptor, Family family, Type type, Protocol protocol = Protocol::AUTO) noexcept : fd_(file_descriptor),
                                                                              family_(family),
                                                                              type_(type),
                                                                              protocol_(protocol) {};

    /**
     * For non-throwing way to creating socket look into Socket::create.
     * @param family
     * @param type
     * @param protocol
     * @throws Socket::Error
     */
    Socket(Family family, Type type, Protocol protocol);

    [[nodiscard]] static inline std::expected<Socket, Socket::Error> create(Family family, Type type, Protocol protocol) noexcept;

    // Disable copying
    Socket(const Socket &socket) = delete;

    Socket &operator=(const Socket &) = delete;

    // Enable moving
    Socket(Socket &&socket) noexcept: fd_(std::exchange(socket.fd_, -1)),
                                      type_(socket.type_), family_(socket.family_),
                                      protocol_(socket.protocol_) {};

    ~Socket();

    [[nodiscard]] inline int get_fd() const noexcept;

    [[nodiscard]] inline std::expected<void, Error> bind(const Socket::Address &address) const noexcept;

    [[nodiscard]] inline std::expected<void, Error> connect(const Socket::Address &address) const noexcept;

    // default max backlog?
    [[nodiscard]] inline std::expected<void, Socket::Error> listen(int maxBacklog = 10) const noexcept;

    [[nodiscard]] inline std::expected<std::pair<Socket, Socket::Address>, Error> accept() const noexcept;

    template<typename T>
    requires std::ranges::sized_range<T>
    [[nodiscard]] inline std::expected<int, Error> send(const T &range, int flags = 0) const noexcept;

    template<typename T>
    requires std::ranges::sized_range<T>
    [[nodiscard]] inline std::expected<int, Error>
    send_to(const Socket::Address &address, const T &range, int flags = 0) const noexcept;

    template<typename T>
    requires std::ranges::sized_range<T>
    [[nodiscard]] inline std::expected<void, Error> send_all(const T &range, int flags = 0) const noexcept;

    template<typename T>
    requires std::ranges::sized_range<T>
    [[nodiscard]] inline std::expected<void, Error>
    send_all_to(const Socket::Address &address, const T &range, int flags = 0) const noexcept;

    template<typename T>
    [[nodiscard]] inline std::expected<std::vector<T>, Socket::Error>
    receive(int buffer_size = DEFAULT_MAX_BUFFER_SIZE, int flags = 0) const noexcept;

    template<typename T, size_t size>
    [[nodiscard]] inline std::expected<int64_t, Socket::Error>
    receive_into(const std::array<T, size> &buffer, int flags) const noexcept;

    template<typename T>
    [[nodiscard]] inline std::expected<std::pair<Address, std::vector<T>>, Socket::Error>
    receive_from(int buffer_size = DEFAULT_MAX_BUFFER_SIZE, int flags = 0) const noexcept;

    template<typename T, size_t size>
    [[nodiscard]] inline std::expected<std::pair<Address, int64_t>, Socket::Error>
    receive_from_into(const std::array<T, size> &buffer, int flags) const noexcept;

    template<typename T>
    [[nodiscard]] inline std::expected<std::vector<T>, Socket::Error>
    receive_to_end(int buffer_size = DEFAULT_MAX_BUFFER_SIZE, int flags = 0) const noexcept;

    template<typename T>
    [[nodiscard]] inline std::expected<std::pair<Address, std::vector<T>>, Socket::Error>
    receive_to_end_from(int buffer_size = DEFAULT_MAX_BUFFER_SIZE, int flags = 0) const noexcept;

    enum class ShutdownType {
        READ = SHUT_RD,
        WRITE = SHUT_WR,
        ALL = SHUT_RDWR
    };

    [[nodiscard]] inline std::expected<void, Socket::Error> shutdown(ShutdownType type) const noexcept;

    [[nodiscard]] inline std::expected<void, Socket::Error> close() noexcept;

    template<typename T>
    [[nodiscard]] inline std::expected<void, Socket::Error> set_option(int option, T value) noexcept;

    template<typename T>
    [[nodiscard]] inline std::expected<T, Socket::Error> get_option(int option) const noexcept;

    [[nodiscard]] inline std::expected<Socket::Address, Socket::Error> get_peer_address() const noexcept;

    [[nodiscard]] inline std::expected<Socket::Address, Socket::Error> get_address() const noexcept;


    // #TODO codes
    class AddressInfoError : public std::runtime_error { ;
    public:
        AddressInfoError(auto message, int code) : std::runtime_error(message), code_(code) {}

        [[nodiscard]] inline int get_code() const noexcept {
            return code_;
        }

    private:
        int code_;
    };

    [[nodiscard]] static inline std::expected<std::vector<AddressInformation>, Socket::AddressInfoError>
    get_address_info(std::string_view address, std::string_view port, Family family, Type type, Protocol protocol = Socket::Protocol::AUTO,
                     int flags = 0) noexcept;

    class NameInfo {
    public:
        NameInfo(std::string host, std::string service) : host_(std::move(host)), service_(std::move(service)) {}

        [[nodiscard]] const std::string &get_host() const noexcept {
            return host_;
        }

        [[nodiscard]] const std::string &get_service() const noexcept {
            return service_;
        }

    private:
        const std::string host_;
        const std::string service_;
    };

    static inline std::expected<Socket::NameInfo, Socket::Error>
    get_name_info(const Socket::Address &address, int flags = 0) noexcept;

private:
    int fd_;
    Family family_;
    Type type_;
    Protocol protocol_;

    static inline std::unexpected<Socket::Error> make_unexpected_() {
        return std::unexpected(Socket::Error(errno, std::system_category()));
    }

    template<typename T>
    static inline std::expected<T, Socket::Error> make_response_(int status, T value) noexcept {
        if (status < 0) {
            return make_unexpected_();
        }
        return {std::forward<T>(value)};
    }


    static inline std::expected<void, Socket::Error> make_response_(int status) {
        if (status < 0) {
            return make_unexpected_();
        }
        return {};
    }
};

inline Socket::Socket(Socket::Family family, Socket::Type type, Socket::Protocol protocol) {
    fd_ = platform_socket(static_cast<int>(family), static_cast<int>(type), static_cast<int>(protocol));
    if (fd_ == -1) {
        throw Socket::Error(errno, std::system_category());
    }
    family_ = family;
    type_ = type;
    protocol_ = protocol;
}

inline Socket::~Socket() {
    close();
}

inline std::expected<void, Socket::Error> Socket::bind(const Socket::Address &address) const noexcept {
    sockaddr *sockAddr = address.get_ptr();
    int status = platform_bind(fd_, sockAddr, sockAddr->sa_len);
    return make_response_(status);
}

inline std::expected<void, Socket::Error> Socket::connect(const Socket::Address &address) const noexcept {
    sockaddr *sockAddr = address.get_ptr();
    int status = platform_connect(fd_, sockAddr, sockAddr->sa_len);
    return make_response_(status);
}

inline std::expected<void, Socket::Error> Socket::listen(int maxBacklog) const noexcept {
    int status = platform_listen(fd_, maxBacklog);
    return make_response_(status);
}

inline std::expected<std::pair<Socket, Socket::Address>, Socket::Error> Socket::accept() const noexcept {
    Socket::Address address;
    sockaddr *sockAddr = address.get_ptr();
    socklen_t sockStorageSize = Socket::Address::get_size();
    int socketFileDescriptor = platform_accept(fd_, sockAddr, &sockStorageSize);

    if (socketFileDescriptor == -1) {
        return make_unexpected_();
    }

    Socket newSocket(socketFileDescriptor, family_, type_, protocol_);
    return {{std::move(newSocket), std::move(address)}};
}

template<typename T>
requires std::ranges::sized_range<T>
inline std::expected<int, Socket::Error> Socket::send(const T &range, int flags) const noexcept {
    auto data = std::ranges::data(range);
    uint32_t data_size = std::ranges::size(range);

    int bytesSent = platform_send(fd_, data, data_size, flags);
    return make_response_(bytesSent, bytesSent);
}

template<typename T>
requires std::ranges::sized_range<T>
std::expected<int, Socket::Error>
inline Socket::send_to(const Socket::Address &address, const T &range, int flags) const noexcept {
    auto data = std::ranges::data(range);
    uint32_t data_size = std::ranges::size(range);

    int bytes_sent = platform_sendto(fd_, data, data_size, flags, address.get_ptr(),
                                     address.get_ptr_length());
    return make_response_(bytes_sent, bytes_sent);
}


template<typename T>
requires std::ranges::sized_range<T>
inline std::expected<void, Socket::Error> Socket::send_all(const T &range, int flags) const noexcept {
    auto begin_iter = std::ranges::begin(range);
    auto end_iter = std::ranges::end(range);

    int64_t total_bytes_sent = 0;
    int64_t bytes_left = std::ranges::size(range);

    while (total_bytes_sent < bytes_left) {
        auto response = send(std::ranges::subrange(begin_iter + total_bytes_sent, end_iter), flags);
        if (!response) {
            return std::unexpected(response.error());
        }
        int64_t bytes_sent = *response;

        total_bytes_sent += bytes_sent;
        bytes_left -= bytes_sent;
    }

    return {};
}

template<typename T>
requires std::ranges::sized_range<T>
inline std::expected<void, Socket::Error>
Socket::send_all_to(const Socket::Address &address, const T &range, int flags) const noexcept {
    auto begin_iter = std::ranges::begin(range);
    auto end_iter = std::ranges::end(range);

    int64_t total_bytes_sent = 0;
    int64_t bytes_left = std::ranges::size(range);

    while (total_bytes_sent < bytes_left) {
        auto response = send_to(address, std::ranges::subrange(begin_iter + total_bytes_sent, end_iter), flags);
        if (!response) {
            return std::unexpected(response.error());
        }
        int64_t bytes_sent = *response;

        total_bytes_sent += bytes_sent;
        bytes_left -= bytes_sent;
    }

    return {};
}

template<typename T>
inline std::expected<std::vector<T>, Socket::Error> Socket::receive(int buffer_size, int flags) const noexcept {
    std::vector<T> buffer{};
    buffer.resize(buffer_size);

    size_t buffer_size_in_bytes = buffer_size * sizeof(T);
    int bytes_received = platform_recv(fd_, buffer.data(), buffer_size_in_bytes, flags);

    // shrink buffer vector to only fit elements we receive
    // we need to std::max in case bytes received is negative because it failed
    size_t num_of_elements_received = bytes_received > 0 ? bytes_received / sizeof(T) : 0ul;
    buffer.resize(num_of_elements_received);

    return make_response_(bytes_received, buffer);
}


template<typename T, size_t size>
inline std::expected<int64_t, Socket::Error>
Socket::receive_into(const std::array<T, size> &buffer, int flags) const noexcept {
    constexpr size_t buffer_size_in_bytes = size * sizeof(T);
    int bytes_received = platform_recv(fd_, buffer.data(), buffer_size_in_bytes, flags);

    // return num of elements we received
    return make_response_(bytes_received, bytes_received / sizeof(T));
}

template<typename T>
inline std::expected<std::pair<Socket::Address, std::vector<T>>, Socket::Error>
Socket::receive_from(int buffer_size, int flags) const noexcept {
    Address address{};
    std::vector<T> buffer{};
    buffer.resize(buffer_size);

    size_t buffer_size_in_bytes = buffer_size * sizeof(T);
    // sockaddr_storage instead of sockaddr so we can receive ipv6 addresses
    socklen_t sock_length = sizeof(sockaddr_storage);

    int bytes_received = platform_recvfrom(fd_, buffer.data(), buffer_size_in_bytes, flags,
                                           address.get_ptr(), &sock_length);

    // shrink buffer vector to only fit elements we received
    size_t num_of_elements_received = bytes_received > 0 ? bytes_received / sizeof(T) : 0ul;
    buffer.resize(num_of_elements_received);

    return make_response_(bytes_received, std::make_pair(std::move(address), std::move(buffer)));
}


template<typename T, size_t size>
inline std::expected<std::pair<Socket::Address, int64_t>, Socket::Error>
Socket::receive_from_into(const std::array<T, size> &buffer, int flags) const noexcept {
    constexpr size_t buffer_size_in_bytes = size * sizeof(T);

    Socket::Address address{};
    // sockaddr_storage instead of sockaddr so we can receive ipv6 addresses
    socklen_t sock_length = sizeof(sockaddr_storage);

    int bytes_received = platform_recv_from(fd_, buffer.data(), buffer_size_in_bytes, flags,
                                            address.get_ptr(), &sock_length);


    size_t num_of_elements_received = bytes_received / sizeof(T);

    return make_response_(bytes_received, std::make_pair(std::move(address), num_of_elements_received));
}

template<typename T>
inline std::expected<std::vector<T>, Socket::Error> Socket::receive_to_end(int buffer_size, int flags) const noexcept {
    std::vector<T> result_buffer;
    while (true) {
        auto buffer = receive<T>(buffer_size, flags);

        if (!buffer) {
            return std::unexpected(buffer.error());
        }
        // we receive until we get an empty buffer which means there so more data to read
        if ((*buffer).size() > 0) {
            result_buffer.insert(result_buffer.end(), (*buffer).begin(), (*buffer).end());
        } else {
            break;
        }
    }
    return result_buffer;
}

template<typename T>
inline std::expected<std::pair<Socket::Address, std::vector<T>>, Socket::Error>
Socket::receive_to_end_from(int buffer_size, int flags) const noexcept {
    std::vector<T> result_buffer;
    Socket::Address last_address;
    while (true) {
        auto response = receive<T>(buffer_size, flags);
        if (!response) {
            return std::unexpected(response.error());
        }

        auto [buffer, address] = *response;
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

inline std::expected<void, Socket::Error> Socket::close() noexcept {
    if (fd_ != -1) {
        int status = platform_close(fd_);
        fd_ = -1;
        return make_response_(status);
    }
    return {};
}

template<typename T>
inline std::expected<void, Socket::Error> Socket::set_option(int option, T value) noexcept {
    int status = platform_setsockopt(fd_, SOL_SOCKET, option, &value, sizeof(T));
    return make_response_(status);
}

inline std::expected<std::vector<Socket::AddressInformation>, Socket::AddressInfoError>
Socket::get_address_info(std::string_view address, std::string_view port, Family family, Type type, Protocol protocol,
                         int flags) noexcept {
    addrinfo hints{flags, // flags
                   static_cast<int>(family), // family
                   static_cast<int>(type), // type
                   static_cast<int>(protocol), // protocol, using 0 to automatically get protocol for type
                   0, // address length
                   nullptr, // canon name
                   nullptr, // address
                   nullptr // next
    };
    addrinfo *response;

    int status = platform_getaddrinfo(address.data(), port.data(), &hints, &response);

    if (status != 0) {
        return std::unexpected(Socket::AddressInfoError(gai_strerror(status), status));
    }

    std::vector<AddressInformation> addresses;

    // iterate over linked list of address and convert them into our platform independent type
    addrinfo *current;
    for (current = response; current != nullptr; current = current->ai_next) {
        addresses.emplace_back(current);
    }

    return addresses;
}


inline std::expected<Socket::NameInfo, Socket::Error>
Socket::get_name_info(const Socket::Address &address, int flags) noexcept {
    char host[1024];
    char service[20];
    sockaddr *addr = address.get_ptr();

    int status = platform_getnameinfo(addr, sizeof(*addr), host, sizeof(host), service, sizeof(service), flags);
    return make_response_<Socket::NameInfo>(status, {host, service});
}

inline std::expected<Socket::Address, Socket::Error> Socket::get_peer_address() const noexcept {
    Socket::Address address{};
    socklen_t sock_addr_length = Socket::Address::get_size();
    int status = platform_getpeername(fd_, address.get_ptr(), &sock_addr_length);
    return make_response_(status, std::move(address));
}

inline std::expected<Socket::Address, Socket::Error> Socket::get_address() const noexcept {
    Socket::Address address{};
    socklen_t sock_addr_length = Socket::Address::get_size();
    int status = platform_getsockname(fd_, address.get_ptr(), &sock_addr_length);
    return make_response_(status, std::move(address));
}

inline std::expected<void, Socket::Error> Socket::shutdown(ShutdownType type) const noexcept {
    int status = platform_shutdown(fd_, static_cast<int>(type));
    return make_response_(status);
}

inline int Socket::get_fd() const noexcept {
    return fd_;
}

inline std::expected<Socket, Socket::Error> Socket::create(Socket::Family family, Socket::Type type, Socket::Protocol protocol) noexcept {
    int fd = platform_socket(static_cast<int>(family), static_cast<int>(type), static_cast<int>(protocol));
    if (fd == -1) {
        return make_unexpected_();
    }
    return Socket {fd, family, type, protocol};
}

template<typename T>
inline std::expected<T, Socket::Error> Socket::get_option(int option) const noexcept {
    T value;
    size_t size = sizeof(T);
    int status = platform_getsockopt(fd_, SOL_SOCKET, option, &value, &size);

    return make_response_(status, value);
}

#endif //BROWSER_SOCKET_H
