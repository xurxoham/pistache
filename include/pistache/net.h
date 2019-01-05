/* net.h
   Mathieu Stefani, 12 August 2015

   Network utility classes
*/

#pragma once

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>

#include <pistache/common.h>

#ifndef _KERNEL_FASTOPEN
#define _KERNEL_FASTOPEN

/* conditional define for TCP_FASTOPEN */
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN   23
#endif
#endif

namespace Pistache {

class Port {
public:
    Port(uint16_t port = 0) :
        port(port)
    {
    }

    operator uint16_t() const { return port; }

    bool isReserved() const {
        return port < 1024;
    }

    // Should not be implemented. See https://stackoverflow.com/a/10294941/5809597
    bool isUsed() const;

    static constexpr uint16_t min() {
        return std::numeric_limits<uint16_t>::min();
    }
    static constexpr uint16_t max() {
        return std::numeric_limits<uint16_t>::max();
    }

private:
    uint16_t port;
};

class Ipv4 {
public:
    constexpr Ipv4( in_addr_t addr ) :
        address_({addr})
    {
    }

    explicit Ipv4( std::string_view host );

    Ipv4( std::array<uint8_t,4> bytes ) :
        address_({htonl(0
            + (static_cast<uint32_t>(bytes[3]) << 24)
            + (static_cast<uint32_t>(bytes[2]) << 16)
            + (static_cast<uint32_t>(bytes[1]) <<  8)
            + (static_cast<uint32_t>(bytes[0])))
        })
    {
    }

    Ipv4(const Ipv4&) = default;
    Ipv4& operator=(const Ipv4&) = default;

    operator in_addr() const { return address_; }

    static constexpr Ipv4 any() { return INADDR_ANY; }
    static constexpr Ipv4 loopback() { return INADDR_LOOPBACK; }

private:
    in_addr address_;
};

class Ipv6 {
public:
    constexpr Ipv6( in6_addr addr ) :
        address_(addr)
    {
    }

    explicit Ipv6( std::string_view host );

    explicit Ipv6( std::array<uint16_t,4> bytes ) :
        address_()
    {
        std::transform(bytes.begin(), bytes.end(), address_.s6_addr16,
            []( uint16_t val ) { return htons(val); });
    }

    explicit Ipv6( std::array<uint8_t,8> bytes ) :
        address_()
    {
        std::copy(bytes.begin(), bytes.end(), address_.s6_addr);
    }

    Ipv6(const Ipv6&) = default;
    Ipv6& operator=(const Ipv6&) = default;

    operator in6_addr () const;

    // Returns 'true' if the kernel/libc support IPV6, false if not.
    static bool supported();

    static constexpr Ipv6 any() { return IN6ADDR_ANY_INIT; }
    static constexpr Ipv6 loopback() { return IN6ADDR_LOOPBACK_INIT; }

private:
    in6_addr address_;
};

class Address {
public:
    enum class Family {
        IPv4,
        IPv6,
        Unix
    };

    Address(const Address& other) = default;
    Address &operator=(const Address& other) = default;

    Family family() const;

    const sockaddr& native_handle() const { return addr_.generic; }

    // Network address host. Returns empty string if not a network address.
    std::string host() const;

    // Returns {true,port} if a network address. Otherwise {false,unspecified}.
    std::pair<bool,Port> port() const;

    // Unix socket file path. Valid for unix addresses only. Otherwise an empty
    // string is returned.
    std::string path() const;

    // Parses an IP address (Ipv4/Ipv6) and port pair from text
    static Address NetworkAddress(std::string_view addr);

    // Constructs a IPv6 socket address
    static Address NetworkAddress(const Ipv4& ip, Port port);

    // Constructs a IPv4 socket address
    static Address NetworkAddress(const Ipv6& ip, Port port);

    // Constructs a Unix socket address from a file path
    static Address UnixAddress(const std::string& path);

private:
    // Constructs an address from an existing socket address
    explicit Address(const sockaddr* socket_addr);

    union SocketAddress {
        sockaddr         generic;
        sockaddr_in      ipv4;
        sockaddr_in6     ipv6;
        sockaddr_un      unix;
        sockaddr_storage storage;
    };

    SocketAddress addr_;
};

class Error : public std::runtime_error {
public:
    Error(const char* message);
    Error(std::string message);
    static Error system(const char* message);
};

// Exception generated from getaddrinfo and getnameinfo errors
class AddrResolutionError : public std::runtime_error {
public:
    AddrResolutionError( int code ) :
        std::runtime_error(message(code))
    {
    }

private:
    static std::string message( int code ) {
        std::string msg("Address resolution failed: ");
        msg += gai_strerror(code);
        return msg;
    }
};

// Wrapper around 'getaddrinfo()' that handles cleanup on destruction.
class AddrInfo {
public:
    class iterator {
    public:
        iterator() :
            ai(nullptr)
        {
        }

        iterator( const iterator& other ) :
            ai(other.ai)
        {
        }

        explicit iterator( const addrinfo* ptr ) :
            ai(ptr)
        {
        }

        const addrinfo* operator->() { return ai; }
        const addrinfo& operator*() { return *ai; }

        iterator operator++(int) {
            iterator it(ai);
            ai = ai->ai_next;
            return it;
        }

        iterator& operator++() {
            ai = ai->ai_next;
            return *this;
        }

    private:
        const addrinfo *ai;
    };

    // Default constructor: sets an empty addrinfo
    AddrInfo() :
        addrs(nullptr)
    {
    }

    // AddrInfo constructor: calls getaddrinfo and stores result pointer locally
    AddrInfo( const char *node, const char *service, const addrinfo *hints ) :
        addrs(nullptr)
    {
        int err = ::getaddrinfo(node, service, hints, &addrs);
        if( err ) {
            throw AddrResolutionError(err);
        }
    }

    ~AddrInfo() {
        if (addrs) {
            ::freeaddrinfo(addrs);
        }
    }

    // Disable copy and copy assignment
    AddrInfo(const AddrInfo &) = delete;
    AddrInfo& operator=(const AddrInfo &) = delete;

    // Move constructor
    AddrInfo( AddrInfo&& other ) :
        addrs(other.addrs)
    {
        other.addrs = nullptr;
    }

    // Move-assignment operator
    AddrInfo& operator=( AddrInfo&& other ) {
        std::swap( addrs, other.addrs );
        return *this;
    }

    iterator begin() const { return iterator(addrs); }
    iterator end()   const { return iterator(); }

private:
    struct addrinfo *addrs;
};

template<typename T>
struct Size;

template<typename T>
size_t
digitsCount(T val) {
    size_t digits = 0;
    while (val % 10) {
        ++digits;

        val /= 10;
    }

    return digits;
}

template<>
struct Size<const char*> {
    size_t operator()(const char *s) const {
        return std::strlen(s);
    }
};

template<size_t N>
struct Size<char[N]> {
    constexpr size_t operator()(const char (&)[N]) const {
        // We omit the \0
        return N - 1;
    }
};

#define DEFINE_INTEGRAL_SIZE(Int) \
    template<> \
    struct Size<Int> { \
        size_t operator()(Int val) const { \
            return digitsCount(val); \
        } \
    }

DEFINE_INTEGRAL_SIZE(uint8_t);
DEFINE_INTEGRAL_SIZE(int8_t);
DEFINE_INTEGRAL_SIZE(uint16_t);
DEFINE_INTEGRAL_SIZE(int16_t);
DEFINE_INTEGRAL_SIZE(uint32_t);
DEFINE_INTEGRAL_SIZE(int32_t);
DEFINE_INTEGRAL_SIZE(uint64_t);
DEFINE_INTEGRAL_SIZE(int64_t);

template<>
struct Size<bool> {
    constexpr size_t operator()(bool) const {
        return 1;
    }
};

template<>
struct Size<char> {
    constexpr size_t operator()(char) const {
        return 1;
    }
};

// Converts an Ipv4 address to a human readable representation
std::string
to_string( const Ipv4& );

// Converts an Ipv6 address to a human readable representation
std::string
to_string( const Ipv6& );

// Writes a text representation of Address into an output stream
std::ostream operator<< (std::ostream& os, const Address& addr );

} // namespace Pistache

