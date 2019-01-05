/* net.cc
   Mathieu Stefani, 12 August 2015
   
*/

#include <stdexcept>
#include <limits>
#include <cstring>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <iostream>

#include <pistache/common.h>
#include <pistache/net.h>
#include <pistache/string_view.h>

using namespace std;

namespace Pistache {

bool
Port::isUsed() const {
    throw std::runtime_error("Unimplemented");
    return false;
}

Ipv4::Ipv4( std::string_view host ) :
    address_()
{
    // inet_pton expects a NULL-terminated char array
    std::array<char,INET_ADDRSTRLEN+1> buff;
    std::copy(host.begin(), host.end(), buff.begin());
    int err = inet_pton(AF_INET, buff.data(), &address_);
    if( err == 0 ) {
        throw std::invalid_argument("Invalid IPv4 address");
    }
}

Ipv6::Ipv6( std::string_view host ) :
    address_()
{
    // inet_pton expects a NULL-terminated char array
    std::array<char,INET6_ADDRSTRLEN+1> buff;
    std::copy(host.begin(), host.end(), buff.begin());
    int err = inet_pton(AF_INET6, buff.data(), &address_);
    if( err == 0 ) {
        throw std::invalid_argument("Invalid IPv6 address");
    }
}

bool Ipv6::supported() {
    struct ifaddrs *ifaddr = nullptr;
    struct ifaddrs *ifa = nullptr;
    int family, n;
    bool supportsIpv6 = false;

    if (getifaddrs(&ifaddr) == -1) {
        throw std::runtime_error("Call to getifaddrs() failed");
    }

    for (ifa = ifaddr, n = 0; ifa != nullptr; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET6) {
            supportsIpv6 = true;
            continue;
        }
    }

    freeifaddrs(ifaddr);
    return supportsIpv6;
}

// Address constructors
Address::Address(const sockaddr* addr) :
    addr_()
{
    switch( addr->sa_family ) {
        case AF_INET: /* Ipv4 */
            addr_.ipv4 = *reinterpret_cast<const sockaddr_in*>(addr);
            break;
        case AF_INET6: /* Ipv6 */
            addr_.ipv6 = *reinterpret_cast<const sockaddr_in6*>(addr);
            break;
        case AF_UNIX: /* Unix */
            addr_.unix = *reinterpret_cast<const sockaddr_un*>(addr);
            break;
        default:
            throw Error("Adress family not supported");
    }
}

Address Address::UnixAddress(const std::string& path)
{
    SocketAddress addr;
    addr.unix = sockaddr_un{ AF_UNIX, {0} };
    std::copy( path.begin(), path.end(), addr.unix.sun_path );
    return Address( &addr.generic );
}

Address Address::NetworkAddress(const Ipv4& ip, Port port)
{
    SocketAddress addr;
    addr.ipv4 = sockaddr_in{ AF_INET,    // sin_family
          static_cast<in_port_t>(port), // sin_port
          static_cast<in_addr>(ip) };    // sin_addr
    return Address( &addr.generic );
}

Address Address::NetworkAddress(const Ipv6& ip, Port port)
{
    SocketAddress addr;
    addr.ipv6 = sockaddr_in6{ AF_INET6, // sin6_family
          static_cast<in_port_t>(port), // sin6_port
          0, // sin6_flowinfo
          static_cast<in6_addr>(ip), // sin6_addr
          0 }; // sin6_scope_id
    return Address( &addr.generic );
}

std::string
Address::host() const {
    int err = 0;
    char host[NI_MAXHOST];
    switch( addr_.generic.sa_family ) {
        case AF_INET:
        case AF_INET6:
            err = getnameinfo(&addr_.generic, sizeof(sockaddr_storage),
                    host, sizeof(host), nullptr, 0, 
                    NI_NUMERICHOST);
            if( err ) {
                throw AddrResolutionError(err);
            }
            return std::string(host);
        case AF_UNIX:
        default:
            return std::string();
    };
}

std::pair<bool,Port>
Address::port() const {
    switch( addr_.generic.sa_family ) {
        case AF_INET:
            return {true, Port(addr_.ipv4.sin_port)};
        case AF_INET6:
            return {true, Port(addr_.ipv6.sin6_port)};
        case AF_UNIX:
        default:
            return {false, Port()};
    };
}



Address::Family
Address::family() const {
    switch( addr_.generic.sa_family ) {
        case AF_INET:  return Family::IPv4;
        case AF_INET6: return Family::IPv6;
        case AF_UNIX:  return Family::Unix;
        default:
            assert( 0 && "Unexpected socket address family" );
    }
}

Address Address::NetworkAddress( std::string_view addr ) {
    using size_type = std::string_view::size_type;

    size_type port_pos = addr.rfind(':');
    size_type ipv6_beg = addr.find('[', port_pos);
    size_type ipv6_end = addr.find(']');

    // Parse port
    long port = 0;
    char* end = 0;
    if( port_pos != std::string_view::npos ) {
        port = strtol(&addr[port_pos+1], &end, 10);
    }
    if (*end != '\0' || port < Port::min() || port > Port::max()) {
        throw std::invalid_argument("Invalid port");
    }

    // Parse IP address
    if (ipv6_beg != std::string::npos && ipv6_end != std::string::npos) {
        //IPv6 address
        std::string_view host = std::string_view(&addr[ipv6_beg+1],ipv6_end-ipv6_beg);
        return NetworkAddress( Ipv6(host), Port(port) );
    } else {
        //IPv4 address
        std::string_view host = std::string_view(addr.begin(), port_pos);
        Ipv4 addr = Ipv4::any();
        if( host != "*" )
            addr = Ipv4(host);
        return NetworkAddress( addr, Port(port) );
    }
}

Error::Error(const char* message)
    : std::runtime_error(message)
{ }

Error::Error(std::string message)
    : std::runtime_error(std::move(message))
{ }

Error
Error::system(const char* message) {
    const char *err = strerror(errno);

    std::string str(message);
    str += ": ";
    str += err;

    return Error(std::move(str));

}

std::string to_string( const Ipv4& address ) {
    in_addr_t addr = static_cast<in_addr>(address).s_addr;
    // Use the built-in ipv4 string length from arpa/inet.h
    std::array<char,INET_ADDRSTRLEN+1> buff;

    // Convert the network format address into display format
    inet_ntop(AF_INET, &addr, buff.data(), buff.size()-1);

    return std::string(buff.data());
}

std::string to_string( const Ipv6& address ) {
    in6_addr addr = address;
    // Use the built-in ipv6 string length from arpa/inet.h
    std::array<char,INET6_ADDRSTRLEN+1> buff;

    inet_ntop(AF_INET6, &addr, buff.data(), buff.size()-1);

    return std::string(buff.data());
}

} // namespace Pistache
