// Package proxyme provides a full implementation of the SOCKS5 protocol, strictly adhering to the specifications
// outlined in RFC 1928, 1929, and 1961. It offers robust support for SOCKS5 proxy operations, including
// authentication mechanisms and IPv6 compatibility, ensuring a secure and compliant proxy solution for
// various applications.
//
// It supports the essential SOCKS5 commands, including CONNECT and BIND. The package also handles multiple
// authentication methods: username/password authentication, no authentication, and GSSAPI authentication flow,
// providing a comprehensive and secure proxy solution.
//
// the package allows wrapping any custom connection in the SOCKS5 protocol and offers custom
// connect/bind callbacks for handling these commands, giving developers flexibility and control over proxy operations.
package proxyme
