# Proxyme
Simple, light & secure **SOCKS5 Proxy Server** on golang without logging.

### Project status: open development

### System requirements:
- Linux >= 3.5
- Golang >= 1.9

## Features
- Small, easy to learn golang codebase;
- Support NoAuth & username/password identities;
- Simple SQL validator for username/password identity;
- Efficient Linux `splice()` method that reduces the cost of context switch and the memory usage, zero-copy forwarding is possible using the `splice()` system call under Linux;

## How to build
```
$ git clone https://github.com/dblokhin/proxyme
$ cd proxyme
$ export GOPATH=`pwd`
$ go build src/cmd/proxyme.go
```

## Contributing
You are welcome! Use github issues for contributing.

## References & useful links
* [RFC 1928: SOCKS Protocol Version 5](http://www.ietf.org/rfc/rfc1928.txt)
* [RFC 1929: Username/Password Authentication for SOCKS V5](http://www.ietf.org/rfc/rfc1929.txt)
* [RFC 1961: GSS-API Authentication Method for SOCKS Version 5](http://www.ietf.org/rfc/rfc1961.txt)
