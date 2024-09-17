# Proxyme SOCKS5 server

[![Go Report Card](https://goreportcard.com/badge/github.com/dblokhin/proxyme)](https://goreportcard.com/report/github.com/dblokhin/proxyme)
[![GoDoc](https://godoc.org/github.com/dblokhin/proxyme?status.svg)](https://godoc.org/github.com/dblokhin/proxyme)

This is an efficient and lightweight implementation of a SOCKS5 Proxy written in pure Go (Golang) without any
dependencies. The proxy supports key features like CONNECT, BIND, and AUTH (both with and without username/password 
authentication, and GSSAPI SOCKS5 authentication flow).

## Project Status
This project is currently **active** and maintained. We aim to continually improve its performance and feature set. 
Feedback and contributions are greatly appreciated!

## Features
This project fully implements all the requirements outlined in the specifications of RFC 1928, RFC 1929, and RFC 1961,
with the exception of the UDP ASSOCIATE command, which may be implemented in the future.

- **CONNECT command**: Standard command for connecting to a destination server.
- **Custom CONNECT**: Allows creating customs tunnels to destination server.
- **BIND command**: Allows incoming connections on a specified IP and port.
- **AUTH support**:
    - No authentication (anonymous access);
    - Username/Password authentication (rfc1929);
    - GSSAPI SOCKS5 protocol flow (rfc1961);
- Custom BIND command (bind callback).

## Getting Started
### Golang package usage
```go
func main() {
	opts := Options{
		AllowNoAuth: true,
	}

	socks5, _ := New(opts)
	ls, _ := net.Listen("tcp", ":1080")
	
	for {
		conn, _ := ls.Accept()   	// accept new client connection
		socks5.Handle(conn, nil) 	// run socks5 over client connection
	}
}
```

### Binary Usage: SOCKS5 server proxyme
Check [this](https://github.com/dblokhin/proxyme-server) out to use socks5 server. You can pull the ready-to-use image from [Docker Hub](https://hub.docker.com/r/dblokhin/proxyme).

## Contributing
We welcome contributions to enhance the functionality and performance of this Socks5 proxy. If you find any bugs or have feature requests, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


## References & useful links
* [RFC 1928: SOCKS Protocol Version 5](http://www.ietf.org/rfc/rfc1928.txt)
* [RFC 1929: Username/Password Authentication for SOCKS V5](http://www.ietf.org/rfc/rfc1929.txt)
* [RFC 1961: GSS-API Authentication Method for SOCKS Version 5](http://www.ietf.org/rfc/rfc1961.txt)

---

We encourage the community to contribute, experiment, and utilize this project for both learning and production purposes. If you are looking for easy-to-use SOCKS5 proxy written in Go, you have come to the right place!

Happy coding!
