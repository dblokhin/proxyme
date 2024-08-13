# Proxyme SOCKS5 server
This is an efficient and lightweight implementation of a Socks5 Proxy written in pure Go (Golang) without any
dependencies. The proxy supports key features like CONNECT, BIND, and AUTH (both with and without username/password 
authentication).

## Project Status
This project is currently **active** and maintained. We aim to continually improve its performance and feature set. 
Feedback and contributions are greatly appreciated!

## Features
- Small, easy to learn Golang codebase;
- **CONNECT command**: Standard command for connecting to a destination server.
- **Custom CONNECT**: Allows creating customs tunnels to destination server.
- **BIND command**: Allows incoming connections on a specified IP and port.
- **AUTH support**:
    - No authentication (anonymous access)
    - Username/Password authentication 
    - GSSAPI SOCKS5 protocol flow (rfc1961)

## Getting Started
### Source usage
```go
func main() {
    opts := proxyme.Options{
        AllowNoAuth: true,
    }

    srv, err := proxyme.New(opts)
    if err != nil {
        log.Fatal(err)
    }

    // start socks5 proxy
    if err := srv.ListenAndServe("tcp4", ":1080"); err != nil {
        log.Println(err)
    }
}
```

### Binary installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/dblokhin/proxyme
   cd proxyme
   ```

2. **Build the binary:**
   ```bash
   # just go build -o proxyme
   make build
   ```

3. **Run the proxy:**
   ```bash
   ./proxyme --usage # show command line options
   ./proxyme --port 1080 --noauth # run without authentication
   ```

4. **Check the proxy:**
   ```bash
   curl --socks5 localhost:1080 https://google.com
   ```
   
### Docker Usage
You can also run the socks5 proxy within a Docker container.

1. **Build the Docker image:**
   ```bash
   docker build -t proxyme .
   ```

2. **Run the Docker container:**
   ```bash
   docker run -d -p 1080:1080 proxyme --auth user:password
   ```

   Replace `--auth user:password` with your desired username and password. Omit this flag for anonymous access.
   ```bash
   curl --socks5 localhost:1080 -U user:password https://google.com
   ```

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
