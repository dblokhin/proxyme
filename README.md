# proxyme
Simple, light & secure **Linux SOCKS5 Proxy Server** without logging.

Project status: unstable.

System requirements: Linux 3.5 and above.

# Features
- Vary small, easy Golang codebase;
- Support NoAuth & username/password identities;
- No double buffering;
- Efficient Linux `splice()` method that reduces the cost of context switch and the memory usage, zero-copy forwarding is possible using the `splice()` system call under Linux;


# How to build
```
$ git clone https://github.com/dblokhin/proxyme
$ cd proxyme
$ export GOPATH=`pwd`
$ go build cmd
```
