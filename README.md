# Proxyme
Simple, light & secure **SOCKS5 Proxy Server** on golang without logging.

### Project status: open development

### System requirements:
- Linux >= 3.5
- Golang >= 1.9

## Features
- Vary small, easy Golang codebase;
- Supports NoAuth & username/password identities;
- Simple SQL validator for username/password identity;
- Wihtout double buffering;
- Efficient Linux `splice()` method that reduces the cost of context switch and the memory usage, zero-copy forwarding is possible using the `splice()` system call under Linux;

## How to build
```
$ git clone https://github.com/dblokhin/proxyme
$ cd proxyme
$ export GOPATH=`pwd`
$ go build src/cmd/proxyme.go
```
