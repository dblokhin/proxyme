// 13.04.18 proxyme
// Author Dmitriy Blokhin. All rights reserved.
// License can be found in the LICENSE file.

package socks

import (
	"net"
	"log"
	"sync"
	"sync/atomic"
	"errors"
)

// NewServer returns new socks5 server
func NewServer(listen string, idents []Identifier) *ProxymeServer {
	return &ProxymeServer {
		listenAddr: listen,
		idents: idents,
	}
}

type ProxymeServer struct {
	listenAddr string
	idents     []Identifier

	// state is server working state. If state is:
	// 0	- initial state
	// 1	- running
	// 2 	- closing
	state int32

	// list of connected clients
	clients []*Client
	sync.Mutex

	// listener
	listener net.Listener
}

const (
	srvStateInit int32 = 0
	srvStateRun  int32 = 1
	srvStateStop int32 = 2
)

// Start runs server instance
func (s *ProxymeServer) Start() error {
	var err error

	// check if running
	if !atomic.CompareAndSwapInt32(&s.state, srvStateInit, srvStateRun) {
		return errors.New("server is already running")
	}

	s.listener, err = net.Listen("tcp4", s.listenAddr)
	if err != nil {
		return err
	}

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return err
		}

		// processes new client in goroutine
		go func() {
			if err := s.processClient(conn); err != nil {
				log.Println(err)
			}
		}()
	}

	// never rich
	return nil
}

// Stop stops the listening server & close all clients
func (s *ProxymeServer) Stop() error {
	s.Lock()
	// check if running
	if !atomic.CompareAndSwapInt32(&s.state, srvStateRun, srvStateStop) {
		return errors.New("server is not running")
	}

	s.listener.Close()

	for _, client := range s.clients {
		client.Close()
	}

	// destroy client list
	s.clients = make([]*Client, 0)
	s.state = srvStateInit
	s.Unlock()

	return nil
}

func (s *ProxymeServer) processClient(conn net.Conn) error {
	client, err := NewClient(conn, s.idents)
	if err != nil {
		return err
	}

	s.Lock()
	// check if running
	if !atomic.CompareAndSwapInt32(&s.state, srvStateRun, srvStateRun) {
		client.Close()

		return errors.New("server is not running")
	}

	s.clients = append(s.clients, client)
	s.Unlock()

	// run CMD
	if err := client.RunCMD(); err != nil {
		return err
	}

	// never rich
	return nil
}
