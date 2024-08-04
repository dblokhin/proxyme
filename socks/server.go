// 13.04.18 proxyme
// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package socks

import (
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// NewServer returns new socks5 server
func NewServer(listen string, idents []Identifier) *Server {
	return &Server{
		listenAddr: listen,
		idents:     idents,
	}
}

// Server is socks5 server structure
type Server struct {
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
func (s *Server) Start() error {
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
		go func(c net.Conn) {
			// recover on each connection
			defer func() {
				if err := recover(); err != nil {
					log.Println(err)
					c.Close()
				}
			}()

			if err := s.processClient(c); err != nil {
				log.Println(err)
			}
		}(conn)
	}

	// never rich
	return nil
}

// Stop stops the listening server & close all clients
func (s *Server) Stop() error {
	s.Lock()
	// check if running
	if !atomic.CompareAndSwapInt32(&s.state, srvStateRun, srvStateStop) {
		return errors.New("server is not running")
	}

	s.listener.Close()

	// save client list
	oldsClients := s.clients

	// destroy client list
	s.clients = make([]*Client, 0)
	s.state = srvStateInit
	s.Unlock()

	// close clients
	for _, client := range oldsClients {
		client.Close()
	}

	return nil
}

func (s *Server) processClient(conn net.Conn) error {
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
