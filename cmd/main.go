// Proxyme Developers. All rights reserved.
// License can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"proxyme"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	maxUsersTotal = 1024 // limit the number of pairs user/password

	envHost   = "PROXY_HOST"    // proxy host to listen to
	envPort   = "PROXY_PORT"    // port number, 1080 defaults
	envBindIP = "PROXY_BIND_IP" // ipv4/ipv6 address to make BIND socks5 operations
	envNoAuth = "PROXY_NOAUTH"  // yes, true, 1
	envUsers  = "PROXY_USERS"   // user:pass,user2:pass2
)

func main() {
	// options
	opts, err := getOpts()
	if err != nil {
		log.Fatal(err)
	}

	port, err := getPort()
	if err != nil {
		log.Fatal(err)
	}

	srv, err := proxyme.New(opts)
	if err != nil {
		log.Fatal(err)
	}

	// graceful shutdown
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		log.Println("shutdown proxyme")
		srv.Close()
		os.Exit(0)
	}()

	// start socks5 proxy
	addr := fmt.Sprintf("%s:%d", os.Getenv(envHost), port)
	log.Println("starting on", addr)
	if err := srv.ListenAndServe("tcp", addr); err != nil {
		log.Println(err)
	}
}

func getPort() (int, error) {
	const defaultPort = "1080"

	port := defaultPort
	if p := os.Getenv(envPort); len(p) > 0 {
		port = p
	}

	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n >= 1<<16 {
		return 0, fmt.Errorf("given invalid port: %q", port)
	}

	return n, nil
}

func getOpts() (proxyme.Options, error) {
	// Examples:
	// PROXY_BIND_IP=x.x.x.x
	// PROXY_NOAUTH=yes
	// PROXY_USERS=admin:admin,secret:pass

	// env PROXY_BIND_IP enables socks5 BIND operations
	bindIP := os.Getenv(envBindIP)
	if len(bindIP) > 0 && net.ParseIP(bindIP) == nil {
		return proxyme.Options{}, fmt.Errorf("failed to configure proxy: invalid bind IP: %q", bindIP)
	}

	// env PROXY_NOAUTH=yes enables noAuth method of socks5 authentication flow
	noauth := slices.Contains([]string{"yes", "true", "1"}, strings.ToLower(os.Getenv(envNoAuth)))

	// make user database
	users := keyValueDB{
		data:    make(map[string]string),
		mu:      sync.Mutex{},
		maxSize: maxUsersTotal,
	}

	// env PROXY_USERS=user:pass enables username/password method of socks5 authentication flow
	for _, cred := range strings.Split(os.Getenv(envUsers), ",") {
		if len(cred) == 0 {
			continue
		}

		parts := strings.Split(cred, ":")
		if len(parts) != 2 {
			return proxyme.Options{}, fmt.Errorf("failed to add users: invalid user/pass string %q", cred)
		}

		if len(parts[0]) == 0 || len(parts[1]) == 0 {
			return proxyme.Options{}, fmt.Errorf("failed to add users: user/password must be a non empty string: %q", cred)
		}

		if err := users.Add(parts[0], parts[1]); err != nil {
			return proxyme.Options{}, fmt.Errorf("failed to add users: %w", err)
		}
	}

	var authenticate func(username, password []byte) error
	if users.Len() > 0 {
		// enable username/password authentication
		authenticate = func(username, password []byte) error {
			denied := errors.New("authentication failed: invalid username or password")

			if len(username) == 0 || len(password) == 0 {
				return denied
			}

			if users.Get(string(username)) != string(password) {
				return denied
			}

			return nil
		}
	}

	opts := proxyme.Options{
		BindIP:       net.ParseIP(bindIP),
		AllowNoAuth:  noauth,
		Authenticate: authenticate,
		//GSSAPI:       nil,
		//Connect:      nil,
	}

	return opts, nil
}

// keyValueDB simple kv mem storage that doesn't allow key duplications.
// Also it limited size by specifying maxSize.
// Concurrent safe.
type keyValueDB struct {
	data    map[string]string
	mu      sync.Mutex
	maxSize int
}

// Add adds k/v to db if k doesn't exist, otherwise throws error
func (d *keyValueDB) Add(key, val string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.data) > d.maxSize {
		return errors.New("too much entries")
	}

	if _, ok := d.data[key]; ok {
		return fmt.Errorf("%q is already exists", key)
	}

	d.data[key] = val
	return nil
}

// Get returns value by key, return empty string if key is not present
func (d *keyValueDB) Get(key string) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.data[key]
}

// Len returns the number of database entries
func (d *keyValueDB) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.data)
}
