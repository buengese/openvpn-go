// Copyright 2020 BlockDev AG
// SPDX-License-Identifier: AGPL-3.0-only
package management

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Addr struct represents local address on which listener waits for incoming management connections
type Addr struct {
	IP   string
	Port int
}

// LocalhostOnRandomPort defines localhost address with randomly bound port
var LocalhostOnRandomPort = Addr{
	IP:   "127.0.0.1",
	Port: 0,
}

// String returns address string representation
func (addr *Addr) String() string {
	return fmt.Sprintf("%s:%d", addr.IP, addr.Port)
}

// Management structure represents connection and interface to openvpn management
type Management struct {
	ctx    context.Context
	cancel context.CancelFunc

	conn         net.Conn
	BoundAddress Addr
	Connected    chan bool

	middlewares []Middleware

	shutdownWaiter sync.WaitGroup
}

// NewManagement creates new manager for given sock address
func NewManagement(ctx context.Context, addr Addr) *Management {
	ctx, cancel := context.WithCancel(ctx)

	return &Management{
		BoundAddress: addr,
		Connected:    make(chan bool, 1),
		ctx:          ctx,
		cancel:       cancel,

		shutdownWaiter: sync.WaitGroup{},
	}
}

// AddMiddleware adds middleware to the management interface.
func (m *Management) AddMiddleware(mw Middleware) {
	m.middlewares = append(m.middlewares, mw)
}

// Stop initiates shutdown of management interface
func (m *Management) Stop() {
	m.cancel()
	if m.conn != nil {
		m.conn.Close()
	}
	m.shutdownWaiter.Wait()
}

// Listen starts listening for incoming connections on given address.
// It's expected that only one connection will be accepted.
func (m *Management) Listen() error {
	listener, err := net.Listen("tcp", m.BoundAddress.String())
	if err != nil {
		return errors.Wrap(err, "failed to bind to socket")
	}

	netAddress := listener.Addr().(*net.TCPAddr)
	m.BoundAddress = Addr{
		netAddress.IP.String(),
		netAddress.Port,
	}

	log.Ctx(m.ctx).Info().
		Str("address", m.BoundAddress.String()).
		Msg("Listening for connection")

	m.shutdownWaiter.Add(1)
	go m.listen(listener)

	return nil
}

// listen method waits for exactly one incoming connection and starts serving it.
func (m *Management) listen(listener net.Listener) {
	defer func() {
		listener.Close()
		close(m.Connected)
		m.shutdownWaiter.Done()
	}()

	// Wait for exactly one connection than stop listening. This goroute will get cleaned up
	// either after connection is accepted or when the calling function returns (due to context cancel)
	connChannel := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			log.Ctx(m.ctx).Error().
				Err(err).
				Msg("Connection accept error")
			close(connChannel)
			return
		}
		connChannel <- conn
	}()

	// We have a 2 second timeout for connection to be accepted. If it's taking any longer, we assume
	// that something is wrong with the openvpn process and we return false on Connected channel.
	// This will cause the openvpn process to be killed.
	select {
	case conn := <-connChannel:
		if conn != nil {
			m.Connected <- true
			m.conn = conn
			go m.serve()
		}
	case <-time.After(2 * time.Second):
		m.Connected <- false
	case <-m.ctx.Done():
		m.Connected <- false
	}
}

// serve
func (m *Management) serve() {
	// ensure connection is closed upon return
	m.shutdownWaiter.Add(1)
	defer func() {
		_ = m.conn.Close()
		m.shutdownWaiter.Done()
	}()

	cmdOutput := make(chan string)
	//make event channel buffered, so we can assure all middlewares are started before first event is delivered to middleware
	events := make(chan string, 100)
	connection := newCommandConnection(m.conn, cmdOutput)

	log.Ctx(m.ctx).Info().
		Str("remote", m.conn.RemoteAddr().String()).
		Msg("New connection accepted")

	connectionWaiter := sync.WaitGroup{}
	connectionWaiter.Add(2)

	// Read lines from openvpn management interface and pass them on via channels
	go func() {
		m.readEvents(cmdOutput, events)
		connectionWaiter.Done()
	}()

	m.startMiddlewares(connection)
	defer m.stopMiddlewares(connection)

	go func() {
		m.processEvents(events)
		connectionWaiter.Done()
	}()
	connectionWaiter.Wait()
}

func (m *Management) startMiddlewares(connection CommandWriter) error {
	for _, middleware := range m.middlewares {
		err := middleware.Start(connection)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Management) stopMiddlewares(connection CommandWriter) {
	for _, middleware := range m.middlewares {
		err := middleware.Stop(connection)
		if err != nil {
			log.Ctx(m.ctx).Error().
				Err(err).
				Msg("failed to stop middleware")
		}
	}
}

func (m *Management) readEvents(cmdOutput, events chan string) {
	reader := textproto.NewReader(bufio.NewReader(m.conn))
	for {
		line, err := reader.ReadLine()
		if err != nil {
			close(cmdOutput)
			close(events)
			return
		}
		log.Ctx(m.ctx).Debug().
			Str("channel", "management").
			Msg(line)

		output := cmdOutput
		if strings.HasPrefix(line, ">") {
			output = events
		}
		output <- line
	}
}

func (m *Management) processEvents(eventChannel chan string) {
	for event := range eventChannel {
		lineConsumed := false
		for _, middleware := range m.middlewares {
			consumed, err := middleware.ProcessEvent(event)
			if err != nil {
				log.Ctx(m.ctx).Error().
					Err(err).
					Msg("failed to consume line")
			}
			lineConsumed = lineConsumed || consumed
		}
	}
}
