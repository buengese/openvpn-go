package management

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"sync"

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
	BoundAddress  Addr
	Connected     chan bool
	ctx           context.Context
	cancelContext context.CancelFunc

	shutdownWaiter sync.WaitGroup
}

// NewManagement creates new manager for given sock address, uses given log prefix for logging and takes a list of middlewares
func NewManagement(ctx context.Context, socketAddress Addr) *Management {
	logger := log.Ctx(ctx).With().Str("component", "ovpn-management").Logger()
	ctx, cancel := context.WithCancel(ctx)
	ctx = logger.WithContext(ctx)

	return &Management{
		BoundAddress:  socketAddress,
		Connected:     make(chan bool, 1),
		ctx:           ctx,
		cancelContext: cancel,

		shutdownWaiter: sync.WaitGroup{},
	}
}

// WaitForConnection method starts listener on bind address and returns "real" bound address (with port not zero) and
// channel which receives true when connection is accepted or false overwise (i.e. listener stop requested). It returns non nil
// error on any error condition
func (management *Management) Listen() error {
	listener, err := net.Listen("tcp", management.BoundAddress.String())
	if err != nil {
		return errors.Wrap(err, "Failed to bind to socket")
	}

	netAddress := listener.Addr().(*net.TCPAddr)
	management.BoundAddress = Addr{
		netAddress.IP.String(),
		netAddress.Port,
	}

	log.Ctx(management.ctx).Info().
		Str("address", management.BoundAddress.String()).
		Msg("Listening for connection")

	management.shutdownWaiter.Add(1)
	go management.listenForConnection(listener)

	return nil
}

// Stop initiates managemnt shutdown. Achieved by context cancel.
func (management *Management) Stop() {
	log.Ctx(management.ctx).Info().Msg("Shutdown reuqested")
	management.cancelContext()

	management.shutdownWaiter.Wait()
	log.Ctx(management.ctx).Info().Msg("Shutdown finished")
}

func (management *Management) listenForConnection(listener net.Listener) {
	defer management.shutdownWaiter.Done()
	defer listener.Close()
	defer close(management.Connected)

	// Wait for exactly one connection than stop listening. This goroute will get cleaned up
	// either after connection is accepted or when the calling function returns (due to context cancel)
	connChannel := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			log.Ctx(management.ctx).Error().
				Err(err).
				Msg("Connection accept error")
			close(connChannel)
			return
		}
		connChannel <- conn
	}()

	// Wait for either connection or context cancel. Listener will be closed upon return.
	select {
	case conn := <-connChannel:
		if conn != nil {
			management.Connected <- true
			go management.serveNewConnection(conn)
		}
	case <-management.ctx.Done():
		management.Connected <- false
	}
}

// serveNewConnection method received events from openvpn management interface. For now it just logs them.
func (management *Management) serveNewConnection(netConn net.Conn) {
	cleanup := make(chan struct{})
	go func() {
		select {
		case <-management.ctx.Done():
			netConn.Close()
		case <-cleanup:
			return
		}
	}()
	// Ensure goroutine is cleaned up
	defer close(cleanup)
	// Close connection on exit or when context is cancelled
	defer netConn.Close()
	management.shutdownWaiter.Add(1)

	log.Ctx(management.ctx).Info().
		Str("remote", netConn.RemoteAddr().String()).
		Msg("New connection accepted")

	connectionHandler := sync.WaitGroup{}
	connectionHandler.Add(1)
	// Read lines from openvpn management interface and pass them on via channels
	go func() {
		defer connectionHandler.Done()
		management.consumeOpenvpnConnectionOutput(netConn)
	}()

	//block until output consumption is done - usually when connection is closed by openvpn process
	connectionHandler.Wait()
	management.shutdownWaiter.Done()
}

func (management *Management) consumeOpenvpnConnectionOutput(input io.Reader) {
	reader := textproto.NewReader(bufio.NewReader(input))
	for {
		line, err := reader.ReadLine()
		if err != nil {
			log.Ctx(management.ctx).Warn().
				Err(err).
				Msg("Connection failed to read")
			return
		}
		log.Ctx(management.ctx).Trace().
			Str("event", line).Send()
	}
}
