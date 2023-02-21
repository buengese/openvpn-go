package openvpn

import (
	"context"

	"github.com/buengese/openvpn-go/config"
	"github.com/buengese/openvpn-go/logging"
	"github.com/buengese/openvpn-go/management"
	"github.com/buengese/openvpn-go/runner/shell"
	"github.com/rs/zerolog/log"

	"errors"
	"sync"
	"time"
)

// ProcessManager represents an openvpn process manager
type ProcessManager struct {
	Management *management.Management
	config     *config.Config
	cmd        *shell.Command
	ctx        context.Context
}

// New returns a new openvpn ProcessManager
func New(ctx context.Context, openvpnBinary string, config *config.Config) *ProcessManager {
	return newProcess(ctx, config, openvpnBinary)
}

func newProcess(ctx context.Context, config *config.Config, openvpnBinary string) *ProcessManager {
	logging.Setup()
	logger := log.Ctx(ctx).With().Str("component", "ovpn-process-manager").Logger()
	managerContext := logger.WithContext(ctx)

	cmd := shell.NewCommand(managerContext, openvpnBinary)

	return &ProcessManager{
		config:     config,
		Management: management.NewManagement(ctx, management.LocalhostOnRandomPort),
		cmd:        cmd,
		ctx:        managerContext,
	}
}

// Start starts the openvpn process
func (openvpn *ProcessManager) Start() error {
	err := openvpn.Management.Listen()
	if err != nil {
		return err
	}

	addr := openvpn.Management.BoundAddress
	openvpn.config.SetManagementAddress(addr.IP, addr.Port)

	arguments, err := (*openvpn.config).ToCli()
	if err != nil {
		openvpn.Management.Stop()
		return err
	}
	openvpn.cmd.AddArgs(arguments...)

	err = openvpn.cmd.Start()
	if err != nil {
		openvpn.Management.Stop()
		return err
	}

	select {
	case connAccepted := <-openvpn.Management.Connected:
		if connAccepted {
			return nil
		}
		return errors.New("management connection failed")
	case exitError := <-openvpn.cmd.CmdExitError:
		openvpn.Management.Stop()
		if exitError != nil {
			return exitError
		}
		return errors.New("openvpn process died too early")
	case <-time.After(2 * time.Second):
		return errors.New("management connection wait timeout")
	}
}

func (openvpn *ProcessManager) Wait() error {
	return openvpn.cmd.Wait()
}

func (openvpn *ProcessManager) Stop() {
	waiter := sync.WaitGroup{}
	waiter.Add(1)
	go func() {
		defer waiter.Done()
		openvpn.cmd.Stop()
	}()

	waiter.Add(1)
	go func() {
		defer waiter.Done()
		openvpn.Management.Stop()
	}()
	waiter.Wait()
}
