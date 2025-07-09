// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package process

import (
	"context"
	"fmt"

	"github.com/buengese/openvpn-go/config"
	"github.com/buengese/openvpn-go/internal/shell"
	"github.com/buengese/openvpn-go/management"
	"github.com/buengese/openvpn-go/middlewares/client/auth"
	"github.com/rs/zerolog/log"

	"github.com/pkg/errors"
)

// Process wraps an openvpn process and provides a management interface to it if requested.
type Process struct {
	ctx context.Context

	config *config.Config
	cmd    *shell.Command

	useManagement bool
	Management    *management.Management
}

// New creates a new openvpn process with the given configuration.
func New(ctx context.Context, openvpnBinary string, config *config.Config, useManagement bool) *Process {
	ctx = log.Ctx(ctx).With().Str("component", "openvpn").Logger().WithContext(ctx)
	cmd := shell.NewCommand(ctx, openvpnBinary)
	cmd.LogOutput(true)

	p := &Process{
		ctx:    ctx,
		config: config,
		cmd:    cmd,

		useManagement: useManagement,
	}
	if useManagement {
		p.Management = management.NewManagement(p.ctx, management.LocalhostOnRandomPort)
	}

	return p
}

// startWithManagement starts the openvpn process and the management interface.
// It returns an error if the process could not be started or the management interface could not be connected.
func (p *Process) startWithManagement() error {
	if p.config.Auth != nil {
		p.Management.AddMiddleware(auth.NewMiddleware(p.config.Auth))
		p.config.AddFlag("management-query-passwords")
	}

	err := p.Management.Listen()
	if err != nil {
		return errors.Wrap(err, "failed to start management listener")
	}

	addr := p.Management.BoundAddress
	p.config.SetManagementAddress(addr.IP, addr.Port)

	arguments, err := p.config.ToCli()
	if err != nil {
		p.Management.Stop()
		return errors.Wrap(err, "could not create cli arguments")
	}

	p.cmd.AddArgs(arguments...)
	p.cmd.SetWorkdir(p.config.Dir())

	err = p.cmd.Start()
	if err != nil {
		p.Management.Stop()
		return errors.Wrap(err, "could not start openvpn process")
	}

	select {
	case connAccepted := <-p.Management.Connected:
		if connAccepted {
			return nil
		}

		return errors.New("management connection failed")
	case exitError := <-p.cmd.CmdExitError:
		p.Management.Stop()

		if exitError != nil {
			return exitError
		}

		return errors.New("openvpn process died")
	}
}

// startNoManagement starts the openvpn process without the management interface.
func (p *Process) startNoManagement() error {
	args, err := p.config.ToCli()
	if err != nil {
		return errors.Wrap(err, "could not create cli arguments")
	}

	p.cmd.AddArgs(args...)

	err = p.cmd.Start()
	if err != nil {
		return errors.Wrap(err, "could not start openvpn process")
	}

	return nil
}

// Start starts the openvpn process.
func (p *Process) Start() error {
	if p.useManagement {
		return p.startWithManagement()
	}

	return p.startNoManagement()
}

// Wait waits for the openvpn process to exit.
func (p *Process) Wait() error {
	return fmt.Errorf("openvpn process wait failed: %w", p.cmd.Wait())
}

// Stop stops the openvpn process.
func (p *Process) Stop() {
	p.Management.Stop()

	p.cmd.Stop()
}

/*
func (p *Process) Stop() {
	waiter := sync.WaitGroup{}
	waiter.Add(1)
	go func() {
		defer waiter.Done()
		p.cmd.Stop()
		fmt.Printf("command stopped\n")
	}()

	waiter.Add(1)
	go func() {
		defer waiter.Done()
		p.Management.Stop()
		fmt.Printf("management stopped\n")
	}()
	waiter.Wait()
}
*/
