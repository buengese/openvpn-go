// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package connect

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/buengese/openvpn-go/config"
	"github.com/buengese/openvpn-go/internal/cmd"
	"github.com/buengese/openvpn-go/internal/logging"
	"github.com/buengese/openvpn-go/middlewares/state"
	"github.com/buengese/openvpn-go/process"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	username string
	password string
)

// Default timeout for establishing VPN connection.
const defaultConnectionTimeout = 5 * time.Second

var Command = &cobra.Command{
	Use:          "connect <config-file>",
	Short:        `connect`,
	SilenceUsage: true,
	RunE: func(command *cobra.Command, args []string) error {
		cmd.CheckArgs(1, 1, command, args)
		return connectE(command.Context(), args[0])
	},
}

func AddFlags(cmdFlags *pflag.FlagSet) {
	cmdFlags.StringVarP(&username, "username", "u", "", "Username for authentication")
	cmdFlags.StringVarP(&password, "password", "p", "", "Password for authentication")
}

func connectE(ctx context.Context, cfgpath string) error {
	conf, err := config.FromFile(cfgpath)
	if err != nil {
		return fmt.Errorf("failed to load configuration file %q: %w", cfgpath, err)
	}

	// Set user password
	if username != "" && password != "" {
		conf.SetAuth(username, password, false)
	}

	proc := process.New(ctx, "openvpn", conf, true)
	statemw := state.NewMiddleware()
	proc.Management.AddMiddleware(statemw)

	err = proc.Start()
	if err != nil {
		return fmt.Errorf("failed to start OpenVPN process: %w", err)
	}

	// Handle process exit errors in a separate goroutine
	processExitError := make(chan error, 1)
	go func() {
		if err := proc.Wait(); err != nil {
			processExitError <- fmt.Errorf("OpenVPN process exited unexpectedly: %w", err)
		}
	}()

	err = statemw.WaitForConnected(defaultConnectionTimeout)
	if err != nil {
		proc.Stop()
		return fmt.Errorf("failed to establish VPN connection within %v: %w", defaultConnectionTimeout, err)
	}

	logging.GetLogger().Info().Msg("VPN connection established successfully")

	// Wait for either a termination signal or process exit
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	select {
	case <-quit:
		logging.GetLogger().Info().Msg("Received interrupt signal, shutting down...")
	case err := <-processExitError:
		proc.Stop()
		return err
	}

	proc.Stop()
	return nil
}
