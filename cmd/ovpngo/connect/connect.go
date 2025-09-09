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
	"github.com/buengese/openvpn-go/logging"
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
		return connectE(command.Context(), command, args[0])
	},
}

func AddFlags(cmdFlags *pflag.FlagSet) {
	cmdFlags.StringVarP(&username, "username", "u", "", "Username for authentication")
	cmdFlags.StringVarP(&password, "password", "p", "", "Password for authentication")
}

func connectE(ctx context.Context, command *cobra.Command, cfgpath string) error {
	conf, err := config.FromFile(cfgpath)
	if err != nil {
		return fmt.Errorf("failed to load configuration file %q: %w", cfgpath, err)
	}

	// Set user password
	if username != "" && password != "" {
		conf.SetAuth(username, password, false)
	}

	// Build logging options based on command line flags
	var logOpts []logging.LogOption

	// Check global flags
	verbose, _ := command.Flags().GetBool("verbose")
	quiet, _ := command.Flags().GetBool("quiet")
	showProcessOutput, _ := command.Flags().GetBool("show-process-output")
	showProtocol, _ := command.Flags().GetBool("show-protocol")

	if quiet {
		logOpts = append(logOpts, logging.WithSilentLogging())
	} else if verbose {
		logOpts = append(logOpts, logging.WithVerboseLogging())
	} else {
		// Use selective logging based on individual flags
		if showProcessOutput {
			logOpts = append(logOpts, logging.WithProcessOutput())
		}
		if showProtocol {
			logOpts = append(logOpts, logging.WithManagementProtocol())
		}
	}

	// Create process with configured logging
	proc := process.New(ctx, "openvpn", conf, true, logOpts...)
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

	// Use the logger from the process to log success
	proc.Logger().LogLifecycle(ctx, "VPN connection established successfully")

	// Wait for either a termination signal or process exit
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	select {
	case <-quit:
		proc.Logger().LogLifecycle(ctx, "Received interrupt signal, shutting down...")
	case err := <-processExitError:
		proc.Stop()
		return err
	}

	proc.Stop()
	return nil
}
