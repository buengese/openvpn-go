// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package connect

import (
	"context"
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
		logging.GetLogger().Fatal().
			Err(err).
			Msg("failed to load config")
	}
	// ser user password
	if username != "" && password != "" {
		conf.SetAuth(username, password, false)
	}

	proc := process.New(ctx, "openvpn", conf, true)
	statemw := state.NewMiddleware()
	proc.Management.AddMiddleware(statemw)

	err = proc.Start()
	if err != nil {
		logging.GetLogger().Fatal().
			Err(err).
			Msg("failed to start openvpn process")
	}

	go func() {
		if err := proc.Wait(); err != nil {
			logging.GetLogger().Fatal().
				Err(err).
				Msg("openvpn process exited")
		}
	}()

	err = statemw.WaitForConnected(defaultConnectionTimeout)
	if err != nil {
		logging.GetLogger().Fatal().
			Err(err).
			Msg("connection failed")
	}

	// Wait for a termination signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	proc.Stop()

	return nil
}
