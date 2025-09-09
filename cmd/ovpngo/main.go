// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package main

import (
	"log/slog"
	"os"

	"github.com/buengese/openvpn-go/cmd/ovpngo/connect"
	"github.com/buengese/openvpn-go/internal/cmd"
	"github.com/buengese/openvpn-go/internal/logging"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	quiet   bool
)

var Root = &cobra.Command{
	Use:               "ovpngo",
	Short:             "OpenVPN Go client",
	DisableAutoGenTag: true,
	SilenceUsage:      true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	PersistentPreRun: setupLogging,
}

func main() {
	Root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	Root.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Disable all logging (default)")

	Root.AddCommand(connect.Command)
	connect.AddFlags(connect.Command.Flags())

	if err := Root.Execute(); err != nil {
		cmd.HandleErr(err)
	}
}

func setupLogging(cmd *cobra.Command, args []string) {
	if quiet {
		// Explicit no-op (this is also the default)
		return
	}

	if verbose {
		// Enable logging to stderr
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
		ctx := logging.ToContext(cmd.Context(), logger)
		cmd.SetContext(ctx)
	}
	// If neither verbose nor quiet is set, we use the default no-op behavior
}
