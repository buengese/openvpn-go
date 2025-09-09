// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package main

import (
	"github.com/buengese/openvpn-go/cmd/ovpngo/connect"
	"github.com/buengese/openvpn-go/internal/cmd"
	"github.com/buengese/openvpn-go/logging"
	"github.com/spf13/cobra"
)

var (
	verbose           bool
	quiet             bool
	showProcessOutput bool
	showProtocol      bool
)

var Root = &cobra.Command{
	Use:               "ovpngo",
	Short:             "OpenVPN Go client",
	DisableAutoGenTag: true,
	SilenceUsage:      true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

func main() {
	// Add global logging flags
	Root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging (all categories)")
	Root.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Disable all logging")
	Root.PersistentFlags().BoolVar(&showProcessOutput, "show-process-output", false, "Show OpenVPN process stdout/stderr")
	Root.PersistentFlags().BoolVar(&showProtocol, "show-protocol", false, "Show management protocol messages (debug)")

	Root.AddCommand(connect.Command)
	connect.AddFlags(connect.Command.Flags())

	if err := Root.Execute(); err != nil {
		cmd.HandleErr(err)
	}
}

// GetLoggingOptions returns logging options based on command line flags
func GetLoggingOptions() []logging.LogOption {
	if quiet {
		return []logging.LogOption{logging.WithSilentLogging()}
	}

	if verbose {
		return []logging.LogOption{logging.WithVerboseLogging()}
	}

	var opts []logging.LogOption

	// Add specific options based on flags
	if showProcessOutput {
		opts = append(opts, logging.WithProcessOutput())
	}

	if showProtocol {
		opts = append(opts, logging.WithManagementProtocol())
	}

	return opts
}
