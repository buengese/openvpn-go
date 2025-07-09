// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package main

import (
	"github.com/buengese/openvpn-go/cmd/ovpngo/connect"
	"github.com/buengese/openvpn-go/internal/cmd"
	"github.com/buengese/openvpn-go/internal/logging"
	"github.com/spf13/cobra"
)

const (
	Debug = false
)

var Root = &cobra.Command{
	Use:               "ovpngo",
	Short:             "Show help for ovpngo commands.",
	DisableAutoGenTag: true,
	SilenceUsage:      true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

func main() {
	cobra.OnInitialize(initConfig)

	Root.AddCommand(connect.Command)
	connect.AddFlags(connect.Command.Flags())

	_ = logging.GetLogger()

	if err := Root.Execute(); err != nil {
		cmd.HandleErr(err)
	}
}

func initConfig() {
	// Setup default context logger
	/*logging.Setup()
	 */
}
