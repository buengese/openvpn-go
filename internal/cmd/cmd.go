// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	ErrWrongArguments     = errors.New("wrong arguments")
	ErrNotEnoughArguments = errors.New("not enough arguments")
	ErrTooManyArguments   = errors.New("too many arguments")

// ErrInvalidArgument    = errors.New("invalid argument")
)

// CheckArgs checks there are enough arguments and prints a message if not.
func CheckArgs(minArgs, maxArgs int, cmd *cobra.Command, args []string) {
	if len(args) < minArgs {
		_ = cmd.Usage()
		_, _ = fmt.Fprintf(os.Stderr, "Command %s needs %d arguments minimum: you provided %d non flag arguments: %q\n",
			cmd.Name(), minArgs, len(args), args)

		HandleErr(ErrNotEnoughArguments)
	} else if len(args) > maxArgs {
		_ = cmd.Usage()
		_, _ = fmt.Fprintf(os.Stderr, "Command %s needs %d arguments maximum: you provided %d non flag arguments: %q\n",
			cmd.Name(), maxArgs, len(args), args)

		HandleErr(ErrTooManyArguments)
	}
}

// Handle err exits the program with the appropriate exit code.
func HandleErr(err error) {
	if err == nil {
		os.Exit(0)
	}

	os.Exit(1)
}
