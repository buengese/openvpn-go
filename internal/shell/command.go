// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package shell

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"

	"github.com/rs/zerolog/log"
)

var (
	ErrEmptyCommand      = errors.New("empty command")
	ErrCommandNotStarted = errors.New("command not started")
)

// Command is a wrapper around exec.Cmd that allows for easier handling of
// commands.
type Command struct {
	path    string
	args    []string
	workdir string

	ctx       context.Context
	logOutput bool

	cmd          *exec.Cmd
	cancel       context.CancelFunc
	CmdExitError chan error
	waitDone     chan struct{}
}

// NewCommand creates a new command wrapper for the given command path and
// arguments.
func NewCommand(ctx context.Context, path string, args ...string) *Command {
	ctx, cancel := context.WithCancel(ctx)

	return &Command{
		path:   path,
		args:   args,
		ctx:    ctx,
		cancel: cancel,

		CmdExitError: make(chan error),
		waitDone:     make(chan struct{}),
	}
}

// AddArgs adds the given arguments to the command.
func (c *Command) AddArgs(args ...string) {
	c.args = append(c.args, args...)
}

// SetWorkdir sets the working directory for the command.
func (c *Command) SetWorkdir(path string) {
	c.workdir = path
}

// LogOutput enables logging of the command output.
func (c *Command) LogOutput(logOutput bool) {
	c.logOutput = logOutput
}

// Start starts the command and returns an error if the command could not be
// started.
func (c *Command) Start() error {
	if c.path == "" {
		return ErrEmptyCommand
	}

	log.Ctx(c.ctx).Trace().
		Str("command", c.path).
		Interface("args", c.args).
		Msg("starting command")

	c.cmd = exec.CommandContext(c.ctx, c.path, c.args...)
	if c.workdir != "" {
		c.cmd.Dir = c.workdir
	}
	if c.logOutput {
		stdout, err := c.cmd.StdoutPipe()
		if err != nil {
			return err
		}
		stderr, err := c.cmd.StderrPipe()
		if err != nil {
			return err
		}
		go c.outputToLog(stdout, "stdout")
		go c.outputToLog(stderr, "stderr")
	}

	err := c.cmd.Start()
	if err != nil {
		return err
	}
	go c.waitForExit()

	return nil
}

// waitForExit waits for the command to exit and sends the exit error to the
// CmdExitError channel.
func (c *Command) waitForExit() {
	err := c.cmd.Wait()
	c.CmdExitError <- err
	close(c.CmdExitError)
}

// Wait waits for the command to exit and returns an error if the command
// exited with an error.
func (c *Command) Wait() error {
	select {
	case <-c.waitDone:
		return nil
	case err := <-c.CmdExitError:
		return err
	}
}

// Stop stops the command.
func (c *Command) Stop() {
	close(c.waitDone)
	c.cancel()
	<-c.CmdExitError
}

// outputToLog reads the output of the command and logs it to the logger.
func (c *Command) outputToLog(output io.ReadCloser, prefix string) {
	scanner := bufio.NewScanner(output)
	logger := log.Ctx(c.ctx).With().Str("channel", prefix).Logger()
	for scanner.Scan() {
		logger.Trace().Msg(scanner.Text())

	}
	if err := scanner.Err(); err != nil {
		logger.Error().Err(err).Msg("failed to read")
	}
}
