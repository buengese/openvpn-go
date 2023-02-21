package shell

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/rs/zerolog/log"
)

var (
	ErrEmptyCommand      = errors.New("empty command")
	ErrCommandNotStarted = errors.New("command not started")
)

type Command struct {
	path string
	args []string

	ctx       context.Context
	logOutput bool
	timeout   time.Duration
	env       *map[string]string

	cmd          *exec.Cmd
	cancel       context.CancelFunc
	CmdExitError chan error
}

func NewCommand(ctx context.Context, path string, args ...string) *Command {
	ctx, cancel := context.WithCancel(ctx)

	return &Command{
		path:    path,
		args:    args,
		ctx:     ctx,
		cancel:  cancel,
		timeout: 0,

		CmdExitError: make(chan error),
	}
}

func (c *Command) AddArgs(args ...string) {
	c.args = append(c.args, args...)
}

func (c *Command) LogOutput(logOutput bool) {
	c.logOutput = logOutput
}

func (c *Command) Start() error {
	if c.path == "" {
		return ErrEmptyCommand
	}

	log.Ctx(c.ctx).Info().
		Str("command", c.path).
		Interface("args", c.args).
		Msg("starting command")

	c.cmd = exec.CommandContext(c.ctx, c.path, c.args...)
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

func (c *Command) waitForExit() {
	err := c.cmd.Wait()
	c.CmdExitError <- err
	close(c.CmdExitError)
}

func (c *Command) Wait() error {
	return <-c.CmdExitError
}

func (c *Command) Stop() error {
	c.cancel()
	return <-c.CmdExitError
}

func (c *Command) Kill() error {
	if c.cmd == nil {
		return ErrCommandNotStarted
	}
	return c.cmd.Process.Kill()
}

func (c *Command) outputToLog(output io.ReadCloser, prefix string) {
	scanner := bufio.NewScanner(output)
	logger := log.Ctx(c.ctx).With().Str("prefix", prefix).Logger()
	for scanner.Scan() {
		logger.Debug().Msg(scanner.Text())

	}
	if err := scanner.Err(); err != nil {
		logger.Error().Err(err).Msg("failed to read")
	} else {
		logger.Info().Msg("stream ended")
	}
}

func (c *Command) Run() error {
	_, err := c.run(false)
	return err
}

func (c *Command) run(output bool) (string, error) {
	if c.path == "" {
		return "", ErrEmptyCommand
	}

	ctx := c.ctx
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(c.ctx, c.timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, c.path, c.args...)
	environment := os.Environ()
	for key, value := range *c.env {
		environment = append(environment, key+"="+value)
	}
	cmd.Env = environment
	if output {
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	return "", cmd.Run()
}

func (c *Command) RunWithOutput() (string, error) {
	return c.run(true)
}

func (c *Command) PollOutput(pattern string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			time.Sleep(1 * time.Second)
			if c.pollOutput(pattern) {
				return nil
			}
		}
	}
}

func (c *Command) pollOutput(pattern string) bool {
	output, err := c.run(true)
	if err != nil {
		return false
	}
	return regexp.MustCompile(pattern).MatchString(output)
}
