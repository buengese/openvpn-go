package shell

import (
	"context"
	"time"
)

type Shell struct {
	// The context for this shell
	ctx context.Context
	// Environment variables for this shell
	env map[string]string
	// Command timeout
	timeout time.Duration
}

func New(ctx context.Context, env map[string]string, timeout time.Duration) *Shell {
	return &Shell{
		ctx:     ctx,
		env:     env,
		timeout: timeout,
	}
}

func NewDefault(ctx context.Context) *Shell {
	return &Shell{
		ctx:     ctx,
		env:     make(map[string]string),
		timeout: 0,
	}
}

func NewWithTimeout(ctx context.Context, timeout time.Duration) *Shell {
	return &Shell{
		ctx:     ctx,
		env:     make(map[string]string),
		timeout: timeout,
	}
}

func (s *Shell) SetEnv(key, value string) {
	s.env[key] = value
}

func (s *Shell) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *Shell) Command(name string, args ...string) *Command {
	return &Command{
		path:    name,
		args:    args,
		ctx:     s.ctx,
		timeout: s.timeout,
	}
}
