// SPDX-License-Identifier: MIT
package auth

import (
	"fmt"
	"regexp"

	"github.com/buengese/openvpn-go/config/auth"
	"github.com/buengese/openvpn-go/management"
)

// Middleware represents the auth middleware.
type Middleware struct {
	commandWriter management.CommandWriter
	auth          *auth.Option
}

var rule = regexp.MustCompile("^>PASSWORD:Need 'Auth' username/password$")

// NewMiddleware creates client user_auth challenge authentication middleware.
func NewMiddleware(auth *auth.Option) *Middleware {
	return &Middleware{
		commandWriter: nil,
		auth:          auth,
	}
}

func (m *Middleware) Start(commandWriter management.CommandWriter) error {
	m.commandWriter = commandWriter
	return nil
}

func (m *Middleware) Stop(_ management.CommandWriter) {}

func (m *Middleware) ProcessEvent(line string) (bool, error) {
	match := rule.FindStringSubmatch(line)
	if len(match) == 0 {
		return false, nil
	}

	_, err := m.commandWriter.SingleLineCommand("password 'Auth' %s", m.auth.Password)
	if err != nil {
		return true, fmt.Errorf("failed to send password to OpenVPN management interface: %w", err)
	}

	_, err = m.commandWriter.SingleLineCommand("username 'Auth' %s", m.auth.Username)
	if err != nil {
		return true, fmt.Errorf("failed to send username to OpenVPN management interface: %w", err)
	}

	return true, nil
}
