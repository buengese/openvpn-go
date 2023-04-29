// Copyright 2020 BlockDev AG
// SPDX-License-Identifier: AGPL-3.0-only
package auth

import (
	"regexp"

	"github.com/buengese/openvpn-go/config/auth"
	"github.com/buengese/openvpn-go/management"
)

type middleware struct {
	commandWriter management.CommandWriter
	auth          *auth.AuthOption
}

var rule = regexp.MustCompile("^>PASSWORD:Need 'Auth' username/password$")

// NewMiddleware creates client user_auth challenge authentication middleware
func NewMiddleware(auth *auth.AuthOption) *middleware {
	return &middleware{
		commandWriter: nil,
		auth:          auth,
	}
}

func (m *middleware) Start(commandWriter management.CommandWriter) error {
	m.commandWriter = commandWriter
	return nil
}

func (m *middleware) Stop(connection management.CommandWriter) error {
	return nil
}

func (m *middleware) ProcessEvent(line string) (consumed bool, err error) {
	match := rule.FindStringSubmatch(line)
	if len(match) == 0 {
		return false, nil
	}

	_, err = m.commandWriter.SingleLineCommand("password 'Auth' %s", m.auth.Password)
	if err != nil {
		return true, err
	}

	_, err = m.commandWriter.SingleLineCommand("username 'Auth' %s", m.auth.Username)
	if err != nil {
		return true, err
	}
	return true, nil
}
