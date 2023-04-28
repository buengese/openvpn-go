// Copyright 2020 BlockDev AG
// SPDX-License-Identifier: AGPL-3.0-only
package management

import (
	"fmt"
)

// MockConnection is mock openvpn management interface used for middleware testing
type MockConnection struct {
	WrittenLines      []string
	LastLine          string
	CommandResult     string
	MultilineResponse []string
}

// SingleLineCommand sends command to mocked connection and expects single line as command output (error or success)
func (conn *MockConnection) SingleLineCommand(format string, args ...interface{}) (string, error) {
	conn.LastLine = fmt.Sprintf(format, args...)
	conn.WrittenLines = append(conn.WrittenLines, conn.LastLine)
	return conn.CommandResult, nil
}

// MultiLineCommand sends command to mocked connection and expects multiple line command response with END marker
func (conn *MockConnection) MultiLineCommand(format string, args ...interface{}) (string, []string, error) {
	_, _ = conn.SingleLineCommand(format, args...)
	return conn.CommandResult, conn.MultilineResponse, nil
}
