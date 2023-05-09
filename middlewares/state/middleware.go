// Copyright 2020 BlockDev AG
// SPDX-License-Identifier: AGPL-3.0-only
package state

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/buengese/openvpn-go/management"
	"github.com/buengese/openvpn-go/process"
)

// Callback is called when openvpn process state changes
type Callback func(state process.State)

const stateEventPrefix = ">STATE:"
const stateOutputMatcher = "^\\d+,([a-zA-Z_]+),.*$"

var rule = regexp.MustCompile(stateOutputMatcher)

type middleware struct {
	listeners []Callback
	state     process.State
	mutex     sync.RWMutex
}

// NewMiddleware creates state middleware for given list of callback listeners
func NewMiddleware(listeners ...Callback) *middleware {
	return &middleware{
		listeners: listeners,
	}
}

func (m *middleware) Start(commandWriter management.CommandWriter) error {
	m.callListeners(process.ProcessStarted)
	_, lines, err := commandWriter.MultiLineCommand("state on all")
	if err != nil {
		return err
	}
	for _, line := range lines {
		state, err := extractOpenvpnState(line)
		if err != nil {
			return err
		}
		m.mutex.Lock()
		m.state = state
		m.mutex.Unlock()
		m.callListeners(state)
	}
	return nil
}

func (m *middleware) Stop(commandWriter management.CommandWriter) error {
	m.callListeners(process.ProcessExited)
	_, err := commandWriter.SingleLineCommand("state off")
	return err
}

func (m *middleware) ProcessEvent(line string) (bool, error) {
	trimmedLine := strings.TrimPrefix(line, stateEventPrefix)
	if trimmedLine == line {
		return false, nil
	}

	state, err := extractOpenvpnState(trimmedLine)
	if err != nil {
		return true, err
	}

	m.mutex.Lock()
	m.state = state
	m.mutex.Unlock()
	m.callListeners(state)
	return true, nil
}

func (m *middleware) Subscribe(listener Callback) {
	m.listeners = append(m.listeners, listener)
}

func (m *middleware) callListeners(state process.State) {
	for _, listener := range m.listeners {
		listener(state)
	}
}

func (m *middleware) WaitForState(state process.State, timeout time.Duration) error {
	startTime := time.Now()
	tickerDuration := 100 * time.Millisecond
	for {
		if time.Since(startTime) >= timeout {
			return errors.New("timeout waiting for state")
		}
		m.mutex.RLock()
		if m.state == state {
			m.mutex.RUnlock()
			return nil
		}
		m.mutex.RUnlock()
		time.Sleep(tickerDuration)
	}
}

func extractOpenvpnState(line string) (process.State, error) {
	matches := rule.FindStringSubmatch(line)
	if len(matches) < 2 {
		return process.UnknownState, errors.New("Line mismatch: " + line)
	}

	return process.State(matches[1]), nil
}
