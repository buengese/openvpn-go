// Copyright 2020 BlockDev AG
// SPDX-License-Identifier: MIT
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

var (
	ErrWaitTimeout = errors.New("timeout waiting for state")

	ErrAuthFailure = errors.New("authentication failure")

	ErrRemoteDisconnect = errors.New("remote disconnect")

	ErrProcessExiting = errors.New("openvpn process exiting")
)

type middleware struct {
	listeners  []Callback
	state      process.State
	lastDetail string
	mutex      sync.RWMutex
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

func (m *middleware) Stop(commandWriter management.CommandWriter) {
	m.callListeners(process.ProcessExited)
}

func (m *middleware) ProcessEvent(line string) (bool, error) {
	trimmedLine := strings.TrimPrefix(line, stateEventPrefix)
	if trimmedLine == line {
		return false, nil
	}
	// Split the line by comma. The expected format is:
	// timestamp,STATE,detail, ...
	parts := strings.Split(trimmedLine, ",")
	if len(parts) < 2 {
		return true, errors.New("invalid state line: " + line)
	}
	newState := process.State(parts[1])
	var detail string
	if len(parts) > 2 {
		detail = parts[2]
	}
	m.mutex.Lock()
	m.state = newState
	m.lastDetail = detail
	m.mutex.Unlock()
	m.callListeners(newState)
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
			return ErrWaitTimeout
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

func (m *middleware) WaitForConnected(timeout time.Duration) error {
	startTime := time.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if time.Since(startTime) >= timeout {
			return ErrWaitTimeout
		}
		m.mutex.RLock()
		currentState := m.state
		currentDetail := m.lastDetail
		m.mutex.RUnlock()

		switch currentState {
		case process.ConnectedState:
			return nil
		case process.ExitingState:
			if currentDetail == "auth-failure" {
				return ErrAuthFailure
			}
			if currentDetail == "exit-with-notification" {
				return ErrRemoteDisconnect
			}
			return ErrProcessExiting
		}
		<-ticker.C
	}
}

func extractOpenvpnState(line string) (process.State, error) {
	matches := rule.FindStringSubmatch(line)
	if len(matches) < 2 {
		return process.UnknownState, errors.New("Line mismatch: " + line)
	}

	return process.State(matches[1]), nil
}
