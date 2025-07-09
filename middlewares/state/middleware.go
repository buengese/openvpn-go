// Copyright 2020 BlockDev AG
// SPDX-License-Identifier: MIT
package state

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/buengese/openvpn-go/management"
	"github.com/buengese/openvpn-go/process"
)

// Callback is called when openvpn process state changes.
type Callback func(state process.State)

const stateEventPrefix = ">STATE:"
const stateOutputMatcher = "^\\d+,([a-zA-Z_]+),.*$"

// Default polling interval for state checking.
const defaultPollingInterval = 100 * time.Millisecond

var rule = regexp.MustCompile(stateOutputMatcher)

var (
	ErrWaitTimeout = errors.New("timeout waiting for OpenVPN state change")

	ErrAuthFailure = errors.New("OpenVPN authentication failure")

	ErrRemoteDisconnect = errors.New("OpenVPN remote server disconnect")

	ErrProcessExiting = errors.New("OpenVPN process is exiting")
)

// Middleware handles state changes in the OpenVPN process.
type Middleware struct {
	listeners  []Callback
	state      process.State
	lastDetail string
	mutex      sync.RWMutex
}

// NewMiddleware creates state middleware for given list of callback listeners.
func NewMiddleware(listeners ...Callback) *Middleware {
	return &Middleware{
		listeners: listeners,
	}
}

func (m *Middleware) Start(commandWriter management.CommandWriter) error {
	m.callListeners(process.ProcessStarted)

	_, lines, err := commandWriter.MultiLineCommand("state on all")
	if err != nil {
		return fmt.Errorf("failed to get state: %w", err)
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

func (m *Middleware) Stop(_ management.CommandWriter) {
	m.callListeners(process.ProcessExited)
}

func (m *Middleware) ProcessEvent(line string) (bool, error) {
	trimmedLine := strings.TrimPrefix(line, stateEventPrefix)
	if trimmedLine == line {
		return false, nil
	}
	// Split the line by comma. The expected format is:
	// timestamp,STATE,detail, ...
	parts := strings.Split(trimmedLine, ",")
	if len(parts) < 2 {
		return true, fmt.Errorf("invalid OpenVPN state line format: %s", line)
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

func (m *Middleware) Subscribe(listener Callback) {
	m.listeners = append(m.listeners, listener)
}

func (m *Middleware) callListeners(state process.State) {
	for _, listener := range m.listeners {
		listener(state)
	}
}

func (m *Middleware) WaitForState(state process.State, timeout time.Duration) error {
	startTime := time.Now()
	tickerDuration := defaultPollingInterval

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

func (m *Middleware) WaitForConnected(timeout time.Duration) error {
	startTime := time.Now()

	ticker := time.NewTicker(defaultPollingInterval)
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
		return process.UnknownState, fmt.Errorf("OpenVPN state line does not match expected format: %s", line)
	}

	return process.State(matches[1]), nil
}
