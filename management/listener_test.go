// SPDX-License-Identifier: MIT

package management

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConnectionAccept(t *testing.T) {
	m := NewManagement(context.Background(), LocalhostOnRandomPort)
	err := m.Listen()
	assert.NoError(t, err)

	_, err = connectTo(m.BoundAddress)
	assert.NoError(t, err)

	select {
	case connected := <-m.Connected:
		assert.True(t, connected)
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "Middleware start method expected to be called in 100 milliseconds")
	}
}

func TestShutdownWithoutConnection(t *testing.T) {
	m := NewManagement(context.Background(), LocalhostOnRandomPort)
	err := m.Listen()
	assert.NoError(t, err)

	m.Stop()

	select {
	case connected := <-m.Connected:
		assert.False(t, connected)
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "Expected to receive false on connected channel in 100 milliseconds")
	}
}

func TestListenerShutdown(t *testing.T) {
	m := NewManagement(context.Background(), LocalhostOnRandomPort)
	err := m.Listen()
	assert.NoError(t, err)

	_, err = connectTo(m.BoundAddress)
	assert.NoError(t, err)

	stopFinished := make(chan bool, 1)
	go func() {
		m.Stop()
		stopFinished <- true
	}()

	select {
	case <-stopFinished:
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "Management interface expected to stop in 100 milliseconds")
	}
}

func TestSendCommand(t *testing.T) {
	mockedMiddleware := &mockMiddleware{}
	cmdResult := make(chan string, 1)
	mockedMiddleware.OnStart = func(cmdWriter CommandWriter) error {
		res, _ := cmdWriter.SingleLineCommand("SAMPLECMD")
		cmdResult <- res
		return nil
	}

	m := NewManagement(context.Background(), LocalhostOnRandomPort)
	m.AddMiddleware(mockedMiddleware)
	err := m.Listen()
	assert.NoError(t, err)

	mockedOpenvpn, err := connectTo(m.BoundAddress)
	assert.NoError(t, err)

	select {
	case cmd := <-mockedOpenvpn.CmdChan:
		assert.Equal(t, "SAMPLECMD", cmd)
		mockedOpenvpn.Send("SUCCESS: MSG\n")
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "MockedOpenvpn expected to receive cmd in 100 milliseconds")
	}

	select {
	case res := <-cmdResult:
		assert.Equal(t, "MSG", res)
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "Middleware expected to receive command result in 100 milliseconds")
	}
}

func TestReceiveEvent(t *testing.T) {
	mockedMiddleware := &mockMiddleware{}
	lineReceived := make(chan string, 1)
	mockedMiddleware.OnLineReceived = func(line string) (bool, error) {
		lineReceived <- line
		return true, nil
	}

	m := NewManagement(context.Background(), LocalhostOnRandomPort)
	m.AddMiddleware(mockedMiddleware)
	err := m.Listen()
	assert.NoError(t, err)

	mockedOpenvpn, err := connectTo(m.BoundAddress)
	assert.NoError(t, err)

	err = mockedOpenvpn.Send(">sampleevent\n")
	assert.NoError(t, err)

	select {
	case line := <-lineReceived:
		assert.Equal(t, ">sampleevent", line)
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "Middleware expected to receive event in 100 milliseconds")
	}
}
