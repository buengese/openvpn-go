// Copyright 2020 BlockDev AG
// SPDX-License-Identifier: AGPL-3.0-only
package management

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSingleOutputCommandHandlesSuccess(t *testing.T) {
	mockWriter := &mockWriter{}
	outputChannel := make(chan string, 1)
	conn := newCommandConnection(mockWriter, outputChannel)
	outputChannel <- "SUCCESS: message"

	success, err := conn.SingleLineCommand("template: %d", 123)
	assert.NoError(t, err)
	assert.Equal(t, "message", success)
	assert.Equal(t, "template: 123\n", mockWriter.receivedCommand)
}

func TestSingleOutputCommandHandlesFailure(t *testing.T) {
	mockWriter := &mockWriter{}
	outputChannel := make(chan string, 1)
	conn := newCommandConnection(mockWriter, outputChannel)
	outputChannel <- "ERROR: error"

	success, err := conn.SingleLineCommand("anything")
	assert.Empty(t, success)
	assert.Equal(t, errors.New("command error: error"), err)
}

func TestSingleOutputCommandHandlesUnknownResponse(t *testing.T) {
	mockWriter := &mockWriter{}
	outputChannel := make(chan string, 1)
	conn := newCommandConnection(mockWriter, outputChannel)
	outputChannel <- "200 OK HTTP/1.1"

	success, err := conn.SingleLineCommand("anything")
	assert.Empty(t, success)
	assert.Equal(t, errors.New("unknown command response: 200 OK HTTP/1.1"), err)

}

func TestMultipleOutputCommandHandlesResults(t *testing.T) {

	mockWriter := &mockWriter{}
	outputChannel := make(chan string, 1)
	conn := newCommandConnection(mockWriter, outputChannel)
	go func() {
		outputChannel <- "SUCCESS: great"
		outputChannel <- "This is"
		outputChannel <- "Multiline cmd output"
		outputChannel <- "END"
	}()

	success, output, err := conn.MultiLineCommand("test: %s , %d", "value", 123)
	assert.NoError(t, err)
	assert.Equal(t, "test: value , 123\n", mockWriter.receivedCommand)
	assert.Equal(t, "great", success)
	assert.Equal(
		t,
		[]string{
			"This is",
			"Multiline cmd output",
		},
		output,
	)

}

func TestClosedOutputChannelCausesCommandSendToFail(t *testing.T) {
	mockWriter := &mockWriter{}
	outputChannel := make(chan string, 1)
	conn := newCommandConnection(mockWriter, outputChannel)
	close(outputChannel)
	_, err := conn.SingleLineCommand("irrelevant")
	assert.Error(t, err)
}

type mockWriter struct {
	receivedCommand string
}

func (mw *mockWriter) Write(buff []byte) (int, error) {
	mw.receivedCommand = string(buff)
	return len(buff), nil
}
