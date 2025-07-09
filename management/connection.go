// SPDX-License-Identifier: MIT
package management

import (
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strings"
)

const cmdSuccess = "SUCCESS"
const cmdError = "ERROR"
const endOfCmdOutput = "END"

// Default capacity for output lines buffer.
const defaultOutputLinesCapacity = 10

type commandConnection struct {
	cmdWriter io.Writer
	cmdOutput chan string
}

func newCommandConnection(cmdWriter io.Writer, cmdOutput chan string) *commandConnection {
	return &commandConnection{
		cmdWriter: cmdWriter,
		cmdOutput: cmdOutput,
	}
}

func (sc *commandConnection) SingleLineCommand(template string, args ...interface{}) (string, error) {
	cmd := fmt.Sprintf(template, args...)

	_, err := fmt.Fprintf(sc.cmdWriter, "%s\n", cmd)
	if err != nil {
		return "", fmt.Errorf("failed to write command: %w", err)
	}

	cmdOutput, more := <-sc.cmdOutput
	if !more {
		return "", errors.New("connection is gone")
	}

	outputParts := strings.Split(cmdOutput, ":")
	messageType := textproto.TrimString(outputParts[0])
	messageText := ""

	if len(outputParts) > 1 {
		messageText = textproto.TrimString(outputParts[1])
	}

	switch messageType {
	case cmdSuccess:
		return messageText, nil
	case cmdError:
		return "", errors.New("command error: " + messageText)
	default:
		return "", errors.New("unknown command response: " + cmdOutput)
	}
}

func (sc *commandConnection) MultiLineCommand(template string, args ...interface{}) (string, []string, error) {
	success, err := sc.SingleLineCommand(template, args...)
	if err != nil {
		return "", nil, err
	}

	outputLines := make([]string, 0, defaultOutputLinesCapacity) // Pre-allocate with reasonable capacity

	for outputLine := range sc.cmdOutput {
		if outputLine == endOfCmdOutput {
			break
		}

		outputLines = append(outputLines, outputLine)
	}

	return success, outputLines, nil
}
