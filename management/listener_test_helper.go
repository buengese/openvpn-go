// SPDX-License-Identifier: MIT
package management

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/textproto"
)

// Default buffer size for test command channel.
const defaultTestCommandChannelBuffer = 100

type mockMiddleware struct {
	OnStart        func(CommandWriter) error
	OnStop         func(CommandWriter) error
	OnLineReceived func(line string) (bool, error)
}

func (m *mockMiddleware) Start(cmdWriter CommandWriter) error {
	if m.OnStart != nil {
		return m.OnStart(cmdWriter)
	}

	return nil
}

func (m *mockMiddleware) Stop(cmdWriter CommandWriter) {
	if m.OnStop != nil {
		_ = m.OnStop(cmdWriter)
	}
}

func (m *mockMiddleware) ProcessEvent(event string) (bool, error) {
	if m.OnLineReceived != nil {
		return m.OnLineReceived(event)
	}

	return true, nil
}

type mockOpenvpnProcess struct {
	conn    net.Conn
	CmdChan chan string
}

func (mop *mockOpenvpnProcess) Send(line string) error {
	_, err := io.WriteString(mop.conn, line)
	if err != nil {
		return fmt.Errorf("failed to write string: %w", err)
	}

	return nil
}

func (mop *mockOpenvpnProcess) Disconnect() error {
	err := mop.conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	return nil
}

func connectTo(addr Addr) (*mockOpenvpnProcess, error) {
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	commandChannel := make(chan string, defaultTestCommandChannelBuffer)
	go sendStringsToChannel(conn, commandChannel)

	return &mockOpenvpnProcess{
		conn:    conn,
		CmdChan: commandChannel,
	}, nil
}

func sendStringsToChannel(input io.Reader, ch chan<- string) {
	reader := textproto.NewReader(bufio.NewReader(input))

	for {
		line, err := reader.ReadLine()
		if err != nil {
			fmt.Println("Woops error:", err)
			return
		}
		ch <- line
	}
}
