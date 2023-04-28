// Copyright 2020 BlockDev AG
// SPDX-License-Identifier: AGPL-3.0-only
package management

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/textproto"
)

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

func (m *mockMiddleware) Stop(cmdWriter CommandWriter) error {
	if m.OnStop != nil {
		return m.OnStop(cmdWriter)
	}
	return nil
}

func (m *mockMiddleware) ProcessEvent(event string) (consumed bool, err error) {
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
	return err
}
func (mop *mockOpenvpnProcess) Disconnect() error {
	return mop.conn.Close()
}

func connectTo(addr Addr) (*mockOpenvpnProcess, error) {
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		return nil, err
	}

	commandChannel := make(chan string, 100)
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
