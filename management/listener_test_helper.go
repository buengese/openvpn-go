package management

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/textproto"
)

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
