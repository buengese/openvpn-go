package main

import (
	"context"

	"github.com/buengese/openvpn-go"
	"github.com/buengese/openvpn-go/config"
	"github.com/buengese/openvpn-go/logging"
)

func main() {
	logging.Setup()
	config, err := config.FromFile("Sebastian.ovpn", "", "")
	if err != nil {
		panic(err)
	}
	proc := openvpn.New(context.Background(), "openvpn", config)
	err = proc.Start()
	if err != nil {
		panic(err)
	}
}
