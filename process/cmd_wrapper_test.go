// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package process

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/buengese/openvpn-go/internal/shell"
	"github.com/stretchr/testify/assert"
)

// TestHelperProcess IS ESSENTIAL FOR CMD MOCKING - DO NOT DELETE.
func TestHelperProcess(_ *testing.T) {
	RunTestExecCmd()
}

func TestWaitAndStopProcessDoesNotDeadLocks(t *testing.T) {
	execTestHelper := NewExecCmdTestHelper("TestHelperProcess")
	execTestHelper.AddExecResult("", "", 0, 10000, "openvpn")

	process := shell.NewCommand(context.Background(), "openvpn", []string{}...)
	processStarted := sync.WaitGroup{}
	processStarted.Add(1)

	processWaitExited := make(chan int, 1)
	processStopExited := make(chan int, 1)

	go func() {
		assert.NoError(t, process.Start())
		processStarted.Done()

		_ = process.Wait()
		processWaitExited <- 1
	}()
	processStarted.Wait()

	go func() {
		// process.Stop()
		processStopExited <- 1
	}()

	select {
	case <-processWaitExited:
	case <-time.After(600 * time.Millisecond):
		assert.Fail(t, "CmdWrapper.Wait() didn't return in 600 miliseconds")
	}

	select {
	case <-processStopExited:
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "CmdWrapper.Stop() didn't return in 100 miliseconds")
	}
}

func TestWaitReturnsIfProcessDies(t *testing.T) {
	execTestHelper := NewExecCmdTestHelper("TestHelperProcess")
	execTestHelper.AddExecResult("", "", 0, 100, "openvpn")

	process := shell.NewCommand(context.Background(), "openvpn", []string{}...)
	processWaitExited := make(chan int, 1)

	go func() {
		_ = process.Wait()
		processWaitExited <- 1
	}()

	assert.NoError(t, process.Start())
	select {
	case <-processWaitExited:
	case <-time.After(3000 * time.Millisecond):
		assert.Fail(t, "CmdWrapper.Wait() didn't return on time")
	}
}
