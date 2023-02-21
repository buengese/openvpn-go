/*
 * go-openvpn -- Go gettable library for wrapping Openvpn functionality in go way.
 *
 * Copyright (C) 2020 BlockDev AG.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License Version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program in the COPYING file.
 * If not, see <http://www.gnu.org/licenses/>.
 */

package management

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConnectionAccept(t *testing.T) {
	mngmnt := NewManagement(context.Background(), LocalhostOnRandomPort)
	err := mngmnt.Listen()
	assert.NoError(t, err)

	_, err = connectTo(mngmnt.BoundAddress)
	assert.NoError(t, err)

	select {
	case connected := <-mngmnt.Connected:
		assert.True(t, connected)
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "Middleware start method expected to be called in 100 milliseconds")
	}
}

func TestStopWithoutConnection(t *testing.T) {
	mngmnt := NewManagement(context.Background(), LocalhostOnRandomPort)
	err := mngmnt.Listen()
	assert.NoError(t, err)

	mngmnt.Stop()

	select {
	case connected := <-mngmnt.Connected:
		assert.False(t, connected)
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "Expected to receive false on connected channel in 100 milliseconds")
	}
}

func TestListenerShutdown(t *testing.T) {
	mngmnt := NewManagement(context.Background(), LocalhostOnRandomPort)
	err := mngmnt.Listen()
	assert.NoError(t, err)

	_, err = connectTo(mngmnt.BoundAddress)
	assert.NoError(t, err)

	stopFinished := make(chan bool, 1)
	go func() {
		mngmnt.Stop()
		stopFinished <- true
	}()

	select {
	case <-stopFinished:

	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "Management interface expected to stop in 100 milliseconds")
	}
}
