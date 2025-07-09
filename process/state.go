// SPDX-License-Identifier: MIT
package process

// State type represents valid openvpn states type
type State string

// ConnectingState is reported by client and server mode and is indicator of openvpn startup
const ConnectingState = State("CONNECTING")

// WaitState is reported by client in udp mode indicating that connect request is send and response is waiting
const WaitState = State("WAIT")

// AuthenticatingState is reported by client indicating that client is trying to authenticate itself to server
const AuthenticatingState = State("AUTH")

// GetConfigState indicates that client is waiting for config from server (push based options)
const GetConfigState = State("GET_CONFIG")

// AssignIpState indicates that client is trying to setup tunnel with provided ip addresses
const AssignIpState = State("ASSIGN_IP")

// AddRoutesState indicates that client is setuping routes on tunnel
const AddRoutesState = State("ADD_ROUTES")

// ConnectedState is reported by both client and server and means that client is successfully connected and server is ready
// to server incoming client connect requests
const ConnectedState = State("CONNECTED")

// ReconnectingState indicates that client lost connection and is trying to reconnect itself
const ReconnectingState = State("RECONNECTING")

// ExitingState is reported by both client and server and means that openvpn process is exiting by any reasons (normal shutdown
// or fatal error reported before this state)
const ExitingState = State("EXITING")

// two "fake" states which has no description in openvpn management interface documentation

// ProcessStarted state is reported by state middleware when middleware start method itself is called
// it means that process successfully connected to management interface
const ProcessStarted = State("PROCESS_STARTED")

// ProcessExited state is reported on state middleware stop method to indicate that process disconnected from
// interface and this is LAST state to report
const ProcessExited = State("PROCESS_EXITED")

// UnknownState is reported when state middleware cannot parse state from string (i.e. it's undefined in list above),
// usually that means that newer openvpn version reports something extra
const UnknownState = State("UNKNOWN")
