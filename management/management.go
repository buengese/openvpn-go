package management

// Management packages contains all functionality related to openvpn management interface
// See https://openvpn.net/index.php/open-source/documentation/miscellaneous/79-management-interface.html

// CommandWriter represents openvpn management interface abstraction for middlewares to be able to send commands to openvpn process
type CommandWriter interface {
	SingleLineCommand(template string, args ...interface{}) (string, error)
	MultiLineCommand(template string, args ...interface{}) (string, []string, error)
}
