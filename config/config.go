// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: AGPL-3.0-only OR MIT
package config

import (
	"bufio"
	"errors"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/buengese/openvpn-go/config/auth"
	"github.com/buengese/openvpn-go/config/file"
	"github.com/buengese/openvpn-go/config/flag"
	"github.com/buengese/openvpn-go/config/param"
)

var (
	ErrCannotReadFile = errors.New("cannot read file")

	// Matches any XML open tag
	// <tag>
	XMLOpenTag = regexp.MustCompile("<([a-zA-Z0-9-_]+)>")
	// Matches any XML close tag
	// </tag>
	XMLCloseTag = regexp.MustCompile("</([a-zA-Z0-9-_]+)>")
)

// ConfigOption is an interface for all configuration options.
type ConfigOption interface {
	Name() string
	ToConfig() (string, error)
	ToCli() ([]string, error)
}

// Config is a representation of a OpenVPN configuration.
type Config struct {
	options    []ConfigOption
	Auth       *auth.AuthOption
	isFile     bool
	isModified bool
	path       string
}

// NewConfig creates a new Config object.
func NewConfig() *Config {
	return &Config{
		options: []ConfigOption{},
	}
}

// FromFile parses a OpenVPN configuration file and returns a Config object.
func FromFile(filePath string) (*Config, error) {
	c := NewConfig()
	c.isFile = true
	c.path = filePath

	return c, c.read()
}

// read reads a OpenVPN configuration file and parses it.
func (c *Config) read() error {
	f, err := os.Open(c.path)
	if err != nil {
		return ErrCannotReadFile
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var inlineFile bool = false
	var buf strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// inlined file
		if inlineFile {
			if XMLCloseTag.MatchString(line) {
				inlineFile = false
				option, err := file.FromConfig(XMLCloseTag.FindStringSubmatch(line)[1], buf.String(), true)
				if err != nil {
					return err
				}
				c.addOptions(option)
				buf.Reset()
				continue
			}
			buf.WriteString(line)
			buf.WriteRune('\n')
			continue
		}
		if XMLOpenTag.MatchString(line) {
			inlineFile = true
			continue
		}
		// try parsing as option first than as flag
		if option, err := param.FromConfig(line); err == nil {
			c.addOptions(option)
			continue
		}
		// parse as flag otherwise
		flag := flag.FromConfig(line)
		c.addOptions(flag)
	}
	return nil
}

// Save serializes the Config object and writes it to a file in the OpenVPN configuration format at the given path.
// It also sets the path of the Config object to the given path.
func (c *Config) Save(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, item := range c.options {
		content, err := item.ToConfig()
		if err != nil {
			return err
		}
		_, err = file.WriteString(content + "\n")
		if err != nil {
			return err
		}
	}
	c.path = filePath
	c.isModified = false
	return nil
}

// ToCli generates the appropriate command line arguments for the OpenVPN binary.
// If the configuration the current configuration has been written to or loaded from a file,
// it uses the --config flag and the path to the file as argument.
// Otherwise it will return all options and flags as command line arguments.
func (c *Config) ToCli() ([]string, error) {
	arguments := make([]string, 0)

	if c.isFile && !c.isModified {
		arguments = append(arguments, "--config", c.path)
		return arguments, nil
	}
	for _, item := range c.options {
		optionValues, err := item.ToCli()
		if err != nil {
			return nil, err
		}

		arguments = append(arguments, optionValues...)
	}
	if c.Auth != nil && c.Auth.AllowFile() {
		authValues, err := c.Auth.ToCli()
		if err != nil {
			return nil, err
		}
		arguments = append(arguments, authValues...)
	}

	return arguments, nil
}

// IsFile returns true if the Config object has been loaded from or written to a file.
func (c *Config) IsFile() bool {
	return c.isFile
}

// Dir returns the directory of the file the Config object has been loaded from or written to.
func (c *Config) Dir() string {
	return path.Dir(c.path)
}

func (c *Config) addOptions(options ...ConfigOption) {
	c.options = append(c.options, options...)
}

// AddOptions adds one or more ConfigOption to the Config object.
func (c *Config) AddOptions(options ...ConfigOption) {
	c.isModified = true
	c.addOptions(options...)
}

// Options returns all ConfigOptions of the Config object.
func (c *Config) Options() []ConfigOption {
	return c.options
}

// SetParam sets the value of a parameter.
func (c *Config) SetParam(name string, values ...string) {
	for i, option := range c.options {
		if option.Name() == name {
			c.isModified = true
			c.options[i] = param.OptionParam(name, values...)
			return
		}
	}
	c.AddOptions(param.OptionParam(name, values...))
}

// SetFlag sets a flag.
func (c *Config) SetFlag(name string) {
	for _, option := range c.options {
		if option.Name() == name {
			return
		}
	}
	c.AddOptions(flag.OptionFlag(name))
}

// SetAuth sets username and password for authentication.
// allowFile controls whether the password can be written to a file or must be send via the management interface.
func (c *Config) SetAuth(username, password string, allowFile bool) {
	c.Auth = auth.OptionAuth(username, password, allowFile)
}

// SetManagementAddress sets the IP address and port of the management interface.
func (c *Config) SetManagementAddress(ip string, port int) {
	c.SetParam("management", ip, strconv.Itoa(port))
	c.SetFlag("management-client")
}

// SetPort sets the port of the OpenVPN server.
func (c *Config) SetPort(port int) {
	c.SetParam("port", strconv.Itoa(port))
}

// SetDevice sets the device of the OpenVPN server.
func (c *Config) SetDevice(device string) {
	c.SetParam("dev", device)
}

// SetTLSCaCert sets the CA certificate for TLS authentication.
func (c *Config) SetTLSCaCert(caFile string) error {
	f, err := file.FromFile("ca", caFile, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

// SetTLSClientCert sets the client certificate for TLS authentication.
func (c *Config) SetTLSPrivatePubKey(certFile string, keyFile string) error {
	f, err := file.FromFile("cert", certFile, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	f, err = file.FromFile("key", keyFile, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

// SetTLSCrypt sets the tls-crypt key for TLS authentication.
func (c *Config) SetTLSCrypt(cryptFile string) error {
	f, err := file.FromFile("tls-crypt", cryptFile, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

// SetReconnectRetry sets the number of reconnect attempts.
func (c *Config) SetReconnectRetry(retry int) {
	c.SetFlag("single-session")
	c.SetFlag("tls-exit")
	c.SetParam("connect-retry-max", strconv.Itoa(retry))
}

// SetKeepAlive sets the keepalive interval and timeout.
func (c *Config) SetKeepAlive(interval, timeout int) {
	c.SetParam("keepalive", strconv.Itoa(interval), strconv.Itoa(timeout))
}

// SetPingRemote sets the ping interval and timeout.
func (c *Config) SetPingRemote() {
	c.SetFlag("ping-timer-rem")
}
