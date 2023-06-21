// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: AGPL-3.0-only OR MIT
package config

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/buengese/openvpn-go/config/auth"
	"github.com/buengese/openvpn-go/config/file"
	"github.com/buengese/openvpn-go/config/flag"
	"github.com/buengese/openvpn-go/config/param"
	"github.com/pkg/errors"
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
	Value() string
	ToLines() (string, error)
}

// Config is a representation of a OpenVPN configuration.
type Config struct {
	Options []ConfigOption
	Auth    *auth.AuthOption
	path    string
}

// NewConfig creates a new Config object.
func NewConfig() *Config {
	return &Config{
		Options: []ConfigOption{},
	}
}

// FromFile parses a OpenVPN configuration file and returns a Config object.
func FromFile(filePath string) (*Config, error) {
	c := NewConfig()
	c.path = filePath

	return c, c.read()
}

// FromString parses a OpenVPN configuration string and returns a Config object.
func FromString(config string) (*Config, error) {
	scanner := bufio.NewScanner(strings.NewReader(config))
	c := NewConfig()
	return c, c.scanConfig(scanner)
}

// isFileOption checks if a line matches a known file option.
func isFileOption(line string) bool {
	for _, opt := range []string{"ca ", "cert ", "dh ", "extra-certs ", "key ",
		"pkcs12 ", "tls-auth ", "tls-crypt "} {
		if strings.HasPrefix(line, opt) {
			return true
		}
	}
	return false
}

// read reads a OpenVPN configuration file and parses it.
func (c *Config) read() error {
	f, err := os.Open(c.path)
	if err != nil {
		return ErrCannotReadFile
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	return c.scanConfig(scanner)
}

// scanConfig parses a OpenVPN configuration file and adds the options to the Config object.
func (c *Config) scanConfig(scanner *bufio.Scanner) error {
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
				option := file.OptionFile(XMLCloseTag.FindStringSubmatch(line)[1], "", buf.String())
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
		// load file
		if isFileOption(line) {
			parts := strings.SplitN(line, " ", 2)
			option, err := file.FromPath(parts[0], path.Join(c.Dir(), parts[1]), true)
			if err != nil {
				return err
			}
			c.addOptions(option)
			continue
		}
		// try parsing as option first
		if option, err := param.FromLine(line); err == nil {
			c.addOptions(option)
			continue
		}
		// parse as flag otherwise
		flag := flag.FromConfig(line)
		c.addOptions(flag)
	}
	return nil
}

// ToString serializes the Config object and returns it as a string in the OpenVPN configuration format.
func (c *Config) ToString() (string, error) {
	var sb strings.Builder
	for _, item := range c.Options {
		content, err := item.ToLines()
		if err != nil {
			return "", err
		}
		_, err = sb.WriteString(content + "\n")
		if err != nil {
			return "", err
		}
	}
	return sb.String(), nil
}

// Save serializes the Config object and writes it to a file in the OpenVPN configuration format at the given path.
// It also sets the path of the Config object to the given path.
func (c *Config) Save(filePath string) error {
	if filePath != "" {
		c.path = filePath
	}
	if c.path == "" && filePath == "" {
		c.path = path.Join(os.TempDir(), fmt.Sprintf("vpn-%d.conf", os.Getpid()))
	}
	file, err := os.Create(c.path)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, item := range c.Options {
		content, err := item.ToLines()
		if err != nil {
			return err
		}
		_, err = file.WriteString(content + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

// ToCli writes the Config to a file and returns the arguments to pass to OpenVPN.
// If no file path is set, the Config is written to a temporary file and must be deleted manually.
func (c *Config) ToCli() ([]string, error) {
	arguments := make([]string, 0)

	err := c.Save("")
	if err != nil {
		return nil, errors.Wrap(err, "failed to write config")
	}
	arguments = append(arguments, "--config", c.path)

	if c.Auth != nil && c.Auth.AllowFile {
		authValues, err := c.Auth.ToCli()
		if err != nil {
			return nil, err
		}
		arguments = append(arguments, authValues...)
	}

	return arguments, nil
}

// Dir returns the directory of the file the Config object has been loaded from or written to.
func (c *Config) Dir() string {
	return path.Dir(c.path)
}

func (c *Config) Path() string {
	return c.path
}

func (c *Config) addOptions(options ...ConfigOption) {
	c.Options = append(c.Options, options...)
}

// AddOptions adds one or more ConfigOption to the Config object.
func (c *Config) AddOptions(options ...ConfigOption) {
	c.addOptions(options...)
}

func (c *Config) GetOption(name string) ConfigOption {
	for _, option := range c.Options {
		if option.Name() == name {
			return option
		}
	}
	return nil
}

func (c *Config) RemoveOption(name string) bool {
	index := -1
	for idx, option := range c.Options {
		if option.Name() == name {
			index = idx
			break
		}
	}
	if index == -1 {
		return false
	}

	c.Options[index] = c.Options[len(c.Options)-1]
	c.Options = c.Options[:len(c.Options)-1]
	return true
}

// SetParam sets the value of a parameter.
func (c *Config) AddParam(name string, values ...string) {
	c.AddOptions(param.OptionParam(name, values...))
}

// SetFlag sets a flag.
func (c *Config) AddFlag(name string) {
	c.AddOptions(flag.OptionFlag(name))
}

func (c *Config) AddFile(name string, content string) {
	c.AddOptions(file.OptionFile(name, "", content))
}

// SetAuth sets username and password for authentication.
// allowFile controls whether the password can be written to a file or must be send via the management interface.
func (c *Config) SetAuth(username, password string, allowFile bool) {
	c.Auth = auth.OptionAuth(username, password, allowFile)
}

// SetManagementAddress sets the IP address and port of the management interface.
func (c *Config) SetManagementAddress(ip string, port int) {
	c.AddParam("management", ip, strconv.Itoa(port))
	c.AddFlag("management-client")
}

// SetPort sets the port of the OpenVPN server.
func (c *Config) SetPort(port int) {
	c.AddParam("port", strconv.Itoa(port))
}

// SetDevice sets the device of the OpenVPN server.
func (c *Config) SetDevice(device string) {
	c.AddParam("dev", device)
}

// SetTLSCaCert sets the CA certificate for TLS authentication.
func (c *Config) SetTLSCaCert(caFile string) error {
	path := path.Join(c.Dir(), caFile)
	f, err := file.FromPath("ca", path, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

// SetTLSClientCert sets the client certificate for TLS authentication.
func (c *Config) SetTLSClientCert(certFile string) error {
	path := path.Join(c.Dir(), certFile)
	f, err := file.FromPath("cert", path, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

// SetTLSPrivateKey sets the client private key for TLS authentication.
func (c *Config) SetTLSPrivateKey(keyFile string) error {
	path := path.Join(c.Dir(), keyFile)
	f, err := file.FromPath("key", path, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

// SetTLSCrypt sets the tls-crypt key for TLS authentication.
func (c *Config) SetTLSCrypt(cryptFile string) error {
	path := path.Join(c.Dir(), cryptFile)
	f, err := file.FromPath("tls-crypt", path, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}
