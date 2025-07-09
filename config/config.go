// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package config

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/buengese/openvpn-go/config/auth"
	"github.com/buengese/openvpn-go/config/file_option"
	"github.com/buengese/openvpn-go/config/flag_option"
	"github.com/buengese/openvpn-go/config/param_option"
	"github.com/pkg/errors"
)

type NetProtocol string

type Endpoint struct {
	Host  string
	Port  int
	Proto NetProtocol
}

const (
	TCP NetProtocol = "tcp"
	UDP NetProtocol = "udp"
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

// ParseOption represents a functional option for parsing configuration.
type ParseOption func(*parseOptions)

// parseOptions holds all parsing configuration options.
type parseOptions struct {
	LoadFileOptions bool // Controls if file options load content from referenced paths
}

// defaultParseOptions returns the default parsing options.
func defaultParseOptions() *parseOptions {
	return &parseOptions{
		LoadFileOptions: false, // Default to false, will be overridden per method
	}
}

// WithLoadFileOptions controls whether file options load content from referenced paths.
func WithLoadFileOptions(load bool) ParseOption {
	return func(opts *parseOptions) {
		opts.LoadFileOptions = load
	}
}

// ConfigOption is an interface for all configuration options.
type ConfigOption interface {
	Name() string
	Value() string
	ToLines() (string, error)
}

// Config is a representation of a OpenVPN configuration.
type Config struct {
	Options      []ConfigOption
	Auth         *auth.AuthOption
	path         string
	parseOptions *parseOptions
}

// NewConfig creates a new Config object.
func NewConfig() *Config {
	return &Config{
		Options:      []ConfigOption{},
		parseOptions: defaultParseOptions(),
	}
}

// FromFile parses a OpenVPN configuration file and returns a Config object.
func FromFile(filePath string, opts ...ParseOption) (*Config, error) {
	options := defaultParseOptions()
	options.LoadFileOptions = true // Default to true for FromFile
	for _, opt := range opts {
		opt(options)
	}

	c := NewConfig()
	c.path = filePath
	c.parseOptions = options

	return c, c.read()
}

// FromString parses a OpenVPN configuration string and returns a Config object.
func FromString(config string, opts ...ParseOption) (*Config, error) {
	options := defaultParseOptions()
	for _, opt := range opts {
		opt(options)
	}

	scanner := bufio.NewScanner(strings.NewReader(config))
	c := NewConfig()
	c.parseOptions = options
	return c, c.scanConfig(scanner)
}

// FromByteSlice parses a OpenVPN configuration byte slice and returns a Config object.
func FromByteSlice(data []byte, opts ...ParseOption) (*Config, error) {
	options := defaultParseOptions()
	for _, opt := range opts {
		opt(options)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	c := NewConfig()
	c.parseOptions = options
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
				option := file_option.New(XMLCloseTag.FindStringSubmatch(line)[1], buf.String())
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
			option, err := file_option.NewFromPath(parts[0], path.Join(c.Dir(), parts[1]), c.parseOptions.LoadFileOptions)
			if err != nil {
				return err
			}
			c.addOptions(option)
			continue
		}
		// try parsing as option first
		if option, err := param_option.FromLine(line); err == nil {
			c.addOptions(option)
			continue
		}
		// parse as flag otherwise
		flag := flag_option.FromConfig(line)
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

// SetParam sets the value of a parameter.
func (c *Config) AddParam(name string, values ...string) {
	c.AddOptions(param_option.New(name, values...))
}

// SetFlag sets a flag.
func (c *Config) AddFlag(name string) {
	c.AddOptions(flag_option.New(name))
}

func (c *Config) AddInlineFile(name string, content string) {
	c.AddOptions(file_option.New(name, content))
}

// SetAuth sets username and password for authentication.
// allowFile controls whether the password can be written to a file or must be send via the management interface.
func (c *Config) SetAuth(username, password string, allowFile bool) {
	c.Auth = auth.OptionAuth(username, password, allowFile)
}

// SetManagementAddress sets the IP address and port of the management interface.
func (c *Config) SetManagementAddress(ip string, port int) {
	c.RemoveAllOptions("management")
	c.RemoveAllOptions("management-client")
	c.AddParam("management", ip, strconv.Itoa(port))
	c.AddFlag("management-client")
}

func (c *Config) SetProto(proto NetProtocol) {
	c.RemoveAllOptions("proto")
	c.AddParam("proto", string(proto))
}

// SetPort sets the port of the OpenVPN server.
func (c *Config) SetPort(port int) {
	c.RemoveAllOptions("port")
	c.AddParam("port", strconv.Itoa(port))
}

// SetDevice sets the device of the OpenVPN server.
func (c *Config) SetDevice(device string) {
	c.RemoveAllOptions("dev")
	c.AddParam("dev", device)
}

// SetTLSCaCert sets the CA certificate for TLS authentication.
func (c *Config) SetTLSCaCert(caFile string) error {
	c.RemoveAllOptions("ca")
	path := path.Join(c.Dir(), caFile)
	f, err := file_option.NewFromPath("ca", path, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

func (c *Config) GetTLSCaCert() {
}

// SetTLSClientCert sets the client certificate for TLS authentication.
func (c *Config) SetTLSClientCert(certFile string) error {
	c.RemoveAllOptions("cert")
	path := path.Join(c.Dir(), certFile)
	f, err := file_option.NewFromPath("cert", path, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

// SetTLSPrivateKey sets the client private key for TLS authentication.
func (c *Config) SetTLSPrivateKey(keyFile string) error {
	c.RemoveAllOptions("key")
	path := path.Join(c.Dir(), keyFile)
	f, err := file_option.NewFromPath("key", path, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

// SetTLSCrypt sets the tls-crypt key for TLS authentication.
func (c *Config) SetTLSCrypt(cryptFile string) error {
	c.RemoveAllOptions("tls-crypt")
	path := path.Join(c.Dir(), cryptFile)
	f, err := file_option.NewFromPath("tls-crypt", path, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

// GetOption returns the first ConfigOption with the given name.
func (c *Config) GetOption(name string) ConfigOption {
	for _, option := range c.Options {
		if option.Name() == name {
			return option
		}
	}
	return nil
}

// GetOptions returns all ConfigOptions with the given name.
func (c *Config) GetOptions(name string) []ConfigOption {
	options := make([]ConfigOption, 0)
	for _, option := range c.Options {
		if option.Name() == name {
			options = append(options, option)
		}
	}
	return options
}

func (c *Config) GetProto() NetProtocol {
	proto := c.GetOption("proto")
	if proto == nil {
		return TCP
	}
	s := strings.TrimSpace(proto.Value())
	s = strings.ToLower(s)
	switch s {
	case "tcp", "tcp4", "tcp6":
		return TCP
	case "udp", "udp4", "udp6":
		return UDP
	default:
		return TCP
	}
}

func (c *Config) GetPort() int {
	port := c.GetOption("port")
	if port == nil || len(port.Value()) == 0 {
		return 0
	}
	p, err := strconv.Atoi(port.Value())
	if err != nil {
		return 0
	}
	return p
}

func (c *Config) GetRemote() (string, int) {
	remote := c.GetOption("remote")
	if remote == nil || len(remote.Value()) == 0 {
		return "", 0
	}
	parts := strings.Split(remote.Value(), " ")
	if len(parts) == 1 {
		return remote.Value(), 0
	}
	if len(parts) > 2 {
		return "", 0
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0
	}
	return parts[0], port
}

func clientProto(clientProto string) NetProtocol {
	switch strings.ToLower(clientProto) {
	case "tcp-client", "tcp4-client", "tcp6-client":
		return TCP
	case "udp-client", "udp4-client", "udp6-client":
		return UDP
	default:
		return TCP // Default to TCP if unknown
	}
}

// GetEndpoints returns all remote endpoints defined in the configuration.
// Parses remote <host> [<port> [<proto>]]
func (c *Config) GetEndpoints() []Endpoint {
	var (
		remoteOptions = c.GetOptions("remote")
		endpoints     = make([]Endpoint, 0, len(remoteOptions))
		port          = c.GetPort()
		proto         = c.GetProto()
	)

	for _, remote := range remoteOptions {
		parts := strings.Split(remote.Value(), " ")
		// Most common case: remote <host>
		if len(parts) == 1 {
			endpoints = append(endpoints, Endpoint{Host: parts[0], Port: port, Proto: proto})
			continue
		}
		if len(parts) > 3 {
			continue // invalid remote option
		}

		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue // invalid port
		}

		// Less common case: remote <host> <port>
		if len(parts) == 2 {
			endpoints = append(endpoints, Endpoint{Host: parts[0], Port: port, Proto: proto})
			continue
		}

		// Least common case: remote <host> <port> <proto>
		endpoints = append(endpoints, Endpoint{Host: parts[0], Port: port, Proto: clientProto(parts[2])})
	}
	return endpoints
}

// RemoveOption removes the first ConfigOption with the given name from the Config object.
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

// RemoveAllOptions removes all ConfigOptions with the given name from the Config object.
// Returns the number of options that were removed.
func (c *Config) RemoveAllOptions(name string) int {
	removed := 0
	for i := 0; i < len(c.Options); {
		if c.Options[i].Name() == name {
			// Remove by swapping with last element and truncating
			c.Options[i] = c.Options[len(c.Options)-1]
			c.Options = c.Options[:len(c.Options)-1]
			removed++
		} else {
			i++
		}
	}
	return removed
}
