package config

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"

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

type ConfigOption interface {
	GetName() string
	ToConfig() (string, error)
	ToCli() ([]string, error)
}

type Config struct {
	runtimeDir       string
	scriptSearchPath string
	options          []ConfigOption
}

func NewConfig(runtimeDir string, scriptSearchPath string) *Config {
	return &Config{
		runtimeDir:       runtimeDir,
		scriptSearchPath: scriptSearchPath,
		options:          []ConfigOption{},
	}
}

// FromFile parses a OpenVPN configuration file and returns a Config object.
func FromFile(filePath string, runtimeDir string, scriptSearchPath string) (*Config, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, ErrCannotReadFile
	}
	defer f.Close()

	c := NewConfig(runtimeDir, scriptSearchPath)

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
					return nil, err
				}
				c.AddOptions(option)
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
			c.AddOptions(option)
			continue
		}
		// parse as flag otherwise
		flag := flag.FromConfig(line)
		c.AddOptions(flag)
	}

	return c, nil
}

func (c *Config) ToFile(filePath string) error {
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
	return nil
}

func (c *Config) ToCli() ([]string, error) {
	arguments := make([]string, 0)

	for _, item := range c.options {
		optionValues, err := item.ToCli()
		if err != nil {
			return nil, err
		}

		arguments = append(arguments, optionValues...)
	}

	return arguments, nil
}

func (c *Config) AddOptions(options ...ConfigOption) {
	c.options = append(c.options, options...)
}

func (c *Config) GetOptions() []ConfigOption {
	return c.options
}

func (c *Config) SetParam(name string, values ...string) {
	for i, option := range c.options {
		if option.GetName() == name {
			c.options[i] = param.OptionParam(name, values...)
			return
		}
	}
	c.AddOptions(param.OptionParam(name, values...))
}

func (c *Config) SetFlag(name string) {
	for _, option := range c.options {
		if option.GetName() == name {
			return
		}
	}
	c.AddOptions(flag.OptionFlag(name))
}

func (c *Config) SetManagementAddress(ip string, port int) {
	c.SetParam("management", ip, strconv.Itoa(port))
	c.SetFlag("management-client")
}

func (c *Config) SetPort(port int) {
	c.SetParam("port", strconv.Itoa(port))
}

func (c *Config) SetDevice(device string) {
	c.SetParam("dev", device)
}

func (c *Config) SetTLSCaCert(caFile string) error {
	f, err := file.FromFile("ca", caFile, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

func (c *Config) SetTLSPrivatePubKexy(certFile string, keyFile string) error {
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

func (c *Config) SetTLSCrypt(cryptFile string) error {
	f, err := file.FromFile("tls-crypt", cryptFile, true)
	if err != nil {
		return err
	}
	c.AddOptions(f)
	return nil
}

func (c *Config) SetReconnectRetry(retry int) {
	c.SetFlag("single-session")
	c.SetFlag("tls-exit")
	c.SetParam("connect-retry-max", strconv.Itoa(retry))
}

func (c *Config) SetKeepAlive(interval, timeout int) {
	c.SetParam("keepalive", strconv.Itoa(interval), strconv.Itoa(timeout))
}

func (c *Config) SetPingRemote() {
	c.SetFlag("ping-timer-rem")
}
