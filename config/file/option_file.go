// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: AGPL-3.0-only OR MIT
package file

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

var (
	ErrNoPath = errors.New("no path")
)

type fileOption struct {
	name     string
	content  string
	filePath string
	inline   bool
}

func OptionFile(name, filePath, content string, inline bool) fileOption {
	return fileOption{
		name:     name,
		filePath: filePath,
		content:  content,
		inline:   inline,
	}
}

func (o fileOption) Name() string {
	return o.name
}

func FromConfig(name, content string, inline bool) (fileOption, error) {
	return fileOption{name: name, content: content, inline: inline}, nil
}

func FromFile(name, filePath string, inline bool) (fileOption, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fileOption{}, err
	}
	return fileOption{name: name, content: string(content), filePath: filePath}, nil
}

func (o fileOption) Save() error {
	if o.filePath == "" {
		return ErrNoPath
	}
	return ioutil.WriteFile(o.filePath, []byte(o.content), 0600)
}

func (o fileOption) tempFile() (string, error) {
	file, err := ioutil.TempFile("", "ovpn-")
	if err != nil {
		return "", err
	}
	defer file.Close()
	file.Write([]byte(o.content))
	return file.Name(), nil
}

func (o fileOption) ToCli() ([]string, error) {
	filePath := o.filePath
	var err error
	if o.filePath != "" {
		err = o.Save()
		if err != nil {
			return nil, err
		}
	} else {
		filePath, err = o.tempFile()
		if err != nil {
			return nil, err
		}
	}

	return []string{"--" + o.name, filePath}, err
}

func (o fileOption) ToConfig() (string, error) {
	if o.inline {
		escaped, err := escapeXml(o.content)
		if err != nil {
			return "", nil
		}
		return fmt.Sprintf("<%s>\n%s</%s>", o.name, escaped, o.name), nil
	}
	filePath, err := o.tempFile()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s %s", o.name, filePath), nil
}

func (o fileOption) String() string {
	return o.content
}

func escapeXml(content string) (string, error) {
	var buf bytes.Buffer
	err := xml.EscapeText(&buf, []byte(content))
	if err != nil {
		return "", err
	}
	escaped := strings.Replace(buf.String(), "&#xA;", "\n", -1)
	return escaped, nil
}
