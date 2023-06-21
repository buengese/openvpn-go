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
}

func OptionFile(name, filePath, content string) fileOption {
	return fileOption{
		name:     name,
		filePath: filePath,
		content:  content,
	}
}

func (o fileOption) Name() string {
	return o.name
}

func (o fileOption) Value() string {
	return o.content
}

func FromPath(name, filePath string, inline bool) (fileOption, error) {
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

func (o fileOption) ToLines() (string, error) {
	escaped, err := escapeXml(o.content)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("<%s>\n%s\n</%s>", o.name, escaped, o.name), nil
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
