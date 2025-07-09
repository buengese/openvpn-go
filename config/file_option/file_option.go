// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package file_option

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	ErrNoPath = errors.New("no path")
)

type FileOption struct {
	name     string
	content  string
	filePath string
	loaded   bool
}

func (o FileOption) Name() string {
	return o.name
}

func (o FileOption) Value() string {
	return o.content
}

func New(name, content string) FileOption {
	return FileOption{name: name, content: content, filePath: "", loaded: true}
}

func NewFromPath(name, filePath string, loadContent bool) (FileOption, error) {
	if !loadContent {
		// Return a file option that just references the path without loading content
		return FileOption{name: name, filePath: filePath, content: "", loaded: false}, nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return FileOption{}, err
	}
	return FileOption{name: name, content: string(content), filePath: filePath, loaded: true}, nil
}

func (o FileOption) IsLoaded() bool {
	return o.loaded
}

func (o FileOption) Save() error {
	if o.filePath == "" {
		return ErrNoPath
	}
	return os.WriteFile(o.filePath, []byte(o.content), 0600)
}

func (o FileOption) ToLines() (string, error) {
	// If no content is loaded, output as a file reference instead of inline content
	if o.content == "" && o.filePath != "" {
		return fmt.Sprintf("%s %s", o.name, o.filePath), nil
	}

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
