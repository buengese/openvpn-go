// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package fileoption

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
		return FileOption{}, fmt.Errorf("failed to read file %s: %w", filePath, err)
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

	if err := os.WriteFile(o.filePath, []byte(o.content), 0600); err != nil {
		return fmt.Errorf("failed to write file %s: %w", o.filePath, err)
	}

	return nil
}

func (o FileOption) ToLines() (string, error) {
	// If no content is loaded, output as a file reference instead of inline content
	if o.content == "" && o.filePath != "" {
		return fmt.Sprintf("%s %s", o.name, o.filePath), nil
	}

	escaped, err := escapeXML(o.content)
	if err != nil {
		return "", nil
	}

	return fmt.Sprintf("<%s>\n%s\n</%s>", o.name, escaped, o.name), nil
}

func escapeXML(content string) (string, error) {
	var buf bytes.Buffer

	err := xml.EscapeText(&buf, []byte(content))
	if err != nil {
		return "", fmt.Errorf("failed to escape XML: %w", err)
	}

	escaped := strings.ReplaceAll(buf.String(), "&#xA;", "\n")

	return escaped, nil
}
