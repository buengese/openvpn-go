// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package param_option

import (
	"errors"
	"strings"
)

var (
	ErrNoParam = errors.New("no param")
)

func New(name string, values ...string) paramOption {
	return paramOption{name: name, values: values}
}

type paramOption struct {
	name   string
	values []string
}

func (o paramOption) Name() string {
	return o.name
}

func (o paramOption) Value() string {
	return strings.Join(o.values, " ")
}

func (o paramOption) ToLines() (string, error) {
	return o.name + " " + strings.Join(o.values, " "), nil
}

func FromLine(content string) (paramOption, error) {
	// need simple state machine here
	var parts []string
	inQuotes := false
	param := ""
	for _, c := range content {
		if c == '"' || c == '\'' {
			inQuotes = !inQuotes
		}
		if inQuotes {
			param += string(c)
			continue
		}
		if c == ' ' && !inQuotes {
			parts = append(parts, param)
			param = ""
			continue
		}
		param += string(c)
	}
	if param != "" {
		parts = append(parts, param)
	}
	if len(parts) < 2 {
		return paramOption{}, ErrNoParam
	}
	return paramOption{name: parts[0], values: parts[1:]}, nil
}
