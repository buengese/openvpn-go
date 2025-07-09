// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package paramoption

import (
	"errors"
	"strings"
)

var (
	ErrNoParam = errors.New("no param")
)

func New(name string, values ...string) ParamOption {
	return ParamOption{name: name, values: values}
}

type ParamOption struct {
	name   string
	values []string
}

func (o ParamOption) Name() string {
	return o.name
}

func (o ParamOption) Value() string {
	return strings.Join(o.values, " ")
}

func (o ParamOption) ToLines() (string, error) {
	return o.name + " " + strings.Join(o.values, " "), nil
}

func FromLine(content string) (ParamOption, error) {
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
		return ParamOption{}, ErrNoParam
	}

	return ParamOption{name: parts[0], values: parts[1:]}, nil
}
