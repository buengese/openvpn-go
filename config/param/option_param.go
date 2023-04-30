// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: AGPL-3.0-only OR MIT
package param

import (
	"errors"
	"strings"
)

var (
	ErrNoParam = errors.New("no param")
)

func OptionParam(name string, values ...string) paramOption {
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

func (o paramOption) ToCli() ([]string, error) {
	return append([]string{"--" + o.name}, o.values...), nil
}

func (o paramOption) ToConfig() (string, error) {
	return o.name + " " + strings.Join(o.values, " "), nil
}

func FromConfig(content string) (paramOption, error) {
	parts := strings.Split(content, " ")
	if len(parts) < 2 {
		return paramOption{}, ErrNoParam
	}
	return paramOption{name: parts[0], values: parts[1:]}, nil
}
