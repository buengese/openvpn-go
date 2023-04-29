// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: AGPL-3.0-only OR MIT
package flag

func OptionFlag(name string) flagOption {
	return flagOption{name: name}
}

type flagOption struct {
	name string
}

func (o flagOption) Name() string {
	return o.name
}

func (o flagOption) ToCli() ([]string, error) {
	return []string{"--" + o.name}, nil
}

func (o flagOption) ToConfig() (string, error) {
	return o.name, nil
}

func FromConfig(content string) flagOption {
	return flagOption{name: content}
}
