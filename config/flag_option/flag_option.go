// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package flag_option

func New(name string) flagOption {
	return flagOption{name: name}
}

type flagOption struct {
	name string
}

func (o flagOption) Name() string {
	return o.name
}

func (o flagOption) Value() string {
	return ""
}

func (o flagOption) ToLines() (string, error) {
	return o.name, nil
}

func FromConfig(content string) flagOption {
	return flagOption{name: content}
}
