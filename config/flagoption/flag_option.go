// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package flagoption

func New(name string) FlagOption {
	return FlagOption{name: name}
}

type FlagOption struct {
	name string
}

func (o FlagOption) Name() string {
	return o.name
}

func (o FlagOption) Value() string {
	return ""
}

func (o FlagOption) ToLines() (string, error) {
	return o.name, nil
}

func FromConfig(content string) FlagOption {
	return FlagOption{name: content}
}
