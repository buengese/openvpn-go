// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package auth

import (
	"fmt"
	"os"
)

type Option struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	AllowFile bool   `json:"allow_file"`
}

func OptionAuth(username, password string, file bool) *Option {
	return &Option{Username: username, Password: password, AllowFile: file}
}

func (o *Option) ToCli() ([]string, error) {
	if o.AllowFile {
		f, err := os.CreateTemp("", "ovpn-pass-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary authentication file: %w", err)
		}

		defer f.Close()

		_, err = f.WriteString(o.Username + "\n" + o.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to write credentials to temporary file: %w", err)
		}

		return []string{"--auth-user-pass", f.Name()}, nil
	}

	return []string{}, nil
}
