// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package auth

import (
	"io/ioutil"

	"github.com/pkg/errors"
)

type AuthOption struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	AllowFile bool   `json:"allow_file"`
}

func OptionAuth(username, password string, file bool) *AuthOption {
	return &AuthOption{Username: username, Password: password, AllowFile: file}
}

func (o *AuthOption) ToCli() ([]string, error) {
	if o.AllowFile {
		f, err := ioutil.TempFile("", "ovpn-pass-")
		if err != nil {
			return nil, errors.Wrap(err, "cannot create temporary file")
		}
		defer f.Close()
		_, err = f.WriteString(o.Username + "\n" + o.Password)
		if err != nil {
			return nil, errors.Wrap(err, "cannot write to temporary file")
		}
		return []string{"--auth-user-pass", f.Name()}, nil
	}
	return []string{}, nil
}
