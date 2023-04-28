// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: AGPL-3.0-only OR MIT
package auth

import (
	"io/ioutil"

	"github.com/pkg/errors"
)

type AuthOption struct {
	username  string
	password  string
	allowFile bool
}

func OptionAuth(username, password string, file bool) *AuthOption {
	return &AuthOption{username: username, password: password, allowFile: file}
}

func (o *AuthOption) ToCli() ([]string, error) {
	if o.allowFile {
		f, err := ioutil.TempFile("", "ovpn-pass-")
		if err != nil {
			return nil, errors.Wrap(err, "cannot create temporary file")
		}
		defer f.Close()
		_, err = f.WriteString(o.username + "\n" + o.password)
		if err != nil {
			return nil, errors.Wrap(err, "cannot write to temporary file")
		}
		return []string{"--auth-user-pass", f.Name()}, nil
	}
	return []string{}, nil
}

func (o *AuthOption) AllowFile() bool {
	return o.allowFile
}

func (o *AuthOption) Username() string {
	return o.username
}

func (o *AuthOption) Password() string {
	return o.password
}
