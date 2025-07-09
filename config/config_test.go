// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package config_test

import (
	"io/ioutil"
	"testing"

	"github.com/buengese/openvpn-go/config"
	"github.com/buengese/openvpn-go/config/file_option"
	"github.com/buengese/openvpn-go/config/flag_option"
	"github.com/buengese/openvpn-go/config/param_option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	caCert = `-----BEGIN CERTIFICATE-----
MIIFTTCCAzWgAwIBAgIJAMs9S3fqwv+mMA0GCSqGSIb3DQEBCwUAMD0xCzAJBgNV
BAYTAlZHMRIwEAYDVQQKDAlTdXJmc2hhcmsxGjAYBgNVBAMMEVN1cmZzaGFyayBS
b290IENBMB4XDTE4MDMxNDA4NTkyM1oXDTI4MDMxMTA4NTkyM1owPTELMAkGA1UE
b3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDEGMNj0aisM63o
SkmVJyZPaYX7aPsZtzsxo6m6p5Wta3MGASoryRsBuRaH6VVa0fwbI1nw5ubyxkua
Na4v3zHVwuSq6F1p8S811+1YP1av+jqDcMyojH0ujZSHIcb/i5LtaHNXBQ3qN48C
c7sqBnTIIFpmb5HthQ/4pW+a82b1guM5dZHsh7q+LKQDIGmvtMtO1+NEnmj81BAp
FayiaD1ggvwDI4x7o/Y3ksfWSCHnqXGyqzSFLh8QuQrTmWUm84YHGFxoI1/8AKdI
yVoB6BjcaMKtKs/pbctk6vkzmYf0XmGovDKPQF6MwUekchLjB5gSBNnptSQ9kNgn
TLqi0OpSwI6ixX52Ksva6UM8P01ZIhWZ6ua/T/tArgODy5JZMW+pQ1A6L0b7egIe
ghpwKnPRG+5CzgO0J5UE6gv000mqbmC3CbiS8xi2xuNgruAyY2hUOoV9/BuBev8t
tE5ZCsJH3YlG6NtbZ9hPc61GiBSx8NJnX5QHyCnfic/X87eST/amZsZCAOJ5v4EP
SaKrItt+HrEFWZQIq4fJmHJNNbYvWzCE08AL+5/6Z+lxb/Bm3dapx2zdit3x2e+m
iGHekuiE8lQWD0rXD4+T+nDRi3X+kyt8Ex/8qRiUfrisrSHFzVMRungIMGdO9O/z
CINFrb7wahm4PqU2f12Z9TRCOTXciQIDAQABo1AwTjAdBgNVHQ4EFgQUYRpbQwyD
ahLMN3F2ony3+UqOYOgwHwYDVR0jBBgwFoAUYRpbQwyDahLMN3F2ony3+UqOYOgw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAn9zV7F/XVnFNZhHFrt0Z
S1Yqz+qM9CojLmiyblMFh0p7t+Hh+VKVgMwrz0LwDH4UsOosXA28eJPmech6/bjf
ymkoXISy/NUSTFpUChGO9RabGGxJsT4dugOw9MPaIVZffny4qYOc/rXDXDSfF2b+
303lLPI43y9qoe0oyZ1vtk/UKG75FkWfFUogGNbpOkuz+et5Y0aIEiyg0yh6/l5Q
5h8+yom0HZnREHhqieGbkaGKLkyu7zQ4D4tRK/mBhd8nv+09GtPEG+D5LPbabFVx
KjBMP4Vp24WuSUOqcGSsURHevawPVBfgmsxf1UCjelaIwngdh6WfNCRXa5QQPQTK
ubQvkvXONCDdhmdXQccnRX1nJWhPYi0onffvjsWUfztRypsKzX4dvM9k7xnIcGSG
EnCC4RCgt1UiZIj7frcCMssbA6vJ9naM0s7JF7N3VKeHJtqe1OCRHMYnWUZt9vrq
X6IoIHlZCoLlv39wFW9QNxelcAOCVbD+19MZ0ZXt7LitjIqe7yF5WxDQN4xru087
FzQ4Hfj7eH1SNLLyKZkA1eecjmRoi/OoqAt7afSnwtQLtMUc2bQDg6rHt5C0e4dC
LqP/9PGZTSJiwmtRHJ/N5qYWIh9ju83APvLm/AGBTR2pXmj9G3KdVOkpIC7L35dI
623cSEC3Q3UZutsEm/UplsM=
-----END CERTIFICATE-----
`

	tlsKey = `-----BEGIN OpenVPN Static key V1-----
b02cb1d7c6fee5d4f89b8de72b51a8d0
c7b282631d6fc19be1df6ebae9e2779e
6d9f097058a31c97f57f0c35526a44ae
09a01d1284b50b954d9246725a1ead1f
f224a102ed9ab3da0152a15525643b2e
ee226c37041dc55539d475183b889a10
e18bb94f079a4a49888da566b9978346
0ece01daaf93548beea6c827d9674897
e7279ff1a19cb092659e8c1860fbad0d
b4ad0ad5732f1af4655dbd66214e552f
04ed8fd0104e1d4bf99c249ac229ce16
9d9ba22068c6c0ab742424760911d463
6aafb4b85f0c952a9ce4275bc821391a
a65fcd0d2394f006e3fba0fd34c4bc4a
b260f4b45dec3285875589c97d3087c9
134d3a3aa2f904512e85aa2dc2202498
-----END OpenVPN Static key V1-----
`
)

var (
	options = []config.ConfigOption{
		flag_option.New("client"),
		param_option.New("dev", "tun"),
		param_option.New("remote", "vpn.example.com", "1443"),
		flag_option.New("nobind"),
		flag_option.New("auth-user-pass"),
		param_option.New("tun-mtu", "1500"),
		flag_option.New("persist-tun"),
		param_option.New("remote-cert-tls", "server"),
		param_option.New("verb", "3"),
		param_option.New("cipher", "AES-256-CBC"),
		param_option.New("auth", "SHA512"),
		param_option.New("pull-filter", "ignore", "\"redirect-gateway ipv6\""),

		file_option.New("ca", caCert),
		param_option.New("key-direction", "1"),
		file_option.New("tls-auth", tlsKey),
	}
)

func TestFromFile(t *testing.T) {
	cfg, err := config.FromFile("testdata/test.ovpn")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	wanted := config.NewConfig()
	wanted.AddOptions(options...)

	assert.ElementsMatch(t, cfg.Options, wanted.Options)

	cli, err := cfg.ToCli()
	require.NoError(t, err)
	require.NotNil(t, cli)
}

func TestToFile(t *testing.T) {
	cfg := config.NewConfig()
	cfg.AddOptions(options...)

	err := cfg.Save("testdata/out.ovpn")
	require.NoError(t, err)
}

func TestToConfig(t *testing.T) {
	cfg, err := config.FromFile("testdata/complex.ovpn")
	require.NoError(t, err)

	_, err = cfg.ToString()
	require.NoError(t, err)
}

func TestToCli(t *testing.T) {
	cfg := config.NewConfig()
	cfg.AddOptions(options...)

	opts, err := cfg.ToCli()
	require.NoError(t, err)
	assert.Contains(t, opts, "--config")
}

func TestToCliComplex(t *testing.T) {
	cfg, err := config.FromFile("testdata/complex.ovpn")
	require.NoError(t, err)
	cfg.AddFlag("route-nopull")

	opts, err := cfg.ToCli()
	require.NoError(t, err)
	assert.Contains(t, opts, "--config")
}

func TestModify(t *testing.T) {
	cfg, err := config.FromFile("testdata/complex.ovpn")
	require.NoError(t, err)

	assert.True(t, cfg.RemoveOption("verb"))
	cfg.AddParam("verb", "3")

	assert.Equal(t, param_option.New("verb", "3"), cfg.GetOption("verb"))
}

func TestStringRoundTrip(t *testing.T) {
	cfg := config.NewConfig()
	cfg.AddOptions(options...)

	s, err := cfg.ToString()
	require.NoError(t, err)
	require.NotEmpty(t, s)

	cfg, err = config.FromString(s)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.ElementsMatch(t, cfg.Options, options)
}

func TestFileRoundTrip(t *testing.T) {
	cfg, err := config.FromFile("testdata/out.ovpn")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	f, err := ioutil.TempFile("", "config-test")
	require.NoError(t, err)
	err = cfg.Save(f.Name())
	require.NoError(t, err)

	// compare files
	original, err := ioutil.ReadFile("testdata/out.ovpn")
	require.NoError(t, err)
	roundtrip, err := ioutil.ReadFile(f.Name())
	require.NoError(t, err)

	assert.Equal(t, original, roundtrip)
}

func TestGetters(t *testing.T) {
	cfg := config.NewConfig()
	cfg.AddOptions(options...)

	assert.Equal(t, config.TCP, cfg.GetProto())
	host, port := cfg.GetRemote()
	assert.Equal(t, "vpn.example.com", host)
	assert.Equal(t, 1443, port)
}

func TestSetMethodsReplace(t *testing.T) {
	cfg := config.NewConfig()

	// Test SetPort replaces existing port options
	cfg.SetPort(1194)
	cfg.SetPort(443)
	portOptions := cfg.GetOptions("port")
	assert.Len(t, portOptions, 1, "Should have only one port option")
	assert.Equal(t, "443", portOptions[0].Value())

	// Test SetDevice replaces existing device options
	cfg.SetDevice("tun0")
	cfg.SetDevice("tap0")
	devOptions := cfg.GetOptions("dev")
	assert.Len(t, devOptions, 1, "Should have only one device option")
	assert.Equal(t, "tap0", devOptions[0].Value())

	// Test SetProto replaces existing proto options
	cfg.SetProto(config.UDP)
	cfg.SetProto(config.TCP)
	protoOptions := cfg.GetOptions("proto")
	assert.Len(t, protoOptions, 1, "Should have only one proto option")
	assert.Equal(t, "tcp", protoOptions[0].Value())

	// Test that adding the same option multiple times only results in one option
	cfg.AddParam("test", "value1")
	cfg.AddParam("test", "value2")
	testOptions := cfg.GetOptions("test")
	assert.Len(t, testOptions, 2, "AddParam should add multiple options")
}
