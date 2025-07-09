// Copyright 2023 Sebastian Bünger
// SPDX-License-Identifier: MIT
package config_test

import (
	"os"
	"testing"

	"github.com/buengese/openvpn-go/config"
	"github.com/buengese/openvpn-go/config/fileoption"
	"github.com/buengese/openvpn-go/config/flagoption"
	"github.com/buengese/openvpn-go/config/paramoption"
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
	options = []config.Option{
		flagoption.New("client"),
		paramoption.New("dev", "tun"),
		paramoption.New("remote", "vpn.example.com", "1443"),
		flagoption.New("nobind"),
		flagoption.New("auth-user-pass"),
		paramoption.New("tun-mtu", "1500"),
		flagoption.New("persist-tun"),
		paramoption.New("remote-cert-tls", "server"),
		paramoption.New("verb", "3"),
		paramoption.New("cipher", "AES-256-CBC"),
		paramoption.New("auth", "SHA512"),
		paramoption.New("pull-filter", "ignore", "\"redirect-gateway ipv6\""),

		fileoption.New("ca", caCert),
		paramoption.New("key-direction", "1"),
		fileoption.New("tls-auth", tlsKey),
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

	assert.Equal(t, paramoption.New("verb", "3"), cfg.GetOption("verb"))
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

	f, err := os.CreateTemp("", "config-test")
	require.NoError(t, err)
	err = cfg.Save(f.Name())
	require.NoError(t, err)

	// compare files
	original, err := os.ReadFile("testdata/out.ovpn")
	require.NoError(t, err)
	roundtrip, err := os.ReadFile(f.Name())
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

func TestGetTLSCaCert(t *testing.T) {
	cfg := config.NewConfig()

	// Test no CA certificate set
	_, err := cfg.GetTLSCaCert()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no CA certificate set")

	// Test with valid CA certificate
	caCert := fileoption.New("ca", caCert)
	cfg.AddOptions(caCert)
	retrievedCaCert, err := cfg.GetTLSCaCert()
	require.NoError(t, err)
	assert.Equal(t, caCert, retrievedCaCert)

	// Test multiple CA certificates (should error)
	cfg.AddOptions(fileoption.New("ca", "another-cert"))
	_, err = cfg.GetTLSCaCert()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple CA certificates set")

	// Test with non-file option
	cfg2 := config.NewConfig()
	cfg2.AddOptions(paramoption.New("ca", "not-a-file"))
	_, err = cfg2.GetTLSCaCert()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA option is not a file option")
}

func TestGetTLSClientCert(t *testing.T) {
	cfg := config.NewConfig()

	// Test no client certificate set
	_, err := cfg.GetTLSClientCert()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no client certificate set")

	// Test with valid client certificate
	clientCert := fileoption.New("cert", "client-cert-content")
	cfg.AddOptions(clientCert)
	retrievedClientCert, err := cfg.GetTLSClientCert()
	require.NoError(t, err)
	assert.Equal(t, clientCert, retrievedClientCert)

	// Test multiple client certificates (should error)
	cfg.AddOptions(fileoption.New("cert", "another-cert"))
	_, err = cfg.GetTLSClientCert()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple client certificates set")

	// Test with non-file option
	cfg2 := config.NewConfig()
	cfg2.AddOptions(paramoption.New("cert", "not-a-file"))
	_, err = cfg2.GetTLSClientCert()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client certificate option is not a file option")
}

func TestGetTLSPrivateKey(t *testing.T) {
	cfg := config.NewConfig()

	// Test no private key set
	_, err := cfg.GetTLSPrivateKey()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no client private key set")

	// Test with valid private key
	privateKey := fileoption.New("key", "private-key-content")
	cfg.AddOptions(privateKey)
	retrievedPrivateKey, err := cfg.GetTLSPrivateKey()
	require.NoError(t, err)
	assert.Equal(t, privateKey, retrievedPrivateKey)

	// Test multiple private keys (should error)
	cfg.AddOptions(fileoption.New("key", "another-key"))
	_, err = cfg.GetTLSPrivateKey()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple client private keys set")

	// Test with non-file option
	cfg2 := config.NewConfig()
	cfg2.AddOptions(paramoption.New("key", "not-a-file"))
	_, err = cfg2.GetTLSPrivateKey()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client private key option is not a file option")
}

func TestGetTLSCrypt(t *testing.T) {
	cfg := config.NewConfig()

	// Test no tls-crypt key set
	_, err := cfg.GetTLSCrypt()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no tls-crypt key set")

	// Test with valid tls-crypt key
	tlsCrypt := fileoption.New("tls-crypt", tlsKey)
	cfg.AddOptions(tlsCrypt)
	retrievedTLSCrypt, err := cfg.GetTLSCrypt()
	require.NoError(t, err)
	assert.Equal(t, tlsCrypt, retrievedTLSCrypt)

	// Test multiple tls-crypt keys (should error)
	cfg.AddOptions(fileoption.New("tls-crypt", "another-key"))
	_, err = cfg.GetTLSCrypt()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple tls-crypt keys set")

	// Test with non-file option
	cfg2 := config.NewConfig()
	cfg2.AddOptions(paramoption.New("tls-crypt", "not-a-file"))
	_, err = cfg2.GetTLSCrypt()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tls-crypt option is not a file option")
}

func TestGetPort(t *testing.T) {
	cfg := config.NewConfig()

	// Test no port set (should return 0)
	port := cfg.GetPort()
	assert.Equal(t, 0, port)

	// Test with valid port
	cfg.AddOptions(paramoption.New("port", "1194"))
	port = cfg.GetPort()
	assert.Equal(t, 1194, port)

	// Test with invalid port (should return 0)
	cfg2 := config.NewConfig()
	cfg2.AddOptions(paramoption.New("port", "invalid"))
	port = cfg2.GetPort()
	assert.Equal(t, 0, port)

	// Test with empty port value
	cfg3 := config.NewConfig()
	cfg3.AddOptions(paramoption.New("port", ""))
	port = cfg3.GetPort()
	assert.Equal(t, 0, port)
}

func TestGetProtoExtended(t *testing.T) {
	tests := []struct {
		name     string
		proto    string
		expected config.NetProtocol
	}{
		{"tcp", "tcp", config.TCP},
		{"tcp4", "tcp4", config.TCP},
		{"tcp6", "tcp6", config.TCP},
		{"udp", "udp", config.UDP},
		{"udp4", "udp4", config.UDP},
		{"udp6", "udp6", config.UDP},
		{"invalid", "invalid", config.TCP},
		{"empty", "", config.TCP},
		{"mixed-case", "TCP", config.TCP},
		{"mixed-case-udp", "UDP", config.UDP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewConfig()
			if tt.proto != "" {
				cfg.AddOptions(paramoption.New("proto", tt.proto))
			}

			result := cfg.GetProto()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRemoteExtended(t *testing.T) {
	tests := []struct {
		name         string
		remote       string
		expectedHost string
		expectedPort int
	}{
		{"host-only", "vpn.example.com", "vpn.example.com", 0},
		{"host-and-port", "vpn.example.com 1443", "vpn.example.com", 1443},
		{"invalid-too-many-parts", "vpn.example.com 1443 tcp extra", "", 0},
		{"invalid-port", "vpn.example.com invalid-port", "", 0},
		{"empty", "", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewConfig()
			if tt.remote != "" {
				cfg.AddOptions(paramoption.New("remote", tt.remote))
			}

			host, port := cfg.GetRemote()
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

func TestGetEndpoints(t *testing.T) {
	cfg := config.NewConfig()

	// Test with no remotes
	endpoints := cfg.GetEndpoints()
	assert.Empty(t, endpoints)

	// Test with single remote (host only)
	cfg.AddOptions(paramoption.New("remote", "vpn1.example.com"))
	cfg.AddOptions(paramoption.New("port", "1194"))
	cfg.AddOptions(paramoption.New("proto", "udp"))
	endpoints = cfg.GetEndpoints()
	require.Len(t, endpoints, 1)
	assert.Equal(t, "vpn1.example.com", endpoints[0].Host)
	assert.Equal(t, 1194, endpoints[0].Port)
	assert.Equal(t, config.UDP, endpoints[0].Proto)

	// Test with multiple remotes with different configurations
	cfg2 := config.NewConfig()
	cfg2.AddOptions(paramoption.New("remote", "vpn1.example.com"))
	cfg2.AddOptions(paramoption.New("remote", "vpn2.example.com 443"))
	cfg2.AddOptions(paramoption.New("remote", "vpn3.example.com 1194 tcp-client"))
	cfg2.AddOptions(paramoption.New("remote", "vpn4.example.com 22 udp-client"))
	cfg2.AddOptions(paramoption.New("port", "1194"))
	cfg2.AddOptions(paramoption.New("proto", "tcp"))

	endpoints = cfg2.GetEndpoints()
	require.Len(t, endpoints, 4)

	// First remote: uses global port and proto
	assert.Equal(t, "vpn1.example.com", endpoints[0].Host)
	assert.Equal(t, 1194, endpoints[0].Port)
	assert.Equal(t, config.TCP, endpoints[0].Proto)

	// Second remote: overrides port but uses global proto
	assert.Equal(t, "vpn2.example.com", endpoints[1].Host)
	assert.Equal(t, 443, endpoints[1].Port)
	assert.Equal(t, config.TCP, endpoints[1].Proto)

	// Third remote: overrides both port and proto
	assert.Equal(t, "vpn3.example.com", endpoints[2].Host)
	assert.Equal(t, 1194, endpoints[2].Port)
	assert.Equal(t, config.TCP, endpoints[2].Proto)

	// Fourth remote: overrides both port and proto (UDP)
	assert.Equal(t, "vpn4.example.com", endpoints[3].Host)
	assert.Equal(t, 22, endpoints[3].Port)
	assert.Equal(t, config.UDP, endpoints[3].Proto)

	// Test with invalid remotes (should be skipped)
	cfg3 := config.NewConfig()
	cfg3.AddOptions(paramoption.New("remote", "valid.example.com"))
	cfg3.AddOptions(paramoption.New("remote", "invalid.example.com invalid-port"))
	cfg3.AddOptions(paramoption.New("remote", "too many parts in this remote"))
	endpoints = cfg3.GetEndpoints()
	require.Len(t, endpoints, 1)
	assert.Equal(t, "valid.example.com", endpoints[0].Host)
}

func TestGetOptionAndGetOptions(t *testing.T) {
	cfg := config.NewConfig()

	// Test GetOption with no options
	opt := cfg.GetOption("nonexistent")
	assert.Nil(t, opt)

	// Test GetOptions with no options
	opts := cfg.GetOptions("nonexistent")
	assert.Empty(t, opts)

	// Add some options
	cfg.AddOptions(
		paramoption.New("verb", "3"),
		paramoption.New("remote", "vpn1.example.com"),
		paramoption.New("remote", "vpn2.example.com"),
		flagoption.New("client"),
	)

	// Test GetOption returns first match
	verbOpt := cfg.GetOption("verb")
	require.NotNil(t, verbOpt)
	assert.Equal(t, "verb", verbOpt.Name())
	assert.Equal(t, "3", verbOpt.Value())

	// Test GetOption with flag option
	clientOpt := cfg.GetOption("client")
	require.NotNil(t, clientOpt)
	assert.Equal(t, "client", clientOpt.Name())

	// Test GetOptions returns all matches
	remoteOpts := cfg.GetOptions("remote")
	require.Len(t, remoteOpts, 2)
	assert.Equal(t, "remote", remoteOpts[0].Name())
	assert.Equal(t, "remote", remoteOpts[1].Name())

	// Test GetOptions with single match
	verbOpts := cfg.GetOptions("verb")
	require.Len(t, verbOpts, 1)
	assert.Equal(t, "verb", verbOpts[0].Name())
	assert.Equal(t, "3", verbOpts[0].Value())
}
