package auth

import (
	"testing"

	"github.com/buengese/openvpn-go/config/auth"
	"github.com/buengese/openvpn-go/management"
	"github.com/stretchr/testify/assert"
)

func TestConsumeLineSkips(t *testing.T) {
	var tests = []struct {
		line string
	}{
		{">SOME_LINE_DELIVERED"},
		{">ANOTHER_LINE_DELIVERED"},
		{">PASSWORD"},
	}
	middleware := NewMiddleware(auth.OptionAuth("testuser", "testpassword", false))

	for _, test := range tests {
		consumed, err := middleware.ProcessEvent(test.line)
		assert.NoError(t, err, test.line)
		assert.False(t, consumed, test.line)
	}
}

func TestConsumeLineTakes(t *testing.T) {
	passwordRequest := ">PASSWORD:Need 'Auth' username/password"

	middleware := NewMiddleware(auth.OptionAuth("testuser", "testpassword", false))
	mockCmdWriter := &management.MockConnection{}
	middleware.Start(mockCmdWriter)

	consumed, err := middleware.ProcessEvent(passwordRequest)
	assert.NoError(t, err)
	assert.True(t, consumed)
	assert.Equal(t,
		mockCmdWriter.WrittenLines,
		[]string{
			"password 'Auth' testpassword",
			"username 'Auth' testuser",
		},
	)
}
