package authtoken_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/newlix/authtoken"
	"github.com/stretchr/testify/assert"
)

var secret = []byte("NcRfTjWnZr4u7x!AAD*G-KaPdSgVkXp2")

func TestConstants(t *testing.T) {
	assert.Equal(t, authtoken.ErrorTokenExpire.Error(), "token expire")
	assert.Equal(t, authtoken.Encoding, base64.RawURLEncoding)
}

func TestValid(t *testing.T) {
	id := "123"
	s, err := authtoken.New(secret, id)
	assert.NoError(t, err)
	assert.NotEqual(t, 0, len(s))
	got, err := authtoken.Parse(secret, 1*time.Minute, s)
	assert.NoError(t, err)
	assert.Equal(t, id, got)
}

func TestInvalid(t *testing.T) {
	id := ""
	_, err := authtoken.New(secret, id)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid id")
}
