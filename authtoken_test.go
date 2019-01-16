package authtoken_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/newlix/authtoken"
	"github.com/stretchr/testify/assert"
)

var secret = []byte("NcRfTjWnZr4u7x!AAD*G-KaPdSgVkXp2")

func TestConstants(t *testing.T) {
	assert.Equal(t, authtoken.Encoding, base64.RawURLEncoding)
}

func TestOK(t *testing.T) {
	id := "123"
	token, err := authtoken.New(secret, id)
	if err != nil {
		t.Error(err)
	}
	if len(token) == 0 {
		t.Errorf("error new: token = %q", token)
	}
	got, err := authtoken.Parse(secret, token, 1*time.Minute)
	if err != nil {
		t.Error(err)
	}
	if id != got {
		t.Errorf("got = %q,want %q", got, id)
	}
}

func TestInvalidID(t *testing.T) {
	id := ""
	_, err := authtoken.New(secret, id)
	if err.Error() != "invalid id" {
		t.Errorf("err = %v, want invalid id", err)
	}
}

func TestIssueExpire(t *testing.T) {
	id := "123"
	token, err := authtoken.New(secret, id)
	if err != nil {
		t.Error(err)
	}
	prefix := "token expired on "
	_, err = authtoken.Parse(secret, token, 0*time.Minute)
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("err = %v, want prefix %q", err, prefix)
	}
}
