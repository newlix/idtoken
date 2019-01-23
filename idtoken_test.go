package idtoken_test

import (
	"testing"
	"time"

	"github.com/newlix/idtoken"
)

var key = []byte("NcRfTjWnZr4u7x!AAD*G-KaPdSgVkXp2")

func TestOK(t *testing.T) {
	id := "123"
	before := time.Now().Unix()
	tok, err := idtoken.New(key, id)
	if err != nil {
		t.Error(err)
	}
	after := time.Now().Unix()
	tokid, issue, err := idtoken.Parse(key, tok)
	if err != nil {
		t.Error(err)
	}
	if tokid != id {
		t.Errorf("id = %q, want %q", tokid, id)
	}
	if issue < before || issue > after {
		t.Errorf("token is not issued now")
	}
}
