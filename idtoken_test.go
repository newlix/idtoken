package idtoken_test

import (
	"testing"
	"time"

	"github.com/newlix/idtoken"
)

var key = []byte("NcRfTjWnZr4u7x!AAD*G-KaPdSgVkXp2")

func TestOK(t *testing.T) {
	id := "123"
	issue := time.Unix(123, 10)
	tok, err := idtoken.New(key, id, issue)
	if err != nil {
		t.Error(err)
	}
	gotid, gotissue, err := idtoken.Parse(key, tok)
	if err != nil {
		t.Error(err)
	}
	if gotid != id {
		t.Errorf("got id = %q, want %q", gotid, id)
	}
	if gotissue != issue {
		t.Errorf("got issue = %q, want %q", gotissue, issue)
	}
}
