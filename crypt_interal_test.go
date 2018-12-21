package token

import (
	"log"
	"math/rand"
	"testing"
	"testing/quick"
)

func randomkey() []byte {
	token := make([]byte, 24)
	_, err := rand.Read(token)
	if err != nil {
		log.Fatal(err)
	}
	return token
}

func TestCrypt(t *testing.T) {
	f := func(x string) bool {
		k := randomkey()
		b, err := encrypt([]byte(x), k)
		if err != nil {
			t.Errorf("error encrypt: %v, x = %q, k = %q", err, x, k)
		}
		y, err := decrypt(b, k)
		if err != nil {
			t.Errorf("error decrypt: %v, x = %q, k = %q", err, x, k)
		}
		return x == string(y)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
