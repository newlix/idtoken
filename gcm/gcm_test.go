package gcm_test

import (
	"log"
	"math/rand"
	"testing"
	"testing/quick"
	"time"

	"github.com/newlix/idtoken/gcm"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func key() []byte {
	idtoken := make([]byte, 32)
	_, err := rand.Read(idtoken)
	if err != nil {
		log.Fatal(err)
	}
	return idtoken
}

func TestCrypt(t *testing.T) {
	f := func(x string) bool {
		k := key()
		b, err := gcm.Encrypt(k, []byte(x))
		if err != nil {
			t.Errorf("error encrypt: %v, x = %x, k = %x", err, x, k)
		}
		y, err := gcm.Decrypt(k, b)
		if err != nil {
			t.Errorf("error decrypt: %v, x = %x, k = %x", err, x, k)
		}
		return x == string(y)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
