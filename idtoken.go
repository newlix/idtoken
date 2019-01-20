package idtoken

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"time"

	"github.com/newlix/idtoken/gcm"
)

type payload struct {
	ID    string
	Issue time.Time
}

func New(key []byte, id string, issuce time.Time) (string, error) {
	p := payload{
		ID:    id,
		Issue: issuce,
	}
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	if err := enc.Encode(&p); err != nil {
		return "", err
	}
	cb, err := gcm.Encrypt(key, b.Bytes())
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(cb), nil
}

func Parse(key []byte, s string) (id string, issue time.Time, err error) {
	p := payload{}
	cb, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", time.Time{}, err
	}
	b, err := gcm.Decrypt(key, cb)
	if err != nil {
		return "", time.Time{}, err
	}
	buf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&p); err != nil {
		return "", time.Time{}, err
	}
	return p.ID, p.Issue, err
}
