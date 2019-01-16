package authtoken

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"time"

	"github.com/newlix/authtoken/gcm"
)

var ErrorInvalidID = errors.New("invalid id")

var Encoding = base64.RawURLEncoding

type Payload struct {
	ID    string
	Issue time.Time
}

func New(secret []byte, id string) (token string, err error) {
	if id == "" {
		return "", ErrorInvalidID
	}
	p := Payload{
		ID:    id,
		Issue: time.Now().UTC(),
	}
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(&p); err != nil {
		return "", err
	}
	cb, err := gcm.Encrypt(buf.Bytes(), secret)
	if err != nil {
		return "", err
	}
	return Encoding.EncodeToString(cb), nil
}

func Parse(secret []byte, token string, life time.Duration) (id string, err error) {
	p := Payload{}
	cb, err := Encoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	b, err := gcm.Decrypt(cb, secret)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&p); err != nil {
		return "", err
	}
	expire := p.Issue.Add(life)
	if expire.Before(time.Now()) {
		return "", fmt.Errorf("token expired on %v", expire)
	}
	return p.ID, nil
}
