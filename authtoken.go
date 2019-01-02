package authtoken

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"time"
)

var ErrorTokenExpire = errors.New("token expire")
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
	cb, err := encrypt(buf.Bytes(), secret)
	if err != nil {
		return "", err
	}
	return Encoding.EncodeToString(cb), nil
}

func Parse(secret []byte, life time.Duration, token string) (id string, err error) {
	p := Payload{}
	cb, err := Encoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	b, err := decrypt(cb, secret)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&p); err != nil {
		return "", err
	}
	if p.Issue.Before(time.Now().Add(-life)) {
		return "", ErrorTokenExpire
	}
	return p.ID, nil
}
