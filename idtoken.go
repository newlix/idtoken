package idtoken

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"time"

	"github.com/newlix/idtoken/gcm"
)

type payload struct {
	ID        string
	IssueUnix int64
}

func New(key []byte, id string) (string, error) {
	p := payload{
		ID:        id,
		IssueUnix: time.Now().Unix(),
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

func Parse(key []byte, s string) (id string, issueUnix int64, err error) {
	p := payload{}
	cb, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", 0, err
	}
	b, err := gcm.Decrypt(key, cb)
	if err != nil {
		return "", 0, err
	}
	buf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&p); err != nil {
		return "", 0, err
	}
	return p.ID, p.IssueUnix, err
}
