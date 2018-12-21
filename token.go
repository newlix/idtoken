package token

import (
	"encoding/base64"
	"errors"

	"time"

	proto "github.com/golang/protobuf/proto"
)

type Type int32

const (
	Access Type = iota
	Refresh
)

func AuthUID(secret []byte, token string) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("missing auth secret")
	}
	if len(token) == 0 {
		return "", nil
	}
	info, err := Parse(secret, token)
	if err != nil {
		return "", err
	}
	if Type(info.Type) != Access {
		return "", errors.New("not access token")
	}
	if info.IssueUnix < time.Now().Add(-1*time.Hour).Unix() {
		return "", errors.New("token expired")
	}
	return info.UserID, nil
}

func New(secret []byte, uid string, t Type) (string, error) {
	info := Info{
		Type:      int32(t),
		UserID:    uid,
		IssueUnix: time.Now().Unix(),
	}
	b, err := proto.Marshal(&info)
	if err != nil {
		return "", err
	}
	cb, err := encrypt(b, secret)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(cb), nil
}

func Parse(secret []byte, tok string) (*Info, error) {
	var info Info
	cb, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return nil, err
	}
	b, err := decrypt(cb, secret)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(b, &info); err != nil {
		return nil, err
	}
	return &info, nil
}
