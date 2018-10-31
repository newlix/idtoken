//go:generate protoc --go_out=. auth.proto
package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	proto "github.com/golang/protobuf/proto"
)

type uidkey struct{}

func UserID(ctx context.Context) string {
	uid, _ := ctx.Value(uidkey{}).(string)
	return uid
}

func Bearer(secret []byte, guest bool, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("Authorization")
		if tok == "" {
			h.ServeHTTP(w, r)
			return
		}
		tok = strings.TrimPrefix(tok, "Bearer ")
		info, err := ParseAccessToken(secret, tok)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if info.IssueUnix > time.Now().Add(-1*time.Hour).Unix() {
			http.Error(w, "token expired", http.StatusBadRequest)
			return
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, uidkey{}, info.UserID)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func NewAccessToken(secret []byte, uid string) (string, error) {
	info := &AccessTokenInfo{
		UserID:    uid,
		IssueUnix: time.Now().Unix(),
	}
	return newToken(secret, info)
}

func NewRefreshToken(secret []byte, uid string) (string, error) {
	info := &RefreshTokenInfo{
		UserID:    uid,
		IssueUnix: time.Now().Unix(),
	}
	return newToken(secret, info)
}

func newToken(secret []byte, info proto.Message) (string, error) {
	b, err := proto.Marshal(info)
	if err != nil {
		return "", err
	}
	cb, err := encrypt(b, secret)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(cb), nil
}

func ParseAccessToken(secret []byte, tok string) (*AccessTokenInfo, error) {
	var info AccessTokenInfo
	if err := parseToken(secret, tok, &info); err != nil {
		return nil, nil
	}
	return &info, nil
}

func ParseRefreshToken(secret []byte, tok string) (*RefreshTokenInfo, error) {
	var info RefreshTokenInfo
	if err := parseToken(secret, tok, &info); err != nil {
		return nil, nil
	}
	return &info, nil
}

func parseToken(secret []byte, tok string, info proto.Message) error {
	cb, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return err
	}
	b, err := decrypt(cb, secret)
	if err != nil {
		return err
	}
	if err := proto.Unmarshal(b, info); err != nil {
		return err
	}
	return nil
}

// https://astaxie.gitbooks.io/build-web-application-with-golang/en/09.6.html
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
