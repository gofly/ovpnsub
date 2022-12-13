package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"math/rand"
	"path"
	"sync"
	"time"
)

type LocalSession struct {
	Username string
	Expires  time.Time
}

func (s *LocalSession) Expired() bool {
	return time.Now().After(s.Expires)
}

type LocalAuthService struct {
	AuthEncKey string
	KeysPath   string
	Sessions   map[string]LocalSession
	lock       sync.RWMutex
}

func (s *LocalAuthService) Authorize(ctx context.Context, username, password string) (string, error) {
	pwdPath := path.Join(s.KeysPath, username, "password")
	data, err := ioutil.ReadFile(pwdPath)
	if err != nil {
		return "", err
	}

	expected := make([]byte, hex.DecodedLen(len(data)))
	n, err := hex.Decode(expected, data)
	if err != nil {
		return "", err
	}

	h := hmac.New(sha1.New, []byte(s.AuthEncKey))
	h.Write([]byte(password))
	fact := h.Sum(nil)
	if bytes.Equal(fact, expected[:n]) {
		randBytes := make([]byte, 1024)
		rand.Read(randBytes)
		h.Write(randBytes)
		s.lock.Lock()
		token := string(h.Sum(nil))
		s.Sessions[token] = LocalSession{
			Username: username,
			Expires:  time.Now().Add(time.Second * 10),
		}
		s.lock.Unlock()
		return token, nil
	}
	return "", errors.New("invalid username or password")
}

func (s *LocalAuthService) VerifyToken(ctx context.Context, token string) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	session, ok := s.Sessions[token]
	if !ok {
		return "", errors.New("invalid token")
	}
	delete(s.Sessions, token)
	return session.Username, nil
}
