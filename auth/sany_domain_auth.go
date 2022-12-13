package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
)

const publicKeyString = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKuOLE86jgOF9wEtsUyyDKLGHMBP2ois
CkeV2CV496ZDE+yE/Am51Omn+KyBGdgOqTpsdJyOt97IiTO7SKuWMJ8CAwEAAQ==
-----END PUBLIC KEY-----`

func encrypt(plainData []byte) ([]string, error) {
	// 加载公钥
	block, _ := pem.Decode([]byte(publicKeyString))
	if block == nil {
		fmt.Println("pem.Decode err")
		return nil, errors.New("pem.Decode err")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("x509.ParsePKIXPublicKey err")
		return nil, errors.New("x509.ParsePKIXPublicKey err")
	}
	publicKey := pubInterface.(*rsa.PublicKey)
	hash := sha1.New()

	// 按照公钥和哈希大小拆分加密内容
	k := (publicKey.N.BitLen() + 7) / 8
	maxSize := k - 2*hash.Size() - 2 //from rsa.go
	toEncrypt := splitMsg(plainData, maxSize)

	result := make([]string, len(toEncrypt))
	for i, part := range toEncrypt {
		encryptedBytes, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, part, nil)
		if err != nil {
			fmt.Println("rsa.EncryptOAEP err")
		}
		result[i] = base64.StdEncoding.EncodeToString(encryptedBytes)
	}
	return result, nil
}

func splitMsg(msg []byte, maxSize int) [][]byte {
	noParts := len(msg) / maxSize
	if noParts*maxSize < len(msg) {
		noParts += 1
	}

	toEncrypt := make([][]byte, noParts)
	for i := range toEncrypt {
		if len(msg) > maxSize {
			toEncrypt[i] = msg[:maxSize]
			msg = msg[maxSize:]
		} else {
			toEncrypt[i] = msg
		}
	}
	return toEncrypt
}

const userAgent = "OvpnSub/1.0"

type SanyAuthService struct {
	Host string
}

type UserToken struct {
	Status  int    `json:"-"`
	Message string `json:"message"`
	Token   string `json:"token"`
}

func (s *SanyAuthService) Authorize(ctx context.Context, username, password string) (string, error) {
	encrypted, err := encrypt([]byte(fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)))
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(map[string]interface{}{
		"rsa": encrypted,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Host+"/api/v3/login", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("login response status %d", resp.StatusCode)
	}
	token := &UserToken{
		Status: resp.StatusCode,
	}
	err = json.NewDecoder(resp.Body).Decode(token)
	if err != nil {
		return "", err
	}
	if token.Message != "ok" {
		return "", fmt.Errorf("login message %s", token.Message)
	}
	return token.Token, nil
}

type userProfile struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
}

func (s *SanyAuthService) VerifyToken(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Host+"/api/v3/profile", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login response status %d", resp.StatusCode)
	}
	profile := &userProfile{}
	err = json.NewDecoder(resp.Body).Decode(profile)
	return profile.Username, err
}
