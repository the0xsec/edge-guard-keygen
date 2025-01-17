package keyGenerator

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

type KeyPair struct {
	ID          string
	Key         []byte
	CreatedTime time.Time
	EncodedKey  string
}

func GenerateKey(keySize int) (*KeyPair, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	id := fmt.Sprintf("KEY_%d", time.Now().Unix())
	id = strings.ToUpper(id)
	encodedKey := base64.StdEncoding.EncodeToString(key)

	return &KeyPair{
		ID:          id,
		Key:         key,
		CreatedTime: time.Now(),
		EncodedKey:  encodedKey,
	}, nil
}
