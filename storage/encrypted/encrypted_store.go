package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/google/uuid"
)

type EncryptionStore struct {
	key   []byte
	nonce []byte
}

func NewEncryptionStore() *EncryptionStore {

	key := []byte(uuid.NewString())
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)

	return &EncryptionStore{
		key:   key,
		nonce: nonce,
	}
}

func (es *EncryptionStore) Encrypt(ctx context.Context, data []byte) ([]byte, error) {

	block, err := aes.NewCipher(es.key)
	if err != nil {
		panic(err.Error())
	}

	if _, err := io.ReadFull(rand.Reader, es.nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, es.nonce, data, nil)
	return ciphertext, nil
}

func (es *EncryptionStore) Decrypt(ctx context.Context, data []byte) ([]byte, error) {

	block, err := aes.NewCipher(es.key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, es.nonce, data, nil)
	if err != nil {
		panic(err.Error())
	}

	return plaintext, nil
}
