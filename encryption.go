package main

import (
	"crypto/aes"
	"crypto/cipher"
)

type EncryptionUtil struct {
	key   []byte
	nonce []byte
}

func NewEncryptionStore() *EncryptionUtil {

	key := make([]byte, 32)
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)

	return &EncryptionUtil{
		key:   key,
		nonce: nonce,
	}
}

func (es *EncryptionUtil) Encrypt(data []byte) ([]byte, error) {

	block, err := aes.NewCipher(es.key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, es.nonce, data, nil)
	return ciphertext, nil
}

func (es *EncryptionUtil) Decrypt(data []byte) ([]byte, error) {

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
