// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

var pluginCore = &PluginCore{
	tokens: map[string]bool{"msp-token": true},
}

type PluginCore struct {
	encryption *EncryptionStore
	tokens     map[string]bool
}

func main() {

	var err error

	fmt.Println("Initializing Vault Auth Plugin...")

	pluginCore, err = initPlugin()

	if err != nil {
		fmt.Println("Error initializing plugin core:", err)
		os.Exit(1)
	}

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()

	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		// set the TLSProviderFunc so that the plugin maintains backwards
		// compatibility with Vault versions that don’t support plugin AutoMTLS
		TLSProviderFunc: tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}

func initPlugin() (*PluginCore, error) {

	encryption := NewEncryptionStore()

	fmt.Println("Generating plugin config...")

	count := 3
	tokenMap := make(map[string]bool)

	filePath := os.Getenv("PLUGIN_CONFIG_PATH")
	if filePath == "" {
		return nil, errors.New("PLUGIN_CONFIG_PATH environment variable is not set")
	}
	f, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	fmt.Println("Creating plugin config file at:", filePath)

	for count > 0 {
		token := uuid.NewString()
		_, err := f.WriteString(token + "\n")
		if err != nil {
			return nil, err
		}

		fmt.Println("Generated token:", token)

		encryptedToken, err := encryption.Encrypt([]byte(token))

		fmt.Println("Encrypted token:", string(encryptedToken))

		tokenMap[string(encryptedToken)] = true
		count--
	}

	return &PluginCore{
		encryption: encryption,
		tokens:     tokenMap,
	}, nil
}

// func generatePluginConfig() (*PluginConfig, error) {

// 	count := 3
// 	tokenMap := make(map[string]bool)

// 	filePath := os.Getenv("PLUGIN_CONFIG_PATH")
// 	if filePath == "" {
// 		return nil, errors.New("PLUGIN_CONFIG_PATH environment variable is not set")
// 	}
// 	f, err := os.Create(filePath)
// 	if err != nil {
// 		return nil, err
// 	}

// 	defer f.Close()

// 	for count > 0 {
// 		token := uuid.NewString()
// 		tokenMap[token] = true
// 		_, err := f.WriteString(token + "\n")
// 		if err != nil {
// 			return nil, err
// 		}
// 	}

// 	return &PluginConfig{
// 		tokens: tokenMap,
// 	}, nil

// }

// func readPluginConfig() (*PluginConfig, error) {

// 	filePath := os.Getenv("PLUGIN_CONFIG_PATH")
// 	if filePath == "" {
// 		return nil, errors.New("PLUGIN_CONFIG_PATH environment variable is not set")
// 	}

// 	viper.SetConfigFile(filePath)
// 	viper.SetConfigType("json")
// 	if err := viper.ReadInConfig(); err != nil {
// 		return nil, err
// 	}

// 	tokenList := viper.GetStringSlice("tokens")
// 	tokenMap := make(map[string]bool, len(tokenList))
// 	for _, token := range tokenList {
// 		tokenMap[token] = true
// 	}
// 	return &PluginConfig{
// 		tokens: tokenMap,
// 	}, nil
// }

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}

func Backend(c *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
		Paths: []*framework.Path{
			{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"password": {
						Type: framework.TypeString,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthLogin,
				},
			},
		},
		RunningVersion: "v1.0.0",
	}

	return &b
}

func (b *backend) pathAuthLogin(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("login requested")

	password := d.Get("password").(string)

	f, err := os.Create("/Users/muraliparthasarathy/work/projects/vault-auth-plugin-example/cmd/vault-auth-plugin-example/plugin.log")

	if err != nil {
		b.Logger().Error("failed to create log file", "err", err)
		return nil, err
	}

	f.WriteString("checking password: " + password + "\n")
	f.WriteString("plugin config tokens: " + fmt.Sprintf("%v", pluginCore.tokens) + "\n")

	encryptedPassword, err := pluginCore.encryption.Encrypt([]byte(password))

	f.WriteString("plugin config encrypted tokens: " + string(encryptedPassword) + "\n")

	if !pluginCore.tokens[string(encryptedPassword)] {
		b.Logger().Error("login failed", "err", logical.ErrPermissionDenied.Error())
		return nil, logical.ErrPermissionDenied
	}

	b.Logger().Trace("login succeeded")

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"secret_value": "abcd1234",
			},
			Policies: []string{"msp-policy"},
			Metadata: map[string]string{
				"fruit": "banana",
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       30 * time.Second,
				MaxTTL:    60 * time.Minute,
				Renewable: true,
			},
		},
	}, nil
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("auth renew requested")
	if req.Auth == nil {
		b.Logger().Error("login failed")
		return nil, errors.New("request auth was nil")
	}

	b.Logger().Trace("auth renew succeeded")

	secretValue := req.Auth.InternalData["secret_value"].(string)
	if secretValue != "abcd1234" {
		return nil, errors.New("internal data does not match")
	}

	return framework.LeaseExtend(30*time.Second, 60*time.Minute, b.System())(ctx, req, d)
}

type EncryptionStore struct {
	key   []byte
	nonce []byte
}

func NewEncryptionStore() *EncryptionStore {

	key := make([]byte, 32)
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)

	return &EncryptionStore{
		key:   key,
		nonce: nonce,
	}
}

func (es *EncryptionStore) Encrypt(data []byte) ([]byte, error) {

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

func (es *EncryptionStore) Decrypt(data []byte) ([]byte, error) {

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
