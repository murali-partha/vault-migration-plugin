// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"fmt"
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
	encryption *EncryptionUtil
	tokens     map[string]bool
}

func main() {

	var err error

	pluginCore, err = initPlugin()

	if err != nil {
		fmt.Println("Error initializing plugin:", err)
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

	count := 3
	tokenMap := make(map[string]bool)

	tempToken := make(map[string]bool)

	filePath := os.Getenv("PLUGIN_OUT_PATH")
	if filePath == "" {
		log.Fatal(errors.New("PLUGIN_OUT_PATH environment variable is not set"))
		return nil, errors.New("PLUGIN_OUT_PATH environment variable is not set")
	}
	f, err := os.Create(filePath)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to create file %s: %w", filePath, err))
		return nil, err
	}

	defer f.Close()

	for count > 0 {
		token := uuid.NewString()
		_, err := f.WriteString(token + "\n")
		if err != nil {
			return nil, err
		}

		tempToken[token] = true

		encryptedToken, err := encryption.Encrypt([]byte(token))

		if err != nil {
			return nil, err
		}

		tokenMap[string(encryptedToken)] = true
		count--
	}

	return &PluginCore{
		encryption: encryption,
		tokens:     tokenMap,
	}, nil
}

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
		RunningVersion: "v0.2.0",
	}

	return &b
}

func (b *backend) pathAuthLogin(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("login requested")

	password := d.Get("password").(string)

	encryptedPassword, _ := pluginCore.encryption.Encrypt([]byte(password))

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
