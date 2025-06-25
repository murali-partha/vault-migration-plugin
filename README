# Migration Auth Plugin for HashiCorp Vault

This repository contains the code for a HashiCorp Vault Auth Plugin. This is a POC for plugin based approach to faciliate migration of a SM cluster to a HVD cluster.


## Setup

You must have a Vault server already running, unsealed, and
authenticated.

1. Build the plugin by navigating to the plugin's root directory and running `go build`. 

2. Move the compiled plugin into Vault's configured `plugin_directory`:

    ```sh
    $ mv vault-migration-plugin /etc/vault/plugins/vault-migration-plugin
    ```

3. Set the environment variable `PLUGIN_OUT_PATH` with the path to a file where you would want the plugin to output the generated tokens.

4. Create a policy named `msp-policy` on the Vault cluster. The Vault tokens that are generated upon succesful authentication with the plugin will inherit these permissions.

3. Calculate the SHA256 of the plugin and register it in Vault's plugin catalog.

    ```sh
    $ export SHA256=$(shasum -a 256 "/etc/vault/plugins/vault-migration-plugin" | cut -d' ' -f1)

    $ vault plugin register \
        -sha256="${SHA256}" \
        -command="vault-migration-plugin" \
        auth vault-migration-plugin
    ```

4. Mount the auth method:

    ```sh
    $ vault auth enable \
        -path="migration" \
        -plugin-name="vault-migration-plugin" plugin
    ```

## Authenticating with the generated token

To authenticate, the user supplies the generated token:

```sh
$ vault write auth/migration/login password="<generated-token>"
```

The response will be a standard auth response with some token metadata:

```text
Key             	Value
---             	-----
token           	b62420a6-ee83-22a4-7a15-a908af658c9f
token_accessor  	9eff2c4e-e321-3903-413e-a5084abb631e
token_duration  	30s
token_renewable 	true
token_policies  	[default msp-policy]
```
