# Vault SGX Plugin

Login to vault using SGX attestation.

## Usage

Read the `Makefile` and `client.sh` to understand the usage. Here's the quickstart:

```bash
# Build plugin 
make

export ENCLAIVE_DEPLOYMENT=$(cat deployment.uuid)

# start Vault dev server with plugin automatically registered
make start
```

Now open a new terminal window and run the following commands:

```bash
# Enable the plugin
make enable

# Create a new enclave with a policy and secrets
make create

# Login using an attestation
make login
```

If not using dev-mode:

```bash
ADDRESS=127.0.0.1:8200
export VAULT_CACERT="certs/attest.pem"
export VAULT_ADDR="https://${ADDRESS}"

openssl s_client -showcerts -connect "${ADDRESS}" </dev/null 2>/dev/null \
  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' \
  > "${VAULT_CACERT}"

HASH=$(sha256sum vault/plugins/vault-plugin-auth-sgx | awk '{print $1}')

vault login
vault plugin register -sha256="${HASH}" auth vault-plugin-auth-sgx

make enable

curl --cacert "${VAULT_CACERT}" https://127.0.0.1:8200/v1/auth/sgx-auth/attest
#TODO verify quote from /attest
```