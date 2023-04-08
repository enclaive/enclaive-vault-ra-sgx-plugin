# Vault SGX Plugin

Login to vault using SGX attestation.

## Usage

Read the `Makefile` and `client.sh` to understand the usage. Here's the quickstart:

```bash
# Build plugin 
make

export ENCLAIVE_DEPLOYMENT=$(cat deployment.id)

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
make enclave

# will output measurement, but can (insecurely) be retrieved later

export ENCLAIVE_PCCS="https://global.acccache.azure.net"
export ENCLAIVE_DEPLOYMENT=$(cat deployment.id)

docker-compose -f vault/docker-compose.yml up -d -t 0

export VAULT_CACERT="certs/attest.pem"
export VAULT_ADDR="https://127.0.0.1:8200"

# get measurement for vault-sgx
docker-compose -f vault/docker-compose.yml exec -T vault cat vault.sig | xxd -s 0x3c0 -l 32 -p -c 32
# verify attestation, will request VAULT_ADDR/premain/attest and write cert to VAULT_CACERT
./client verify -ref 57dfc81bfee343f41b4d425ade15b9a910aec222a519291614c02d8db78a30cb

# vault-cli is now using RA-TLS certificate from enclave

# skip if second start
vault operator init -key-shares=1 -key-threshold=1
> Unseal Key 1: xj2wEpBrin8MhVF3uZ3DqjhGjuI9hhp2lIQlwQtdY24=
> Initial Root Token: hvs.RuBvon6HxTDWxMWbgJeV9CGg

vault operator unseal
vault login

# re-register
vault auth disable sgx-auth
vault plugin deregister sgx-auth

# only if not registered yet
HASH=$(sha256sum vault/plugins/vault-plugin-auth-sgx | awk '{print $1}')
vault plugin register -sha256="${HASH}" auth vault-plugin-auth-sgx

# enable plugin and other engines
make enable

# create entry for enclave
make create
```