# Vault SGX Plugin

Login to vault using SGX attestation.

## Usage

Read the `Makefile` and `client.sh` to understand the usage. Here's the quickstart:

```bash
# Build plugin 
make

export ENCLAIVE_NAMESPACE="default"

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

## SGX Deployment

If using k8s:

```bash
make pccs

make vault
# Measurement: d5b93e4c47c4ad5e5c65ebe9fc2fc1383ee7d07152c6c70de85d2981bf83144e

make docker/redis
# Measurement: 5cd731b2990478b4542eb9f9f362f3e8de8845fa2e19146737f11ded92298a66

docker push enclaive/sgx-pccs:latest
docker push enclaive/hashicorp-vault-sgx:k8s
docker push enclaive/redis-sgx:k8s

# set APIKEY in pccs.yaml
scp pccs/pccs.yaml vault/vault.yaml apps/redis/redis.yaml apps/redis/redis-cli.yaml k8s-host:

export ENCLAIVE_NAMESPACE="default"
export VAULT_CACERT="certs/attest.pem"
export VAULT_ADDR="https://127.0.0.1:8200"

kubectl apply -f ./pccs.yaml
kubectl apply -f ./redis.yaml
kubectl get pods # Status: Init:0/1
kubectl apply -f ./vault.yaml

mkdir -p certs
kubectl port-forward svc/enclaive-vault-sgx 8200:8200 &

make client

# verify attestation, will request VAULT_ADDR/premain/attest and write cert to VAULT_CACERT
./client verify -ref d5b93e4c47c4ad5e5c65ebe9fc2fc1383ee7d07152c6c70de85d2981bf83144e

# vault-cli is now using RA-TLS certificate from enclave

# if using local vault binary
export PATH="${PATH}:${PWD}"

vault operator init -key-shares=1 -key-threshold=1
> Unseal Key 1: 5dpPMXx7ce4CadUYCxsCax3urT5r7wApoClajs+2/LA=
> Initial Root Token: hvs.XlG6nCfIr5YT5or03tYXpRiG

vault operator unseal
vault login

vault plugin register -sha256="f4a2ad37c5177baaaf8559a80a2edca3e158c1b9161e1274e7289e6628d1745e" auth vault-plugin-auth-sgx

# enable plugin and other engines, will create certs (Root-CA, Intermediate-CA, admin.client.deployment.enclaive)
./client.sh enable

# register enclave, set measurement in client.sh
./client.sh create

fg # ctrl+c kubectl port-forward

kubectl apply -f ./redis-cli.yaml
kubectl cp certs/ enclaive-redis-cli:/data/
kubectl exec -it enclaive-redis-cli -- bash
redis-cli -h enclaive-redis-sgx --tls --cacert certs/sgx-ca.pem --cert certs/sgx-cert.pem --key certs/sgx-key.pem
```