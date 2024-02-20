# Vault Remote Attestation Plugin using Intel SGX

The plugin enriches the HashiCorp Key and Identity Management to deal with SGX remote attestation. The plug-in implements Intel's DCAP remote attestation protocol. The HahsiCorp Vault can run both enclaved and non-enclaved workloads, enforce access policies, and provision workload with secrets with the addition that now the workload is cryptographically authenticated. By running the HashiCorp Vault in an enclave (see [enclaive-docker-hashicorp-vault repo](https://github.com/enclaive/enclaive-docker-hashicorp-vault-sgx)), secret and identity management is encrypted while in use. (By default, Vault encrypts the communication and the secrets at rest through Shamir's secret sharing.)

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
# Measurement: e211ba4d0a996136d1131f8b837ea20758a396a732f5123d71d22b544f4ff240

make docker/redis
# Measurement: 5cd731b2990478b4542eb9f9f362f3e8de8845fa2e19146737f11ded92298a66

docker push enclaive/sgx-pccs:latest
docker push enclaive/hashicorp-vault-sgx:k8s
docker push enclaive/redis-sgx:k8s

# set APIKEY in pccs.yaml
scp pccs/pccs.yaml vault/vault.yaml apps/redis/redis.yaml k8s-host:

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
./client verify -ref e211ba4d0a996136d1131f8b837ea20758a396a732f5123d71d22b544f4ff240

# vault-cli is now using RA-TLS certificate from enclave

vault operator init -key-shares=1 -key-threshold=1
> Unseal Key 1: NuOdkesZvcOprMJf3ktr6A/kt6RwYBekTgPgx0UW+/w=
> Initial Root Token: hvs.NxFQYAJTnrW2uv1Rrk0F03ar

vault operator unseal
vault login

docker pull enclaive/hashicorp-vault-sgx:k8s
HASH=$(docker run --rm -it --entrypoint sha256sum enclaive/hashicorp-vault-sgx:k8s plugins/vault-plugin-auth-sgx | awk '{print $1}')
vault plugin register -sha256="${HASH}" auth vault-plugin-auth-sgx

# enable plugin and other engines, will create certs (Root-CA, Intermediate-CA, admin.client.deployment.enclaive)
make enable

# register enclave, set measurement in client.sh
make create

fg # ctrl+c kubectl port-forward

kubectl port-forward svc/enclaive-redis-sgx 6379:6379 &

redis-cli --tls --cacert certs/sgx-ca.pem --cert certs/sgx-cert.pem --key certs/sgx-key.pem
```
