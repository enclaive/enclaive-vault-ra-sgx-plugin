GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

EC_ADDRESS = https://127.0.0.1:8200
EC_TYPE = debug
EC_MRENCLAVE = 123123123123
EC_ATTESTATION = yolo
EC_SECRET = '{"environment": {"VAULT": "1"}, "files": {"/tmp/debug.txt":"aGVsbG8K"}, "argv": []}'

.DEFAULT_GOAL := all

all: fmt build start

create:
	vault write \
		-ca-cert=certs/vault-ca.pem \
		-client-key=certs/vault-key.pem \
		-client-cert=certs/vault-cert.pem \
		-format=json \
		-address=$(EC_ADDRESS) \
		auth/sgx-auth/enclave/$(EC_TYPE) mrenclave=$(EC_MRENCLAVE)
	vault kv put \
		-ca-cert=certs/vault-ca.pem \
		-client-key=certs/vault-key.pem \
		-client-cert=certs/vault-cert.pem \
		-format=json \
		-address=$(EC_ADDRESS) \
		secret/sgx/$(EC_TYPE) provision=$(EC_SECRET)
	cat vault.sgx.policy.template | \
		env -i ENCLAIVE_TYPE=$(EC_TYPE) envsubst | \
		vault policy write \
		-ca-cert=certs/vault-ca.pem \
		-client-key=certs/vault-key.pem \
		-client-cert=certs/vault-cert.pem \
		-address=$(EC_ADDRESS) \
		sgx/$(EC_TYPE) -

login:
	vault write \
		-ca-cert=certs/vault-ca.pem \
		-client-key=certs/vault-key.pem \
		-client-cert=certs/vault-cert.pem \
		-format=json \
		-address=$(EC_ADDRESS) \
		auth/sgx-auth/login id=$(EC_TYPE) attestation=$(EC_ATTESTATION)

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-auth-sgx cmd/vault-plugin-auth-sgx/main.go

start:
	mkdir -p certs
	vault server -dev -dev-tls -dev-tls-cert-dir=certs -dev-listen-address=0.0.0.0:8200 -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault auth enable \
		-ca-cert=certs/vault-ca.pem \
		-client-key=certs/vault-key.pem \
		-client-cert=certs/vault-cert.pem \
		-address=$(EC_ADDRESS) \
		-path=sgx-auth vault-plugin-auth-sgx

clean:
	rm -f ./vault/plugins/vault-plugin-auth-sgx

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
