GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

create:
	vault write \
		-ca-cert=certs/vault-ca.pem \
		-client-key=certs/vault-key.pem \
		-client-cert=certs/vault-cert.pem \
		-format=json \
		-address=https://127.0.0.1:8200 \
		auth/sgx-auth/enclave/123 mrenclave=123123123123

login:
	vault write \
		-ca-cert=certs/vault-ca.pem \
		-client-key=certs/vault-key.pem \
		-client-cert=certs/vault-cert.pem \
		-format=json \
		-address=https://127.0.0.1:8200 \
		auth/sgx-auth/login id=123 attestation=yolo

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-auth-sgx cmd/vault-plugin-auth-sgx/main.go

start:
	mkdir -p certs
	vault server -dev -dev-tls -dev-tls-cert-dir=certs -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault auth enable \
		-ca-cert=certs/vault-ca.pem \
		-client-key=certs/vault-key.pem \
		-client-cert=certs/vault-cert.pem \
		-path=sgx-auth vault-plugin-auth-sgx

clean:
	rm -f ./vault/plugins/vault-plugin-auth-sgx

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
