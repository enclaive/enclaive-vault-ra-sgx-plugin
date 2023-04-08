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

GOBUILD := CGO_ENABLED=0 GOOS=$(OS) GOARCH="$(GOARCH)" go build

all: fmt build

setup:
	./client.sh setup

enable:
	./client.sh enable

create:
	./client.sh create

login:
	./client.sh login

build: setup
	$(GOBUILD) -o vault/plugins/vault-plugin-auth-sgx cmd/vault-plugin-auth-sgx/main.go
	strip vault/plugins/vault-plugin-auth-sgx
	upx -1 vault/plugins/vault-plugin-auth-sgx

client:
	$(GOBUILD) -o ./client cmd/client/main.go

premain: premain-app premain-vault

premain-app:
	$(GOBUILD) -o ./premain cmd/premain-app/main.go

premain-vault:
	$(GOBUILD) -o ./vault/premain-vault cmd/premain-vault/main.go

start:
	mkdir -p certs
	vault server -dev -dev-tls -dev-tls-cert-dir=certs -dev-listen-address=0.0.0.0:8200 -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enclave: build client premain
	cd vault/ && docker-compose build

clean:
	rm -f ./vault/plugins/vault-plugin-auth-sgx
	rm -f ./premain ./vault/premain-vault

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable client premain premain-app premain-vault enclave
