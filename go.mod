module github.com/enclaive/vault-sgx-auth

go 1.12

require (
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/vault/api v1.9.0
	github.com/hashicorp/vault/sdk v0.8.1
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/oasisprotocol/oasis-core/go v0.2202.1-0.20230403170358-8f3cf28a7490
	github.com/urfave/cli/v2 v2.25.1
	golang.org/x/sys v0.6.0
)

replace github.com/oasisprotocol/oasis-core/go => ./attest/oasis
