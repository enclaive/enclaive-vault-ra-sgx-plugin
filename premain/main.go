package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	auth "github.com/enclaive/vault-sgx-auth"
	"github.com/enclaive/vault-sgx-auth/attest"
	vault "github.com/hashicorp/vault/api"
	"golang.org/x/sys/unix"
	"net/http"
	"os"
	"path/filepath"
)

const (
	EnvEnclaveType   = "ENCLAIVE_TYPE"
	EnvEnclaveServer = "ENCLAIVE_SERVER"

	// VaultMount default mount path for KV v2 in dev mode
	VaultMount = "secret"
)

func vaultClient(certificate *tls.Certificate) *vault.Client {
	config := vault.DefaultConfig()

	config.Address = envConfig(EnvEnclaveServer)

	var peerCertificates [][]byte = nil
	transport := config.HttpClient.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	transport.TLSClientConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if peerCertificates == nil {
			peerCertificates = rawCerts
		} else {
			for i, rawCert := range rawCerts {
				if !bytes.Equal(peerCertificates[i], rawCert) {
					return fmt.Errorf("peer certificate '%d' changed", i)
				}
			}
		}

		return nil
	}
	transport.TLSClientConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return certificate, nil
	}

	config.HttpClient.Transport = transport

	client, err := vault.NewClient(config)
	check(err)

	return client
}

func vaultRequest(client *vault.Client, request *attest.Request) *attest.Secrets {
	info, err := client.Auth().Login(context.Background(), auth.NewSgxAuth(request))
	check(err)

	//TODO use vault signed certificate
	check(json.NewEncoder(os.Stdout).Encode(info.Auth.Metadata["response"]))

	kvSecret, err := client.KVv2(VaultMount).Get(context.Background(), "sgx/"+request.Type)
	check(err)

	secrets := new(attest.Secrets)
	check(json.Unmarshal([]byte(kvSecret.Data["provision"].(string)), secrets))

	return secrets
}

func secretsProvision(secrets *attest.Secrets) {
	args := make([]string, len(os.Args))
	copy(args, os.Args)
	args = append(args, secrets.Argv...)
	args[0] = filepath.Base(args[0])

	for k, v := range secrets.Environment {
		check(os.Setenv(k, v))
	}

	//FIXME gramine encrypted mount keys must be written first
	for path, content := range secrets.Files {
		check(os.WriteFile(path, content, 0600))
	}

	check(unix.Exec(os.Args[0], args, os.Environ()))
}

func main() {
	enclaveType := envConfig(EnvEnclaveType)

	privateKey, err := generateEcKey()
	check(err)

	tlsCtx := &tlsContext{
		publicKey:   privateKey.Public(),
		privateKey:  privateKey,
		enclaveType: enclaveType,
	}

	selfSignedCertificate, err := generateCert(tlsCtx)
	check(err)

	rawQuote := attest.NewGramineIssuer().Issue(selfSignedCertificate.Raw)

	csr, err := generateCsr(tlsCtx)
	check(err)

	client := vaultClient(&tls.Certificate{
		Certificate: [][]byte{selfSignedCertificate.Raw},
		PrivateKey:  privateKey,
	})

	response := vaultRequest(client, &attest.Request{
		Type:  enclaveType,
		Quote: rawQuote,
		CSR:   csr.Raw,
	})

	secretsProvision(response)
}
