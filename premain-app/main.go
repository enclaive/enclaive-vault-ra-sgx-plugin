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
	EnvEnclaveName   = "ENCLAIVE_NAME"
	EnvEnclaveServer = "ENCLAIVE_SERVER"

	// VaultMount default mount path for KV v2 in dev mode
	VaultMount = "sgx-app"
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

func vaultRequest(client *vault.Client, request *attest.Request) (*attest.Secrets, *attest.TlsConfig) {
	info, err := client.Auth().Login(context.Background(), auth.NewSgxAuth(request))
	check(err)

	kvSecret, err := client.KVv2(VaultMount).Get(context.Background(), request.Name)
	check(err)

	secrets := new(attest.Secrets)
	check(json.Unmarshal([]byte(kvSecret.Data["provision"].(string)), secrets))

	path := fmt.Sprintf("sgx-pki/issue/%s", info.Auth.Metadata["domain"])
	tlsSecret, err := client.Logical().WriteWithContext(context.Background(), path, map[string]interface{}{
		"common_name": info.Auth.Metadata["domain"],
		"format":      "der",
	})
	check(err)

	tlsConfig := new(attest.TlsConfig)
	tlsRaw, err := json.Marshal(tlsSecret.Data)
	check(err)

	check(json.Unmarshal(tlsRaw, tlsConfig))

	return secrets, tlsConfig
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
	enclaveName := envConfig(EnvEnclaveName)

	privateKey, err := attest.GenerateEcKey()
	check(err)

	tlsCtx := attest.NewTlsContext(privateKey, enclaveName)

	selfSignedCertificate, err := attest.GenerateCert(tlsCtx)
	check(err)

	//rawQuote, err := attest.NewGramineIssuer().Issue(selfSignedCertificate.Raw)
	//check(err)
	rawQuote := []byte("yolo")

	client := vaultClient(&tls.Certificate{
		Certificate: [][]byte{selfSignedCertificate.Raw},
		PrivateKey:  privateKey,
	})

	secrets, tlsConfig := vaultRequest(client, &attest.Request{
		Name:  enclaveName,
		Quote: rawQuote,
	})

	//check(tlsConfig.Save("/secrets/tmp"))

	json.NewEncoder(os.Stdout).Encode(secrets)
	json.NewEncoder(os.Stdout).Encode(tlsConfig)
	//secretsProvision(response)
}
