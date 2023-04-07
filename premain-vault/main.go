package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"github.com/enclaive/vault-sgx-auth/attest"
	"golang.org/x/sys/unix"
	"os"
)

const (
	EnvEnclaiveCertificateHash = "ENCLAIVE_CERTIFICATE_HASH"
)

func main() {
	privateKey, err := attest.GenerateEcKey()
	check(err)

	tlsCtx := attest.NewTlsContext(privateKey, "vault")

	selfSignedCertificate, err := attest.GenerateCert(tlsCtx)
	check(err)

	rawPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	check(err)

	check(os.MkdirAll("/secrets/tmp", 0700))

	tlsConfig := &attest.TlsConfig{
		Certificate: selfSignedCertificate.Raw,
		PrivateKey:  rawPrivateKey,
	}

	check(tlsConfig.Save("/secrets/tmp"))

	certificateHash := sha256.Sum256(tlsConfig.Certificate)

	check(os.Setenv(EnvEnclaiveCertificateHash, hex.EncodeToString(certificateHash[:])))

	check(unix.Exec(os.Args[0], os.Args, os.Environ()))
}
