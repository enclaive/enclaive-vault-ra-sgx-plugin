package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

var (
	defaultDnsNames    = []string{"localhost"}
	defaultIpAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

	certificateTemplate = x509.Certificate{
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth | x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
)

type tlsContext struct {
	publicKey   crypto.PublicKey
	privateKey  crypto.PrivateKey
	enclaveType string
}

func generateEcKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func generateCert(ctx *tlsContext) (*x509.Certificate, error) {
	template := certificateTemplate
	template.DNSNames = defaultDnsNames
	template.IPAddresses = defaultIpAddresses

	currentTime := time.Now()
	template.NotBefore = currentTime
	template.NotAfter = currentTime.Add(time.Hour * 24 * 365 * 10)

	template.SerialNumber = big.NewInt(1)

	template.Subject = pkix.Name{
		CommonName: ctx.enclaveType,
	}

	rawCertificate, err := x509.CreateCertificate(rand.Reader, &template, &template, ctx.publicKey, ctx.privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(rawCertificate)
}

func generateCsr(ctx *tlsContext) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{}
	template.DNSNames = defaultDnsNames
	template.IPAddresses = defaultIpAddresses

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, ctx.privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(csr)
}
