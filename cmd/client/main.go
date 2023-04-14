package main

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/enclaive/vault-sgx-auth/attest"
	"github.com/urfave/cli/v2"
	"io"
	"net/http"
	"os"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

const (
	pathVaultAttest = "/premain/attest"
)

var (
	pathAttestationCertificate  string
	valueAttestationMeasurement string
	valueVaultAddress           string
)

func verify(cCtx *cli.Context) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	client := &http.Client{Transport: transport}

	req, err := http.NewRequest(http.MethodGet, valueVaultAddress+pathVaultAttest, nil)
	if err != nil {
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	quote, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}

	rawCertificate := res.TLS.PeerCertificates[0].Raw
	certificateHash := sha512.Sum512(rawCertificate)
	if err = attest.Verify(certificateHash, quote, valueAttestationMeasurement); err != nil {
		return err
	}

	fmt.Println("OK: attestation verified, writing certificate")

	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawCertificate})
	if err = os.WriteFile(pathAttestationCertificate, certificate, 0600); err != nil {
		return err
	}

	return nil
}

func main() {
	app := &cli.App{
		Name:  "client",
		Usage: "A cli to interact with sgx-vault",
		Commands: []*cli.Command{
			{
				Name:   "verify",
				Usage:  "verify vault attestation",
				Action: verify,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "vault",
						Usage:       "address of vault",
						Required:    true,
						Destination: &valueVaultAddress,
						EnvVars:     []string{"VAULT_ADDR"},
					},
					&cli.StringFlag{
						Name:        "ref",
						Usage:       "reference value for measurement",
						Required:    true,
						Destination: &valueAttestationMeasurement,
					},
					&cli.StringFlag{
						Name:        "cert",
						Usage:       "path to attestation certificate",
						Required:    true,
						Destination: &pathAttestationCertificate,
						EnvVars:     []string{"VAULT_CACERT"},
					},
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
