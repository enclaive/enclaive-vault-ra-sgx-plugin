package attest

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"math/rand"
	"os"
	"path/filepath"
)

var (
	logger *log.Logger
)

func init() {
	file, err := os.Create("plugin.log.txt")
	if err != nil {
		panic(err)
	}
	logger = log.New(file, "", log.LstdFlags|log.Lshortfile)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

type Request struct {
	Name  string
	Quote []byte
}

type Response struct {
	Quote       []byte
	Certificate *x509.Certificate
}

type Secrets struct {
	Environment map[string]string `json:"environment,omitempty"`
	Files       map[string][]byte `json:"files,omitempty"`
	Argv        []string          `json:"argv,omitempty"`
}

type TlsConfig struct {
	CaChain     [][]byte `json:"ca_chain,omitempty"`
	Certificate []byte   `json:"certificate,omitempty"`
	PrivateKey  []byte   `json:"private_key,omitempty"`
}

func (c *TlsConfig) Save(prefix string) (err error) {
	if c.CaChain != nil {
		caChain := make([][]byte, len(c.CaChain))
		for i, ca := range c.CaChain {
			caChain[i] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})
		}

		err = os.WriteFile(filepath.Join(prefix, "ca.pem"), bytes.Join(caChain, []byte("")), 0400)
		if err != nil {
			return err
		}
	}

	if c.Certificate != nil {
		certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate})
		err = os.WriteFile(filepath.Join(prefix, "cert.pem"), certificate, 0400)
		if err != nil {
			return err
		}
	}

	if c.PrivateKey != nil {
		privateKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: c.PrivateKey})
		err = os.WriteFile(filepath.Join(prefix, "key.pem"), privateKey, 0400)
		if err != nil {
			return err
		}
	}

	return
}

// Verify
// TODO add nonce to quote generation and verification
func Verify(certificate *x509.Certificate, request *Request, reference string) error {
	logger.Print("Certificate:", string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})))
	rawRequest, _ := json.Marshal(request)
	logger.Println("Request:", string(rawRequest))
	logger.Println("Measurement:", reference)

	// TODO implement verification
	if int(rand.Float64()*10) <= 5 {
		return errors.New("missing implementation")
	} else {
		return nil
	}
}
