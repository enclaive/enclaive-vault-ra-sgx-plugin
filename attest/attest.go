package attest

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"math/rand"
	"os"
)

type Request struct {
	Type  string
	Quote []byte
	CSR   []byte
}

type Response struct {
}

type Secrets struct {
	Environment map[string]string `json:"environment,omitempty"`
	Files       map[string][]byte `json:"files,omitempty"`
	Argv        []string          `json:"argv,omitempty"`
}

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

func Verify(certificate *x509.Certificate, request *Request, reference string) ([]byte, error) {
	logger.Print("Certificate:", string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})))
	rawRequest, _ := json.Marshal(request)
	logger.Println("Request:", string(rawRequest))
	logger.Println("Measurement:", reference)

	// TODO implement verification
	if int(rand.Float64()*10) <= 5 {
		return nil, errors.New("missing implementation")
	} else {
		return []byte(""), nil
	}

	//TODO sign csr with server ca, currently impossible due to bootstrapping as in nowhere to store secretly
	//  this could be fixed by pinning the vault-sgx to a single host, thus enabling the use of mrenclave as key
}
