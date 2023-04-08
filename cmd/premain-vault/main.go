package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/enclaive/vault-sgx-auth/attest"
	"golang.org/x/sys/unix"
	"net/http"
	"os"
	"time"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

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

	quote, _ := attest.NewGramineIssuer().Issue(tlsConfig.Certificate)

	server := &http.Server{Addr: ":8200"}

	http.HandleFunc("/premain/attest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(base64.StdEncoding.EncodeToString(quote)))
		if err != nil {
			fmt.Println("error:", err)
		} else {
			go func() {
				fmt.Println("shutting down")
				time.Sleep(time.Second)
				check(server.Shutdown(context.TODO()))
			}()
		}
	})

	fmt.Println("tls on 0.0.0.0:8200")
	err = server.ListenAndServeTLS("/secrets/tmp/cert.pem", "/secrets/tmp/key.pem")
	if err != http.ErrServerClosed {
		check(err)
	}

	check(unix.Exec(os.Args[0], os.Args, os.Environ()))
}
