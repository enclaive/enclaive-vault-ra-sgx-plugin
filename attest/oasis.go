package attest

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	pccsUrlBase string
)

//goland:noinspection GoUnusedConst
const (
	envEnclaivePccs    = "ENCLAIVE_PCCS"
	pathSgxDefaultQcnl = "/etc/sgx_default_qcnl.conf"

	pccsPathBase       = "/sgx/certification/v4"
	pccsPathPckCrl     = "/pckcrl?ca=platform"
	pccsPathTcb        = "/tcb"
	pccsPathQeIdentity = "/qe/identity"
	pccsPathRootCaCrl  = "/rootcacrl"

	pccsHeaderCrlChain     = "SGX-PCK-CRL-Issuer-Chain"
	pccsHeaderTcbChain     = "SGX-TCB-Info-Issuer-Chain"
	pccsHeaderEnclaveChain = "SGX-Enclave-Identity-Issuer-Chain"
)

func init() {
	pccsUrlBase = os.Getenv(envEnclaivePccs)

	if pccsUrlBase == "" {
		data, err := os.ReadFile(pathSgxDefaultQcnl)
		if err != nil {
			fmt.Printf("configure PCCS via '%s' or configure in '%s'", envEnclaivePccs, pathSgxDefaultQcnl)
			panic(err)
		}

		var config map[string]interface{}
		if err = json.Unmarshal(data, &config); err != nil {
			fmt.Printf("error parsing '%s'", pathSgxDefaultQcnl)
			panic(err)
		}

		var ok bool
		pccsUrlBase, ok = config["pccs_url"].(string)
		if !ok {
			fmt.Println("pccs_url was not a string")
			panic(err)
		}

		if strings.HasSuffix(pccsUrlBase, "/") {
			pccsUrlBase = strings.TrimSuffix(pccsUrlBase, "/")
		}
	} else {
		pccsUrlBase += pccsPathBase
	}
}

func requestPccs(path string, query url.Values, out interface{}) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, pccsUrlBase+path, nil)
	if err != nil {
		return nil, err
	}

	req.URL.RawQuery = query.Encode()

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(data, out); err != nil {
		return nil, err
	}

	return res, nil
}

func getTcbBundle(fsmpc []byte) (*pcs.TCBBundle, error) {
	tcbBundle := &pcs.TCBBundle{
		TCBInfo:      pcs.SignedTCBInfo{},
		QEIdentity:   pcs.SignedQEIdentity{},
		Certificates: nil,
	}

	tcbQuery := map[string][]string{"fmspc": {hex.EncodeToString(fsmpc)}}
	tcbResponse, err := requestPccs(pccsPathTcb, tcbQuery, &tcbBundle.TCBInfo)
	if err != nil {
		return nil, err
	}

	certificates, err := url.QueryUnescape(tcbResponse.Header.Get(pccsHeaderTcbChain))
	if err != nil {
		return nil, err
	}

	tcbBundle.Certificates = []byte(certificates)

	_, err = requestPccs(pccsPathQeIdentity, url.Values{}, &tcbBundle.QEIdentity)
	if err != nil {
		return nil, err
	}

	return tcbBundle, nil
}

func verifyQuote(rawQuote []byte) (*sgx.VerifiedQuote, error) {
	var err error

	var quote pcs.Quote
	check(quote.UnmarshalBinary(rawQuote))

	quoteSignature, ok := quote.Signature.(*pcs.QuoteSignatureECDSA_P256)
	if !ok {
		return nil, errors.New("unsupported attestation key type")
	}

	switch quoteSignature.CertificationData.(type) {
	case *pcs.CertificationData_PCKCertificateChain:
	default:
		return nil, errors.New("unsupported certification data")
	}

	pckInfo, err := quoteSignature.VerifyPCK(time.Now())
	check(err)

	tcbBundle, err := getTcbBundle(pckInfo.FMSPC)
	check(err)

	quotePolicy := &pcs.QuotePolicy{
		Disabled:                   false,
		TCBValidityPeriod:          90, // in days
		MinTCBEvaluationDataNumber: pcs.DefaultMinTCBEvaluationDataNumber,
	}

	attested, err := quote.Verify(quotePolicy, time.Now(), tcbBundle)
	check(err)

	return attested, nil
}
