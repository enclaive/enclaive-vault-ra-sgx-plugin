package attest

import (
	"crypto/sha512"
	"os"
)

const (
	GramineUserReportData = "/dev/attestation/user_report_data"
	GramineQuote          = "/dev/attestation/quote"
)

func NewGramineIssuer() *GramineIssuer {
	return &GramineIssuer{}
}

type GramineIssuer struct{}

func (i *GramineIssuer) Issue(data []byte) []byte {
	hash := sha512.Sum512(data)

	check(os.WriteFile(GramineUserReportData, hash[:], 0600))

	rawQuote, err := os.ReadFile(GramineQuote)
	check(err)

	return rawQuote
}
