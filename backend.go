package vault_sgx_plugin

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/enclaive/vault-sgx-auth/attest"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	mountPath = "auth/sgx-auth/login"
)

// backend wraps the backend framework and adds a map for storing key value pairs.
type backend struct {
	*framework.Backend

	//TODO this should be persisted
	//  unknown property SealWrap
	//	req.Storage.Put(ctx, &logical.StorageEntry{
	//		Key:      "enclave/"+id,
	//		Value:    mrenclave,
	//		SealWrap: false,
	//	})
	enclaves map[string]string
}

var _ logical.Factory = Factory

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*backend, error) {
	b := &backend{
		enclaves: make(map[string]string),
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(sgxHelp),
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
				"attest",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathLogin(),
				b.pathAttest(),
				b.pathUsersList(),
			},
			b.pathUsers(),
		),
	}

	return b, nil
}

func NewSgxAuth(request *attest.Request) *SgxAuth {
	return &SgxAuth{request: request}
}

type SgxAuth struct {
	request *attest.Request
}

func (s *SgxAuth) Login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	attestation, err := json.Marshal(s.request)
	if err != nil {
		return nil, err
	}

	loginData := map[string]interface{}{
		"id":          s.request.Name,
		"attestation": attestation,
	}

	resp, err := client.Logical().WriteWithContext(ctx, mountPath, loginData)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"id": {
				Type:        framework.TypeString,
				Description: "enclave id",
			},
			"attestation": {
				Type:        framework.TypeString,
				Description: "sgx attestation",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Log in using en enclave id and attestation",
			},
		},
	}
}

func (b *backend) pathAttest() *framework.Path {
	return &framework.Path{
		Pattern: "attest$",
		Fields: map[string]*framework.FieldSchema{
			"nonce": {
				Type:        framework.TypeString,
				Description: "freshness nonce",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleAttest,
				Summary:  "Get vault attestation",
			},
		},
	}
}

func (b *backend) handleLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.Connection == nil || req.Connection.ConnState == nil {
		return logical.ErrorResponse("tls connection required"), nil
	}

	connState := req.Connection.ConnState

	if connState.PeerCertificates == nil || len(connState.PeerCertificates) == 0 {
		return logical.ErrorResponse("tls client certificate required"), nil
	}

	attestation := data.Get("attestation").(string)
	if attestation == "" {
		return logical.ErrorResponse("attestation must be provided"), nil
	}

	request := new(attest.Request)
	rawRequest, err := base64.StdEncoding.DecodeString(attestation)
	if err != nil {
		return logical.ErrorResponse("attestation was not base64 encoded"), nil
	}

	if err = json.Unmarshal(rawRequest, request); err != nil {
		return logical.ErrorResponse("attestation was not base64 encoded"), nil
	}

	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("id must be provided"), nil
	}

	measurement, ok := b.enclaves[id]
	if !ok {
		return logical.ErrorResponse("unknown enclave name"), nil
	}

	if err = attest.Verify(connState.PeerCertificates[0], request, measurement); err != nil {
		return logical.ErrorResponse("attestation failed"), nil
	}

	domain := fmt.Sprintf("%s.app.%s.enclaive", measurement, os.Getenv("ENCLAIVE_DEPLOYMENT"))

	// Compose the response
	resp := &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"attestation": attestation,
			},
			// Policies can be passed in as a parameter to the request
			Policies:        []string{"sgx-app/" + id},
			NoDefaultPolicy: true,
			Metadata: map[string]string{
				"domain": domain,
			},

			// Lease options can be passed in as parameters to the request
			LeaseOptions: logical.LeaseOptions{
				TTL:       30 * time.Second,
				MaxTTL:    60 * time.Minute,
				Renewable: true,
			},
		},
	}

	return resp, nil
}

func (b *backend) handleAttest(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	//nonce := data.Get("nonce").(string)
	//if nonce == "" {
	//	return logical.ErrorResponse("no nonce provided"), nil
	//}

	certificateHash := os.Getenv("ENCLAIVE_CERTIFICATE_HASH")
	rawHash, err := hex.DecodeString(certificateHash)
	if err != nil {
		return logical.ErrorResponse("could not decode certificate hash to bytes"), nil
	}

	rawQuote, _ := attest.NewGramineIssuer().Issue(rawHash)

	return &logical.Response{
		Data: map[string]interface{}{
			"quote":            rawQuote,
			"certificate_hash": certificateHash,
		},
	}, nil
}

func (b *backend) pathUsers() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "enclave/" + framework.GenericNameRegex("id"),

			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Specifies the enclave id",
				},
				"mrenclave": {
					Type:        framework.TypeString,
					Description: "Specifies the expected mrenclave",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleUserWrite,
					Summary:  "Adds a new enclave to the auth method.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleUserWrite,
					Summary:  "Updates a enclave on the auth method.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleUserDelete,
					Summary:  "Deletes a enclave on the auth method.",
				},
			},

			ExistenceCheck: b.handleExistenceCheck,
		},
	}
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	id := data.Get("id").(string)
	_, ok := b.enclaves[id]

	return ok, nil
}

func (b *backend) pathUsersList() *framework.Path {
	return &framework.Path{
		Pattern: "enclaves/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleUsersList,
				Summary:  "List existing enclaves.",
			},
		},
	}
}

func (b *backend) handleUsersList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	enclaveList := make([]string, len(b.enclaves))

	i := 0
	for u, _ := range b.enclaves {
		enclaveList[i] = u
		i++
	}

	sort.Strings(enclaveList)

	return logical.ListResponse(enclaveList), nil
}

func (b *backend) handleUserWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("id must be provided"), nil
	}

	password := data.Get("mrenclave").(string)
	if password == "" {
		return logical.ErrorResponse("password must be provided"), nil
	}

	// Store kv pairs in map at specified path
	b.enclaves[id] = password

	return nil, nil
}

func (b *backend) handleUserDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	enclavename := data.Get("id").(string)
	if enclavename == "" {
		return logical.ErrorResponse("id must be provided"), nil
	}

	// Remove entry for specified path
	delete(b.enclaves, enclavename)

	return nil, nil
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	enclavename := req.Auth.Metadata["id"]
	pw := req.Auth.InternalData["attestation"].(string)

	storedPassword, ok := b.enclaves[enclavename]
	if !ok {
		return nil, errors.New("attestation on the token could not be found")
	}

	if subtle.ConstantTimeCompare([]byte(pw), []byte(storedPassword)) != 1 {
		return nil, errors.New("internal data does not match")
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = 30 * time.Second
	resp.Auth.MaxTTL = 60 * time.Minute

	return resp, nil
}

const sgxHelp = `
login with sgx attestation
`
