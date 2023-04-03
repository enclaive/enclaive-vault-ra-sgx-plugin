package sgx

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend wraps the backend framework and adds a map for storing key value pairs.
type backend struct {
	*framework.Backend

	//TODO this should be persisted
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
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathLogin(),
				b.pathUsersList(),
			},
			b.pathUsers(),
		),
	}

	return b, nil
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

func (b *backend) handleLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("id must be provided"), nil
	}

	attestation := data.Get("attestation").(string)
	if attestation == "" {
		return logical.ErrorResponse("attestation must be provided"), nil
	}

	mrsigner, ok := b.enclaves[id]
	if !ok {
		return nil, logical.ErrPermissionDenied
	}

	_ = mrsigner

	//FIXME check attestation here

	// Compose the response
	resp := &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"attestation": attestation,
			},
			// Policies can be passed in as a parameter to the request
			Policies: []string{"my-policy", "other-policy"},
			Metadata: map[string]string{
				"id": id,
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
