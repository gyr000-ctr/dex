package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/storage"
)

func (d dexAPI) GetClient(ctx context.Context, req *api.GetClientReq) (*api.GetClientResp, error) {
	c, err := d.s.GetClient(ctx, req.Id)
	if err != nil {
		return nil, err
	}

	return &api.GetClientResp{
		Client: &api.Client{
			Id:                     c.ID,
			Name:                   c.Name,
			Secret:                 c.Secret,
			RedirectUris:           c.RedirectURIs,
			TrustedPeers:           c.TrustedPeers,
			Public:                 c.Public,
			LogoUrl:                c.LogoURL,
			AllowedConnectors:      c.AllowedConnectors,
			SsoSharedWith:          c.SSOSharedWith,
			BackchannelLogoutUri:   c.BackchannelLogoutURI,
			PostLogoutRedirectUris: c.PostLogoutRedirectURIs,
			RefreshTokenLifetime:   c.RefreshTokenLifetime,
			Jwks:                   marshalJWKS(c.JWKS),
		},
	}, nil
}

func (d dexAPI) CreateClient(ctx context.Context, req *api.CreateClientReq) (*api.CreateClientResp, error) {
	if req.Client == nil {
		return nil, errors.New("no client supplied")
	}

	if req.Client.Id == "" {
		req.Client.Id = storage.NewID()
	}
	if req.Client.Secret == "" && !req.Client.Public {
		req.Client.Secret = storage.NewID() + storage.NewID()
	}

	if err := storage.ValidateRefreshTokenLifetime(req.Client.RefreshTokenLifetime); err != nil {
		return nil, err
	}

	jwks, err := parseJWKS(req.Client.Jwks)
	if err != nil {
		return nil, err
	}

	c := storage.Client{
		ID:                     req.Client.Id,
		Secret:                 req.Client.Secret,
		RedirectURIs:           req.Client.RedirectUris,
		TrustedPeers:           req.Client.TrustedPeers,
		Public:                 req.Client.Public,
		Name:                   req.Client.Name,
		LogoURL:                req.Client.LogoUrl,
		AllowedConnectors:      req.Client.AllowedConnectors,
		SSOSharedWith:          req.Client.SsoSharedWith,
		BackchannelLogoutURI:   req.Client.BackchannelLogoutUri,
		PostLogoutRedirectURIs: req.Client.PostLogoutRedirectUris,
		RefreshTokenLifetime:   req.Client.RefreshTokenLifetime,
		JWKS:                   jwks,
	}
	if err := d.s.CreateClient(ctx, c); err != nil {
		if err == storage.ErrAlreadyExists {
			return &api.CreateClientResp{AlreadyExists: true}, nil
		}
		d.logger.Error("failed to create client", "err", err)
		return nil, fmt.Errorf("create client: %v", err)
	}

	return &api.CreateClientResp{
		Client: req.Client,
	}, nil
}

func (d dexAPI) UpdateClient(ctx context.Context, req *api.UpdateClientReq) (*api.UpdateClientResp, error) {
	if req.Id == "" {
		return nil, errors.New("update client: no client ID supplied")
	}
	if err := storage.ValidateRefreshTokenLifetime(req.GetRefreshTokenLifetime()); err != nil {
		return nil, err
	}
	// Parsed before the update so a malformed key set fails the call instead of
	// being written half-way through.
	jwks, err := parseJWKS(req.GetJwks())
	if err != nil {
		return nil, err
	}

	err = d.s.UpdateClient(ctx, req.Id, func(old storage.Client) (storage.Client, error) {
		if req.RedirectUris != nil {
			old.RedirectURIs = req.RedirectUris
		}
		if req.TrustedPeers != nil {
			old.TrustedPeers = req.TrustedPeers
		}
		if req.Name != "" {
			old.Name = req.Name
		}
		if req.LogoUrl != "" {
			old.LogoURL = req.LogoUrl
		}
		if req.AllowedConnectors != nil {
			old.AllowedConnectors = req.AllowedConnectors
		}
		if req.SsoSharedWith != nil {
			old.SSOSharedWith = req.SsoSharedWith
		}
		// Explicit presence, so that sending an empty string clears the URI rather
		// than being indistinguishable from not mentioning it.
		if req.BackchannelLogoutUri != nil {
			old.BackchannelLogoutURI = req.GetBackchannelLogoutUri()
		}
		if req.PostLogoutRedirectUris != nil {
			old.PostLogoutRedirectURIs = req.PostLogoutRedirectUris
		}
		if req.RefreshTokenLifetime != nil {
			old.RefreshTokenLifetime = req.GetRefreshTokenLifetime()
		}
		// Explicit presence again: an empty jwks clears the client's request
		// object keys, which is how signed requests are switched off.
		if req.Jwks != nil {
			old.JWKS = jwks
		}
		return old, nil
	})
	if err != nil {
		if err == storage.ErrNotFound {
			return &api.UpdateClientResp{NotFound: true}, nil
		}
		d.logger.Error("failed to update the client", "err", err)
		return nil, fmt.Errorf("update client: %v", err)
	}
	return &api.UpdateClientResp{}, nil
}

func (d dexAPI) DeleteClient(ctx context.Context, req *api.DeleteClientReq) (*api.DeleteClientResp, error) {
	err := d.s.DeleteClient(ctx, req.Id)
	if err != nil {
		if err == storage.ErrNotFound {
			return &api.DeleteClientResp{NotFound: true}, nil
		}
		d.logger.Error("failed to delete client", "err", err)
		return nil, fmt.Errorf("delete client: %v", err)
	}
	return &api.DeleteClientResp{}, nil
}

func (d dexAPI) ListClients(ctx context.Context, req *api.ListClientReq) (*api.ListClientResp, error) {
	clientList, err := d.s.ListClients(ctx)
	if err != nil {
		d.logger.Error("failed to list clients", "err", err)
		return nil, fmt.Errorf("list clients: %v", err)
	}

	clients := make([]*api.ClientInfo, 0, len(clientList))
	for _, client := range clientList {
		c := api.ClientInfo{
			Id:                     client.ID,
			Name:                   client.Name,
			RedirectUris:           client.RedirectURIs,
			TrustedPeers:           client.TrustedPeers,
			Public:                 client.Public,
			LogoUrl:                client.LogoURL,
			AllowedConnectors:      client.AllowedConnectors,
			SsoSharedWith:          client.SSOSharedWith,
			BackchannelLogoutUri:   client.BackchannelLogoutURI,
			PostLogoutRedirectUris: client.PostLogoutRedirectURIs,
			RefreshTokenLifetime:   client.RefreshTokenLifetime,
			Jwks:                   marshalJWKS(client.JWKS),
		}
		clients = append(clients, &c)
	}

	return &api.ListClientResp{
		Clients: clients,
	}, nil
}

// marshalJWKS renders a client key set for the API response. A client without
// a key set reports an empty string rather than an empty JSON object, so callers
// can tell "not configured" from "configured with no keys".
func marshalJWKS(jwks *jose.JSONWebKeySet) string {
	if jwks == nil {
		return ""
	}
	data, err := json.Marshal(jwks)
	if err != nil {
		return ""
	}
	return string(data)
}

// parseJWKS reads a client key set supplied as JSON. An empty string means no
// key set; anything else must parse and carry only public, otherwise valid keys,
// since a private or symmetric key has no business in a client registration and
// would silently never be used for verification.
func parseJWKS(raw string) (*jose.JSONWebKeySet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(raw), &jwks); err != nil {
		return nil, fmt.Errorf("parse client jwks: %v", err)
	}
	for i, key := range jwks.Keys {
		if !key.Valid() {
			return nil, fmt.Errorf("parse client jwks: key %d is not a valid JWK", i)
		}
		if !key.IsPublic() {
			return nil, fmt.Errorf("parse client jwks: key %d is not a public key", i)
		}
	}
	return &jwks, nil
}
