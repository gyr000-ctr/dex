package authflow

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

const requestObjectTestIssuer = "https://dex.example.com"

// requestObjectKey is a signing key for the tests, with a kid that matches the
// key set registered for the client.
type requestObjectKey struct {
	private *rsa.PrivateKey
	kid     string
}

func newRequestObjectKey(t *testing.T, kid string) *requestObjectKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &requestObjectKey{private: key, kid: kid}
}

// sign signs the claims and returns the compact JWS.
func (k *requestObjectKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: k.private},
		(&jose.SignerOptions{}).WithHeader("kid", k.kid).WithType("oauth-authz-req+jwt"),
	)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	compact, err := jws.CompactSerialize()
	require.NoError(t, err)
	return compact
}

// jwks returns the key set a client registers, carrying only the public key.
func (k *requestObjectKey) jwks(t *testing.T) *jose.JSONWebKeySet {
	t.Helper()
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &k.private.PublicKey,
		KeyID:     k.kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
}

func newRequestObjectHandler(t *testing.T) *Handler {
	t.Helper()
	logger := newLogger(t)
	issuerURL, err := url.Parse(requestObjectTestIssuer)
	require.NoError(t, err)
	return &Handler{
		IssuerURL: oauth2.IssuerURL{URL: *issuerURL},
		Storage:   memory.New(logger),
		Logger:    logger,
		Now:       func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	}
}

func validRequestObjectClaims(kid string) map[string]any {
	return map[string]any{
		"iss":           "client-1",
		"aud":           requestObjectTestIssuer,
		"exp":           time.Unix(1_800_000_600, 0).Unix(),
		"nbf":           time.Unix(1_800_000_000, 0).Unix(),
		"client_id":     "client-1",
		"redirect_uri":  "https://client.example.com/cb",
		"response_type": "code",
		"scope":         "openid email",
		"state":         "signed-state",
	}
}

// requestObjectRequest builds a /auth request carrying a request object.
func requestObjectRequest(t *testing.T, params map[string]string) *http.Request {
	t.Helper()
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	return httptest.NewRequest(http.MethodGet, "/auth?"+q.Encode(), nil)
}

func TestResolveRequestObjectByValue(t *testing.T) {
	h := newRequestObjectHandler(t)
	key := newRequestObjectKey(t, "key-1")
	require.NoError(t, h.Storage.CreateClient(t.Context(), storage.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://client.example.com/cb"},
		JWKS:         key.jwks(t),
	}))

	signed := key.sign(t, validRequestObjectClaims(key.kid))
	r := requestObjectRequest(t, map[string]string{
		"client_id":    "client-1",
		"redirect_uri": "https://client.example.com/cb",
		"request":      signed,
	})
	require.NoError(t, r.ParseForm())

	require.NoError(t, h.resolveRequestObject(r))
	assert.Equal(t, "signed-state", r.Form.Get("state"))
	assert.Equal(t, "code", r.Form.Get("response_type"))
	assert.Equal(t, "openid email", r.Form.Get("scope"))
	// The signed reference survives so later parses of this request verify the
	// same object instead of trusting expanded parameters.
	assert.Equal(t, signed, r.Form.Get("request"))
	// JWT claims are not OAuth parameters.
	assert.Empty(t, r.Form.Get("iss"))
	assert.Empty(t, r.Form.Get("aud"))
	assert.Empty(t, r.Form.Get("exp"))
}

// An unsigned URL parameter never overrides the signed one: the object wins, and
// the disagreement is reported as a conflict.
func TestResolveRequestObjectConflictingParameter(t *testing.T) {
	h := newRequestObjectHandler(t)
	key := newRequestObjectKey(t, "key-1")
	require.NoError(t, h.Storage.CreateClient(t.Context(), storage.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://client.example.com/cb"},
		JWKS:         key.jwks(t),
	}))

	// The redirect_uri in the URL points at the attacker, but the signed object
	// names the registered client callback.
	signed := key.sign(t, validRequestObjectClaims(key.kid))
	r := requestObjectRequest(t, map[string]string{
		"client_id":    "client-1",
		"redirect_uri": "https://client.example.com/cb",
		"request":      signed,
		"state":        "tampered",
	})
	require.NoError(t, r.ParseForm())

	err := h.resolveRequestObject(r)
	require.Error(t, err)
	redirect, ok := err.(*redirectedAuthErr)
	require.True(t, ok, "expected a redirect error, got %T", err)
	assert.Equal(t, oauth2.InvalidRequestObject, redirect.Type)
	assert.Contains(t, redirect.Description, "conflicts")
	// The signature is not what failed, so the object was still the source of
	// truth: the redirect goes to the signed callback, not the URL one.
	assert.Equal(t, "https://client.example.com/cb", redirect.RedirectURI)
}

func TestResolveRequestObjectErrors(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()

	tests := []struct {
		name string
		// extraKey registers a second key for the client, to exercise kid
		// selection.
		extraKey bool
		mutate   func(t *testing.T, key *requestObjectKey) string
		wantType string
	}{
		{
			name: "expired",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				claims := validRequestObjectClaims(key.kid)
				claims["exp"] = now.Add(-time.Minute).Unix()
				return key.sign(t, claims)
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "not yet valid",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				claims := validRequestObjectClaims(key.kid)
				claims["nbf"] = now.Add(time.Minute).Unix()
				return key.sign(t, claims)
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "missing exp",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				claims := validRequestObjectClaims(key.kid)
				delete(claims, "exp")
				return key.sign(t, claims)
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "wrong audience",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				claims := validRequestObjectClaims(key.kid)
				claims["aud"] = "https://other-as.example.com"
				return key.sign(t, claims)
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "missing audience",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				claims := validRequestObjectClaims(key.kid)
				delete(claims, "aud")
				return key.sign(t, claims)
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "wrong issuer",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				claims := validRequestObjectClaims(key.kid)
				claims["iss"] = "someone-else"
				return key.sign(t, claims)
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "client_id mismatch",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				claims := validRequestObjectClaims(key.kid)
				claims["client_id"] = "another-client"
				return key.sign(t, claims)
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "unknown signing key",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				// Signed by a different key with the same kid: the signature does
				// not verify against the registered key.
				other := newRequestObjectKey(t, key.kid)
				return other.sign(t, validRequestObjectClaims(key.kid))
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "unregistered kid",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				other := newRequestObjectKey(t, "unknown-kid")
				return other.sign(t, validRequestObjectClaims(key.kid))
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "not a JWS",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				return "not-a-jws"
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "nested request object",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				claims := validRequestObjectClaims(key.kid)
				claims["request"] = "another"
				return key.sign(t, claims)
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name:     "missing kid with several registered keys",
			extraKey: true,
			mutate: func(t *testing.T, key *requestObjectKey) string {
				// A second key is registered below; signing without a kid leaves
				// the choice ambiguous.
				payload, err := json.Marshal(validRequestObjectClaims(key.kid))
				require.NoError(t, err)
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key.private}, nil)
				require.NoError(t, err)
				jws, err := signer.Sign(payload)
				require.NoError(t, err)
				compact, err := jws.CompactSerialize()
				require.NoError(t, err)
				return compact
			},
			wantType: oauth2.InvalidRequestObject,
		},
		{
			name: "repeated parameter",
			mutate: func(t *testing.T, key *requestObjectKey) string {
				claims := validRequestObjectClaims(key.kid)
				claims["scope"] = []string{"openid", "admin"}
				return key.sign(t, claims)
			},
			wantType: oauth2.InvalidRequestObject,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newRequestObjectHandler(t)
			key := newRequestObjectKey(t, "key-1")
			jwks := key.jwks(t)
			if tc.extraKey {
				second := newRequestObjectKey(t, "key-2")
				jwks.Keys = append(jwks.Keys, second.jwks(t).Keys...)
			}
			require.NoError(t, h.Storage.CreateClient(t.Context(), storage.Client{
				ID:           "client-1",
				RedirectURIs: []string{"https://client.example.com/cb"},
				JWKS:         jwks,
			}))

			params := map[string]string{
				"client_id":    "client-1",
				"redirect_uri": "https://client.example.com/cb",
				"request":      tc.mutate(t, key),
			}
			r := requestObjectRequest(t, params)
			require.NoError(t, r.ParseForm())

			err := h.resolveRequestObject(r)
			require.Error(t, err)
			redirect, ok := err.(*redirectedAuthErr)
			require.True(t, ok, "expected a redirect error, got %T", err)
			assert.Equal(t, tc.wantType, redirect.Type)
			assert.Equal(t, "https://client.example.com/cb", redirect.RedirectURI)
		})
	}
}

// A client without registered keys keeps the old behaviour: the request
// parameter is unsupported, and the response is a standard OAuth2 error rather
// than a 500.
func TestResolveRequestObjectWithoutKeys(t *testing.T) {
	h := newRequestObjectHandler(t)
	require.NoError(t, h.Storage.CreateClient(t.Context(), storage.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://client.example.com/cb"},
	}))

	r := requestObjectRequest(t, map[string]string{
		"client_id":    "client-1",
		"redirect_uri": "https://client.example.com/cb",
		"request":      "anything",
	})
	require.NoError(t, r.ParseForm())

	err := h.resolveRequestObject(r)
	require.Error(t, err)
	redirect, ok := err.(*redirectedAuthErr)
	require.True(t, ok, "expected a redirect error, got %T", err)
	assert.Equal(t, oauth2.RequestNotSupported, redirect.Type)
}

// An oversized request object is refused before it is parsed, by value and by
// reference alike.
func TestRequestObjectSizeLimit(t *testing.T) {
	h := newRequestObjectHandler(t)
	key := newRequestObjectKey(t, "key-1")
	require.NoError(t, h.Storage.CreateClient(t.Context(), storage.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://client.example.com/cb"},
		JWKS:         key.jwks(t),
	}))

	huge := strings.Repeat("x", maxRequestObjectSize+1)
	r := requestObjectRequest(t, map[string]string{
		"client_id":    "client-1",
		"redirect_uri": "https://client.example.com/cb",
		"request":      huge,
	})
	require.NoError(t, r.ParseForm())

	err := h.resolveRequestObject(r)
	require.Error(t, err)
	redirect, ok := err.(*redirectedAuthErr)
	require.True(t, ok, "expected a redirect error, got %T", err)
	assert.Equal(t, oauth2.InvalidRequestObject, redirect.Type)
	assert.Contains(t, redirect.Description, "too large")
}

func TestResolveRequestObjectByReference(t *testing.T) {
	h := newRequestObjectHandler(t)
	key := newRequestObjectKey(t, "key-1")
	require.NoError(t, h.Storage.CreateClient(t.Context(), storage.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://client.example.com/cb"},
		JWKS:         key.jwks(t),
	}))

	signed := key.sign(t, validRequestObjectClaims(key.kid))

	// A TLS host serving the request object, as RFC 9101 requires.
	objectServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", requestObjectMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer objectServer.Close()
	h.HTTPClient = objectServer.Client()

	r := requestObjectRequest(t, map[string]string{
		"client_id":    "client-1",
		"redirect_uri": "https://client.example.com/cb",
		"request_uri":  objectServer.URL,
	})
	require.NoError(t, r.ParseForm())

	require.NoError(t, h.resolveRequestObject(r))
	assert.Equal(t, "signed-state", r.Form.Get("state"))
	assert.Equal(t, objectServer.URL, r.Form.Get("request_uri"))
}

func TestResolveRequestObjectByReferenceErrors(t *testing.T) {
	h := newRequestObjectHandler(t)
	key := newRequestObjectKey(t, "key-1")
	require.NoError(t, h.Storage.CreateClient(t.Context(), storage.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://client.example.com/cb"},
		JWKS:         key.jwks(t),
	}))

	signed := key.sign(t, validRequestObjectClaims(key.kid))

	t.Run("plain http is refused", func(t *testing.T) {
		r := requestObjectRequest(t, map[string]string{
			"client_id":    "client-1",
			"redirect_uri": "https://client.example.com/cb",
			"request_uri":  "http://client.example.com/request.jwt",
		})
		require.NoError(t, r.ParseForm())

		err := h.resolveRequestObject(r)
		redirect := requireRedirectError(t, err)
		assert.Equal(t, oauth2.InvalidRequestURI, redirect.Type)
	})

	t.Run("server error", func(t *testing.T) {
		objectServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		defer objectServer.Close()
		h.HTTPClient = objectServer.Client()

		r := requestObjectRequest(t, map[string]string{
			"client_id":    "client-1",
			"redirect_uri": "https://client.example.com/cb",
			"request_uri":  objectServer.URL,
		})
		require.NoError(t, r.ParseForm())

		err := h.resolveRequestObject(r)
		redirect := requireRedirectError(t, err)
		assert.Equal(t, oauth2.InvalidRequestURI, redirect.Type)
	})

	t.Run("oversized body", func(t *testing.T) {
		objectServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", maxRequestObjectSize+1)))
		}))
		defer objectServer.Close()
		h.HTTPClient = objectServer.Client()

		r := requestObjectRequest(t, map[string]string{
			"client_id":    "client-1",
			"redirect_uri": "https://client.example.com/cb",
			"request_uri":  objectServer.URL,
		})
		require.NoError(t, r.ParseForm())

		err := h.resolveRequestObject(r)
		redirect := requireRedirectError(t, err)
		assert.Equal(t, oauth2.InvalidRequestURI, redirect.Type)
		assert.Contains(t, redirect.Description, "too large")
	})

	t.Run("both request and request_uri", func(t *testing.T) {
		r := requestObjectRequest(t, map[string]string{
			"client_id":    "client-1",
			"redirect_uri": "https://client.example.com/cb",
			"request":      signed,
			"request_uri":  "https://client.example.com/request.jwt",
		})
		require.NoError(t, r.ParseForm())

		err := h.resolveRequestObject(r)
		redirect := requireRedirectError(t, err)
		assert.Equal(t, oauth2.InvalidRequestObject, redirect.Type)
	})
}

// The authorization endpoint turns every request object failure into an OAuth2
// error response, never a 500 or a panic.
func TestHandleAuthorizationRequestObjectErrors(t *testing.T) {
	ctx := t.Context()
	_, s := newTestHandler(t, nil)
	key := newRequestObjectKey(t, "key-1")
	require.NoError(t, s.Storage.CreateClient(ctx, storage.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://client.example.com/cb"},
		Name:         "client-1",
		JWKS:         key.jwks(t),
	}))

	claims := validRequestObjectClaims(key.kid)
	claims["exp"] = s.Now().Add(-time.Minute).Unix()
	expired := key.sign(t, claims)

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth?"+url.Values{
		"client_id":    {"client-1"},
		"redirect_uri": {"https://client.example.com/cb"},
		"request":      {expired},
	}.Encode(), nil))

	require.Equal(t, http.StatusSeeOther, rr.Code)
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://client.example.com/cb", loc.Scheme+"://"+loc.Host+loc.Path)
	assert.Equal(t, oauth2.InvalidRequestObject, loc.Query().Get("error"))
}

func requireRedirectError(t *testing.T, err error) *redirectedAuthErr {
	t.Helper()
	require.Error(t, err)
	redirect, ok := err.(*redirectedAuthErr)
	require.True(t, ok, "expected a redirect error, got %T", err)
	return redirect
}
