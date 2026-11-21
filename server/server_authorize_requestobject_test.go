package server

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
)

// requestObjectKey is a client's signing key for the end-to-end tests.
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

func (k *requestObjectKey) jwks() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &k.private.PublicKey,
		KeyID:     k.kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
}

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

// A client that signs its authorization request gets an ordinary code flow out
// of it: the signed parameters drive login, and a parameter tampered with in the
// URL is reported instead of honoured.
func TestAuthorizationWithSignedRequestObject(t *testing.T) {
	ctx := t.Context()
	const (
		clientID    = "signed-client"
		redirectURI = "http://127.0.0.1:5555/callback"
	)

	httpServer, s := newTestServer(t, func(c *Config) {
		c.SkipApprovalScreen = true
	})

	key := newRequestObjectKey(t, "key-1")
	require.NoError(t, s.storage.CreateClient(ctx, storage.Client{
		ID:           clientID,
		Name:         "signed client",
		RedirectURIs: []string{redirectURI},
		JWKS:         key.jwks(),
	}))

	claims := func() map[string]any {
		return map[string]any{
			"iss":           clientID,
			"aud":           httpServer.URL,
			"exp":           time.Now().Add(5 * time.Minute).Unix(),
			"client_id":     clientID,
			"redirect_uri":  redirectURI,
			"response_type": "code",
			"scope":         "openid email",
			"state":         "signed-state",
		}
	}

	t.Run("issues a code", func(t *testing.T) {
		authURL := httpServer.URL + "/auth?" + url.Values{
			"client_id":    {clientID},
			"redirect_uri": {redirectURI},
			"request":      {key.sign(t, claims())},
		}.Encode()

		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, authURL, nil))
		final := followServerRedirects(t, s, httpServer.URL, rr)

		// The flow ends at the client's callback with a code and the signed state,
		// not an OAuth2 error.
		require.True(t, final.Code == http.StatusFound || final.Code == http.StatusSeeOther, "unexpected status %d", final.Code)
		loc, err := url.Parse(final.Header().Get("Location"))
		require.NoError(t, err)
		assert.Empty(t, loc.Query().Get("error"))
		assert.NotEmpty(t, loc.Query().Get("code"))
		assert.Equal(t, "signed-state", loc.Query().Get("state"))
	})

	t.Run("rejects a tampered parameter", func(t *testing.T) {
		authURL := httpServer.URL + "/auth?" + url.Values{
			"client_id":    {clientID},
			"redirect_uri": {redirectURI},
			"state":        {"tampered"},
			"request":      {key.sign(t, claims())},
		}.Encode()

		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, authURL, nil))

		require.Equal(t, http.StatusSeeOther, rr.Code)
		loc, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, oauth2.InvalidRequestObject, loc.Query().Get("error"))
	})

	t.Run("rejects an expired object", func(t *testing.T) {
		expired := claims()
		expired["exp"] = time.Now().Add(-time.Minute).Unix()

		authURL := httpServer.URL + "/auth?" + url.Values{
			"client_id":    {clientID},
			"redirect_uri": {redirectURI},
			"request":      {key.sign(t, expired)},
		}.Encode()

		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, authURL, nil))

		require.Equal(t, http.StatusSeeOther, rr.Code)
		loc, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, oauth2.InvalidRequestObject, loc.Query().Get("error"))
	})

	t.Run("rejects a wrong audience", func(t *testing.T) {
		wrongAud := claims()
		wrongAud["aud"] = "https://other-as.example.com"

		authURL := httpServer.URL + "/auth?" + url.Values{
			"client_id":    {clientID},
			"redirect_uri": {redirectURI},
			"request":      {key.sign(t, wrongAud)},
		}.Encode()

		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, authURL, nil))

		require.Equal(t, http.StatusSeeOther, rr.Code)
		loc, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, oauth2.InvalidRequestObject, loc.Query().Get("error"))
	})

	t.Run("rejects a bad signature", func(t *testing.T) {
		// Signed by a key the client did not register, with the registered kid.
		forged := newRequestObjectKey(t, "key-1")
		authURL := httpServer.URL + "/auth?" + url.Values{
			"client_id":    {clientID},
			"redirect_uri": {redirectURI},
			"request":      {forged.sign(t, claims())},
		}.Encode()

		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, authURL, nil))

		require.Equal(t, http.StatusSeeOther, rr.Code)
		loc, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, oauth2.InvalidRequestObject, loc.Query().Get("error"))
	})
}

// followServerRedirects walks redirects that stay on the dex server, including
// the mock connector's login and callback, until the flow leaves for the
// client's redirect_uri.
func followServerRedirects(t *testing.T, s *Server, issuer string, rr *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	for range 20 {
		if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
			return rr
		}
		loc := rr.Header().Get("Location")
		u, err := url.Parse(loc)
		require.NoError(t, err)
		if u.IsAbs() && !strings.HasPrefix(u.String(), issuer) {
			return rr
		}
		next := httptest.NewRecorder()
		s.ServeHTTP(next, httptest.NewRequest(http.MethodGet, loc, nil))
		rr = next
	}
	t.Fatal("followServerRedirects did not settle")
	return rr
}

// A request object larger than the limit is refused without being parsed, and
// the response is an OAuth2 error rather than a 500.
func TestAuthorizationWithOversizedRequestObject(t *testing.T) {
	ctx := t.Context()
	const (
		clientID    = "signed-client"
		redirectURI = "http://127.0.0.1:5555/callback"
	)

	httpServer, s := newTestServer(t, nil)
	key := newRequestObjectKey(t, "key-1")
	require.NoError(t, s.storage.CreateClient(ctx, storage.Client{
		ID:           clientID,
		Name:         "signed client",
		RedirectURIs: []string{redirectURI},
		JWKS:         key.jwks(),
	}))

	huge := make([]byte, 128<<10)
	_, err := rand.Read(huge)
	require.NoError(t, err)

	authURL := httpServer.URL + "/auth?" + url.Values{
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
		"request":      {string(huge)},
	}.Encode()

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, authURL, nil))

	require.Equal(t, http.StatusSeeOther, rr.Code)
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, oauth2.InvalidRequestObject, loc.Query().Get("error"))
}
