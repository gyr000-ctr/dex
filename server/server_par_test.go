package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

// newPARTestServer builds a server with one confidential client registered for
// the pushed authorization request tests.
func newPARTestServer(t *testing.T, updateConfig func(c *Config)) (*httptest.Server, *Server) {
	t.Helper()
	return newTestServer(t, func(c *Config) {
		require.NoError(t, c.Storage.CreateClient(t.Context(), storage.Client{
			ID:           "par-client",
			Secret:       "par-secret",
			RedirectURIs: []string{"https://client.example/callback"},
		}))
		if updateConfig != nil {
			updateConfig(c)
		}
	})
}

func validPARForm() url.Values {
	return url.Values{
		"client_id":             {"par-client"},
		"client_secret":         {"par-secret"},
		"response_type":         {"code"},
		"redirect_uri":          {"https://client.example/callback"},
		"scope":                 {"openid"},
		"state":                 {"test-state"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}
}

// doPAR POSTs a pushed authorization request and returns the recorded response.
func doPAR(t *testing.T, s *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeHTTP(rr, req)
	return rr
}

// pushValid pushes a valid authorization request and returns the request_uri.
func pushValid(t *testing.T, s *Server) string {
	t.Helper()
	rr := doPAR(t, s, validPARForm())
	require.Equal(t, http.StatusCreated, rr.Code, "body: %s", rr.Body.String())

	var resp struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	require.True(t, strings.HasPrefix(resp.RequestURI, "urn:ietf:params:oauth:request_uri:"), "request_uri %q", resp.RequestURI)
	require.Greater(t, resp.ExpiresIn, 0)
	return resp.RequestURI
}

// oauth2ErrorBody decodes a JSON OAuth2 error response body.
func oauth2ErrorBody(t *testing.T, rr *httptest.ResponseRecorder) (typ, description string) {
	t.Helper()
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	return body.Error, body.Description
}

// followRedirect issues one GET against the Location rr redirected to and
// returns the new response, for walking the connector login and callback hops
// that precede the dispatcher chain followFlow knows.
func followRedirect(t *testing.T, s *Server, rr *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, rr.Code, "body: %s", rr.Body.String())
	next := httptest.NewRecorder()
	s.ServeHTTP(next, httptest.NewRequest(http.MethodGet, rr.Header().Get("Location"), nil))
	return next
}

// followRedirects walks internal redirect hops until the chain leaves the
// server, and returns the final Location (the client redirect).
func followRedirects(t *testing.T, httpServer *httptest.Server, s *Server, rr *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	serverHost, err := url.Parse(httpServer.URL)
	require.NoError(t, err)
	for range 10 {
		loc, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		if loc.IsAbs() && loc.Host != serverHost.Host {
			return loc
		}
		rr = followRedirect(t, s, rr)
	}
	t.Fatal("followRedirects: redirect chain did not leave the server")
	return nil
}

// TestPushedAuthorizationRequestFlow pushes an authorization request, redeems
// the reference at /auth, and follows the login chain to the client redirect —
// the pinned parameters drive the flow exactly as if the browser had carried
// them. The reference is single-use.
func TestPushedAuthorizationRequestFlow(t *testing.T) {
	httpServer, s := newPARTestServer(t, nil)
	defer httpServer.Close()

	requestURI := pushValid(t, s)

	// The browser carries only the reference (and client_id).
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/auth?client_id=par-client&request_uri="+url.QueryEscape(requestURI), nil))
	require.Equal(t, http.StatusFound, rr.Code, "body: %s", rr.Body.String())

	// The first hop replays the pinned parameters toward the connector.
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/auth/mock", loc.Path)
	q := loc.Query()
	require.Equal(t, "par-client", q.Get("client_id"))
	require.Equal(t, "https://client.example/callback", q.Get("redirect_uri"))
	require.Equal(t, "openid", q.Get("scope"))
	require.Equal(t, "test-state", q.Get("state"))
	require.Equal(t, "test-challenge", q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	// The reference itself does not leak into the flow.
	require.Empty(t, q.Get("request_uri"))
	// The client secret is never pinned nor replayed.
	require.Empty(t, q.Get("client_secret"))

	// The chain continues — connector login, callback, dispatcher — and settles
	// on the client redirect with a code and the pinned state.
	finalLoc := followRedirects(t, httpServer, s, rr)
	require.Equal(t, "https", finalLoc.Scheme)
	require.Equal(t, "client.example", finalLoc.Host)
	require.Equal(t, "/callback", finalLoc.Path)
	require.NotEmpty(t, finalLoc.Query().Get("code"))
	require.Equal(t, "test-state", finalLoc.Query().Get("state"))

	// Single-use: the reference is gone.
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/auth?client_id=par-client&request_uri="+url.QueryEscape(requestURI), nil))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "invalid_request_uri")
}

// TestPushedAuthorizationEndpointErrors covers the PAR endpoint's OAuth2 error
// surface: client authentication, parameter conflicts, and PKCE validation all
// answer with standard JSON errors, never a 500.
func TestPushedAuthorizationEndpointErrors(t *testing.T) {
	withForm := func(form url.Values, key, value string) url.Values {
		if value == "" {
			form.Del(key)
		} else {
			form.Set(key, value)
		}
		return form
	}

	tests := []struct {
		name         string
		enforecePKCE bool
		mutate       func(form url.Values) url.Values
		method       string
		wantStatus   int
		wantError    string
	}{
		{
			name:       "wrong client secret",
			mutate:     func(f url.Values) url.Values { return withForm(f, "client_secret", "wrong") },
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
		{
			name:       "unknown client",
			mutate:     func(f url.Values) url.Values { return withForm(f, "client_id", "no-such-client") },
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
		{
			name: "missing client authentication",
			mutate: func(f url.Values) url.Values {
				f.Del("client_id")
				f.Del("client_secret")
				return f
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_client",
		},
		{
			name: "request_uri inside pushed request",
			mutate: func(f url.Values) url.Values {
				return withForm(f, "request_uri", "urn:ietf:params:oauth:request_uri:abc")
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "unregistered redirect_uri",
			mutate:     func(f url.Values) url.Values { return withForm(f, "redirect_uri", "https://evil.example/callback") },
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "missing openid scope",
			mutate:     func(f url.Values) url.Values { return withForm(f, "scope", "email") },
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_scope",
		},
		{
			name:       "unsupported response_type",
			mutate:     func(f url.Values) url.Values { return withForm(f, "response_type", "foo") },
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "unsupported PKCE method",
			mutate:     func(f url.Values) url.Values { return withForm(f, "code_challenge_method", "S512") },
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:         "missing PKCE when enforced",
			enforecePKCE: true,
			mutate:       func(f url.Values) url.Values { return withForm(f, "code_challenge", "") },
			wantStatus:   http.StatusBadRequest,
			wantError:    "invalid_request",
		},
		{
			name:       "GET is not allowed",
			mutate:     func(f url.Values) url.Values { return f },
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
			wantError:  "invalid_request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpServer, s := newPARTestServer(t, func(c *Config) {
				if tc.enforecePKCE {
					c.PKCE.Enforce = true
				}
			})
			defer httpServer.Close()

			form := tc.mutate(validPARForm())
			var rr *httptest.ResponseRecorder
			if tc.method == http.MethodGet {
				rr = httptest.NewRecorder()
				s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/par?"+form.Encode(), nil))
			} else {
				rr = doPAR(t, s, form)
			}

			require.Equal(t, tc.wantStatus, rr.Code, "body: %s", rr.Body.String())
			typ, _ := oauth2ErrorBody(t, rr)
			require.Equal(t, tc.wantError, typ)
		})
	}
}

// TestPushedAuthorizationClientIDConflict: credentials in the Authorization
// header conflicting with the form client_id are rejected.
func TestPushedAuthorizationClientIDConflict(t *testing.T) {
	httpServer, s := newPARTestServer(t, nil)
	defer httpServer.Close()

	form := validPARForm()
	form.Set("client_id", "some-other-client")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("par-client", "par-secret")
	s.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	typ, _ := oauth2ErrorBody(t, rr)
	require.Equal(t, "invalid_request", typ)
}

// TestAuthorizeRequestURIErrors covers the authorization endpoint's handling of
// a request_uri: unknown, malformed, expired, conflicting, and mismatched
// references are standard OAuth2 errors rendered to the browser, never a 500.
func TestAuthorizeRequestURIErrors(t *testing.T) {
	validURI := "urn:ietf:params:oauth:request_uri:" + storage.NewID()

	tests := []struct {
		name     string
		query    string
		wantBody string
	}{
		{
			name:     "unknown reference",
			query:    "client_id=par-client&request_uri=" + url.QueryEscape(validURI),
			wantBody: "invalid_request_uri",
		},
		{
			name:     "malformed reference",
			query:    "client_id=par-client&request_uri=https%3A%2F%2Fevil.example%2Frequest.jwt",
			wantBody: "invalid_request_uri",
		},
		{
			name:     "parameters conflicting with the reference",
			query:    "client_id=par-client&scope=openid&request_uri=" + url.QueryEscape(validURI),
			wantBody: "invalid_request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpServer, s := newPARTestServer(t, nil)
			defer httpServer.Close()

			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth?"+tc.query, nil))
			require.Equal(t, http.StatusBadRequest, rr.Code, "body: %s", rr.Body.String())
			require.Contains(t, rr.Body.String(), tc.wantBody)
		})
	}
}

// TestAuthorizeRequestURIClientMismatch: the client_id at /auth must name the
// client that pushed the request.
func TestAuthorizeRequestURIClientMismatch(t *testing.T) {
	httpServer, s := newPARTestServer(t, nil)
	defer httpServer.Close()

	requestURI := pushValid(t, s)

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/auth?client_id=another-client&request_uri="+url.QueryEscape(requestURI), nil))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "invalid_request")
}

// TestAuthorizeRequestURIExpired: an expired reference is rejected and
// consumed; it cannot be redeemed later.
func TestAuthorizeRequestURIExpired(t *testing.T) {
	now := time.Now()
	httpServer, s := newPARTestServer(t, func(c *Config) {
		c.Now = func() time.Time { return now }
	})
	defer httpServer.Close()

	requestURI := pushValid(t, s)

	// Move past the reference lifetime (default 1 minute).
	now = now.Add(2 * time.Minute)

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/auth?client_id=par-client&request_uri="+url.QueryEscape(requestURI), nil))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "invalid_request_uri")
	require.Contains(t, rr.Body.String(), "expired")

	// The expired reference was consumed: it stays rejected.
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/auth?client_id=par-client&request_uri="+url.QueryEscape(requestURI), nil))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "invalid_request_uri")
}

// TestDiscoveryAdvertisesPAR: the discovery document names the pushed
// authorization request endpoint (RFC 9126 §5).
func TestDiscoveryAdvertisesPAR(t *testing.T) {
	httpServer, s := newPARTestServer(t, nil)
	defer httpServer.Close()

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	require.Equal(t, http.StatusOK, rr.Code)

	var doc map[string]interface{}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&doc))
	require.Equal(t, httpServer.URL+"/auth/par", doc["pushed_authorization_request_endpoint"])
}
