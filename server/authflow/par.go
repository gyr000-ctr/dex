package authflow

// par.go implements OAuth 2.0 Pushed Authorization Requests (RFC 9126). The
// client POSTs the authorization parameters to the PAR endpoint directly and
// gets back a one-time request_uri; the browser then carries only that
// reference to /auth, so the parameters cannot be read or altered in transit.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dexidp/dex/server/grants"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

// requestURIPrefix is the URN scheme every issued request_uri carries
// (RFC 9126 §2.1).
const requestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// defaultPARRequestsValidFor bounds the reference lifetime when the server
// config sets none. RFC 9126 expects the reference to be short-lived: it only
// has to survive the redirect from the client's backend to the browser.
const defaultPARRequestsValidFor = time.Minute

// pushedAuthorizationResponse is the PAR success response (RFC 9126 §2.1).
type pushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// parRequestsValidFor is the configured reference lifetime, or the default.
func (h *Handler) parRequestsValidFor() time.Duration {
	if h.PARRequestsValidFor > 0 {
		return h.PARRequestsValidFor
	}
	return defaultPARRequestsValidFor
}

// writeOAuth2Error writes a JSON OAuth2 error response (RFC 6749 §5.2).
func (h *Handler) writeOAuth2Error(w http.ResponseWriter, typ, description string, status int) {
	oauth2.WriteErrorResponse(h.Logger, w, typ, description, status)
}

// handlePushedAuthorization serves the pushed authorization request endpoint
// (RFC 9126 §2). It authenticates the client, validates the authorization
// parameters exactly as /auth would, pins them in storage, and answers with a
// single-use request_uri and its lifetime. Every failure is an OAuth2 error
// response; this endpoint never renders HTML.
func (h *Handler) handlePushedAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeOAuth2Error(w, oauth2.InvalidRequest, "Pushed authorization requires a POST request.", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.writeOAuth2Error(w, oauth2.InvalidRequest, "Failed to parse request.", http.StatusBadRequest)
		return
	}
	// A pushed request carries the parameters themselves; referencing another
	// request from here is a parameter conflict (RFC 9126 §2).
	if r.Form.Get("request_uri") != "" {
		h.writeOAuth2Error(w, oauth2.InvalidRequest, "The request_uri parameter is not allowed in a pushed authorization request.", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// RFC 9126 §2: the client MUST authenticate as it would at the token
	// endpoint. Public clients (empty secret) authenticate by client_id alone.
	clientID, clientSecret, oerr := grants.ClientCredentials(r, r.Form)
	if oerr != nil {
		h.writeOAuth2Error(w, oerr.Type, oerr.Description, oerr.Status)
		return
	}
	client, oerr := grants.AuthenticateClient(ctx, h.Storage, h.Logger, clientID, clientSecret)
	if oerr != nil {
		h.writeOAuth2Error(w, oerr.Type, oerr.Description, oerr.Status)
		return
	}
	// When credentials came from the Authorization header, a form client_id
	// naming a different client is a conflict.
	switch formID := r.Form.Get("client_id"); {
	case formID == "":
		r.Form.Set("client_id", client.ID)
	case formID != client.ID:
		h.writeOAuth2Error(w, oauth2.InvalidRequest, "The client_id parameter does not match the authenticated client.", http.StatusBadRequest)
		return
	}

	// Validate the pushed parameters exactly as the authorization endpoint
	// would — client, redirect URI, PKCE, scopes, response types — so a bad
	// request fails here, before the browser is ever involved.
	if _, _, err := h.parseAuthorizationRequest(r); err != nil {
		switch authErr := err.(type) {
		case *displayedAuthErr:
			typ := oauth2.InvalidRequest
			if authErr.Status >= http.StatusInternalServerError {
				typ = oauth2.ServerError
			}
			h.writeOAuth2Error(w, typ, authErr.Description, authErr.Status)
		case *redirectedAuthErr:
			status := http.StatusBadRequest
			if authErr.Type == oauth2.ServerError {
				status = http.StatusInternalServerError
			}
			h.writeOAuth2Error(w, authErr.Type, authErr.Description, status)
		default:
			h.writeOAuth2Error(w, oauth2.ServerError, "", http.StatusInternalServerError)
		}
		return
	}

	// Pin the parameters as received, minus the credentials.
	params := make(url.Values, len(r.Form))
	for k, v := range r.Form {
		params[k] = slices.Clone(v)
	}
	params.Del("client_secret")

	validFor := h.parRequestsValidFor()
	par := storage.PushedAuthRequest{
		ID:       storage.NewID(),
		ClientID: client.ID,
		Params:   params,
		Expiry:   h.Now().Add(validFor),
	}
	if err := h.Storage.CreatePushedAuthRequest(ctx, par); err != nil {
		h.Logger.ErrorContext(ctx, "failed to store pushed authorization request", "err", err)
		h.writeOAuth2Error(w, oauth2.ServerError, "Failed to store the pushed authorization request.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(pushedAuthorizationResponse{
		RequestURI: requestURIPrefix + par.ID,
		ExpiresIn:  int(validFor / time.Second),
	}); err != nil {
		h.Logger.ErrorContext(ctx, "failed to write pushed authorization response", "err", err)
	}
}

// resolveRequestURI handles an authorization request carrying a request_uri
// (RFC 9126 §4): it validates the reference against the pushed request,
// consumes it, and swaps the pinned parameters into the request form so the
// flow continues exactly as if the browser had brought them. It reports
// whether processing may continue; on false the error is already rendered.
func (h *Handler) resolveRequestURI(w http.ResponseWriter, r *http.Request) bool {
	// Only client_id may accompany the reference; any other parameter would
	// conflict with the pinned ones (RFC 9126 §4).
	for k := range r.Form {
		if k != "request_uri" && k != "client_id" {
			h.renderError(r, w, http.StatusBadRequest, "invalid_request: no parameters besides client_id may accompany request_uri.")
			return false
		}
	}

	uri := r.Form.Get("request_uri")
	id, ok := strings.CutPrefix(uri, requestURIPrefix)
	if !ok || id == "" {
		h.renderError(r, w, http.StatusBadRequest, "invalid_request_uri: malformed request_uri.")
		return false
	}

	ctx := r.Context()
	par, err := h.Storage.GetPushedAuthRequest(ctx, id)
	if err != nil {
		if err == storage.ErrNotFound {
			h.renderError(r, w, http.StatusBadRequest, "invalid_request_uri: unknown request_uri.")
			return false
		}
		h.Logger.ErrorContext(ctx, "failed to get pushed authorization request", "err", err)
		h.renderError(r, w, http.StatusInternalServerError, "Database error.")
		return false
	}
	if h.Now().After(par.Expiry) {
		// Best-effort cleanup; garbage collection is the real bound.
		if err := h.Storage.DeletePushedAuthRequest(ctx, id); err != nil {
			h.Logger.ErrorContext(ctx, "failed to delete expired pushed authorization request", "err", err)
		}
		h.renderError(r, w, http.StatusBadRequest, "invalid_request_uri: request_uri has expired.")
		return false
	}
	if clientID := r.Form.Get("client_id"); clientID != "" && clientID != par.ClientID {
		h.renderError(r, w, http.StatusBadRequest, "invalid_request: client_id does not match the pushed authorization request.")
		return false
	}

	// The reference is single-use: the delete is atomic, so a concurrent or
	// repeated request loses the race and is rejected as unknown.
	if err := h.Storage.DeletePushedAuthRequest(ctx, id); err != nil {
		if err == storage.ErrNotFound {
			h.renderError(r, w, http.StatusBadRequest, "invalid_request_uri: unknown request_uri.")
			return false
		}
		h.Logger.ErrorContext(ctx, "failed to consume pushed authorization request", "err", err)
		h.renderError(r, w, http.StatusInternalServerError, "Database error.")
		return false
	}

	// Replay the pinned parameters as the request's own.
	form := make(url.Values, len(par.Params))
	for k, v := range par.Params {
		form[k] = slices.Clone(v)
	}
	r.Form = form
	r.PostForm = nil
	r.URL.RawQuery = ""
	return true
}
