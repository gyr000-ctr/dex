package authflow

// requestobject.go implements signed authorization request objects (RFC 9101,
// "JWT-Secured Authorization Request" / JAR). A client signs the whole
// authorization request with its own private key and passes the JWS either
// by value in the "request" parameter or by reference in "request_uri"; dex
// verifies the signature against the key set registered for that client and
// takes every authorization parameter from the verified object. The browser
// then only carries an opaque signed blob, so a third party who changes
// redirect_uri in transit cannot alter the request without invalidating the
// signature.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

const (
	// maxRequestObjectSize bounds a request object taken by value. A request
	// object is a set of short OAuth parameters; anything approaching this size
	// is not a request we should spend memory parsing and is refused before the
	// body is read.
	maxRequestObjectSize = 64 << 10 // 64 KiB

	// maxRequestURISize bounds the request_uri value itself (RFC 9101 §5.2 asks
	// for at most 512 ASCII characters).
	maxRequestURISize = 8 << 10

	// requestObjectFetchTimeout bounds the request_uri fetch; the user is
	// waiting on this request in a browser.
	requestObjectFetchTimeout = 10 * time.Second

	// requestObjectMediaType is the media type of a request object (RFC 9101
	// §9.4). Deployments in the wild also serve it as application/jwt.
	requestObjectMediaType = "application/oauth-authz-req+jwt"
)

// requestObjectClaims is the subset of a request object dex interprets as JWT
// claims rather than as OAuth authorization parameters.
type requestObjectClaims struct {
	Issuer    string          `json:"iss"`
	Audience  json.RawMessage `json:"aud"`
	Expiry    *json.Number    `json:"exp"`
	NotBefore *json.Number    `json:"nbf"`
	IssuedAt  *json.Number    `json:"iat"`
}

// requestObjectAlgorithms are the JWS algorithms a request object may use. Only
// asymmetric algorithms are accepted: a symmetric (HMAC) request object would be
// signed with a shared secret, which a public client cannot keep, and "none"
// would be no protection at all. The list is advertised in the discovery
// document.
var requestObjectAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// RequestObjectAlgorithmsSupported returns the advertised JWS algorithms for
// signed request objects, as strings.
func RequestObjectAlgorithmsSupported() []string {
	algs := make([]string, len(requestObjectAlgorithms))
	for i, alg := range requestObjectAlgorithms {
		algs[i] = string(alg)
	}
	return algs
}

// requestObjectError is a failed request object, carrying the OAuth2 error code
// (RFC 9101 §7) the authorization endpoint must return. It is reported to the
// client by redirect once the client and redirect_uri are known to be valid.
type requestObjectError struct {
	Type        string
	Description string
}

func (e *requestObjectError) Error() string { return e.Description }

func newRequestObjectError(typ, format string, a ...interface{}) *requestObjectError {
	return &requestObjectError{Type: typ, Description: fmt.Sprintf(format, a...)}
}

// verifiedRequestObject is a request object whose signature, issuer, audience
// and time claims have been checked, with the payload decoded into the
// authorization parameters it carries.
type verifiedRequestObject struct {
	params url.Values
}

// present reports whether the HTTP request carries a request object either by
// value or by reference. The caller must have parsed the form.
func requestObjectPresent(form url.Values) bool {
	return form.Get("request") != "" || form.Get("request_uri") != ""
}

// readSignedRequestObject obtains the signed request object from the request,
// either the "request" parameter value or the content fetched from
// "request_uri", and enforces the size bound before anything is parsed.
func (h *Handler) readSignedRequestObject(ctx context.Context, form url.Values) (string, error) {
	byValue := form.Get("request")
	byReference := form.Get("request_uri")

	switch {
	case byValue != "" && byReference != "":
		// RFC 9101 §5: the two are mutually exclusive.
		return "", newRequestObjectError(oauth2.InvalidRequestObject, "Only one of request and request_uri may be provided.")
	case byValue != "":
		if len(byValue) > maxRequestObjectSize {
			return "", newRequestObjectError(oauth2.InvalidRequestObject, "The request object is too large.")
		}
		return byValue, nil
	case byReference != "":
		return h.fetchRequestObject(ctx, byReference)
	default:
		return "", nil
	}
}

// fetchRequestObject resolves a request_uri reference. Per RFC 9101 §5.2.3 dex
// fetches the object itself over HTTPS; a plain HTTP URI or a URI dex would have
// to resolve through itself is refused rather than followed.
func (h *Handler) fetchRequestObject(ctx context.Context, rawURI string) (string, error) {
	if len(rawURI) > maxRequestURISize {
		return "", newRequestObjectError(oauth2.InvalidRequestURI, "The request_uri is too long.")
	}
	u, err := url.Parse(rawURI)
	if err != nil || !u.IsAbs() {
		return "", newRequestObjectError(oauth2.InvalidRequestURI, "The request_uri is not an absolute URI.")
	}
	// RFC 9101 §5.2: a request_uri that is not issued by the authorization
	// server must be an https URI. Dex does not issue request URIs, so only
	// https is accepted.
	if u.Scheme != "https" {
		return "", newRequestObjectError(oauth2.InvalidRequestURI, "The request_uri must use https.")
	}
	// Never fetch dex's own endpoints: a request_uri pointing back at the
	// authorization endpoint is the recursive-fetch attack RFC 9101 §10.4 warns
	// about, and a client has no reason to host a request object inside dex.
	if strings.EqualFold(u.Host, h.IssuerURL.Host) {
		return "", newRequestObjectError(oauth2.InvalidRequestURI, "The request_uri must not point at the authorization server.")
	}

	fetchCtx, cancel := context.WithTimeout(ctx, requestObjectFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, rawURI, nil)
	if err != nil {
		return "", newRequestObjectError(oauth2.InvalidRequestURI, "The request_uri could not be retrieved.")
	}
	req.Header.Set("Accept", requestObjectMediaType+", application/jwt")

	client := h.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to fetch request_uri", "request_uri", rawURI, "err", err)
		return "", newRequestObjectError(oauth2.InvalidRequestURI, "The request_uri could not be retrieved.")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		h.Logger.ErrorContext(ctx, "request_uri returned an error", "request_uri", rawURI, "status", resp.StatusCode)
		return "", newRequestObjectError(oauth2.InvalidRequestURI, "The request_uri could not be retrieved.")
	}

	// Read one byte past the limit to tell an oversized body from one exactly at
	// the limit, without buffering the rest.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestObjectSize+1))
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to read request_uri", "request_uri", rawURI, "err", err)
		return "", newRequestObjectError(oauth2.InvalidRequestURI, "The request_uri could not be retrieved.")
	}
	if len(body) > maxRequestObjectSize {
		return "", newRequestObjectError(oauth2.InvalidRequestURI, "The request object is too large.")
	}
	return string(bytes.TrimSpace(body)), nil
}

// verifyRequestObject verifies the JWS of a request object against the client's
// registered keys and validates its iss, aud, exp and nbf claims. The signature
// is checked before the payload is decoded, so unverified parameters are never
// used for anything but error reporting.
func (h *Handler) verifyRequestObject(ctx context.Context, client storage.Client, raw string) (*verifiedRequestObject, error) {
	if raw == "" {
		return nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object is empty.")
	}
	if len(raw) > maxRequestObjectSize {
		return nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object is too large.")
	}
	keys := publicClientKeys(client)
	if len(keys.Keys) == 0 {
		return nil, newRequestObjectError(oauth2.InvalidRequestObject, "The client has no registered keys for signed request objects.")
	}

	sig, err := jose.ParseSigned(raw, requestObjectAlgorithms)
	if err != nil {
		// Also covers an encrypted (JWE) object: dex advertises no encryption
		// support, so it cannot be unwrapped.
		return nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object is not a valid signed JWS.")
	}
	if len(sig.Signatures) != 1 {
		// RFC 9101 §6.2: exactly one signature is validated against exactly one
		// client key; a multi-signature object would leave which key applies
		// ambiguous.
		return nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object must carry exactly one signature.")
	}

	// The "kid" must select one of the client's keys. With several keys and no
	// kid there is nothing to choose by, so that is ambiguous too.
	if err := checkRequestObjectKeyID(client, sig.Signatures[0]); err != nil {
		return nil, err
	}
	payload, err := sig.Verify(keys)
	if err != nil {
		return nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object signature could not be verified.")
	}

	claims, params, err := decodeRequestObject(payload)
	if err != nil {
		return nil, err
	}
	if err := h.validateRequestObjectClaims(client, claims); err != nil {
		return nil, err
	}
	return &verifiedRequestObject{params: params}, nil
}

// publicClientKeys returns the client's registered keys usable for verifying a
// request object. Only public keys can verify a signature; a registered private
// or symmetric key is ignored rather than used, and a client whose key set holds
// nothing else cannot use signed request objects.
func publicClientKeys(client storage.Client) jose.JSONWebKeySet {
	if client.JWKS == nil {
		return jose.JSONWebKeySet{}
	}
	keys := jose.JSONWebKeySet{}
	for _, key := range client.JWKS.Keys {
		if key.Valid() && key.IsPublic() {
			keys.Keys = append(keys.Keys, key)
		}
	}
	return keys
}

// checkRequestObjectKeyID enforces RFC 9101 §6.2: if a kid is present it must
// name a key of the client, and with several registered keys a kid is required
// to make the choice unambiguous.
func checkRequestObjectKeyID(client storage.Client, signature jose.Signature) error {
	kid := signature.Header.KeyID
	if kid == "" {
		if len(publicClientKeys(client).Keys) > 1 {
			return newRequestObjectError(oauth2.InvalidRequestObject, "The request object must identify its signing key with a kid.")
		}
		return nil
	}
	for _, key := range publicClientKeys(client).Keys {
		if key.KeyID == kid {
			return nil
		}
	}
	return newRequestObjectError(oauth2.InvalidRequestObject, "The request object is signed with a key that is not registered for the client.")
}

// decodeRequestObject splits the verified payload into JWT claims and
// authorization parameters. Parameter values must be JSON strings, as RFC 9101
// §4 requires; a client repeating a parameter (a JSON array) is refused rather
// than having one of the values silently picked.
func decodeRequestObject(payload []byte) (requestObjectClaims, url.Values, error) {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return requestObjectClaims{}, nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object payload is not a JSON object.")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return requestObjectClaims{}, nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object payload has trailing data.")
	}

	params := make(url.Values, len(raw))
	for name, value := range raw {
		switch name {
		case "iss", "aud", "exp", "nbf", "iat", "jti", "sub":
			// Registered JWT claims belong to the JWT, not to the OAuth request
			// (RFC 9101 §9.1); they are validated below and not passed on.
			continue
		case "request", "request_uri":
			// RFC 9101 §4: a request object must not nest another request.
			return requestObjectClaims{}, nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object must not contain request or request_uri.")
		}
		var str string
		switch name {
		case "max_age":
			// RFC 9101 §4: numerical values are JSON numbers. max_age is the one
			// OAuth parameter dex defines as an integer.
			var n json.Number
			if err := json.Unmarshal(value, &n); err == nil {
				str = n.String()
			}
		}
		if str == "" {
			decoded, ok := decodeRequestObjectString(value)
			if !ok {
				return requestObjectClaims{}, nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object parameter %q must be a single JSON string.", name)
			}
			str = decoded
		}
		params[name] = []string{str}
	}

	claims := requestObjectClaims{
		Issuer:    decodeRequestObjectClaimString(raw["iss"]),
		Audience:  raw["aud"],
		Expiry:    numberValue(raw["exp"]),
		NotBefore: numberValue(raw["nbf"]),
		IssuedAt:  numberValue(raw["iat"]),
	}
	return claims, params, nil
}

func decodeRequestObjectClaimString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func firstValue(params url.Values, name string) string {
	if v := params[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// numberValue parses a JWT NumericDate claim. A fractional part is allowed, but
// anything that is not a JSON number yields nil so the caller reports the claim
// as missing rather than silently treating it as zero.
func numberValue(raw json.RawMessage) *json.Number {
	if len(raw) == 0 {
		return nil
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil {
		return nil
	}
	return &n
}

// decodeRequestObjectString accepts exactly one JSON string. Any other type —
// including an array of repeated values — is rejected.
func decodeRequestObjectString(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	return "", false
}

// validateRequestObjectClaims enforces the JWT claims of RFC 9101 §6.2: aud
// must name this authorization server, iss and client_id must both name the
// client the request was made as, and exp/nbf must bracket now.
func (h *Handler) validateRequestObjectClaims(client storage.Client, claims requestObjectClaims) error {
	now := h.Now()

	// aud is compared against the issuer URL (RFC 9101 §4). The client_id in
	// the object is checked in the caller, where the client_id parameter is
	// compared too.
	if err := checkRequestObjectAudience(claims.Audience, h.IssuerURL.String()); err != nil {
		return err
	}
	// iss names the client (RFC 9101 §4, the request object's issuer is the
	// client that signed it).
	if claims.Issuer != client.ID {
		return newRequestObjectError(oauth2.InvalidRequestObject, "The request object iss does not match the client.")
	}
	if claims.Expiry == nil {
		return newRequestObjectError(oauth2.InvalidRequestObject, "The request object must have an exp claim.")
	}
	expiry, err := numericDate(*claims.Expiry)
	if err != nil {
		return newRequestObjectError(oauth2.InvalidRequestObject, "The request object exp claim is not a valid NumericDate.")
	}
	if !now.Before(expiry) {
		return newRequestObjectError(oauth2.InvalidRequestObject, "The request object has expired.")
	}
	if claims.NotBefore != nil {
		nbf, err := numericDate(*claims.NotBefore)
		if err != nil {
			return newRequestObjectError(oauth2.InvalidRequestObject, "The request object nbf claim is not a valid NumericDate.")
		}
		if now.Before(nbf) {
			return newRequestObjectError(oauth2.InvalidRequestObject, "The request object is not valid yet.")
		}
	}
	// iat is not a validity gate, but a value far in the future means the
	// client's clock is wrong and its exp cannot be trusted either.
	if claims.IssuedAt != nil {
		iat, err := numericDate(*claims.IssuedAt)
		if err != nil {
			return newRequestObjectError(oauth2.InvalidRequestObject, "The request object iat claim is not a valid NumericDate.")
		}
		if iat.After(now.Add(requestObjectClockSkew)) {
			return newRequestObjectError(oauth2.InvalidRequestObject, "The request object iat claim is in the future.")
		}
	}
	return nil
}

// requestObjectClockSkew tolerates the small clock difference between a client
// and the server when an iat is checked.
const requestObjectClockSkew = time.Minute

// checkRequestObjectAudience accepts an aud that is the issuer string, or a
// JSON array containing it, as JWT §4.1.3 allows.
func checkRequestObjectAudience(raw json.RawMessage, issuer string) error {
	if len(raw) == 0 {
		return newRequestObjectError(oauth2.InvalidRequestObject, "The request object must have an aud claim.")
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == issuer {
			return nil
		}
		return newRequestObjectError(oauth2.InvalidRequestObject, "The request object aud does not match this authorization server.")
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, audience := range many {
			if audience == issuer {
				return nil
			}
		}
	}
	return newRequestObjectError(oauth2.InvalidRequestObject, "The request object aud does not match this authorization server.")
}

// numericDate parses a JWT NumericDate, which may carry a fractional part.
func numericDate(n json.Number) (time.Time, error) {
	seconds, err := n.Float64()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, int64(seconds*float64(time.Second))).UTC(), nil
}

// resolveRequestObject verifies the signed request object carried by r and
// replaces r.Form with its parameters. Failures become a *displayedAuthErr (the
// client or its redirect_uri is not trustworthy, so there is nowhere to
// redirect) or a *redirectedAuthErr carrying the RFC 9101 error code. The
// caller must have parsed the form and checked that a request object is present.
func (h *Handler) resolveRequestObject(r *http.Request) error {
	query := r.Form
	ctx := r.Context()

	// A client_id is needed to select the keys. It may be in the URL, or only in
	// the object; the latter cannot be read safely before the signature is
	// verified, so the URL copy is what dex looks the client up by.
	clientID := query.Get("client_id")
	state := query.Get("state")
	redirectURI := query.Get("redirect_uri")

	if clientID == "" {
		// Without a client there is no key set to verify against, so nothing in
		// the object can be acted on.
		return newDisplayedErr(http.StatusBadRequest, "Invalid client_id.")
	}
	client, err := h.Storage.GetClient(ctx, clientID)
	if err != nil {
		if err == storage.ErrNotFound {
			h.Logger.ErrorContext(ctx, "invalid client_id provided", "client_id", clientID)
			return newDisplayedErr(http.StatusNotFound, "Invalid client_id.")
		}
		h.Logger.ErrorContext(ctx, "failed to get client", "client_id", clientID, "err", err)
		return newDisplayedErr(http.StatusInternalServerError, "Database error.")
	}

	// A client that registered no keys cannot have a request object verified.
	// Such a request is refused the way the old server refused every request
	// object: the feature is simply not available to this client. This keeps a
	// deployment that knows nothing about request objects behaving as before.
	if len(publicClientKeys(client).Keys) == 0 {
		redirectURI = h.normalizeRedirectURI(client, redirectURI)
		if !validateRedirectURI(client, redirectURI) {
			h.Logger.ErrorContext(ctx, "unregistered redirect_uri", "redirect_uri", redirectURI, "client_id", clientID)
			return newDisplayedErr(http.StatusBadRequest, "Unregistered redirect_uri.")
		}
		if query.Get("request") != "" {
			return &redirectedAuthErr{State: state, RedirectURI: redirectURI, Type: oauth2.RequestNotSupported, Description: "Server does not support request parameter."}
		}
		return &redirectedAuthErr{State: state, RedirectURI: redirectURI, Type: oauth2.RequestURINotSupported, Description: "Server does not support request_uri parameter."}
	}

	// The redirect_uri the error must go to is the URL's, validated the same way
	// an ordinary request's is; an unregistered one is displayed, not redirected
	// to (RFC 6749 §4.1.2.1). The object may carry the redirect_uri itself, in
	// which case there is nowhere safe to redirect before the signature is
	// verified and errors are displayed.
	redirectURI = h.normalizeRedirectURI(client, redirectURI)
	if redirectURI != "" && !validateRedirectURI(client, redirectURI) {
		h.Logger.ErrorContext(ctx, "unregistered redirect_uri", "redirect_uri", redirectURI, "client_id", clientID)
		return newDisplayedErr(http.StatusBadRequest, "Unregistered redirect_uri.")
	}

	// redirectErr reports a request object failure. Without a pre-verified
	// redirect URI there is nobody to redirect to, so it is displayed instead.
	redirectErr := func(typ, description string) error {
		if redirectURI == "" {
			return newDisplayedErr(http.StatusBadRequest, "%s: %s", typ, description)
		}
		return &redirectedAuthErr{State: state, RedirectURI: redirectURI, Type: typ, Description: description}
	}

	raw, err := h.readSignedRequestObject(ctx, query)
	if err != nil {
		h.Logger.ErrorContext(ctx, "invalid signed request object reference", "client_id", clientID, "err", err)
		return redirectErr(requestObjectErrorType(err), err.Error())
	}
	object, err := h.verifyRequestObject(ctx, client, raw)
	if err != nil {
		h.Logger.ErrorContext(ctx, "invalid signed request object", "client_id", clientID, "err", err)
		return redirectErr(requestObjectErrorType(err), err.Error())
	}

	// The client_id has to agree between the URL and the object; the object's
	// other parameters replace the URL's.
	requestKey := "request"
	if query.Get(requestKey) == "" {
		requestKey = "request_uri"
	}
	merged, err := mergeRequestObjectParameters(query, object, requestKey)
	if err != nil {
		h.Logger.ErrorContext(ctx, "request object conflicts with the authorization request", "client_id", clientID, "err", err)
		return redirectErr(requestObjectErrorType(err), err.Error())
	}

	r.Form = merged
	if r.PostForm != nil {
		r.PostForm = nil
	}
	return nil
}

// requestObjectErrorType maps a request object failure to its OAuth2 error
// code, falling back to invalid_request_object for anything not carrying one.
func requestObjectErrorType(err error) string {
	var objectErr *requestObjectError
	if errors.As(err, &objectErr) {
		return objectErr.Type
	}
	return oauth2.InvalidRequestObject
}

// normalizeRedirectURI applies the device-flow redirect_uri rewrite the ordinary
// parse does, so validation and the error redirect agree with it.
func (h *Handler) normalizeRedirectURI(client storage.Client, redirectURI string) string {
	if redirectURI == oauth2.DeviceCallbackURI && client.Public {
		return h.IssuerURL.AbsPath(oauth2.DeviceCallbackURI)
	}
	return redirectURI
}

func mergeRequestObjectParameters(query url.Values, object *verifiedRequestObject, requestKey string) (url.Values, error) {
	objectClientID := object.params.Get("client_id")
	if objectClientID == "" {
		return nil, newRequestObjectError(oauth2.InvalidRequestObject, "The request object must contain a client_id.")
	}
	// RFC 9101 §6.3: the client_id from the URL and the object's client_id claim
	// must be identical.
	if queryClientID := query.Get("client_id"); queryClientID != "" && queryClientID != objectClientID {
		return nil, newRequestObjectError(oauth2.InvalidRequestObject, "The client_id in the request object does not match the client_id parameter.")
	}

	for name, values := range query {
		// The request object is what is being validated, not a duplicated
		// parameter; neither is connector_id, dex's own hint about which
		// connector the browser picked from the selection page.
		if name == "request" || name == "request_uri" {
			continue
		}
		objectValues, ok := object.params[name]
		if !ok {
			continue
		}
		if !equalValues(values, objectValues) {
			return nil, newRequestObjectError(oauth2.InvalidRequestObject, "The %q parameter conflicts with the request object.", name)
		}
	}

	merged := make(url.Values, len(object.params)+2)
	for name, values := range object.params {
		merged[name] = values
	}
	// Re-publish the object reference so every later parse of this request
	// verifies the same signed parameters instead of trusting the merged form.
	if requestKey != "" {
		merged.Set(requestKey, query.Get(requestKey))
	}
	return merged, nil
}

// authorizationRedirectQuery returns the parameters a /auth hop carries to the
// next step in its query. For an ordinary request that is every parameter. For
// a signed request object it is only the object reference (and the client_id
// needed to select its keys), so the browser never carries the signed
// parameters in the clear: the next step verifies the object again.
func authorizationRedirectQuery(form url.Values) string {
	if _, ok := form["request"]; ok {
		q := url.Values{"request": form["request"]}
		if clientID := form.Get("client_id"); clientID != "" {
			q.Set("client_id", clientID)
		}
		return q.Encode()
	}
	if _, ok := form["request_uri"]; ok {
		q := url.Values{"request_uri": form["request_uri"]}
		if clientID := form.Get("client_id"); clientID != "" {
			q.Set("client_id", clientID)
		}
		return q.Encode()
	}
	return form.Encode()
}

// equalValues compares two copies of a repeated parameter positionally.
func equalValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
