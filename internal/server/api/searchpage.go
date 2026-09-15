package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// pageToken is what a Search `next_token` decodes to. It is serialised
// as base64url'd JSON and treated as opaque by callers, per AuthZEN
// §8.2: the PEP is specified to echo the token back verbatim, never to
// construct or interpret one.
//
// Offset is where the next candidate window starts. Fingerprint pins
// the request the token was minted for: §8.2 requires every entity and
// pagination parameter other than the token itself to be identical
// across a paginated sequence, and says the PDP SHOULD error when one
// changed. Carrying the fingerprint inside the token enforces that
// without the PDP holding per-cursor state, which matters here because
// any replica can serve the next page.
type pageToken struct {
	Offset      int    `json:"off"`
	Fingerprint string `json:"fp"`
}

// errPageTokenMismatch is returned when a token is well-formed but was
// minted for a different request.
var errPageTokenMismatch = errors.New("page.token was issued for a different request: every field except page.token must be identical across a paginated sequence (AuthZEN 1.0 section 8.2)")

// fingerprintOf hashes everything about a Search request except its
// page token, so two requests that differ in any entity, in the
// context, or in the page limit produce different fingerprints.
//
// The request is hashed through its JSON encoding - which is also its
// wire form - with `page.token` removed, so every field a caller can
// vary is covered without this helper knowing any request's shape.
// Encoding through a map also makes key order deterministic, which
// encoding/json guarantees for maps but not for the `any` values
// inside a free-form `context`.
func fingerprintOf(req any) (string, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("fingerprint search request: %w", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "", fmt.Errorf("fingerprint search request: %w", err)
	}
	if page, ok := generic["page"].(map[string]any); ok {
		delete(page, "token")
		if len(page) == 0 {
			// `{"page":{"token":"..."}}` and no page object at all name
			// the same request; collapsing keeps their fingerprints equal
			// so the first next_token stays valid on the second page.
			delete(generic, "page")
		}
	}
	normalised, err := json.Marshal(generic)
	if err != nil {
		return "", fmt.Errorf("fingerprint search request: %w", err)
	}
	sum := sha256.Sum256(normalised)
	// Half the digest is 128 bits, far past what a tamper-detection
	// check on a non-secret needs, and keeps the token short.
	return base64.RawURLEncoding.EncodeToString(sum[:16]), nil
}

// encodePageToken renders the cursor for the next page.
func encodePageToken(offset int, fingerprint string) (string, error) {
	raw, err := json.Marshal(pageToken{Offset: offset, Fingerprint: fingerprint})
	if err != nil {
		return "", fmt.Errorf("encode page token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// decodePageToken parses a caller-supplied token and checks it against
// the fingerprint of the request carrying it.
func decodePageToken(token, fingerprint string) (int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("page.token is not a valid token: %w", err)
	}
	var pt pageToken
	if err := json.Unmarshal(raw, &pt); err != nil {
		return 0, fmt.Errorf("page.token is not a valid token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(pt.Fingerprint), []byte(fingerprint)) != 1 {
		return 0, errPageTokenMismatch
	}
	if pt.Offset < 0 {
		return 0, errors.New("page.token carries a negative offset")
	}
	return pt.Offset, nil
}

// searchWindow resolves the request's page object into the half-open
// candidate window [start, end) over a search space of size total, plus
// the response page object to echo back.
//
// The window is over the search space rather than over the matches:
// candidates are evaluated only inside it, which is what bounds the PDP
// work and the audit rows one request can cost. limit is clamped to
// MaxSearchCandidates for the same reason.
func searchWindow(page *SearchPageRequest, total int, fingerprint string) (start, end int, next string, err error) {
	limit := MaxSearchCandidates
	if page != nil {
		if page.Limit != nil {
			switch {
			case *page.Limit < 0:
				return 0, 0, "", errors.New("page.limit must not be negative")
			case *page.Limit < limit:
				// Zero lands here and is honoured as written: the caller
				// asked for at most no results, and gets an empty page
				// plus a token that says whether more exist.
				limit = *page.Limit
			}
		}
		if page.Token != "" {
			start, err = decodePageToken(page.Token, fingerprint)
			if err != nil {
				return 0, 0, "", err
			}
		}
	}
	if start > total {
		start = total
	}
	end = min(start+limit, total)
	if end < total {
		next, err = encodePageToken(end, fingerprint)
		if err != nil {
			return 0, 0, "", err
		}
	}
	return start, end, next, nil
}
