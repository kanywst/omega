package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// RequestIDHeader is the header AuthZEN 1.0 §10.1.3 recommends for the
// request identifier. A PDP that receives one MUST return the same
// identifier on the response.
const RequestIDHeader = "X-Request-ID"

// MaxRequestIDBytes bounds a request identifier omega records as is.
// 128 bytes holds a UUID, a ULID, a W3C trace id or a hex digest with
// room to spare.
const MaxRequestIDBytes = 128

// ValidRequestID reports whether id is a request identifier omega
// records verbatim in the audit chain and on spans: 1 to
// MaxRequestIDBytes bytes of letters, digits and the punctuation
// `-._~:/+=@;`. That covers UUIDs, ULIDs, base64 and the common proxy
// formats while keeping quotes, backslashes, spaces, control characters
// and non-ASCII bytes out of stored data.
func ValidRequestID(id string) bool {
	if id == "" || len(id) > MaxRequestIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_', c == '~', c == ':', c == '/', c == '+', c == '=', c == '@', c == ';':
		default:
			return false
		}
	}
	return true
}

// RequestIDFrom returns the request identifier the caller sent, or ""
// when it sent none. Several header lines are one field (RFC 9110
// §5.3), so they are combined with ", " and echoed as that one value.
// The spec calls the identifier an arbitrary string, so any value is
// accepted here; net/http has already refused the control characters
// that could split a response header.
func RequestIDFrom(h http.Header) string {
	return strings.Join(h.Values(RequestIDHeader), ", ")
}

// RequestIDForAudit is how an identifier is stored. One that passes
// ValidRequestID is returned as plain; any other is returned only as
// its hex SHA-256 in digest, so an oversized or log-unsafe caller string
// never reaches the audit chain, and the row can still be matched by
// hashing the PEP's own copy of the id.
func RequestIDForAudit(id string) (plain, digest string) {
	if id == "" {
		return "", ""
	}
	if ValidRequestID(id) {
		return id, ""
	}
	sum := sha256.Sum256([]byte(id))
	return "", hex.EncodeToString(sum[:])
}
