package policy

import "net/http"

// RequestIDHeader is the header AuthZEN 1.0 §10.1.3 recommends for the
// request identifier. A PDP that receives one MUST return the same
// identifier on the response.
const RequestIDHeader = "X-Request-ID"

// MaxRequestIDBytes bounds a request identifier. The spec calls the
// value an arbitrary string; omega bounds it because the id is written
// into the audit chain and logs, where an unbounded caller-chosen
// string is a storage and injection surface. 128 bytes holds a UUID,
// a ULID, a W3C trace id or a hex digest with room to spare.
const MaxRequestIDBytes = 128

// ValidRequestID reports whether id is a request identifier omega will
// echo and record: 1 to MaxRequestIDBytes bytes of letters, digits and
// the punctuation `-._~:/+=@;`. That covers UUIDs, ULIDs, base64 and
// the common proxy formats while keeping quotes, backslashes, spaces,
// control characters and non-ASCII bytes out of the audit log.
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

// RequestIDFrom returns the request identifier the caller sent, and
// whether it is acceptable. A request without the header is fine and
// returns ("", true). More than one header, or a value ValidRequestID
// rejects, returns ok false: the PDP cannot echo "the same identifier"
// when it was given two, and will not record one it cannot store
// safely.
func RequestIDFrom(h http.Header) (id string, ok bool) {
	vals := h.Values(RequestIDHeader)
	switch len(vals) {
	case 0:
		return "", true
	case 1:
		return vals[0], ValidRequestID(vals[0])
	default:
		return "", false
	}
}
