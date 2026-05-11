package oidc

import (
	"errors"
	"fmt"
	"strings"
)

// RenderSPIFFEID interpolates the placeholders {sub}, {idp}, {email},
// {preferred_username}, {name} in template using values from c. A
// placeholder that resolves to an empty string is a hard error so a
// misconfigured template fails fast instead of producing a SPIFFE ID
// with an empty path segment.
//
// Substitution is single-pass via strings.NewReplacer, so a claim
// value that happens to contain another placeholder literal (e.g.
// an email "alice+{sub}@example.com") cannot trigger a second
// round of replacement.
//
// Result is intentionally NOT URL-escaped: the caller (api package)
// passes the rendered string into spiffeid.FromString, which is the
// canonical validator. Operators are responsible for choosing
// placeholders whose values are SPIFFE-path-safe (no `/` in `email`
// is the most common gotcha; `preferred_username` is usually a good
// pick).
func RenderSPIFFEID(template string, c *Claims) (string, error) {
	if c == nil {
		return "", errors.New("oidc: claims are nil")
	}
	// Pre-flight: reject empty claim values for placeholders that
	// appear in the template. The order here is the canonical order
	// of the Replacer pairs below; keep them in sync.
	checks := []struct{ placeholder, value string }{
		{"{sub}", c.Subject},
		{"{idp}", c.IdPName},
		{"{email}", c.Email},
		{"{preferred_username}", c.PreferredUN},
		{"{name}", c.Name},
	}
	for _, ck := range checks {
		if ck.value == "" && strings.Contains(template, ck.placeholder) {
			return "", fmt.Errorf("oidc: template uses %s but the claim is empty", ck.placeholder)
		}
	}
	return strings.NewReplacer(
		"{sub}", c.Subject,
		"{idp}", c.IdPName,
		"{email}", c.Email,
		"{preferred_username}", c.PreferredUN,
		"{name}", c.Name,
	).Replace(template), nil
}
