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
// Result is intentionally NOT URL-escaped, but substituted claim
// values are sanitized: a value carrying a `/` or a control character
// is rejected before rendering. Downstream only checks
// MemberOf(trustDomain), which validates the domain but not the path,
// so an unescaped `/` in a claim like name="admin/svc" would forge an
// extra, possibly privileged, path segment. The caller still passes
// the rendered string into spiffeid.FromString as the canonical
// structural validator.
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
		if !strings.Contains(template, ck.placeholder) {
			continue
		}
		if ck.value == "" {
			return "", fmt.Errorf("oidc: template uses %s but the claim is empty", ck.placeholder)
		}
		if err := checkSPIFFEPathSegment(ck.placeholder, ck.value); err != nil {
			return "", err
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

// checkSPIFFEPathSegment rejects a claim value that would inject extra
// SPIFFE path structure when substituted into the ID template. A `/`
// forges an additional path segment (e.g. name="admin/svc"); control
// characters (incl. NUL, CR, LF) are never valid in a SPIFFE path and
// indicate a malicious or malformed claim.
func checkSPIFFEPathSegment(placeholder, value string) error {
	if strings.ContainsRune(value, '/') {
		return fmt.Errorf("oidc: claim for %s contains '/', which would inject an extra SPIFFE path segment", placeholder)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("oidc: claim for %s contains a control character", placeholder)
		}
	}
	return nil
}
