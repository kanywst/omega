package identity

// SourceKind identifies where Omega's SPIFFE identities come from. It is
// a different axis from Kind: Kind selects the CA backend that signs
// (disk / vault-pki / step-ca) when Omega is the issuer, whereas
// SourceKind selects whether Omega issues at all or consumes identities
// minted by an upstream SPIFFE issuer.
type SourceKind string

const (
	// SourceBuiltIn means Omega issues its own SVIDs through an
	// Authority (the CA backend selected by Kind). The self-signed disk
	// default is for dev/eval; vault-pki / step-ca are production CAs.
	SourceBuiltIn SourceKind = "built-in"

	// SourceSPIREUpstream means Omega consumes SPIFFE identities issued
	// by an upstream SPIRE/Istio trust domain instead of issuing its
	// own. Reserved: the consuming Source is not implemented yet.
	SourceSPIREUpstream SourceKind = "spire-upstream"
)

// Source is the identity-source seam that sits above Authority. Today the
// only implementation wraps a built-in Authority, so Source embeds the
// full Authority method set; an upstream-SPIFFE Source (consuming SPIRE)
// will satisfy the same interface by proxying issuance/validation to the
// upstream, letting the API server depend on Source without caring which
// origin is wired in.
type Source interface {
	Authority

	// SourceKind reports the identity origin, for diagnostics and for
	// the dev/eval-only guard on the self-signed built-in CA.
	SourceKind() SourceKind
}

// ReloadableSource is a Source whose trust material can be replaced while
// the process runs. Only a consuming source implements it: an issuing
// Authority owns its key material and has nothing to re-read. Callers
// type-assert rather than depend on it.
type ReloadableSource interface {
	Source

	// Reload installs replacement trust material, reporting whether it
	// differed. Fail-closed: on error the previous material stays.
	Reload(x509BundlePEM, jwtJWKS []byte) (bool, error)
}

// BundleSequencer backs the SPIFFE `spiffe_sequence` field. A Source that
// cannot rotate mid-process does not implement it, and callers fall back
// to a fixed sequence.
type BundleSequencer interface {
	BundleSequence() int64
}

// builtinSource adapts an Authority (Omega-as-issuer) to the Source seam.
type builtinSource struct {
	Authority
}

func (builtinSource) SourceKind() SourceKind { return SourceBuiltIn }

// BundleSequence forwards to an authority that rotates (the disk CA), so
// spiffe_sequence advances across a CA rotation; others stay at 1.
func (b builtinSource) BundleSequence() int64 {
	if s, ok := b.Authority.(BundleSequencer); ok {
		return s.BundleSequence()
	}
	return 1
}

// UpstreamCAKeeper is an issuing authority backed by an external issuer
// (Vault PKI, step-ca) that keeps a CA the issuer rotated out trusted for
// --upstream-ca-grace. SetKeptCAHook reports every change to that kept
// set; DistrustCAs replaces the operator's list of CAs never to keep,
// dropping any kept one at once, and returns how many it dropped.
type UpstreamCAKeeper interface {
	SetKeptCAHook(func(KeptCAEvent))
	DistrustCAs([][32]byte) int
}

// CAReloader is an issuing authority whose CAs can be rotated at runtime
// by re-reading its directory (see rotation.go).
type CAReloader interface {
	ReloadCA() (bool, error)
}

// NewBuiltInSource wraps an issuing Authority as the built-in identity
// source.
func NewBuiltInSource(a Authority) Source {
	return builtinSource{Authority: a}
}

// AsSource returns a as a Source unchanged when it already is one,
// otherwise wraps it as the built-in source. It lets call sites keep
// passing a bare Authority while the server depends on the Source seam.
func AsSource(a Authority) Source {
	if a == nil {
		// Keep the nil interface nil; wrapping it would make the
		// returned Source non-nil while its embedded Authority panics.
		return nil
	}
	if s, ok := a.(Source); ok {
		return s
	}
	return NewBuiltInSource(a)
}
