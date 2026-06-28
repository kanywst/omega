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

// builtinSource adapts an Authority (Omega-as-issuer) to the Source seam.
type builtinSource struct {
	Authority
}

func (builtinSource) SourceKind() SourceKind { return SourceBuiltIn }

// NewBuiltInSource wraps an issuing Authority as the built-in identity
// source.
func NewBuiltInSource(a Authority) Source {
	return builtinSource{Authority: a}
}

// AsSource returns a as a Source unchanged when it already is one,
// otherwise wraps it as the built-in source. It lets call sites keep
// passing a bare Authority while the server depends on the Source seam.
func AsSource(a Authority) Source {
	if s, ok := a.(Source); ok {
		return s
	}
	return NewBuiltInSource(a)
}
