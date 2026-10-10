// Permits an ID-JAG grant only for AI agents (path prefix /agents/)
// acting for a federated human (path prefix /humans/). Without a permit
// on token.id_jag every grant is denied.

@id("allow-ai-agent-id-jag")
permit (
  principal is Spiffe,
  action == Action::"token.id_jag",
  resource is Spiffe
) when {
  principal has kind &&
  principal.kind == "ai" &&
  principal.acting_for like "spiffe://omega.local/humans/*"
};
