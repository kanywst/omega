# Rotating the built-in CA

A running control plane has its CA replaced with `omega ca prepare`, `activate` and `retire`, each followed by `SIGHUP`. See [docs/ca-rotation.md](../../docs/ca-rotation.md) and [ADR 0019](../../docs/adr/0019-runtime-ca-rotation.md).

## Run

```bash
make demo
```

| Step | Expected |
| --- | --- |
| start | one trusted CA, `spiffe_sequence` 1 |
| prepare | two trusted CAs, tokens still signed by the old key, sequence 2 |
| activate | new tokens carry the new key id, a token from the old CA still verifies, sequence 3 |
| retire (`--force`) | one trusted CA, the old key gone from the JWKS, a token from the old CA refused, sequence 4 |

`make down` cleans up.
