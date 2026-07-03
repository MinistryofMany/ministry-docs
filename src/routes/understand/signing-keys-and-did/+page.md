---
title: Signing Keys and the DID
description: Minister's did:web issuer identity and its two-key model - the KMS badge key in assertionMethod and the in-process token key - why the split exists, and how JWKS and the DID document serve them.
order: 4
---

## Minister's identity is a did:web

Minister issues under a single Decentralized Identifier, `did:web:ministry.id`
(dev default `did:web:minister.local`). did:web resolution is just an HTTPS
fetch: a verifier turns the DID into `https://ministry.id/.well-known/did.json`,
fetches the DID document, and reads the public keys out of it. The document is
public, cacheable, and CORS-permissive. Two documents anchor everything a
relying party (RP) verifies:

- `/.well-known/did.json` - the DID document, listing verification methods and,
  crucially, which of them may attest credentials (`assertionMethod`).
- `/.well-known/jwks.json` - a standard JWKS serving Minister's public signing
  keys, `kid`-distinguished.

The issuer DID is derived from the host alone. A non-default port is
percent-encoded per did:web (for example `did:web:localhost%3A3000`).

## Two keys, not one

Minister signs two different kinds of artifact, and it uses a **separate key for
each**:

- **`#key-2`, the badge key.** Signs badge VCs (`issueVc` and the disclosure-time
  `reMintVc`). In production it is AWS-KMS-backed: non-extractable, HSM-held,
  pinned to RAW + `ED25519_SHA_512`, verified against a pinned public JWK at boot
  (fail-closed, no local fallback). In dev it wraps a local Ed25519 key persisted
  to a gitignored file.
- **`#key-3`, the token key.** Signs the OIDC `id_token` and access token. It is
  always in-process (from `TOKEN_SIGNING_JWK`, or a dev key), never routed
  through KMS.

Both are Ed25519 (`alg: EdDSA`). Both public halves are served in JWKS. Only one
of them - the badge key - appears in the DID document's `assertionMethod`.

## Why two keys

The split is forced by a hard KMS constraint and then turned into a security
property.

**The KMS constraint.** A KMS `Sign` call with `MessageType=RAW` caps the
message at exactly 4096 bytes. An `id_token` embeds the disclosed badge VCs in
its `minister_badges` array, and each badge is itself a full JWT-VC. Once a
handful of badges are embedded, the token's signing input blows past 4 KB, so it
**cannot** be signed by KMS at all. The badge key is small artifacts (a single
VC) and fits; the token key must handle large ones. So tokens keep an in-process
key that has no size cap, and the KMS signer rejects any input over 4096 bytes
before it ever hits the network.

**The security property.** Because the two keys are distinct and only the badge
key is listed in `assertionMethod`, the token key **attests nothing**. A
correct badge verifier resolves badge signing keys from the DID document's
`assertionMethod` - not from the raw JWKS - and rejects any badge whose `kid` is
not listed there. So even though the token key's public half sits in the same
JWKS, a badge signed with the token key will not verify against a verifier that
pins to `assertionMethod`. A leaked or misused token key cannot forge a badge.
This pinning is the H1 property; see
[Trust and Security Model](/understand/trust-and-security-model).

The caveat: the split only holds for verifiers that pin to `assertionMethod`. A
verifier that instead trusts the raw JWKS and selects a key by `kid` **would**
accept a `#key-3`-signed badge. The reference SDK
(`@ministryofmany/client`) pins correctly; a hand-rolled verifier must do the
same.

## The DID document

`getDidDocument` emits a document whose `verificationMethod` carries the badge
key as a `JsonWebKey2020`, and lists that key in both `assertionMethod` and
`authentication`:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:ministry.id",
  "verificationMethod": [
    {
      "id": "did:web:ministry.id#key-2",
      "type": "JsonWebKey2020",
      "controller": "did:web:ministry.id",
      "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
    }
  ],
  "assertionMethod": ["did:web:ministry.id#key-2"],
  "authentication": ["did:web:ministry.id#key-2"]
}
```

`assertionMethod` lists **only** `#key-2`. That single entry is the whole
badge-trust anchor: it says "these, and only these, keys may attest a Minister
credential." The token key is deliberately absent.

## The JWKS

The JWKS serves **both** public keys, `kid`-distinguished:

```json
{
  "keys": [
    { "kty": "OKP", "crv": "Ed25519", "kid": "did:web:ministry.id#key-2", "x": "..." },
    { "kty": "OKP", "crv": "Ed25519", "kid": "did:web:ministry.id#key-3", "x": "..." }
  ]
}
```

An OIDC RP verifying an `id_token` uses this endpoint (it is the `jwks_uri` in
discovery) and selects the token key `#key-3` by `kid`. A `jose`-based RP
refetches JWKS on an unknown `kid`, so a freshly rotated token key verifies even
against a warm cache. Badge verification does **not** use this raw JWKS for key
selection; it uses the DID document's `assertionMethod`, which is why serving the
token key here is safe.

## Which key verifies which artifact

| Artifact | Signed by | Verifier resolves the key from |
| --- | --- | --- |
| `id_token`, access token | `#key-3` (token key, in-process) | JWKS `jwks_uri`, by `kid` |
| Badge VC (`issueVc` / `reMintVc`) | `#key-2` (badge key, KMS in prod) | DID document `assertionMethod` |

The practical upshot for an RP: verify the `id_token` against the discovered
JWKS, and verify each badge against the DID document's assertion key set. The
SDK does both correctly, and this separation is what makes the token key a dead
end for badge forgery.
