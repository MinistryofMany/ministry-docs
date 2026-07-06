---
title: Signatures, Keys, and the DID
description: Ed25519/EdDSA as a primitive - RFC 8032, pure not prehash, 32-byte keys, 64-byte signatures - then the crypto-level mechanics of Minister's two-key model, the KMS RAW-sign cap, the boot pin check, and why assertionMethod pinning, not the signature scheme itself, is what makes the H1 property hold.
order: 4
---

## Ed25519 as a primitive

In plain terms, a signature scheme lets a key holder stamp a message so
anyone with the matching public key can confirm it came from that key and
wasn't altered in transit, without the verifier ever touching the private
key. Ed25519 is the EdDSA signature scheme from RFC 8032, instantiated over
Curve25519. A key pair is a 32-byte public key and a 32-byte seed (private
key); a signature is always exactly 64 bytes. Security is ~128-bit. In JOSE
contexts (JWS, JWKS, DID documents) it's registered as `alg: "EdDSA"` per RFC
8037, with key type `OKP` and curve `Ed25519`.

One property matters more than usual here: Ed25519 as specified is **pure**,
not prehashed. The signer takes the message itself (not a digest of it) and
hashes internally as part of the algorithm - there's a separate variant,
Ed25519ph, that takes a pre-hashed message instead, and Minister uses neither
Ed25519ph nor any prehash convention. This is why AWS KMS's algorithm
identifier for this key, `ED25519_SHA_512`, names a hash at all: that's the
hash *internal* to standard Ed25519's own signing procedure, not something the
caller does before calling `Sign`. Concretely, both of Minister's signers pass
the full message straight in - the KMS client sends the raw bytes with
`MessageType = RAW`, and the in-process signer calls Node's
`crypto.sign(null, message, key)`, where `null` tells Node there is no
external digest algorithm to apply because EdDSA supplies its own.

Ed25519 signatures carry no built-in notion of *purpose* - nothing in the
signature itself says "this key may only sign badge VCs" or "this key may only
sign tokens." That separation, covered below, is enforced entirely by which
keys a verifier is willing to trust for which artifact, not by anything
cryptographic in the signature scheme.

## Two keys, two trust mechanisms

Why two keys, and not one? Because badges and tokens have different threat
profiles. We sign two different kinds of Ed25519 artifact under two
different keys, described conceptually in
[Signing Keys and the DID](/understand/signing-keys-and-did). This page goes
one level deeper, into how each key is actually invoked.

### `#key-2` - the KMS badge key

Production badge signing goes through AWS KMS, never a local private key:

- `SigningAlgorithm = ED25519_SHA_512`, `MessageType = RAW` - a per-signature
  `kms:Sign` network call, no local key material exists to leak.
- Non-extractable: it's an HSM-backed key (prod key id
  `ff0ac3ab-e770-4e54-a142-8e0cfb5592d0`, `ECC_NIST_EDWARDS25519`,
  `SIGN_VERIFY`) with no export path.
- Every call enforces the KMS RAW-sign message cap - **4096 bytes** - in
  application code *before* the network call, and asserts the returned
  signature is exactly 64 bytes after it. Neither check is an EdDSA property;
  both are defensive code around a KMS API contract. The 4096-byte cap is also
  the reason id_tokens can't use this key at all - see
  [Signing Keys and the DID](/understand/signing-keys-and-did) for why that
  forced the second key to exist.
- A boot-time trust anchor: at startup, Minister calls KMS `GetPublicKey`,
  derives the public key, and compares it against a pinned expected value
  (`ISSUER_KMS_PUBLIC_JWK`). A mismatch refuses to boot (it fails closed,
  which is the behavior you want here). This catches configuration drift -
  an alias silently repointed to a different KMS key - before it can produce
  badges signed under a key nobody has pinned or published.
- No local fallback exists on the KMS path. Dev/local environments use an
  entirely separate code path: a raw `ISSUER_PRIVATE_JWK` or a persisted dev
  key, never a degraded mode of the production signer.

### `#key-3` - the in-process token key

id_token and access_token signing never touches KMS. The key comes from
`TOKEN_SIGNING_JWK` - production refuses to boot without it, and dev generates
and persists a local key instead - and signing is a local
`crypto.sign(null, ...)` call: no network round trip, no 4096-byte cap, no
boot pin check. This is the key that has to handle large signing inputs,
because an id_token can embed several full badge VCs in its
`minister_badges` array.

That's the trade the split buys: `#key-2` is slow, hardware-backed, and
guarded by a boot-time pin check because it mints something long-lived and
high-trust; `#key-3` is fast and local because it has to sign on every
token mint. A leaked `#key-3` can forge tokens, but it cannot forge a badge -
and that is the whole point of not sharing a key across the two jobs.

## JWKS serves both, the DID document serves one

Both public keys are published in Minister's JWKS, `kid`-distinguished as
`#key-2` and `#key-3`. But the DID document's `assertionMethod` - the list a
correct badge verifier is supposed to consult - lists only `#key-2`. `#key-3`
is absent from it entirely, even though its public half sits right next to
`#key-2`'s in the same JWKS response.

## The H1 pinning property, at the signature level

This is the crypto-level version of the property named in
[Trust and Security Model](/understand/trust-and-security-model): a badge
signed with `#key-3` does not verify against a verifier that pins to
`assertionMethod`.

Why does that rejection actually happen? The guarantee is easy to mis-locate,
so be precise about where it lives. Ed25519 signature verification itself
cannot express "only sign artifact type X with this key" - a signature is
either valid for a given (key, message) pair or it isn't, full stop. If someone signed a badge-shaped JWT-VC payload with
`#key-3` instead of `#key-2`, the signature would be perfectly valid Ed25519 -
`#key-3`'s public key is real, published, and would verify it correctly. The
property that a badge verifier "rejects" it holds only because the verifier
does an authorization check *in addition to* signature verification: it looks
up the `kid` from the JWS header, and refuses to accept the badge unless that
`kid` is a member of `assertionMethod`. Skip that second check - trust the raw
JWKS and select purely by `kid`, as an OIDC token verifier legitimately does -
and a `#key-3`-signed badge verifies just fine.

> The guarantee lives entirely in the DID document's `assertionMethod` list, an
> application-level allow-list checked by the verifier - not in anything the
> Ed25519 signature scheme enforces on its own. A hand-rolled verifier that
> selects badge-signing keys by `kid` from JWKS instead of from
> `assertionMethod` silently loses this property. The reference SDK
> (`@ministryofmany/client`) pins to `assertionMethod` correctly.

## Where to look in the source

- Key loading, KMS wiring, and DID/JWKS key selection: `packages/vc/src/key.ts`.
- KMS RAW-sign cap enforcement, boot pin check, and the KMS signer itself:
  `packages/vc/src/kms.ts` (`kmsSigner`, `assertKmsPublicKeyMatches`).
- In-process token signer: `packages/vc/src/signer.ts` (`localSigner`).
- Compact JWS construction for badge VCs: `packages/vc/src/signer.ts`
  (`signCompactJwt`), `packages/vc/src/issue.ts`.
- DID document (`assertionMethod` listing only `#key-2`): `packages/vc/src/did.ts`.
- Token minting under `#key-3`: `apps/minister/src/lib/oidc-tokens.ts`.
