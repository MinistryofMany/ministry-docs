---
title: Glossary and Notation
description: Plain-language definitions of every cryptographic term used across this track, plus the notation conventions every page relies on.
order: 2
---

## Notation

These conventions are used consistently across every page in this track.

- `base64url(x)` - RFC 4648 section 5 base64url encoding, no padding, unless a
  page states otherwise.
- `HMAC-SHA-256(k, m)` - FIPS 198-1 HMAC keyed with `k` over message `m`. Plain
  `SHA-256` / `SHA-512` mean the FIPS 180-4 hash function alone, no key.
- `HKDF-SHA-512(ikm, salt, info, L)` - RFC 5869 extract-then-expand key
  derivation: input keying material `ikm`, an optional `salt`, a domain-
  separating `info` string, and an `L`-byte output. `HKDF-SHA-256` is the same
  construction with SHA-256 as the hash.
- `||` - byte-string concatenation. It never means logical OR on these pages.
- `LP(x)` - a 2-byte big-endian length prefix followed by the bytes of `x`.
  This is the length-prefixed domain separation the nullifier constructions
  use to concatenate several fields safely: `"ab" || "c"` and `"a" || "bc"`
  are the same bytes, but with a length prefix on each field the two tuples
  can't collide.
- Ed25519 signatures are `EdDSA` per RFC 8032, the pure variant (the whole
  message is signed directly, not a prehash of it).

## Terms

**AAL / IAL.** Authenticator Assurance Level and Identity Assurance Level, the
NIST SP 800-63 scales (AAL from 800-63B, IAL from 800-63A) for "how strongly
was this session's login proven" (AAL) versus "how strongly is the underlying
identity claim backed" (IAL). Minister
uses AAL 0-2 (0 = none, 1 = single factor like a magic link or recovery code,
2 = phishing-resistant, like a passkey or paired TOTP) to gate privileged
actions such as account merge. See
[Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge).

**AEAD.** Authenticated Encryption with Associated Data. An encryption mode
that gives you confidentiality and an integrity check in one operation, and
optionally binds the ciphertext to extra context (the "associated data") that
isn't itself encrypted but must match on decrypt or the whole thing fails.
AES-256-GCM, used throughout this ecosystem for sealing keys and vaults at
rest, is an AEAD construction.

**assertionMethod.** A field in a DID document that lists which verification
methods (keys) may attest a credential on that DID's behalf. Minister's DID
document lists only its badge-signing key (`#key-2`) here - its token-signing
key (`#key-3`) is deliberately absent, so a verifier that correctly checks
`assertionMethod` before trusting a badge signature can never be tricked into
accepting a badge signed with the token key. See
[Signatures, Keys, and the DID](/crypto/signatures-and-signing-keys).

**Blind signature.** A signature scheme where the signer signs a message
without ever seeing its plaintext content: the requester "blinds" the message
first, the signer signs the blinded version, and the requester "unblinds" the
result to get a valid signature on the original message. RSA blind signatures
(RFC 9474) are used for FreedInk's vote tokens, so a vote can be signed as
"a legitimate vote" without the signer learning which vote it was signing.

**Commitment.** A value that binds you to a piece of data without revealing
it - you can later "open" the commitment to prove what it hides, but nobody
can extract the hidden value from the commitment alone. A Semaphore identity
commitment is one: a Poseidon hash derived from the identity's key material
(its public key in Semaphore v4, its secret in v3) that serves as the public
leaf in a membership tree without revealing the identity secret it was built
from.

**DID (Decentralized Identifier).** A URI scheme for identifiers that resolve
to a document listing public keys and other metadata, without needing a
central registry. Minister uses `did:web`, which resolves by just fetching
`https://<host>/.well-known/did.json` over HTTPS - no blockchain involved.

**DLEQ proof.** "Discrete Log Equality" proof: a zero-knowledge proof that two
values were computed with the same secret exponent, without revealing the
exponent. In the VOPRF construction here, it proves that Signet evaluated the
blinded input with the same secret key whose public half is `pkS`, so a
client can catch a server that tries to swap in a different key mid-protocol.

**Domain separation.** Deriving distinct keys or hashing distinct contexts so
that output computed for one purpose can never collide with, or be replayed
as, output computed for another purpose - even if the same underlying secret
is used. Usually done with a fixed "info" or "purpose" string baked into the
input, and ideally combined with length-prefixing (`LP`) so variable-length
fields can't be shuffled into each other.

**Holder binding.** The property that a credential is provably tied to the
entity presenting it, not just to whoever it was originally issued to. Here
it's done by stamping the disclosed VC's `credentialSubject.id` with a DID
derived from the same login's pairwise `sub` - so a badge disclosed in one
`id_token` can't be replayed alongside a different login's token.

**HKDF.** HMAC-based Key Derivation Function (RFC 5869). Takes some input
keying material (which may not be uniformly random on its own) and an
`info` string, and stretches/separates it into one or more output keys that
are cryptographically independent of each other, provided the `info` strings
differ.

**KEK.** Key-encryption key: a key whose only job is to encrypt other keys at
rest. Signet's `SIGNET_KEK` (256 bits, supplied via the environment and wiped
from it after parsing) seals the VOPRF master seed, the imported pairwise
secret, and every blind-RSA private key with AES-256-GCM before any of them
touches its database. See
[Signet: The Crypto-Core Service](/crypto/signet-service).

**Merkle tree.** A binary tree where every internal node is the hash of its
two children, so a single root hash commits to an entire set of leaves. Proving
that one specific leaf belongs to the tree (a "Merkle proof" or, when done in
zero knowledge, part of a membership proof) takes a path of siblings up to the
root, not the whole tree. Semaphore and RLN both use one, hashed with
Poseidon instead of SHA-256 because Poseidon is far cheaper to prove in a
zk-SNARK circuit.

**mTLS.** Mutual TLS: both sides of a TLS connection present a certificate,
not just the server. Signet requires mTLS for every connection and refuses
any client that doesn't present a certificate chaining to its configured CA -
there's no unauthenticated fallback.

**Nullifier.** A value derived from a secret and some context (an action, a
scope, a time epoch) that's unique per `(secret, context)` pair, disclosed
alongside a proof so a verifier can detect reuse - "this same secret already
did this same thing" - without the nullifier revealing which secret produced
it. This ecosystem uses the word for two different constructions: a
Semaphore/RLN circuit nullifier (a zk-SNARK output, prevents double-posting or
tracks rate-limit violations) and Minister's badge Sybil-dedup nullifier (a
VOPRF/HMAC construction, prevents one person registering two badges off the
same real-world anchor). They are not interchangeable and use different math
- see [The Badge Nullifier](/crypto/badge-nullifier) versus
[Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge).

**OPRF / VOPRF.** Oblivious Pseudorandom Function: a protocol where a client
gets the output of a keyed PRF evaluated on its own input, without revealing
that input to the server, and without learning the server's key. VOPRF adds
Verifiability: the server also proves (via a DLEQ proof) that it evaluated
honestly with the key whose public half the client already trusts. RFC 9497
standardizes both. Signet runs a VOPRF over the ristretto255 group with
SHA-512 for the badge nullifier's stage-1 dedup step.

**Pairwise subject / pseudonym.** An identifier that's different for every
relying party a user logs into, so no two RPs can compare notes and discover
they're talking to the same person. Minister computes it as
`base64url(HMAC-SHA-256(OIDC_PAIRWISE_SECRET, userId || ":" || clientId))`,
then uses the result as the OIDC `sub` claim. See
[Pairwise Subjects](/crypto/pairwise-subjects).

**PKCE.** Proof Key for Code Exchange (RFC 7636), an OIDC/OAuth extension that
binds an authorization code to the client that requested it. The client
generates a random `verifier`, sends `challenge = base64url(SHA-256(verifier))`
with the authorize request, then presents the raw `verifier` at the token
endpoint - only the party that generated the original verifier can complete
the exchange, closing the authorization-code-interception attack.

**Shamir secret sharing.** A way to split a secret into `n` shares such that
any `k` of them reconstruct it but `k-1` reveal nothing. Discreetly's RLN uses
a degree-1 version of this as a deliberate trap: each RLN proof reveals one
point on a line whose y-intercept is the identity secret, so any two
same-epoch messages from the same identity reveal two points and let the
server recover and ban that identity - one point alone reveals nothing.

**Semaphore.** A zk-SNARK protocol and toolkit for anonymous group membership
and signaling: prove you belong to a group (via a Merkle tree of identity
commitments) and are the author of a specific action, without revealing which
member you are. FreedInk uses Semaphore v4 (dynamic-depth trees) for blog
membership; Discreetly's RLN is built on Semaphore v3's identity math and a
fixed depth-20 tree underneath its own rate-limiting layer.

**RLN (Rate-Limiting Nullifier).** An extension of Semaphore-style membership
proofs that adds a per-epoch message limit enforced by cryptography: proving
more than once in the same epoch leaks enough information (via the Shamir
construction above) to recover and de-anonymize the sender. It's reactive
rate limiting - punished after the fact, not physically prevented - not a
hard cap.

**Verifiable credential / JWT-VC.** A W3C-standardized way to package a signed
claim about a subject so any third party can verify who issued it and that
it hasn't been altered. Minister issues W3C VC Data Model 2.0 credentials
serialized as compact JWTs (`typ: "vc+jwt"`), signed EdDSA, rather than as
JSON-LD with a separate proof block. See
[Verifiable Credentials and Holder Binding](/crypto/verifiable-credentials).

## Where to go next

Start at [Cryptographic Overview](/crypto/overview) for how these terms fit
together in an actual login, or jump straight to
[Hashing, HMAC, and Key Derivation](/crypto/hashing-hmac-and-kdfs) for the
shared symmetric building blocks.
