---
title: Cryptographic Overview
description: The canonical primitives table, the three secrets and three key origins, and an end-to-end walk of a login, a badge issuance, and a room gate, naming every construction as it fires.
order: 1
---

## What this track covers

The [Understand](/understand/what-is-minister) track explains the privacy model:
pairwise identity, selective disclosure, why a relying party (RP) never sees
your real identity twice. This track is the algorithm-level companion. It
names the primitive, the standard it implements, its parameters, its bit
strength, and what it does and does not guarantee, so you can audit the
constructions instead of trusting a description of them.

Three systems carry the crypto: **Minister** (the OIDC identity provider and
badge issuer), **Signet** (a separate Rust trust boundary that holds the
nullifier and pairwise key material), and the relying parties **FreedInk** and
**Discreetly** (each running its own zero-knowledge membership proof on top of
a Minister login). This page is the map of how they fit together. Every deep
page it links to owns one construction in full.

## The canonical primitives table

Every other page in this track uses these exact names and numbers. If a page
disagrees with this table, the table is wrong and should be fixed, not the
other way round.

| Primitive | Standard | Params as used | ~Security | Where used |
|---|---|---|---|---|
| SHA-256 | FIPS 180-4 | 256-bit digest | 128-bit collision | PKCE S256, HMAC, HKDF-256, drift cache, ECDSA certs |
| SHA-512 | FIPS 180-4 | 512-bit digest | 256-bit collision | VOPRF finalize, HKDF-512 key schedule |
| HMAC-SHA-256 | FIPS 198-1 | key = `OIDC_PAIRWISE_SECRET` (32+ chars) or a 32-byte derived key; 32-byte tag, 43-char base64url | ~256-bit PRF | pairwise `sub`/`jti`, interim nullifier, stage-2 disclose, session/tickets (via HS256) |
| HKDF | RFC 5869 | SHA-256 for the interim nullifier key; SHA-512 for the Signet key schedule; 32-byte outputs | matches hash | nullifier key derivation, Signet per-RP keys |
| Argon2id | RFC 9106 | memoryCost 19 MiB, timeCost 2, parallelism 1 | memory-hard | recovery-code hashing, OIDC client-secret hashing |
| PBKDF2-HMAC-SHA-256 | RFC 8018 | 600,000 iterations (FreedInk); 210,000 (Discreetly) | password-stretch | client-side identity vaults |
| AES-256-GCM | NIST SP 800-38D | 256-bit key (KEK), 96-bit random nonce, 128-bit tag; blob = 1-byte version, then nonce, then ciphertext+tag | 128-bit AEAD | Signet seed/keystore sealing at rest, both apps' vaults |
| Ed25519 / EdDSA | RFC 8032 | 32-byte pubkey, 64-byte signature | ~128-bit | badge VC signing (`#key-2`), OIDC token signing (`#key-3`) |
| ECDSA P-256 (secp256r1) + SHA-256 | FIPS 186-4 | prime256v1 | ~128-bit | Signet mTLS PKI (CA, server, client certs) |
| VOPRF, ristretto255-SHA-512 | RFC 9497, verifiable mode `0x01` | 32-byte elements, 64-byte DLEQ proof (two 32-byte scalars `c`, `s`), 64-byte finalize output | ~128-bit | badge nullifier stage-1 dedup (Signet) |
| RSAPBSSA-SHA384-PSS (randomized) | RFC 9474 + partially-blind extension | 2048-bit modulus default (2048-4096, safe primes) | ~112-bit at 2048 | FreedInk blind-RSA voting surface (inert in prod) |
| Groth16 zk-SNARK | over BN254 (alt-bn128) | Poseidon hash (`poseidon-lite@0.2.0`), Merkle tree (depth per app, below) | ~100-bit | Semaphore membership (FreedInk), RLN (Discreetly) |
| Shamir secret sharing | - | over the BN254 scalar field; recovers the identity secret from 2 same-epoch shares | - | RLN over-rate slashing (Discreetly) |
| PKCE S256 | RFC 7636 | `base64url(SHA-256(verifier))` | - | OIDC authorization-code binding |

> BN254 is estimated at roughly 100-bit effective security after recent TNFS
> advances, not the naive 128-bit the curve size suggests. The table says
> ~100-bit deliberately; don't round it up.

Depth for the Semaphore/RLN Merkle trees isn't one number: FreedInk's
membership tree is dynamic-depth (it grows with a blog's member count, warmed
at depths 1 and 4), while Discreetly's RLN tree is a fixed depth of 20. See
[Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge).

## The three secrets

Minister holds three independent secrets. They are never interchangeable, and
mixing them up is the single most common mistake in reading this codebase.

- **`OIDC_PAIRWISE_SECRET`** (32+ chars). Keys the pairwise `sub`/`jti` HMAC,
  and is the HKDF root for the interim nullifier key. Also imported byte-for-
  byte into Signet as the pairwise HMAC root, so both sides derive identical
  output. See [Pairwise Subjects](/crypto/pairwise-subjects).
- **`AUTH_SECRET`**. The HS256 key for the Auth.js session cookie, the merge
  donor-proof JWT, and recovery tickets. Not the same secret as
  `OIDC_PAIRWISE_SECRET` - the old silent fallback between them was removed.
  See [Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge).
- **`TOKEN_SIGNING_JWK`**. The in-process Ed25519 key that signs OIDC
  `id_token`s and access tokens (`#key-3`). See
  [Signatures, Keys, and the DID](/crypto/signatures-and-signing-keys).

Plus a fourth key that isn't a Minister-held secret at all: the **KMS badge
key** (`#key-2`), non-extractable inside AWS KMS under alias
`alias/minister-issuer`. It signs badge VCs and nothing else.

## The three key origins (Signet)

Signet is a separate service and a separate trust boundary, not a subtree of
Minister's secrets. It has three distinct key origins with nothing shared
between them:

1. **`master_seed`** (32 random bytes, minted once from the OS RNG, never
   rotated) feeds `HKDF-SHA-512` to derive `seed_null`, which becomes the
   VOPRF keypair `(skS, pkS)` used for stage-1 dedup. The same `master_seed`
   also derives per-RP disclose keys,
   `k_disc(clientId) = HKDF-SHA-512(master_seed, info="minister/v1/nullifier/disclose" || LP(clientId))`.
2. **The pairwise HMAC secret** is *imported*, not derived - it's the same
   `OIDC_PAIRWISE_SECRET` bytes as Minister's, sealed at rest, so Signet's
   `/prf/pairwise` oracle and Minister's in-process HMAC produce byte-identical
   output.
3. **The blind-RSA group keys** are generated independently per group, with no
   relationship to the seed at all.

All three are sealed at rest under `SIGNET_KEK` with AES-256-GCM. See
[Signet: The Crypto-Core Service](/crypto/signet-service).

> The two crypto-core seams (`MINISTER_SUB_BACKEND`, `MINISTER_NULLIFIER_BACKEND`)
> are env-flag staged, and the flag value drifts over time - this page
> describes the constructions and the seam between them rather than pinning
> today's flag state. The prod-relevant fact worth knowing: the nullifier dedup
> path is designed to run through Signet's VOPRF specifically because the
> in-Minister interim HMAC is a dictionary oracle (deterministic HMAC output,
> co-resident key, in Minister's own Postgres). See
> [The Badge Nullifier](/crypto/badge-nullifier) for the full stage-1/stage-2
> construction and backend comparison.

## Walking a login end to end

Three things happen, in order: a relying-party login, a badge issuance and
disclosure, and a Discreetly room gate. Here's every primitive that fires,
named as it's used.

### 1. RP login (authorization code + PKCE)

A user clicks "sign in with Minister" on FreedInk or Discreetly.

1. The RP generates a PKCE verifier and sends the authorize request with
   `code_challenge = base64url(SHA-256(verifier))` (RFC 7636 S256), plus
   `state` and `nonce`. See
   [OIDC Flow Hardening and Disclosure](/crypto/oidc-flow-hardening).
2. Minister authenticates the user (passkey, TOTP, email link, or recovery
   code - see [Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge)
   for what each buys you in AAL terms), then redirects back with a single-use,
   60-second authorization code.
3. The RP posts the code plus the PKCE verifier to `/token`. Minister
   recomputes `base64url(SHA-256(verifier))` and compares it to the stored
   challenge with a timing-safe equality check.
4. Minister mints an `id_token` (600 s TTL) and an access token (RFC 9068
   `at+jwt`, 3600 s TTL), both signed EdDSA with `#key-3`. The `sub` claim is
   not the user's real id - it's a **pairwise subject**, an HMAC-SHA-256 of
   `userId:clientId` keyed by `OIDC_PAIRWISE_SECRET`, unique per RP. See
   [Pairwise Subjects](/crypto/pairwise-subjects).
5. The RP verifies the `id_token` against Minister's JWKS, selecting `#key-3`
   by `kid`. See [Signatures, Keys, and the DID](/crypto/signatures-and-signing-keys).

At this point the RP knows *a* pairwise identity signed in. It knows nothing
about badges yet unless it asked for them.

### 2. Badge issuance and disclosure

If the RP requested badge scopes (Discreetly does; FreedInk requests only
`openid profile` and stops here), a second layer engages at consent time.

1. Minister evaluates the RP's `minister_policy` (a boolean `allOf`/`anyOf`/
   `atLeast` tree over badge types, capped at 4096 bytes, depth 8, 64 nodes)
   against the badges the user actually holds, and picks the smallest
   satisfying set with the best anonymity. See
   [OIDC Flow Hardening and Disclosure](/crypto/oidc-flow-hardening).
2. For each disclosed badge, Minister re-mints the stored VC: it verifies the
   stored EdDSA signature first (so this can never become a signing oracle
   over arbitrary DB content), strips reserved claims, stamps a fresh
   `credentialSubject.id` equal to `did:web:<host>:u:<pairwise sub>`, and
   signs the result EdDSA with `#key-2` - the KMS-backed badge key, distinct
   from the token key. See
   [Verifiable Credentials and Holder Binding](/crypto/verifiable-credentials)
   and [Signatures, Keys, and the DID](/crypto/signatures-and-signing-keys).
3. Before any of that, at original issuance time, the badge's Sybil-dedup
   nullifier was computed. Stage 1 hashes an anchor (an email, an OAuth
   account id) into a 64-byte VOPRF output via Signet - Signet never sees the
   anchor, only a blinded group element - and Minister DLEQ-verifies the
   result before registering it in a `UNIQUE`-indexed ledger that refuses a
   second badge over the same anchor for a different account. Stage 2, run at disclosure
   time, derives a per-RP nullifier from that stage-1 value with
   HMAC-SHA-256, so two different RPs can never correlate the same badge to
   each other. See [The Badge Nullifier](/crypto/badge-nullifier).
4. The disclosed VC rides inside the `id_token`'s `minister_badges` array
   (which is exactly why the token key can't be KMS-backed: embedding a
   handful of VCs blows past KMS's 4096-byte RAW-sign cap).

### 3. Discreetly room gate

A user tries to join a Discreetly room that requires, say, one of
`age-over-21` or `residency-state`.

1. Discreetly's `apps/web` sent that requirement as the `minister_policy`
   param on the authorize request in step 2, so the user only disclosed
   whichever single badge satisfied it.
2. `services/api` receives the presented `id_token` as a Bearer token and
   re-verifies it on every gated call - the `createMinisterVerifier` instance
   is reused per process, but no verification *decision* is ever cached.
   Verification checks the EdDSA signature against Minister's JWKS, the `aud`
   claim against Discreetly's own client id (the SDK only enforces `aud` when
   a client id is configured, so Discreetly's verifier wrapper refuses to
   construct without one), and then verifies each embedded badge VC's
   signature against the DID document's `assertionMethod`, not the raw JWKS.
3. A badge whose subject DID doesn't match `did:web:<host>:u:<sub>` for this
   specific `id_token`, or whose issuer key isn't the pinned `#key-2`, gets
   dropped into `rejected` rather than throwing - so one bad badge doesn't
   take down the whole login.
4. The surviving verified badges are checked against the room's policy tree,
   server-side, fail-closed. Only then does the user get a Semaphore identity
   commitment added to the room's membership tree, and only then can they
   send RLN-proved messages. See
   [Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge).

Note the coupling trap that sits underneath all of this: the SDK derives the
expected badge-issuer DID from the OIDC issuer's host string alone. If
Discreetly's `MINISTER_ISSUER` host doesn't exactly equal Minister's
`MINISTER_ISSUER_DOMAIN`, login keeps working (id_token verification doesn't
touch the VC issuer) but every badge silently lands in `rejected`. See
[Trust and Security Model](/understand/trust-and-security-model) and
[Threat Model and Known Gaps](/crypto/threat-model).

## Where to go next

- Building blocks shared everywhere: [Hashing, HMAC, and Key Derivation](/crypto/hashing-hmac-and-kdfs)
- Signing identity: [Signatures, Keys, and the DID](/crypto/signatures-and-signing-keys)
- Unlinkable identity per RP: [Pairwise Subjects](/crypto/pairwise-subjects)
- The credential itself: [Verifiable Credentials and Holder Binding](/crypto/verifiable-credentials)
- Sybil resistance: [The Badge Nullifier](/crypto/badge-nullifier)
- The separate trust boundary: [Signet: The Crypto-Core Service](/crypto/signet-service)
- The OIDC wire protocol: [OIDC Flow Hardening and Disclosure](/crypto/oidc-flow-hardening)
- Losing and merging accounts: [Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge)
- The relying parties' own ZK proofs: [Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge)
- Every accepted gap in one place: [Threat Model and Known Gaps](/crypto/threat-model)
- Definitions and notation: [Glossary and Notation](/crypto/glossary)
- The privacy narrative this page assumes: [What is Minister?](/understand/what-is-minister)
