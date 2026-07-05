---
title: Hashing, HMAC, and Key Derivation
description: The shared symmetric primitives underneath everything else - SHA-256 and SHA-512, HMAC-SHA-256, HKDF (256 vs 512), Argon2id, PBKDF2-HMAC-SHA-256, and AES-256-GCM - with exact parameters, bit strengths, and where each shows up across Minister, Signet, FreedInk, and Discreetly.
order: 3
---

## Seven primitives, reused everywhere

Every construction described elsewhere in this track - the pairwise subject, the
badge nullifier, seed sealing in Signet, the client-side identity vaults in
FreedInk and Discreetly - bottoms out in one of seven symmetric primitives: two
hash functions, one keyed hash, one key-derivation function used with two
different hashes, two password KDFs, and one AEAD cipher. This page names each
one precisely so the rest of the track can just say "HKDF-SHA-512, see here for
params" instead of re-deriving it.

## SHA-256 and SHA-512

Both are FIPS 180-4 hash functions. SHA-256 produces a 256-bit digest with
~128-bit collision resistance (half the digest width, by the birthday bound);
SHA-512 produces a 512-bit digest with ~256-bit collision resistance. Neither is
used bare as often as you'd think - almost every appearance below is inside HMAC
or HKDF - but a few places hash directly:

- **SHA-256**, unkeyed: the PKCE `code_challenge` (`base64url(SHA-256(verifier))`,
  see [OIDC Flow Hardening](/crypto/oidc-flow-hardening)), and the stage-2
  nullifier drift check `SHA-256(salt || N_rp)` in Minister
  (`nullifier/drift-cache.ts`). Signet's mTLS PKI also signs its certificates
  with ECDSA P-256 over SHA-256.
- **SHA-512**, only ever inside a construction: it's the hash embedded in
  Signet's VOPRF ciphersuite (`ristretto255-SHA512`, RFC 9497) that produces the
  64-byte `N_dedup` finalize output, and it's the hash Signet's HKDF uses for its
  whole key schedule (below).

The split is not symmetric, so keep it straight when reading a construction:
Minister's own HMAC and HKDF machinery stays on SHA-256 throughout, while
Signet derives keys with HKDF-SHA-512 (matching the hash baked into its VOPRF
ciphersuite name) but still MACs with HMAC-SHA-256 - its stage-2 disclose and
`/prf/pairwise` outputs are 32 bytes, not 64. The reliable tell is the output
width: a 32-byte value has SHA-256 underneath, a 64-byte value has SHA-512.

## HMAC-SHA-256

FIPS 198-1 keyed hash: `HMAC-SHA-256(k, m)`. Output is 32 bytes, which shows up
encoded as a 43-character base64url string (RFC 4648 §5, no padding) in every
construction that surfaces it externally. As a keyed PRF its security is the
full ~256-bit key space, distinct from - and not weakened by - SHA-256's
128-bit collision floor as an unkeyed hash.

The key varies by use:

| Use | Key | Where |
| --- | --- | --- |
| Pairwise `sub` / `jti` (Minister in-process, and Signet's `/prf/pairwise` oracle) | `OIDC_PAIRWISE_SECRET` (raw UTF-8 bytes, env-required, ≥32 chars; the same bytes imported into Signet) | [Pairwise Subjects](/crypto/pairwise-subjects) |
| Interim nullifier (both stages) | `k_int`, a 32-byte HKDF-SHA-256 output (below) | [The Badge Nullifier](/crypto/badge-nullifier) |
| Signet stage-2 disclose | `k_disc(clientId)`, a 32-byte HKDF-SHA-512 output per RP | [The Badge Nullifier](/crypto/badge-nullifier), [Signet](/crypto/signet-service) |
| Session cookie, donor-proof ticket, recovery ticket (all HS256) | `AUTH_SECRET` (raw UTF-8, ≥32 chars) | [Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge) |

`OIDC_PAIRWISE_SECRET` and `AUTH_SECRET` are different secrets with different
jobs - the first roots the pairwise subject and the interim nullifier key, the
second roots session and ticket signing. Neither falls back to the other.

## HKDF: one RFC, two hashes

RFC 5869 extract-then-expand key derivation, `HKDF(ikm, salt, info, L)`. Two
independent uses in the system, deliberately on different hashes:

**HKDF-SHA-256**, Minister-side, derives the interim nullifier key from the
pairwise secret:

```text
k_int = HKDF-SHA256(ikm = OIDC_PAIRWISE_SECRET, salt = "",
                     info = "minister/v1/nullifier-interim", L = 32)
```

**HKDF-SHA-512**, Signet-side, derives the whole nullifier key schedule from a
32-byte OS-random `master_seed`:

```text
seed_null = HKDF-SHA512(ikm = master_seed, salt = "",
                        info = "minister/v1/nullifier", L = 32)
k_disc(clientId) = HKDF-SHA512(ikm = master_seed, salt = "",
                        info = "minister/v1/nullifier/disclose" || LP(clientId), L = 32)
```

`seed_null` then feeds RFC 9497's `DeriveKeyPair` to produce the VOPRF keypair
`(skS, pkS)`; `k_disc(clientId)` is a distinct 32-byte HMAC key per relying
party, so a leaked per-RP key only de-anonymizes that one RP's disclosed
nullifiers. The disclose derivation length-prefixes the client id - `LP(x)` is
a 2-byte big-endian length followed by the bytes of `x` - so a variable-length
`clientId` can never smear into the fixed info literal. See
[The Badge Nullifier](/crypto/badge-nullifier) and
[Signet: The Crypto-Core Service](/crypto/signet-service) for the full
constructions these keys feed into.

> Minister's pairwise HMAC and its interim nullifier key are HKDF-separated
> outputs of the *same* `OIDC_PAIRWISE_SECRET` root. They can't collide with
> each other, but a single leak of that one secret breaks both.

## Argon2id

RFC 9106 memory-hard password hash, via `@node-rs/argon2`. Same OWASP-baseline
parameters everywhere it's used: `memoryCost = 19 * 1024` KiB (19 MiB),
`timeCost = 2`, `parallelism = 1`. Its security property is memory-hardness
(making GPU/ASIC parallelism expensive), not a fixed bit number the way a hash
digest has.

Two call sites share these exact parameters:

- **OIDC client-secret hashing** (`oidc-clients.ts`) - the `client_secret`
  (32 random bytes, base64url) is hashed at rest with Argon2id before storage.
- **Recovery-code hashing** (`recovery-codes.ts`) - each of the ten 60-bit
  recovery codes per batch is hashed the same way; see
  [Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge) for the
  code format and redemption flow.

## PBKDF2-HMAC-SHA-256

RFC 8018 password-based KDF, built entirely on WebCrypto (`crypto.subtle`) in
the two relying-party apps that keep a client-side identity secret. Same
primitive, different iteration counts:

| App | File | Iterations | Feeds |
| --- | --- | --- | --- |
| FreedInk | `src/lib/client/vault.ts` | 600,000 | AES-GCM-256 |
| Discreetly | `apps/web/src/lib/identity.ts` | 210,000 | AES-GCM-256 |

FreedInk's 600,000 iterations is OWASP's published floor for
PBKDF2-HMAC-SHA-256. Discreetly's 210,000 - its source comment calls it a
"spec floor" - is OWASP's floor for PBKDF2-HMAC-**SHA-512**; applied to
SHA-256 it sits well under the 600,000 figure, so the Discreetly vault is
meaningfully cheaper to brute-force offline than FreedInk's if the password is
weak. Neither count is user-configurable, and both apps use PBKDF2 at all only
because they derive keys in the browser and WebCrypto has no Argon2. See
[Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge)
for the full vault construction (salt and nonce sizes, wire format, session
caching, and FreedInk's separate BIP-39 mnemonic backup).

## AES-256-GCM

NIST SP 800-38D AEAD, used in Signet to seal every long-lived secret at rest
under a single KEK (`SIGNET_KEK`):

- Key: 256-bit KEK.
- Nonce: 96 bits (12 bytes), freshly random per seal.
- Tag: 128 bits (16 bytes), the GCM default.
- Sealed blob layout: `version(1B = 0x01) || nonce(12B) || ciphertext+tag`.
- AAD: `group_id_bytes || key_id` (8-byte big-endian). Service secrets (the
  master seed, purpose `"master-seed-v1"`, and the imported pairwise secret,
  purpose `"pairwise-hmac-v1"`) always seal under `key_id = 0`; every group's
  blind-RSA private key seals under its own row id, `key_id >= 1`. That 0-vs-≥1
  split is what makes a blob swapped between the two tables fail GCM
  authentication rather than silently decrypt.

One KEK seals all three secret classes. See
[Signet: The Crypto-Core Service](/crypto/signet-service) for the KEK's own
lifecycle (how it's supplied, zeroized, and the accepted `/proc/<pid>/environ`
residual-exposure caveat).

> The browser-side vaults (FreedInk, Discreetly) also end in AES-GCM-256, via
> WebCrypto rather than Signet's Rust `aes-gcm` crate. Same cipher, same key
> size, different runtime and different key origin (a PBKDF2 output of a user
> password, not an operator-held KEK).

## Where to look in the source

- SHA-256 drift check: `apps/minister/src/lib/nullifier/drift-cache.ts`.
- Pairwise HMAC-SHA-256 and secret handling: `apps/minister/src/lib/pairwise-backend.ts`.
- Interim nullifier HKDF-SHA-256 and HMAC-SHA-256 stages:
  `apps/minister/src/lib/nullifier/encoding.ts`.
- OIDC client-secret Argon2id hashing: `apps/minister/src/lib/oidc-clients.ts`.
- Recovery-code Argon2id hashing: `apps/minister/src/lib/recovery-codes.ts`.
- Signet's HKDF-SHA-512 schedule and HMAC-SHA-256 disclose formula: `Signet/src/prf.rs`.
- Signet's AES-256-GCM sealing and blob format: `Signet/src/keystore.rs`.
- Signet's master-seed lifecycle and key-fork guards: `Signet/src/dedup.rs`.
- FreedInk's PBKDF2-HMAC-SHA-256 vault: `FreedInk/src/lib/client/vault.ts`.
- Discreetly's PBKDF2-HMAC-SHA-256 vault: `Discreetly/apps/web/src/lib/identity.ts`.
