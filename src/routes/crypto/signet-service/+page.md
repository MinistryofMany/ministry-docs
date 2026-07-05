---
title: "Signet: The Crypto-Core Service"
description: The separate Rust trust domain holding the nullifier and pairwise key material - its three independent key origins, its AES-256-GCM sealing, its PRF/dedup and blind-RSA endpoints, and the mTLS PKI that gates them.
order: 8
---

## Why a separate trust domain

Signet is not a Minister module running in another process for deployment
convenience. It is a deliberate second trust boundary: Minister never holds the
keys that link an anchor to a nullifier, so a Minister database leak - Postgres
dump, backup, or a compromised app process - cannot by itself reconstruct the
dedup namespace or forge a disclosed nullifier. Reconstructing either requires
Signet's own key material, which never leaves Signet and is sealed at rest under
its own key-encryption key.

The interim in-Minister nullifier backend (see
[The Badge Nullifier](/crypto/badge-nullifier)) is the cautionary example this
design avoids: there, the deriving key is co-resident with the ledger it protects,
so one compromise gets an attacker both halves of a dictionary oracle. Moving dedup
into Signet doesn't make key compromise impossible, but it does mean a Minister
compromise alone is not sufficient - the attacker also needs Signet, which sits
behind its own mTLS boundary and its own key custody.

Signet is one Rust binary (crate `signet`, edition 2021) exposing **two disjoint
surfaces gated by separate configuration**:

- **(A) Blind-RSA signing** (`/sign`, `/key*`) - the original FreedInk vote-token
  role.
- **(B) Crypto-core PRF/dedup** (`/prf/*`, `/dedup/*`) - the Minister nullifier and
  pairwise role this page mostly covers.

Both surfaces are reached only over mandatory mTLS with per-connection identity
pinning (below), and in the live Minister-only deployment surface (A) is
deliberately inert.

## Three key origins, not one tree

It is tempting to assume everything Signet holds derives from one master secret.
It does not - there are **three independent origins**, and conflating them is a
common mistake reading this system:

1. **`master_seed`** - 32 random bytes from the OS RNG, minted exactly once. It
   feeds `HKDF-SHA-512` to derive `seed_null`, which becomes the VOPRF keypair
   `(skS, pkS)` via RFC 9497's `DeriveKeyPair`. The same `master_seed` also derives
   every per-RP disclose key, `k_disc(clientId)`. Both derivations are covered in
   detail in [The Badge Nullifier](/crypto/badge-nullifier).
2. **The pairwise HMAC secret** is **imported**, not derived from the seed at all.
   It is the same `OIDC_PAIRWISE_SECRET` byte string Minister uses for its own
   in-process pairwise `sub`/`jti` HMAC, sealed into Signet so its `/prf/pairwise`
   oracle produces byte-identical output to Minister's local derivation.
3. **The blind-RSA group keys** are generated independently, per voting group,
   with safe primes - no relationship to `master_seed` or the pairwise secret.

```text
master_seed (32 B, OsRng, one-shot init only)     [service_keys purpose "master-seed-v1"]
  |- seed_null = HKDF-SHA512(master_seed, salt="", info="minister/v1/nullifier", L=32)
  |     `- (skS, pkS) = DeriveKeyPair(seed_null, info="minister/v1/nullifier/dedup")
  `- k_disc(clientId) = HKDF-SHA512(master_seed, salt="",
                          info="minister/v1/nullifier/disclose" || LP(clientId), L=32)

pairwise_secret (imported once, sealed; exact UTF-8 bytes)  [purpose "pairwise-hmac-v1"]
group RSA keys (independently generated per group, safe primes)
```

All three are sealed at rest with the same mechanism (below), but nothing is
shared between them: leaking one does not expose the others.

**Lifecycle guards against a silent key fork** (`Signet/src/dedup.rs`):

- `master_seed` is minted **only** by `signet init-service-keys` /
  `SIGNET_INIT_SERVICE_KEYS=1`, which prints `pkS` and nothing else - never the
  seed bytes - then exits.
- A node with `SIGNET_DEDUP_PUBKEY_PIN` set refuses to run init at all: a pinned
  seed already exists somewhere by definition, so that node must restore its
  keystore, never mint. This closes the fork where a stray
  `SIGNET_INIT_SERVICE_KEYS=1` left in a persistent unit env mints a fresh seed
  on a replica that boots before its keystore restore completes.
- Ordinary boot never generates a seed. If PRF is configured with no seed present,
  boot refuses. If a seed is present but its derived `pkS` doesn't match
  `SIGNET_DEDUP_PUBKEY_PIN`, boot refuses. If keys are initialized but
  `SIGNET_PRF_CLIENT_IDS` is empty, boot refuses.
- The `service_keys` table insert is write-once; a second `init-service-keys` run
  refuses rather than silently rotating.

## Sealing at rest

**Cipher.** AES-256-GCM (`aes-gcm` crate `0.10`), not libsodium or XChaCha.

- KEK: 256 bits, parsed from `SIGNET_KEK` (hex or base64), zeroized on drop.
- Nonce: 96 bits (12 bytes), fresh per seal, from `rand::rng()`.
- Auth tag: 16 bytes, GCM default.
- Sealed blob layout: `version(1 byte, = 0x01) || nonce(12 bytes) || ciphertext+tag`
  (`Signet/src/keystore.rs:8-11, 19, 69-73`).
- AAD: `group_id_bytes || key_id.to_be_bytes()` (`key_id` an 8-byte big-endian
  suffix, `Signet/src/keystore.rs:100-105`). Service keys (the master seed, the
  imported pairwise secret) seal under **`key_id = 0`**, with the purpose string
  as the `group_id`. Every group's blind-RSA private key seals under its own
  autoincrement rowid, which is always **≥ 1**. That 0-vs-≥1 split - not the
  purpose string - is what makes swapping a sealed blob between the two tables
  fail GCM authentication rather than silently decrypt.

One KEK seals everything: the 32-byte VOPRF master seed, the imported pairwise
secret, and every group's RSA PKCS#8 private key.

`SIGNET_KEK` and `SIGNET_IMPORT_PAIRWISE_HMAC` are read before the tokio runtime
starts (single-threaded at that point), parsed, zeroized, and removed from the
process environment with `remove_var` (`Signet/src/config.rs:100-145`). Pairwise
import is one-shot: it seals only on the first ordinary boot that passes every
validation, including the `pkS` pin check; a boot that refuses never persists it,
and a second import attempt also refuses.

> `remove_var` only mutates the runtime's view of the environment.
> `/proc/<pid>/environ` on Linux still exposes the original `SIGNET_KEK` bytes for
> the life of the process (it requires the same UID or `CAP_SYS_PTRACE` to read).
> This is accepted; the operational runbook prefers delivering the KEK over a file
> or file descriptor instead of an environment variable where possible.

## The PRF and dedup endpoints

All binary fields on this surface are base64url, no padding. Every route is
mounted only when Signet's boot policy actually enables the PRF surface.

| Endpoint | Method | Request | Response | Construction |
| --- | --- | --- | --- | --- |
| `/prf/evaluate` | POST | `{blinded_element}` | `{evaluation_element, proof}` | VOPRF blind evaluate + DLEQ |
| `/prf/public-key` | GET | - | `{suite: "ristretto255-SHA512", public_key}` | pinned `pkS` |
| `/dedup/register` | POST | `{value (= N_dedup), owner_handle, badge_type}` | `{status, entry_ref}` | ledger insert, `UNIQUE(value)` |
| `/dedup/release` | POST | `{entry_ref, owner_handle}` | `{status}` | owner-checked delete |
| `/dedup/reassign` | POST | `{entry_refs[], from_owner_handle, to_owner_handle}` | `{status, reassigned}` | merge re-tag, all-or-nothing transaction |
| `/prf/disclose` | POST | `{entry_ref, owner_handle, client_id}` | `{nullifier: "mnv1:..."}` | per-RP HMAC-SHA-256 |
| `/prf/pairwise` | POST | `{input}` (up to 512 bytes) | `{output}` | keyed HMAC-SHA-256 oracle over the imported pairwise secret |

The full stage-1/stage-2 construction behind `/prf/evaluate` and `/prf/disclose` is
covered in [The Badge Nullifier](/crypto/badge-nullifier). `/prf/pairwise` is a
generic keyed-HMAC oracle over the same imported secret Minister uses locally, so
`MINISTER_SUB_BACKEND`'s `local`, `shadow`, `signet-fallback`, and `signet` modes
all produce byte-identical output.

## The blind-RSA voting surface (inert in prod)

Signet's other surface, `/sign` and `/key*`, predates the crypto-core role and
serves FreedInk's blind vote tokens. It shares Signet's mTLS boundary and KEK
sealing but no key material with the PRF surface.

**Primitive.** RSAPBSSA-SHA384-PSS-Randomized - RFC 9474 RSA blind signatures plus
the partially-blind public-metadata extension
(`draft-amjad-cfrg-partially-blind-rsa`), via the `blind-rsa-signatures` crate
(`=0.17.2`), interop-tested against `@cloudflare/blindrsa-ts`'s
`RSAPBSSA.SHA384.PSS.Randomized`.

**Params.** Modulus size is `SIGNET_KEY_BITS`, defaulting to 2048 bits, constrained
to the range 2048-4096 and a multiple of 16. Keygen requires safe primes and
retries (bounded at 64 attempts) until the modulus is exactly the requested bit
length, because a short modulus breaks the TypeScript library's
`kLen = ceil(modulusLength / 8)` assumption. Signing hash is SHA-384, used for both
PSS padding and the metadata key derivation.

**Public metadata.** `version_info(versionId) = "freedink-vote:" || versionId`,
must match FreedInk's own `versionInfo` exactly. The per-metadata signing key is
derived crate-internally as `HKDF-SHA384(ikm = "key" || metadata || 0x00, salt =
modulus n, info = "PBRSA")`, where `metadata` is the version-info bytes above -
byte-identical to the TypeScript library; a token blinded under one metadata
version fails to verify under another.

**Signing.** The server receives only an already-blinded integer, computes
`s = m^d' mod n` with the per-metadata private exponent, and re-checks
`m == s^e' mod n` before returning - a fault-attack defense. It never sees or
unblinds the underlying token nonce, which is what keeps the signature
anonymity-preserving.

**Key management.** Each group's RSA key lives in `group_keys`: the public SPKI in
the clear, the PKCS#8 private key AES-256-GCM-sealed under the KEK (AAD-bound to
its own rowid). Insert-then-reseal-under-the-real-id happens in one transaction, so
no unopenable "active" row can survive a crash. At most one active key per group.
Key rotation is admin-only and synchronous.

**Status.** Inert in the Minister-only production deployment: a placeholder
`SIGNET_ALLOWED_CLIENT_IDS`, `SIGNET_AUTO_CREATE_KEYS=false`, no admin ids
configured. An identity pinned as PRF-only is explicitly refused on `/sign` and
`/key*`.

> RSA keygen (and the test-path blinding) uses the crate's `DefaultRng`, not an
> explicitly-audited `OsRng` call in Signet's own code. It is believed to be OS-backed via the crate,
> but it has not been audited as Signet code the way the VOPRF and AES-GCM RNG
> sources have. Since this surface is inert in prod, the risk is currently
> theoretical - but worth knowing before flipping it on.

## The mTLS PKI and identity pinning

**Transport.** rustls `0.23` with the **ring** crypto provider, installed
explicitly at startup. Client authentication is **mandatory**: the server builds
its client verifier with `WebPkiClientVerifier::builder(roots).build()` and
deliberately never calls `allow_unauthenticated()`, so a connection with no client
certificate never completes. ALPN is pinned to `http/1.1`; handshake timeout is
10 seconds (a slow-loris guard).

**PKI.** All three certificates in the production chain use **ECDSA P-256**
(`prime256v1`) with SHA-256 signatures - a different curve and a different
purpose from the VOPRF's ristretto255, and worth keeping distinct in your head.

| Cert | Subject | Key usage |
| --- | --- | --- |
| CA | `CN=Signet Prod CA` | `keyCertSign, cRLSign`; `CA:TRUE, pathlen:0`; kept offline |
| Server | `CN=signet`, `SAN=DNS:signet` | `serverAuth`, `digitalSignature` |
| Minister client | `CN=prf-minister` | `clientAuth` |

The server SAN must be the exact DNS name Minister dials (the compose service
name, `signet`) - the client side verifies it during the handshake. The
Minister client cert's exact `CN` (`prf-minister`) is what gets listed in
`SIGNET_PRF_CLIENT_IDS` to grant the PRF role - see below.

**Identity pinning.** Passing mTLS only proves a certificate chains to the CA; it
does not by itself authorize anything. Signet layers role-based authorization on
top by classifying the leaf certificate's CN plus every DNS SAN against three
allow-lists:

- `SIGNET_ALLOWED_CLIENT_IDS` grants the `Client` role (`/sign`, `/key`). Left
  empty, this is **open back-compat mode** - any cert with a valid chain becomes a
  `Client` - and Signet warns loudly about it at startup.
- `SIGNET_ADMIN_IDS` grants `Admin` (adds `/key/rotate`); empty means rotation is
  disabled for everyone.
- `SIGNET_PRF_CLIENT_IDS` grants the `Prf` role and sets `prf_allowed`. This is
  the **only** source of `prf_allowed` - it is never granted by the open-mode
  client allow-list, so a misconfigured `SIGNET_ALLOWED_CLIENT_IDS` cannot
  accidentally expose the PRF surface.

**Two-layer, fail-closed PRF authorization.** Every PRF request is checked twice:
`identity.may_prf()` (the pinned `prf_allowed` flag from the TLS handshake) and,
inside the handler, a fresh membership check that the pinned identity's name is
still in `PrfState.allowed_client_ids`. A `Prf`-role identity is refused on
`/sign` and `/key*` (`may_sign()` is false for it). An unauthorized caller gets
403 **before** the rate limiter runs, so it cannot burn rate-limit budget trying.
The TLS accept layer itself also drops peers who match no allow-list at all,
before the request layer sees them.

> Because candidate names include every DNS SAN on the certificate, a CA willing
> to sign a CSR-supplied SAN verbatim could smuggle a `prf-`-looking name onto an
> unrelated certificate and gain the PRF surface, including the pairwise HMAC
> oracle. The real security boundary is operator-controlled certificate issuance
> - CN and SAN fixed by policy, never taken verbatim from a CSR - not this
> name check, which only narrows the blast radius if issuance discipline slips.
> See [Threat Model and Known Gaps](/crypto/threat-model).

## Known gaps

> **Never-rotate keys.** Anchors are discarded immediately after nullification, so
> there is no re-derivation path if a key is ever rotated. The `pkS` pin plus
> one-shot initialization prevent a silent key fork, but the flip side is that
> recovering from a genuine key compromise means losing the entire dedup namespace
> - there is no "rotate and re-key" story.

> **KEK residual in `/proc/<pid>/environ`.** Covered above; accepted, ptrace-gated.

> **CSR-SAN smuggling.** Covered above; the mitigation is issuance discipline, not
> code.

> **RSA keygen randomness.** The blind-RSA surface uses the crate's `DefaultRng`
> rather than an explicitly audited `OsRng`; low real risk while that surface
> stays inert in production.

See [Threat Model and Known Gaps](/crypto/threat-model) for the full accepted-gaps
register alongside the rest of the crypto-core.

## Where to look in the source

- `Signet/src/dedup.rs` - key-fork guards, fail-closed boot matrix, one-shot init
  (`:87-104, 152-263`)
- `Signet/src/keystore.rs` - AES-256-GCM sealing, blob layout, AAD construction
  (`:1-24, 48-57, 69-105`)
- `Signet/src/config.rs` - `SIGNET_KEK` / `SIGNET_IMPORT_PAIRWISE_HMAC` pre-runtime
  handling and zeroization (`:100-145, 164-169`)
- `Signet/src/crypto.rs` - blind-RSA signing, per-metadata key derivation, fault
  recheck (`:1-129, 163`)
- `Signet/src/db.rs` - `group_keys` sealed storage, atomic reseal, issuance ledger
  (`:253-293, 295-319, 586-624`)
- `Signet/src/tls.rs` - mandatory client-auth verifier, ALPN, handshake timeout
  (`:19-43`)
- `Signet/src/identity.rs` - SAN/CN classification, three allow-lists, two-layer
  PRF gate (`:29-41, 163-211, 219-344`)
- `Signet/src/handlers.rs` - PRF surface authorization order and 403-before-rate-
  limit (`:155-166, 459-489`)
- `Signet/src/main.rs` - ring provider install, open-back-compat startup warning
  (`:38-50, 84-109, 112-115, 177-183`)
- `Signet/docs/crypto-core-operations.md` - the production PKI (CA/server/client
  cert fields) (`:44-99`)
- `Signet/examples/gen_certs.rs` - dev certificate generation (rcgen, ECDSA P-256)
- `ecosystem-planner/adr/signet-crypto-core-build-plan.md` - the design record
  Signet implements
