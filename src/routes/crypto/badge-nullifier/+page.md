---
title: The Badge Nullifier
description: The two-stage Sybil-dedup construction behind badge issuance - a blinded VOPRF dedup stage Signet never sees the anchor for, and a per-RP HMAC disclose stage - plus the interim backend it is replacing and why.
order: 7
---

## The problem

A badge like `oauth-account` or `email-domain` should be issuable once per real-world
anchor - one GitHub account, one email domain - no matter how many Minister accounts
someone creates. Enforcing that one-per-anchor rule the naive way (storing the anchor
in a table and checking for a duplicate) means Minister holds a plaintext, queryable
list of every user's GitHub id or email address forever. That is exactly the
correlatable, single-database blast radius the rest of this track works to avoid.

The badge nullifier solves it without ever storing the anchor. It is a **gating-only**
construction: it decides whether to *issue* a badge, and it is not the same thing as
the Poseidon/BN254 nullifiers Semaphore and RLN use inside a zero-knowledge circuit
(see [Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge)).
This one runs entirely server-side, in two stages with different trust properties:

| Stage | Primitive | Output | What Minister learns | What Signet learns |
| --- | --- | --- | --- | --- |
| 1: dedup | VOPRF, ristretto255-SHA-512 | `N_dedup`, 64 bytes | The finalized value, after independently DLEQ-verifying it | A blinded group element at evaluate time, plus the finalized `N_dedup` values it stores in the ledger - never the anchor |
| 2: disclose | HMAC-SHA-256 | `N_rp`, 32 bytes, `mnv1:`-prefixed | The per-RP nullifier, trusted without proof | The stored `N_dedup` and the requesting `clientId` |

Stage 1 answers "has this anchor already claimed a badge of this type, under a
different account?" Stage 2 answers "what value do I show *this* relying party,
such that it can never be linked to the value another RP sees for the same badge?"

## Stage 1: dedup, blinded

**Primitive.** VOPRF, verifiable mode `0x01`, ciphersuite `ristretto255-SHA512`
(RFC 9497). Signet's Rust `voprf` crate (`=0.5.0`, curve25519-dalek backend) implements
it; RFC 9497 Appendix A.1.2 test vectors are asserted in-repo, and an interop harness
cross-checks the TypeScript `@cloudflare/voprf-ts` implementation.

**Sizes.** Group elements (the blinded element, the evaluation element, `pkS`) are
32 bytes. The DLEQ proof is 64 bytes - two 32-byte scalars, `c` and `s`. The finalized
output `N_dedup` is 64 bytes (a SHA-512 Finalize output). Security is roughly
**128-bit**: ristretto255 is a prime-order group of order close to `2^252`, with no
cofactor or invalid-point classes to reject - the stated reason the build plan chose
ristretto255 over P-256 for this stage.

**Domain-separation constants**, quoted from `Signet/src/prf.rs:74-79`:

```text
TAG_PROTOCOL         = "minister/null/v1"
TAG_DEDUP            = "dedup"
INFO_NULLIFIER_SEED  = b"minister/v1/nullifier"
INFO_DEDUP_KEYPAIR   = b"minister/v1/nullifier/dedup"
```

Every input to the construction is built with `LP(x)`, a 2-byte big-endian length
prefix followed by the bytes of `x` (`Signet/src/prf.rs:81-90`), never bare
concatenation. This matters because one of the concatenated fields - the raw anchor,
called `sybil_id` in the code - is attacker-influenced and variable-length.
`LP("ab") || LP("c")` and `LP("a") || LP("bc")` are distinct byte strings, where the
bare concatenations `"ab" || "c"` and `"a" || "bc"` would collide. Length-prefixing
every field closes that shuffle off.

The dedup input (`Signet/src/prf.rs:92-108`, built as `dedup_input`):

```text
input = LP("minister/null/v1") || LP("dedup") || LP(sybil_id) || LP(badge_type)
```

**The protocol.**

1. Minister builds `input` and **blinds it client-side** before sending anything.
   Signet never sees the anchor - only the blinded group element crosses the wire.
2. Minister calls `POST /prf/evaluate` with `{blinded_element}`. Signet deserializes
   the ristretto255 element (rejecting non-canonical encodings *and* the identity
   element, per RFC 9497), computes the evaluation element (`skS · B` - deterministic
   in the input), and returns `{evaluation_element, proof}`, where `proof` is a
   randomized DLEQ proof that the evaluation used the secret key behind `pkS`
   (`Signet/src/handlers.rs:585-609`).
3. Minister finalizes the response into the deterministic 64-byte `N_dedup`, but only
   after **DLEQ-verifying the proof against its own, independently pinned copy of
   `pkS`** (`Minister/apps/minister/src/env.ts:64-67`). A Signet that returned a
   forged evaluation without the matching proof fails verification here, fail-closed.
4. Minister calls `POST /dedup/register` with `{value: N_dedup, owner_handle, badge_type}`.
   This is a record-first `UNIQUE(value)` insert; the unique index itself decides
   the outcome.

Determinism is the whole trick: the same `(skS, input)` pair always finalizes to the
same `N_dedup`, regardless of which random blind was used to hide it in transit. That
lets Signet compare finalized outputs by plain byte equality without ever having
learned the anchor that produced them.

**The ledger.** `dedup_entries(entry_ref BLOB PK, value BLOB UNIQUE, owner_tag,
badge_type, created_at)` (`Signet/src/db.rs:195-201`). `value` is the 64-byte
`N_dedup`, and `UNIQUE(value)` **is** the dedup comparison. Three outcomes
(`Signet/src/db.rs:400-449`):

- a new value → `Registered`;
- the same value, the same owner → `AlreadyYours` (re-issue, same ref - owner
  compared constant-time via `subtle::ConstantTimeEq`);
- the same value, a **different** owner → `Taken` → **HTTP 409** - the one-credential,
  one-account refusal.

`entry_ref` is a 16-byte OS-random opaque handle, persisted on the Minister side as
`Badge.nullifierRef`; `owner_tag` is an opaque per-user handle Minister mints, never a
raw user id.

**Key pinning.** `skS`/`pkS` come from `VoprfServer::new_from_seed(seed_null,
info="minister/v1/nullifier/dedup")` - RFC 9497 §3.2.1 `DeriveKeyPair`. Signet derives
`pkS` at boot from its sealed seed and compares it against `SIGNET_DEDUP_PUBKEY_PIN`
(a base64url-encoded 32-byte pin); a mismatch **refuses startup** rather than silently
serving a forked key. `GET /prf/public-key` exposes `pkS` for independent client-side
verification. See [Signet: The Crypto-Core Service](/crypto/signet-service) for the
full key schedule.

**Frozen golden vector** (`Signet/interop/prf-vectors.json`, asserted
`Signet/src/prf.rs:391-426`, forever-stable):

```text
seed  = "MINISTER-TEST-VECTOR-SEED-0001!!"
pkS   = 8uMuBaBUTsZb-btCd6BMV_NdqYdyXqOkoh5NepCesAg
N_dedup(gh:1234567, oauth-account) = bf13858616d5...bb2a21   (64 bytes)
```

## Stage 2: per-RP disclose

**Primitive.** HMAC-SHA-256 (RFC 2104 / FIPS 198-1), computed **inside Signet, over
the already-stored `N_dedup`** - not blinded, not proof-carrying. That is deliberate:
the input to this stage is already the output of a verified PRF, so a proof here
would only recreate an equality oracle that Minister's own database would then hold.

**Formula** (`Signet/src/prf.rs:12-13, 198-224`):

```text
N_rp = "mnv1:" || base64url_nopad( HMAC-SHA256( k_disc(clientId),
          LP("minister/null/v1") || LP("rp") || LP(N_dedup) || LP(clientId) ) )
```

Output is 32 bytes of HMAC-SHA-256, 43 base64url characters, prefixed `mnv1:`
(`NULLIFIER_PREFIX`, length asserted at `Signet/src/prf.rs:436-443`). `clientId`
appears in both the key derivation below and the MAC message itself - belt and
braces against a derivation bug that would otherwise collapse two RPs' nullifier
spaces together.

**Per-RP key** (`Signet/src/prf.rs:76, 199-207`):

```text
k_disc(clientId) = HKDF-SHA512(ikm = master_seed, salt = "",
    info = "minister/v1/nullifier/disclose" || LP(clientId), L = 32)
```

Note the hash asymmetry: stage 1's keypair derivation and its 64-byte `N_dedup` use
**SHA-512**; stage 2's `k_disc` derivation is also HKDF-SHA-512, but the disclose MAC
itself and its 32-byte `N_rp` output are **HMAC-SHA-256**. Do not conflate the two.

A distinct `k_disc` per RP means a leaked RP key de-anonymizes only that one RP's
nullifier space, not every RP's.

**Wire.** `POST /prf/disclose {entry_ref, owner_handle, client_id}` returns
`{nullifier}`. The entry is fetched by `entry_ref` and the supplied `owner_handle`
must equal the stored `owner_tag`, constant-time compared, or the call returns
**403** - this is what stops an attacker who can write `Badge.nullifierRef` in
Minister's database from presenting someone else's nullifier.

> **No DLEQ on stage 2.** Minister trusts Signet for stage-2 *correctness* with no
> cryptographic check. A compromised Signet could drift `N_rp` (evading a ban) or
> collide it across two users (false-linking them at one RP), and neither is
> detectable by Minister's crypto alone. Minister runs a salted drift cache
> (`NullifierRpCheck`) that catches accidental drift - it cannot catch deliberate
> false-linking. See [Threat Model and Known Gaps](/crypto/threat-model).

**The drift cache.** SHA-256, `check = SHA-256(salt || UTF8(N_rp))`, with a fresh
16-byte random salt per row so two rows that happen to share an `N_rp` don't produce
comparable digests (`Minister/apps/minister/src/lib/nullifier/drift-cache.ts:38-42,
95`). On every disclosure of a ref-bearing badge, Minister recomputes and compares;
a mismatch throws `NullifierDriftError` and the badge is omitted from disclosure
rather than sent out stale. Rows are never reaped.

**Golden vector** (`Signet/interop/prf-vectors.json`):

```text
client_id = mc_golden_client_0001
N_rp = mnv1:b1Er88B8RZaAeBIMLBpKCBfk7zuF5O3JZv75aSZQbmI
```

## Two backends, one interface

`MINISTER_NULLIFIER_BACKEND` selects which implementation runs behind the same
frozen interface (`Minister/apps/minister/src/lib/nullifier/index.ts:43-94`):

| | Interim (in-Minister) | Signet (VOPRF) |
| --- | --- | --- |
| Primitive | HMAC-SHA-256, keyed by `k_int` (HKDF-SHA-256 from `OIDC_PAIRWISE_SECRET`) | VOPRF, ristretto255-SHA-512 |
| Stage-1 value | 32 raw bytes | 64-byte SHA-512 Finalize output, `N_dedup` |
| Anchor visibility | Minister computes the HMAC directly over the plaintext anchor | Signet only ever sees a blinded group element |
| Ledger location | Minister's own Postgres, `NullifierEntry` | Signet's SQLite, `dedup_entries` |
| Key custody | `k_int` is co-resident with the ledger it protects | `skS` never leaves Signet, sealed under `SIGNET_KEK` |
| Protocol tag | deliberately omits `"minister/null/v1"` | carries `TAG_PROTOCOL = "minister/null/v1"` |
| Selected by | `MINISTER_NULLIFIER_BACKEND=interim` (code default) | `MINISTER_NULLIFIER_BACKEND=signet` |

The interim stage-1 formula (`Minister/apps/minister/src/lib/nullifier/encoding.ts:72-77`):

```text
value = HMAC-SHA256(k_int, LP("dedup") || LP(anchor) || LP(badge_type))
k_int = HKDF-SHA256(ikm = OIDC_PAIRWISE_SECRET, salt = "",
    info = "minister/v1/nullifier-interim", L = 32)
```

It deliberately omits the `"minister/null/v1"` protocol tag the VOPRF construction
carries, so a throwaway interim value can never be mistaken for a real, forever
VOPRF value if the two ever needed to be told apart later.

> **Why dedup moved to Signet.** The interim backend derives `k_int` from
> `OIDC_PAIRWISE_SECRET` and stores deterministic HMAC outputs, `UNIQUE`-indexed,
> in Minister's own Postgres - with the deriving key co-resident in the same
> environment as the ledger it protects. Anyone who reads both (a DB dump plus the
> key) can hash candidate anchors - guessed emails, GitHub ids - and match them
> against stored values, recovering who holds which badge. That is a dictionary
> oracle, and it is the reason the dedup ledger was moved into Signet: Signet never
> receives the anchor at all, so there is nothing in its database to dictionary-attack
> back to an anchor even with full key and database compromise. The interim path is
> accepted only as a fallback, behind a hard users-equals-zero deploy gate. See
> [Threat Model and Known Gaps](/crypto/threat-model).

## Email anchor normalization

An email-address anchor has to be canonicalized before it is fed into either
backend, or the same person's `alice+minister@gmail.com` and
`Alice@Gmail.com` would dedup as two different anchors. The rules
(`Minister/apps/minister/src/lib/nullifier/normalize.ts:50-94`):

- Trim and lowercase, always.
- `googlemail.com` is rewritten to `gmail.com`.
- Gmail addresses strip a `+tag` suffix **and** every dot in the local part.
- Outlook, Hotmail, and Live addresses strip a `+tag` suffix but leave dots alone.
- Every other domain is lowercased only, with no local-part rewriting.
- A non-ASCII character anywhere in the address is rejected outright rather than
  silently normalized: lowercasing non-ASCII can collapse distinct addresses (the
  Kelvin-sign homoglyph hazard, `U+212A` lowercasing to `k`) or leave visually
  identical forms as distinct anchors.

The rule set is versioned, `ANCHOR_NORMALIZATION_VERSION = 1`
(`normalize.ts:30`), under an append-only contract: changing a rule re-keys every
anchor it touches, so rules only ever get added, never edited in place.

> Coverage is intentionally minimal, not exhaustive: iCloud, Proton, Fastmail, and
> regional Microsoft domains get no special-case handling today. Every `email-*`
> badge type is marked `sybilResistance: "weak"` for exactly this reason. See
> [Threat Model and Known Gaps](/crypto/threat-model).

## Where to look in the source

- `Signet/src/prf.rs` - VOPRF stage 1, disclose stage 2, domain-separation
  constants, `LP`, golden-vector tests (`:1-108, 154-224, 280-359, 391-426`)
- `Signet/src/handlers.rs` - `/prf/evaluate`, `/prf/disclose`, `/dedup/register`
  handlers (`:432-489, 585-688, 717-733`)
- `Signet/src/db.rs` - `dedup_entries` schema and record-first classify
  (`:44-55, 98-101, 195-201, 400-449`)
- `Signet/src/dedup.rs` - `pkS` pin check and fail-closed boot matrix
  (`:87-104, 152-263`)
- `Signet/interop/prf-vectors.json` - the frozen cross-repo golden vectors
- `Minister/apps/minister/src/env.ts` - pinned `MINISTER_SIGNET_DEDUP_PUBKEY` (`:64-67`)
- `Minister/apps/minister/src/lib/nullifier/index.ts` - the frozen backend interface
  (`:43-94, 99-110`)
- `Minister/apps/minister/src/lib/nullifier/encoding.ts` - interim formulas and caps
  (`:18-27, 30-42, 72-77, 112-117`)
- `Minister/apps/minister/src/lib/nullifier/interim.ts` - interim ledger ops and
  release atomicity (`:31-150`)
- `Minister/apps/minister/src/lib/nullifier/drift-cache.ts` - stage-2 drift check
  (`:38-58, 67-111`)
- `Minister/apps/minister/src/lib/nullifier/normalize.ts` - email anchor
  normalization (`:30, 50-94`)
- `ecosystem-planner/adr/minister-crypto-core.md` - the design record this
  construction implements
