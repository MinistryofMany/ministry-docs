---
title: Threat Model and Known Gaps
description: What each part of the crypto stack protects against whom, and the full register of accepted gaps across Minister, Signet, FreedInk, and Discreetly, stated plainly rather than papered over.
order: 12
---

## What this page is for

Every other page in this track explains a construction. This one asks the
question an auditor actually asks: given a specific adversary, what does the
system claim to protect, and does it? The first table names five assets
worth protecting and the adversary each one is actually defended against. The
second section is the full register of accepted gaps across this ecosystem -
every one of them a place where the honest answer is "not fully," stated
without softening. If you're deciding whether to trust this system with real
users, read the gap register before you read anything else in this track.

## Assets, adversaries, and controls

| Asset | Adversary | What stops them | Implemented in |
|---|---|---|---|
| The pairwise-unlinkability guarantee (no two RPs can join their user tables on a shared identifier) | Two colluding relying parties comparing notes | `sub` is `HMAC-SHA-256(OIDC_PAIRWISE_SECRET, userId:clientId)` - one-way, and different per RP for the same user. A disclosed badge's `credentialSubject.id` is re-minted to the same per-RP pairwise DID, so the badge isn't a correlator either. | [Pairwise Subjects](/crypto/pairwise-subjects), [Verifiable Credentials and Holder Binding](/crypto/verifiable-credentials) |
| The badge trust anchor (`#key-2`, the only key listed in `assertionMethod`) | A leaked or misused token key (`#key-3`) | `assertionMethod` in the DID document lists only `#key-2`. A verifier that resolves badge-signing keys from `assertionMethod`, not the raw JWKS, will never accept a badge signed with `#key-3`, even though that key's public half sits in the same JWKS. | [Signatures, Keys, and the DID](/crypto/signatures-and-signing-keys), [Trust and Security Model](/understand/trust-and-security-model) |
| The dedup namespace (the nullifier ledger that stops one person registering two badges off the same real-world anchor) | A Minister database and key leak | Depends entirely on which nullifier backend is live. Under Signet's VOPRF, Signet never sees the anchor, only a blinded group element, so a Minister-only leak recovers nothing. Under the interim in-Minister HMAC backend, there is no such protection - see the gap register below. | [The Badge Nullifier](/crypto/badge-nullifier), [Signet: The Crypto-Core Service](/crypto/signet-service) |
| User identity secrets (the Semaphore/RLN secrets held in FreedInk's and Discreetly's client-side vaults) | A network attacker, or a compromise of the app's own database | The secret is encrypted client-side with AES-GCM under a PBKDF2-derived key and never leaves the browser in the clear; the server custodies only an opaque ciphertext blob plus public commitments. | [Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge) |
| User identity secrets, and a room's anti-spam guarantee | A malicious or over-rate app user in a Discreetly room | Not preventive - RLN's per-epoch counter is client-side only. A second same-epoch proof from the same identity leaks two Shamir points that reconstruct that user's own identity secret, letting the server ban them and record the recovered secret for audit. The deterrent is that abusing the system forfeits the abuser's own anonymity. | [Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge) |
| The `id_token` (session bearer artifact carrying the pairwise `sub` and, optionally, disclosed badges) | A network attacker with no valid credential, on-path or replaying captured traffic | Mandatory PKCE S256 with a timing-safe compare, required `state`/`nonce`, single-use 60-second authorization codes, exact redirect-URI matching, and no implicit or password flow. | [OIDC Flow Hardening and Disclosure](/crypto/oidc-flow-hardening) |
| The PRF oracles Signet exposes (pairwise HMAC, VOPRF evaluate, per-RP disclose) | Anything on the network that is not Minister | Mandatory mTLS with no unauthenticated fallback, plus a fail-closed per-route identity allow-list - a valid certificate chain alone does not grant the PRF surface. | [Signet: The Crypto-Core Service](/crypto/signet-service) |

## Key rotation - the honest state

There is no published rotation runbook for this ecosystem yet. Here's what we
can say accurately, straight from the code:

- **`#key-2` (the KMS badge key).** Boot pins the KMS-derived public key
  against a hardcoded `ISSUER_KMS_PUBLIC_JWK` and refuses to start on a
  mismatch. That's a strong anti-fork guard, but it also means rotating this
  key today is a manual, coordinated operation: generate the new KMS key,
  update the pinned JWK, and redeploy in lockstep, or every instance refuses
  to boot. There's no documented hot-rotation or overlap-window procedure.
- **`#key-3` (the in-process token key).** Cheaper to rotate in principle -
  it's a JWK you can swap and JWKS-serve immediately, and `id_token`s expire
  in 600 seconds, so an old signature stops mattering fast. Still, no rotation
  script or runbook is documented; today it's "replace `TOKEN_SIGNING_JWK` and
  redeploy."
- **Signet's `master_seed`.** Deliberately never rotated, by design, not by
  gap. Anchors are discarded after nullification, so there's no re-derivation
  path if the seed changed - rotating it would silently orphan every existing
  dedup entry. The `pkS` boot pin and one-shot init exist specifically to stop
  an accidental fork, not to enable rotation. A genuine seed compromise means
  losing the entire dedup namespace and starting over, not rotating in place.
- **Signet's blind-RSA per-group keys** (the FreedInk vote-token surface,
  inert in prod) are the one piece of this ecosystem with actual rotation
  support: admin-only, synchronous, one active key per group.
- **`OIDC_PAIRWISE_SECRET` and `AUTH_SECRET`.** No rotation procedure is
  documented in the inventoried code. Rotating `OIDC_PAIRWISE_SECRET` would
  change every derived pairwise `sub` at once, breaking every RP's existing
  account linkage - this needs a real migration plan (a `SubjectOverride`-style
  mechanism, or a dual-secret verify window) that doesn't exist today.

The individual postures are documented - the never-rotate seed is an explicit
ADR decision, covered on
[Signet: The Crypto-Core Service](/crypto/signet-service) - but the absence
of any rotation runbook is not recorded as a gap anywhere else, so let's say
it plainly here: rotation is possible for some keys and effectively a
one-way door for others, and there is no written runbook for any of it yet.

## The accepted-gaps register

Every gap below is either currently accepted, or accepted for a bounded
period with a stated condition. None of them are secret from the people who
built this - they're documented in the codebase's own ADRs and TODOs. Listing
them here in one place is the point of this page.

### H-1: the credential-quarantine cooldown is written but never enforced

**Severity: high.** We built the quarantine window; we never wired it up.
Minister sets a `quarantinedUntil` field on a freshly
added credential (for example, a passkey just grafted onto an account) and
displays it in the UI, but no production code path actually reads that field
before allowing a privileged action. A session that just reached AAL2 via a
still-quarantined credential can immediately start an account merge, generate
recovery codes, or change the account's primary email. This isn't a new
unauthenticated takeover path - it still requires reaching AAL2 first - but
the advertised blast-radius containment (a freshly added credential can't
immediately unlock the account's highest-value actions) doesn't actually
exist. It's accepted for the alpha; the fix (thread the acting credential's
id onto the session JWT, require a non-quarantined AAL2 credential for merge
and recovery-code generation) is flagged to land before those flows reach
real users. See
[Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge).

### The interim nullifier backend is a dictionary oracle

**Severity: high, while it's the live backend.** The default
`MINISTER_NULLIFIER_BACKEND=interim` derives the dedup nullifier with a
deterministic HMAC keyed by `OIDC_PAIRWISE_SECRET`, and stores the result
`UNIQUE`-indexed in Minister's own Postgres, with the deriving key co-resident
in the same environment. A database-plus-key leak lets an attacker hash
candidate anchors (guessed emails, known OAuth account ids) and match them
against stored values, recovering exactly the real-world identifiers the
nullifier was supposed to keep opaque. This is accepted only under a hard,
code-enforced `users == 0` deploy gate, and it's exactly why we moved dedup
into Signet's blinded VOPRF in the first place - Signet never sees the
anchor, only a blinded group element, so the same leak against Signet
recovers nothing. If you're checking whether this gap applies to a live
deployment, confirm which backend is actually selected; the construction
matters more than today's flag value, which is why this page describes both
rather than asserting one. See [The Badge Nullifier](/crypto/badge-nullifier).

### Stage-2 disclosure has no DLEQ - Minister just trusts Signet

**Severity: medium.** Stage-1 dedup carries a DLEQ proof - discrete-log
equality, a proof that the same secret key was used to produce two different
values, without revealing the key - that Minister verifies against a pinned
public key, so Signet can't quietly swap in a different key mid-protocol. Stage-2, the per-RP disclosed nullifier, is a
plain HMAC computed inside Signet with no accompanying proof - deliberately,
since a proof over an already-derived PRF output would recreate the same
equality-oracle risk the VOPRF design was meant to avoid. The consequence:
if Signet is compromised or misbehaves, a false link (the same disclosed
nullifier handed to two different users at one RP) is cryptographically
undetectable by Minister. Minister's salted `NullifierRpCheck` drift cache
catches accidental drift (the value changing when it shouldn't), but it
cannot catch deliberate false-linking, and the design accepts that as the
edge of Signet's trust envelope. See
[The Badge Nullifier](/crypto/badge-nullifier),
[Signet: The Crypto-Core Service](/crypto/signet-service).

### The pairwise input encoding is untagged, not length-prefixed

**Severity: low, structurally sound today.** The four frozen pairwise input
families (`userId:clientId`, `jti:badgeId:clientId`, and their share-link
variants) are colon-delimited strings, not length-prefixed. That's only safe
because every id involved is a cuid and every `clientId` is enforced to match
`^mc_[A-Za-z0-9_-]+$` at creation time - no colon can appear in either side of
the delimiter, so there's no `a:b` versus `ab` collision hazard today. It's a
hardening item precisely because the safety depends on that charset guard
covering every client-creation path, rather than on the encoding itself
ruling out collisions. A future non-`mc_`-prefixed client id path would
reintroduce the risk. See [Pairwise Subjects](/crypto/pairwise-subjects).

### `SIGNET_KEK` residual in `/proc/<pid>/environ`

**Severity: low, accepted.** Signet consumes `SIGNET_KEK` from its
environment before the async runtime starts and calls `remove_var` on it
afterward, but on Linux that only mutates the process's runtime view of its
own environment - the original value is still readable from
`/proc/<pid>/environ` for the life of the process, to anyone with the same
UID or `CAP_SYS_PTRACE`. The operational runbook prefers file- or
fd-based secret delivery over an environment variable for exactly this
reason, but the code path still accepts an env var, and this residual is
accepted rather than closed. See
[Signet: The Crypto-Core Service](/crypto/signet-service).

### A CA that signs CSR-supplied SANs could smuggle a PRF identity

**Severity: low if certificate issuance is disciplined; high if it isn't.**
Signet's mTLS identity pinning classifies a connecting client by its leaf
certificate's CN and every DNS SAN. If the CA that issues client certs ever
signs a CSR's SANs verbatim rather than fixing them at issuance time, an
attacker who can get any certificate signed could add a `prf-`-prefixed name
and land in the `Prf` role - including the pairwise HMAC oracle. The
mitigation isn't in Signet's code at all; it's operator discipline in
certificate issuance (fixed CN/SAN, never CSR-verbatim). Signet's in-handler
allow-list re-check narrows the blast radius but doesn't close this if
issuance discipline fails. See
[Signet: The Crypto-Core Service](/crypto/signet-service).

### Discreetly's per-epoch RLN message limit is client-side only

**Severity: low, by RLN's own design.** The counter that's supposed to stop
a client from sending more than `userMessageLimit` messages in one epoch
lives in browser `localStorage` and is trivially bypassable by a modified
client. This is RLN's intended design, not an oversight in Discreetly's
implementation - the real enforcement is reactive, not preventive: a second
same-epoch proof from the same identity leaks the Shamir points that let the
server recover and ban that identity after the fact. Don't read the
client-side counter as a security boundary; the honest framing is "abuse
gets punished after one collision," not "abuse is rate-limited in real
time." See
[Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge).

### `poseidon-lite@0.2.0` is pinned exactly, and that pin is load-bearing

**Severity: low today, high if ever violated.** Discreetly's RLN package
pins `poseidon-lite` to exactly `0.2.0`, with no caret, because a routine
minor-version bump of that package could silently change the Poseidon
permutation and invalidate every existing identity commitment, nullifier,
and Merkle root in production - with no runtime error to flag it. Golden
Poseidon test vectors guard against this being missed in CI, but any future
dependency bump of this specific package has to be treated as a breaking
migration, coordinated with re-enrollment, not a routine `pnpm update`. See
[Zero-Knowledge in the Relying Parties](/crypto/relying-party-zero-knowledge).

### Signet's RSA keygen uses the crate's `DefaultRng`, not an audited `OsRng`

**Severity: low, and the surface is inert in prod.** Signet's blind-RSA
signing surface (the FreedInk vote-token role) generates keys and blinds
messages using the `blind-rsa-signatures` crate's own `DefaultRng`, rather
than an `OsRng` explicitly chosen and audited in Signet's own code. It's
believed to be OS-backed via the crate, but that's trusting the dependency's
default rather than Signet's own randomness discipline elsewhere (which does
use explicit `OsRng` for the master seed, dedup entry refs, and VOPRF
proofs). This surface is deliberately inert in the current Minister-only
production deployment, which limits the practical exposure today. See
[Signet: The Crypto-Core Service](/crypto/signet-service).

### Account merge leaves a short stale-token window

**Severity: low, bounded.** When two accounts merge, the donor's
`OidcGrant` rows aren't migrated to the survivor, and the donor's still-valid
`OidcAuthorizationCode` rows survive the merge - the `/token` endpoint
doesn't check the merge tombstone before redeeming them. That leaves a window,
bounded by the authorization code's own 60-second TTL, where a code issued to
the donor just before a merge could still be redeemed just after it. This is
not a cross-account data leak - it just means the donor's pre-merge login
attempt can complete for roughly the width of one code TTL after the merge
commits. See
[Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge).

### The issuer-host coupling trap

**Severity: medium, and the one gap most likely to bite an operator, not an
attacker.** The SDK derives the badge-VC issuer DID it expects from the RP's
configured OIDC issuer host alone, with no override. If a relying party's
`MINISTER_ISSUER` host doesn't exactly match Minister's own
`MINISTER_ISSUER_DOMAIN`, every disclosed badge silently lands in `rejected`
while `id_token` verification - which never touches the VC issuer - keeps
succeeding. Login works, badge gating silently fails, and nothing throws an
error to say why. It fails closed (no badge is ever wrongly accepted on a
mismatch) but it fails silently, and this has already been observed
empirically in a cross-app integration test with a mismatched
`MINISTER_ISSUER_DOMAIN`. This is covered in full, including the fix and the
detection signal, in
[Trust and Security Model](/understand/trust-and-security-model) - that page
owns this gap; this entry exists so the register is complete in one place.

## Where to look in the source

- H-1 and the quarantine gap: Minister `TODO.md` ("Account assurance /
  recovery - security follow-ups" section) and `apps/minister/src/lib/assurance.ts`.
- Interim nullifier dictionary-oracle acceptance and the `users == 0` gate:
  `minister-crypto-core.md` (Minister ADR), `apps/minister/src/lib/nullifier/interim.ts`,
  `scripts/count-users.ts`.
- Stage-2 no-DLEQ trust boundary: `signet-crypto-core-build-plan.md` §2.1
  ("Stage-2 trust boundary"), Signet `prf.rs`.
- Untagged pairwise encoding: `minister-crypto-core.md` (review finding L4),
  `apps/minister/src/lib/pairwise-backend.ts`.
- `SIGNET_KEK` `/proc` residual: Signet `config.rs`, `docs/crypto-core-operations.md`.
- CSR-SAN smuggling: Signet `identity.rs`.
- RLN client-side limit and the Shamir recovery path: `minister-client/packages/rln/src/shamir.ts`,
  `Discreetly/apps/web/src/lib/rln.ts`, `Discreetly/services/api/src/messaging/ban.ts`.
- `poseidon-lite` pin: `minister-client/packages/rln/src/constants.ts`.
- RSA `DefaultRng`: Signet `crypto.rs`.
- Merge stale-token window: Minister `TODO.md` (merge/token findings section),
  `apps/minister/src/lib/merge.ts`.
- Issuer-host coupling: `minister-client/src/did.ts`, and the empirical
  confirmation noted in the ecosystem's own root `CLAUDE.md`.
