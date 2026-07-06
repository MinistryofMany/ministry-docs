---
title: Zero-Knowledge in the Relying Parties
description: The Semaphore membership proofs and RLN rate-limiting nullifiers that FreedInk and Discreetly run themselves, separate from Minister's OIDC and badge crypto, plus the client-side identity vaults and server-side badge-policy gating around them.
order: 11
---

## A separate crypto stack from Minister's

Everything in the rest of this track happens inside Minister and Signet: a
login, a badge, a nullifier that stops one person registering two badges off
the same anchor. None of that is zero-knowledge in the SNARK sense - it's
signatures, HMACs, and a blinded PRF.

FreedInk and Discreetly each run a second, independent zero-knowledge stack on
top of a Minister login, to prove group membership without revealing which
member you are. Think of a guest list at the door: the proof lets you show
you're on it without pointing at your name, and the person checking can
confirm the proof is genuine without ever learning who you are. FreedInk uses
Semaphore directly for blog membership.
Discreetly uses RLN (Rate-Limiting Nullifier), a Semaphore variant, for room
messaging. Neither app hand-rolls this math: both consume a shared package
family, `@ministryofmany/membership` and `@ministryofmany/rln`, published from
`minister-client/packages/*` and wrapping `@semaphore-protocol/*` / `rlnjs`
underneath. Discreetly also has its own in-repo `packages/crypto` (a directly
vendored `rlnjs@3.2.0` and `@semaphore-protocol/group@3.10.1`) and a
`@discreetly/policy` package - both are dead code today. A grep across
`apps/` and `services/` in Discreetly finds zero imports of
`@discreetly/crypto`; every live RLN call site imports `@ministryofmany/rln`
instead, and `@discreetly/policy` is now a one-line re-export of
`@ministryofmany/policy`. Worth flagging for cleanup, but it doesn't change
what's actually running.

In both cases the shape is the same: proving happens in the browser, the
server only verifies, and a nullifier - a tag derived from your secret that
flags reuse without revealing the secret itself - stops the same secret from
being reused in a way that should be caught.

## FreedInk - Semaphore membership proofs

FreedInk gates posting, commenting, and reviewing on a per-blog Merkle tree of
Semaphore identity commitments. A user proves membership in that tree without
revealing which leaf is theirs.

**Library.** `@ministryofmany/membership@0.2.1`, wrapping
`@semaphore-protocol/{identity,group,proof}@4.14.2` (Semaphore v4), with
`@zk-kit/eddsa-poseidon@1.0.4`, `@zk-kit/baby-jubjub@1.0.3`, and
`@zk-kit/lean-imt@2.2.4` underneath for the dynamic incremental Merkle tree.

**Construction.**

- Proof system: **Groth16**, the Semaphore v4 default circuit. Not overridden
  anywhere in FreedInk's code.
- Curve: **BN254** (`alt-bn128`) - the circom/Semaphore v4 default. FreedInk
  never restates this in app code, so treat it as `(library default)`. BN254
  is roughly **100-bit** effective security after the TNFS advances, not the
  128-bit its size suggests - see the
  [Cryptographic Overview](/crypto/overview).
- Identity commitment: `poseidon2(publicKey)`, where `publicKey` is an
  EdDSA-Poseidon public key over Baby Jubjub:

  ```js
  // node_modules/@semaphore-protocol/identity/dist/index.js:44
  this._commitment = poseidon2(this._publicKey)
  ```

- The Merkle tree is a `@zk-kit/lean-imt` LeanIMT with Poseidon-hashed
  internal nodes (`(library default)`, not restated in FreedInk's code).
- Tree depth: **dynamic**, not fixed. FreedInk declares
  `shape: { kind: 'dynamic' }` against the membership package's
  `MerkleGroupProvider` contract, and the depth grows with a blog's member
  count. The app pre-warms depths `1` and `4` and vendors per-depth circuit
  artifacts fetched at build time.
- Nullifier: the standard Semaphore nullifier, a function of the identity
  secret and a `scope` (the "external nullifier" in Semaphore terminology) -
  deterministic per `(identity, scope)`, so one identity gets exactly one
  nullifier per scope.

**What's proven, what stays secret.** The proof states "I know an identity
secret whose commitment is one of the leaves in this specific frozen Merkle
tree (this root), and I authored this `(scope, message)` pair" - without
saying which leaf. The identity secret never leaves the browser; only the
proof, the tree root, the nullifier, and the plaintext `message`/`scope`
cross the wire.

`scope` and `message` are chosen by the app and bind the proof to a specific
action, which is what stops a nullifier from one context being replayed in
another:

```text
// src/routes/api/blog/post/+server.ts:51-52
expectedScope   = `post:${blog.id}`
expectedMessage = `${title}\n\n${content}`

// src/routes/api/post/comment/+server.ts:43-44
expectedScope   = `comment:${post_version_id}`
expectedMessage = body
```

> The capability a proof is generated against (`author` vs `comment`) is not
> itself part of the Semaphore statement - a proof binds a Merkle root, not
> which capability tree that root belongs to. FreedInk's server pins the
> lookup to `(blogId, capability, root)` in its own snapshot store rather than
> trusting a client-claimed capability (`src/lib/server/semaphore.ts:22-27`).

**Replay defense.** The server-verified `nullifier` is stored under a
`UNIQUE(post_id, nullifier)` / `UNIQUE(post_version_id, nullifier)`
constraint, so the same nullifier can't post or comment twice. One caveat: the
review flow (`post_reviews`) has moved its anti-replay key off the Semaphore
nullifier onto a separate blind-token mechanism, and its nullifier columns are
legacy-only - don't assume every proof-gated action in FreedInk uses
nullifier-uniqueness uniformly.

> The shared package's engine defaults `requireCurrentRoot` to `true`
> (fail-closed), but FreedInk's `verifyMembership` wrapper overrides that to
> its historically tolerant default of `false` for any call site that omits
> the flag - a stale (pre-ban, pre-revoke) snapshot then still passes. The
> author, edit, and comment paths all pass an explicit `true` today
> (`src/lib/server/semaphore.ts:28-48`), but that's call-site-by-call-site
> discipline, not a structural guarantee.

**Client-side only, by construction.** `@semaphore-protocol/proof` is
excluded from server-side rendering and lazily imported, so proving code
never ships to or runs on the server:

```js
// vite.config.ts:22-30 (ssr.external), :37-46 (optimizeDeps.exclude)
ssr: { external: ['@semaphore-protocol/core', '@semaphore-protocol/group', '@semaphore-protocol/proof'] }
optimizeDeps: { exclude: ['@semaphore-protocol/proof'] }
```

The actual lazy import lives in `src/lib/client/semaphore.ts:29-48`
(`loadMembership()`). The server (`src/lib/server/semaphore.ts`) only ever
calls `membership.verify()` from the same shared package - it never
constructs a proof.

## Discreetly - RLN (rate-limiting nullifier)

Discreetly gates room messaging with RLN: a per-room Semaphore-style Merkle
tree plus a per-epoch message limit whose violation cryptographically
de-anonymizes the sender - deterrence, not a hard preventive cap (the
blockquote below spells that out).

**Library.** `@ministryofmany/rln@0.2.1` ("Self-contained Semaphore v3 + RLN
... privately bundles Semaphore v3 + rlnjs 3.2.0 + the depth-20 circuit"),
consumed by both `services/api` and `apps/web` via a pnpm link into
`minister-client/packages/rln`. Its own dependencies:
`rlnjs@3.2.0`, `@semaphore-protocol/group@3.10.1` (v3, not v4 - RLN in this
ecosystem is bound to Semaphore v3 identity math, a different lineage from
FreedInk's v4 membership proofs), `poseidon-lite@0.2.0`, `ffjavascript@0.2.60`.

**Construction.**

- Proof system: Groth16 (rlnjs's compiled circuit).
- Curve/field: **BN254 scalar field**, stated as an explicit constant rather
  than left implicit:

  ```js
  // minister-client/packages/rln/src/constants.ts:18-20
  SNARK_FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
  ```

- Identity secret (Semaphore v3 style): `secret = poseidon2([nullifier,
  trapdoor])` - the nullifier is hashed first, verified byte-for-byte against
  `@semaphore-protocol/identity@3.15.0`'s own constructor
  (`identity.ts:36-38`).
- Identity commitment: `commitment = poseidon1([secret])` (`identity.ts:41-43`).
- Rate commitment, the actual RLN Merkle leaf: `rateCommitment =
  poseidon2([identityCommitment, userMessageLimit])` (`field.ts:40-45`).
- Signal hash, which binds a message to a proof, is **not** Poseidon:
  `keccak256(utf8(signal)) >> 8n` (`signal-hash.ts:5-9`) - a keccak-then-
  truncate to fit the field, distinct from the Poseidon `getMessageHash` used
  only for internal bookkeeping.
- Tree depth: **fixed at 20** (`MERKLE_TREE_DEPTH = 20`, `constants.ts:23`),
  matching the compiled circuit artifacts Discreetly ships in
  `@discreetly/circuits`. This is the one place in this ecosystem where the
  Merkle depth is pinned exactly rather than a library default - contrast
  with FreedInk's dynamic depth above.

**The epoch and the message limit.** Each room configures `rateLimit`
(milliseconds per epoch) and `userMessageLimit` (messages allowed per epoch).
The current epoch is `floor(Date.now() / room.rateLimit)`, computed
identically on client and server, with a tolerance window of `epochErrorRange
= 1n` epoch either side.

**What's proven, what leaks on abuse.** The proof states "I hold an identity
secret whose rate-commitment leaf is in this room's tree, and I'm sending
message number `messageId` under `rlnIdentifier` for this `epoch`, with
signal-hash `x` matching my message content" - without revealing which
identity, unless the same identity proves twice in the same epoch. RLN binds
two secret-sharing points `(x, y)` to each message, on a degree-1 polynomial
whose y-intercept is the identity secret. One point reveals nothing; two
points from the same identity in the same epoch let anyone reconstruct the
secret via Shamir interpolation:

```js
// minister-client/packages/rln/src/shamir.ts:14-18
shamirRecovery(x1, x2, y1, y2)  // over the BN254 scalar field, via ffjavascript's ZqField
```

Discreetly's `banOnCollision` (`services/api/src/messaging/ban.ts:25-61`)
calls this on a detected epoch collision, re-derives the identity commitment
and rate commitment, and bans the membership by pruning its leaves - recording
the recovered secret in `Ban.shamirSecret` for audit. There's no staked
deposit burned here (this isn't a staked RLN deployment); the slashing outcome
is permanent room-membership revocation plus de-anonymization of the spammer's
identity, not a financial penalty.

> The per-epoch message counter that's supposed to stop a client sending more
> than `userMessageLimit` messages is enforced **client-side only**, in
> `localStorage` (`apps/web/src/lib/rln.ts:93-123`). A malicious client can
> trivially bypass it. The real enforcement is the Shamir recover-and-ban path
> above, which fires after the fact - this is RLN's standard design (economic
> and social deterrence, not a hard cap), but don't read the client-side
> counter as a security boundary. See
> [Threat Model and Known Gaps](/crypto/threat-model).

> `poseidon-lite` is pinned to exact version `0.2.0`, no caret, on purpose - a
> comment in `constants.ts:1-15` calls this out explicitly: a future `0.4.x`
> could silently change the Poseidon permutation and break every existing
> commitment, nullifier, and Merkle root with no runtime error. Golden Poseidon
> test vectors are asserted against the installed version to catch this. Any
> future bump of this dependency has to be treated as a breaking migration,
> not a routine update. See
> [Threat Model and Known Gaps](/crypto/threat-model).

**Client vs server split.** The client (`apps/web/src/lib/rln.ts`,
`apps/web/src/lib/identity.ts`) builds the identity, computes its own rate
commitment, and calls a lazily-imported `generateRlnProof` against
browser-fetched wasm/zkey artifacts. The server
(`services/api/src/messaging/verify-message.ts`) recomputes the expected
Merkle root from the room's live leaf set, recomputes the expected signal hash
from the actual message content itself (a client-claimed hash that doesn't
match the message fails), enforces the epoch window, and only then calls
`verifyRlnProof` against a statically-injected depth-20 verification key.
`pipeline.ts` orchestrates verify, dedup/collision-check, ban-on-collision,
then publish.

## The client-side identity vaults

Both apps keep the ZK identity secret out of server custody entirely, using
the same shape of construction with different parameters. Both start from a
password and stretch it through PBKDF2 - a deliberately slow, repeated-hash
key derivation, so brute-forcing a stolen ciphertext costs real computation -
to produce the key that locks the secret at rest.

| | FreedInk | Discreetly |
|---|---|---|
| KDF | PBKDF2-HMAC-SHA-256 | PBKDF2-HMAC-SHA-256 |
| Iterations | 600,000 | 210,000 |
| AEAD | AES-GCM, 256-bit key | AES-GCM, 256-bit key |
| Salt / IV | 16 B / 12 B, fresh per encryption | 16 B / 12 B |
| Stored where | server DB (opaque ciphertext) | browser `localStorage` |
| Serialization | `IdentityRecord` wire format | canonical Semaphore v3 `[trapdoor, nullifier]` hex tuple |

FreedInk's `src/lib/client/vault.ts` (browser-only, guarded by
`assertBrowser()`) derives an AES-256-GCM key from a password with WebCrypto's
native PBKDF2:

```js
// vault.ts:47-59
crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', ... }, ...)
// DEFAULT_ITERS = 600_000  (vault.ts:29)
```

> FreedInk's own `README.md` and `MINISTER_OIDC.md` describe an Argon2id
> vault and a four-path login model. Both are stale. Commit `82f72f3` ("make
> Sign in with Tessera the only sign-in method") removed passkeys, SIWE,
> email magic-link, and account recovery, leaving Minister OIDC as the sole
> sign-in path, and the docs were never updated. The vault code itself uses
> PBKDF2-HMAC-SHA-256, not Argon2id - WebCrypto has no native Argon2id, so
> that was never actually an option in the browser. Cite the code, not the
> README.

The server-side record (`IdentityRecord`) holds the public commitment, the
public key, the ciphertext, the salt, the nonce, and KDF params - never the
secret itself. FreedInk additionally supports a BIP-39 24-word mnemonic
backup of the raw 32-byte identity secret, which is deliberately *not*
encrypted (a second, password-independent recovery path whose custody is
entirely on the user).

Discreetly's `apps/web/src/lib/identity.ts` uses the same PBKDF2-then-AES-GCM
shape at 210,000 iterations (`PBKDF2_ITERATIONS`, `identity.ts:30`),
persisting to `localStorage` under `discreetly.identity.v1` rather than any
server-side record - the server never custodies even the ciphertext.

The two iteration counts are not equivalent. FreedInk's 600,000 is OWASP's
2023 recommended floor for PBKDF2-HMAC-SHA-256. Discreetly's 210,000 - its
source comment calls it a "spec floor" - is OWASP's floor for
PBKDF2-HMAC-**SHA-512**, misapplied here to SHA-256, so the Discreetly vault
sits well under the SHA-256 recommendation (see
[Hashing, HMAC, and Key Derivation](/crypto/hashing-hmac-and-kdfs)). And
either count is meaningfully weaker against GPU/ASIC brute force than a
memory-hard KDF like Argon2id would be. PBKDF2 is a deliberate trade -
WebCrypto has no native Argon2id - but it puts real weight on the strength of
the user's vault password.

## Discreetly's badge-policy gating - verification, not zero-knowledge

Discreetly gates room access on badges disclosed through Minister, in
addition to (not instead of) the RLN membership proof above. This part is
plain verification: the server sees the badge claims in the clear. The
selective-disclosure step that keeps a badge's holder anonymous already
happened Minister-side, before the badge ever reached Discreetly - see
[Verifiable Credentials and Holder Binding](/crypto/verifiable-credentials)
and [Selective Disclosure and Anonymity](/understand/selective-disclosure-and-anonymity)
for that part.

**Policy structure.** `@ministryofmany/policy` (re-exported by the
now-trivial local `@discreetly/policy` shim) is a recursive, Zod-validated
boolean tree over three node kinds:

```text
{ badge: { type, where?, maxAgeDays? } }   // leaf
{ allOf: [...] }
{ anyOf: [...] }
{ atLeast: { n, of: [...] } }
```

Every object is `.strict()`, so an unknown key is rejected. An empty
`allOf: []` admits everyone; an empty `anyOf: []` admits no one.

**Evaluation.** `services/api/src/gate/gate.ts`'s `evaluateGate` verifies the
presented Minister `id_token` via an injected verify function, gets back
`{ sub, badges }`, re-parses the stored policy JSON through the same schema
(so a tampered or legacy DB row fails closed on parse, not only on a runtime
evaluation throw), evaluates the policy against the badges, and defaults
`allowed = false` on any parse or evaluation failure. This is inline,
per-room-join, token-only evaluation against whatever badges the freshly
presented token happens to carry - there's deliberately no durable
"proven-badge" store or cross-session union.

**`id_token` Bearer re-verification on every gated call.**
`services/api/src/trpc/trpc.ts`'s `adminProcedure` requires the raw Bearer
token from the `Authorization` header (never carried in a query input or
URL) and calls `ctx.verify()` on it fresh, on every admin-gated call - a
cached "already logged in" decision is never trusted. `ctx.verify` is
`@ministryofmany/minister-verify`'s `makeVerifier`, wrapping
`@ministryofmany/client`'s `createMinisterVerifier`, cached per-process (it
fetches Minister's JWKS via OIDC discovery once).

> `makeVerifier` throws at construction time if its `audience` (mapped to the
> SDK's `clientId`) is falsy. The reason: `@ministryofmany/client` only
> enforces the `id_token`'s `aud` claim when `clientId` is truthy internally,
> so an empty or undefined audience would silently skip `aud` checking and
> accept a token minted for a different relying party. Failing construction
> rather than accepting a misconfigured verifier is the fix.

A rejected individual badge (forged, expired, wrong issuer, unknown type)
never throws - `verifier.verifyBadges(idToken)` drops it into a `rejected`
list and returns only the verified ones, so one bad badge doesn't take down
policy evaluation. The non-throwing `onRejectedBadges` callback that
Discreetly wires into its logger surfaces `sub`, a count, and per-entry error
messages - explicitly never the raw VC JWT, to avoid leaking token material
into logs.

**Badge age handling.** `issuedAtFromIssuanceMonth` maps Minister's coarse
`credentialSubject.issuanceMonth` claim (`"YYYY-MM"`) to the start of that UTC
month as the policy engine's `issuedAt`, deliberately never the VC's `iat`
(which Minister re-stamps to the disclosure instant, not the true issuance
time) - so a `maxAgeDays` policy leaf can only ever read a badge as *at
least* as old as it really is, never younger.

## DID resolution both apps share

Both apps use `did:web` exclusively (no `did:key` anywhere in either app or in
`minister-client`). `didFromIssuer(issuer)` derives the expected badge-VC
issuer DID purely from the configured OIDC issuer's host - `https://ministry.id`
becomes `did:web:ministry.id` - and is total and fail-loud: a path-bearing or
query-bearing issuer throws at RP config time rather than silently truncating.
`buildPairwiseSubjectDid(issuer, sub)` appends `:u:<sub>` to get the per-RP
pairwise subject DID a disclosed badge's `credentialSubject.id` must equal.

This is also the coupling this ecosystem has already been burned by once: see
[Threat Model and Known Gaps](/crypto/threat-model) for the issuer-host trap
where a mismatched host makes every badge silently land in `rejected` while
login keeps working.

## Where to look in the source

- FreedInk Semaphore client build/verify:
  `FreedInk/src/lib/client/semaphore.ts`, `FreedInk/src/lib/server/semaphore.ts`.
- FreedInk SSR exclusion for the proof library: `FreedInk/vite.config.ts`.
- FreedInk replay constraints: `FreedInk/src/lib/db/schema.ts`
  (`blog_post_versions_post_nullifier_key`, `post_comments_version_nullifier_key`).
- FreedInk client-side vault: `FreedInk/src/lib/client/vault.ts`.
- Shared membership wrapper: `@ministryofmany/membership` (published from
  `minister-client/packages/membership`).
- Shared RLN wrapper (constants, identity, field, signal hash, Shamir):
  `minister-client/packages/rln/src/{constants,identity,field,signal-hash,shamir}.ts`,
  plus the proof verifier at `minister-client/packages/rln/src/rln/verifier.ts`.
- Discreetly RLN client/server: `Discreetly/apps/web/src/lib/{rln,identity}.ts`,
  `Discreetly/services/api/src/messaging/{verify-message,pipeline,ban}.ts`.
- Discreetly Merkle leaves: `Discreetly/services/api/prisma/schema.prisma`
  (`MembershipLeaf`, `Ban`).
- Discreetly policy schema and evaluation:
  `minister-client/packages/policy/src/schema.ts`,
  `Discreetly/services/api/src/gate/gate.ts`.
- Discreetly id_token verification wiring:
  `minister-client/packages/minister-verify/src/verify.ts`,
  `Discreetly/services/api/src/minister/production-verifier.ts`,
  `Discreetly/services/api/src/trpc/trpc.ts`.
- did:web derivation shared by both apps: `minister-client/src/did.ts`.
