---
title: Pairwise Subjects
description: The HMAC-SHA-256 construction behind Minister's pairwise sub and jti - the four frozen input families, the domain-separation caveat, the MINISTER_SUB_BACKEND seam to Signet, and SubjectOverride at merge.
order: 5
---

## The construction

The pairwise `sub` (and the disclosure `jti`, and the two share-link
pseudonyms) are all one primitive applied to four different tagged inputs:
`HMAC-SHA-256(key, input)`, 32 raw bytes, `base64url`-encoded (RFC 4648 §5, no
padding) to a 43-character string.

The key is `OIDC_PAIRWISE_SECRET`: an environment-required string of at least
32 characters, read directly at call time with no fallback.

```ts
// apps/minister/src/lib/pairwise-backend.ts:118-128
function pairwiseSecret(): string {
  const secret = process.env.OIDC_PAIRWISE_SECRET;
  if (!secret) {
    throw new Error("OIDC_PAIRWISE_SECRET must be set");
  }
  return secret;
}

// apps/minister/src/lib/pairwise-backend.ts:133-135
export function deriveLocalPairwise(input: string): string {
  return createHmac("sha256", pairwiseSecret()).update(input).digest("base64url");
}
```

That last function is the whole primitive: no iteration, no stretching. It is
a keyed PRF over internal ids the server already controls (cuids and
`mc_`-prefixed client ids), not a password hash, so unsalted single-pass HMAC
is the right tool - there is nothing low-entropy an attacker could brute-force
offline the way there would be with a user-chosen secret.

There is no `AUTH_SECRET` fallback here. An older version of this
construction fell back to `AUTH_SECRET` when `OIDC_PAIRWISE_SECRET` was unset;
that fallback was removed because a silent fallback would re-key every
pairwise value the moment `OIDC_PAIRWISE_SECRET` went missing. Today, a
missing secret is a hard boot failure, not a quiet re-key. (The companion page,
[Pairwise Subjects and Unlinkability](/understand/pairwise-subjects-and-unlinkability),
covers the same identifiers from the privacy-model angle.)

## The four frozen input families

Every pairwise value Minister ever derives comes from one of four tagged
input strings, each built in exactly one place so the local HMAC and the
Signet oracle (below) can never drift on what they hash:

| family | tagged input | builder |
|---|---|---|
| OIDC `sub` | `${userId}:${clientId}` | `pairwiseSubInput` |
| disclosure `jti` | `jti:${badgeId}:${clientId}` | `pairwiseJtiInput` |
| share-link `sub` | `sharelink:${userId}:${shareLinkId}` | `shareLinkPairwiseSubInput` |
| share-link `jti` | `jti:sharelink:${badgeId}:${shareLinkId}` | `shareLinkPairwiseJtiInput` |

These four encodings are frozen: they're pinned by golden test vectors and
must stay byte-for-byte stable, because a persisted pairwise `sub` cannot be
recomputed differently later without breaking every relying party that keyed
an account on it.

> **The untagged-encoding caveat.** Domain separation between these families
> comes from the `jti:` / `sharelink:` string prefixes alone, not from a
> length prefix. `` `${userId}:${clientId}` `` is safe only because a
> `userId` is a cuid and a `clientId` is always `` `mc_[A-Za-z0-9_-]+` ``
> (enforced by a charset guard at client creation, with one legacy exact-match
> exception for the seeded demo client) - neither can contain a colon, so the
> two fields can't be shuffled across the separator the way `("ab","c")` and
> `("a","bc")` could collide under naive concatenation. This is closed by the
> charset guard, not by re-encoding, because the four inputs are frozen for
> byte-stability. A future client id format that isn't `mc_`-prefixed would
> reopen the collision risk. See
> [Threat Model and Known Gaps](/crypto/threat-model) for the full writeup.

`OIDC_PAIRWISE_SECRET` does double duty: it also keys the interim nullifier's
HKDF root (a separate construction, see
[The Badge Nullifier](/crypto/badge-nullifier)). The nullifier key is an HKDF
expansion of the secret under a distinct info string, never the raw bytes, so
the two HMAC spaces never share a key - but one secret leak still breaks both.

## The MINISTER_SUB_BACKEND seam

Pairwise derivation can run in Minister's own process, or against Signet - a
separate crypto-core service - through a generic keyed-HMAC oracle at
`/prf/pairwise`. Which one runs is one env var, read per call rather than
cached at module load - switching backends is a config change, not a code
change:

| backend | behavior |
|---|---|
| `local` | compute in-process (the default). |
| `shadow` | serve the local value; fire an async, non-blocking compare against Signet and log any mismatch. Never blocks, never changes what's served. |
| `signet-fallback` | serve the Signet value under a tight timeout; on transport error, timeout, or a value that disagrees with the local HMAC, serve the local value instead and alert. |
| `signet` | Signet only - legal only once `OIDC_PAIRWISE_SECRET` is removed from Minister entirely; a Signet failure here is a hard failure by design. |

The reason all four modes can coexist without changing behavior is that
Signet's `/prf/pairwise` is not a pairwise-specific endpoint - it's a generic
keyed-HMAC-SHA-256 oracle over the same opaque tagged-input string:
`base64url(HMAC-SHA-256(imported key, input))`. Signet's imported key is the
identical UTF-8 bytes of `OIDC_PAIRWISE_SECRET` that Minister's own
`createHmac` call consumes, so the local and Signet paths are byte-identical
for every one of the four families. A fallback or a shadow mismatch is
therefore either a transport hiccup or a real key-import bug, never an
expected divergence.

The hot path (token mint, userinfo, share-link render) runs a tight,
independently tunable budget - the default deadline is 500 ms, decoupled from
the nullifier backend's own timeout so tuning one never squeezes the other.
Input is length-capped at 512 bytes so the local and Signet paths agree on
what's even admissible before a flip, rather than diverging on a validation
error.

> **This is a design description, not a status report.** Which mode is live
> in production changes independently of this page. Treat `local`,
> `shadow`, `signet-fallback`, and `signet` as four points on one seam with an
> identical byte-level contract, not as a roadmap with a "current step."

One place tightens this further: a pairwise `sub` computed for *persistence*
(what gets frozen into a `SubjectOverride` at account merge, below) adds a
crosscheck. While `OIDC_PAIRWISE_SECRET` is still configured, the seam-served
value is re-derived locally and the two must match exactly, or the write
throws and the merge aborts (safe to retry). A `SubjectOverride` row is never
recomputed once written, so a wrong value at that moment would otherwise
re-key a donor's identity at an RP permanently and invisibly - the crosscheck
is free while the local secret still exists, and it only becomes a real trust
decision once `OIDC_PAIRWISE_SECRET` is eventually retired from Minister.

## SubjectOverride and account merge

Pairwise `sub` is normally a pure function of `(userId, clientId)`. Merging
two Minister accounts breaks that purity on purpose: the donor's historical
`sub` at each relying party has to keep working after the merge, even though
the surviving account's `userId` would hash to something different. Minister
resolves this with a `SubjectOverride` table, consulted before the plain HMAC
on every subject resolution. The full merge mechanics, including the
dual-control ticket that authorizes writing an override, live in
[Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge); the
override lookup itself is covered in
[Pairwise Subjects and Unlinkability](/understand/pairwise-subjects-and-unlinkability).

## Where to look in the source

- Tagged-input builders, local HMAC, and the backend seam:
  `apps/minister/src/lib/pairwise-backend.ts` (`pairwiseSubInput`,
  `pairwiseJtiInput`, `shareLinkPairwiseSubInput`, `shareLinkPairwiseJtiInput`,
  `deriveLocalPairwise`, `selectSubBackend`, `derivePairwise`,
  `derivePairwiseSubForPersistence`).
- Sync convenience wrappers used by golden fixtures: `oidc-tokens.ts`
  (`pairwiseSub`, `pairwiseJti`), `share-links.ts`.
- Merge override read: `apps/minister/src/lib/oidc-subject.ts` (`resolveSub`).
- Pairwise subject DID shape: `packages/vc/src/did.ts`
  (`buildPairwiseUserDid`).
- Env validation for `OIDC_PAIRWISE_SECRET` (min 32 chars, required) and the
  `MINISTER_SUB_BACKEND` enum: `apps/minister/src/env.ts`.
