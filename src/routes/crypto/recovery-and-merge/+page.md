---
title: Recovery, Assurance, and Account Merge
description: The AAL/IAL assurance model, recovery codes, weighted threshold badge recovery, and dual-control account merge - with the unenforced quarantine gap stated plainly.
order: 10
---

## What this page covers

Losing every credential, and merging two accounts into one, are both
identity-lifecycle events we treat with real cryptographic weight: a
donor-proof JWT, Argon2id-hashed recovery codes (Argon2id is a slow,
memory-hard hash, so a stolen hash file doesn't hand an attacker a fast way
back to the original code), and a weighted live re-proof threshold. This
page walks the constructions and states the one known gap that matters most
for anyone deciding whether to trust this today.

Read this alongside
[Pairwise Subjects](/crypto/pairwise-subjects) for how `SubjectOverride`
keeps a merged account stable per RP, and
[Threat Model and Known Gaps](/crypto/threat-model) for the full accepted-gap
register.

## The assurance model: AAL and IAL

Minister tracks two separate ladders, both NIST SP 800-63B-flavored but
serving different questions. **AAL** (authentication assurance level) asks
how phishing-resistant the credential that authenticated this session was.
**IAL** (identity assurance level) asks how strong the real-world binding
behind a *badge* is, and doubles as its weight in recovery scoring (below).

```ts
// apps/minister/src/lib/assurance.ts:20-31 (aalForCredential)
export function aalForCredential(kind: "passkey" | "email" | "recovery-code" | "totp"): Aal {
  switch (kind) {
    case "passkey": return 2;
    case "totp": return 2;
    case "email": return 1;
    case "recovery-code": return 1;
  }
}
```

| AAL | Credential | Property |
|---|---|---|
| 0 | none / public | unauthenticated |
| 1 | magic link, recovery code | single-factor, not phishing-resistant |
| 2 | passkey, paired TOTP | phishing-resistant |

A session that signs in via a recovery code lands at AAL1 and is flagged
`recovered` - a quarantined, reduced-assurance session distinct from a normal
AAL1 email sign-in.

### The credential quarantine window

A newly added email or passkey doesn't get full privilege immediately:

```ts
// apps/minister/src/lib/assurance.ts:42
export const CREDENTIAL_QUARANTINE_MS = 72 * 60 * 60 * 1000; // 72 hours
```

The intent is real: it's the window meant to let a "credential was added"
notification reach the account owner - who might be asleep or traveling -
before that fresh credential can be used to pivot into merge, recovery-code
generation, or an email change. That's the theory.

> **H-1 (High), accepted, unenforced.** The quarantine cooldown is written
> (`quarantinedUntil` on the credential row) and shown in the UI, but no
> production code path actually reads it before allowing a privileged
> action. A session that just reached AAL2 via a freshly grafted,
> still-quarantined passkey can immediately start an account merge, generate
> recovery codes, or change the primary email. It is not a new
> unauthenticated takeover - reaching AAL2 is still a precondition - but the
> advertised blast-radius containment does not exist today. Accepted for the
> alpha; flagged to fix (thread the acting credential id onto the session
> JWT, require a non-quarantined AAL2 credential) before merge or
> recovery-code generation is exposed to real users. See
> [Threat Model and Known Gaps](/crypto/threat-model) and
> `Minister/TODO.md` "Account assurance / recovery - security follow-ups."

## Recovery codes

The cold-start backstop: ten codes issued at once, shown in plaintext
exactly once, stored only as Argon2id hashes.

```ts
// apps/minister/src/lib/recovery-codes.ts:25-30
const ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ0123456789"; // Crockford-ish, I/L/O/U removed
const GROUPS = 3;
const GROUP_LEN = 4;
const CODE_SYMBOLS = GROUPS * GROUP_LEN; // 12 symbols
```

Twelve symbols from a 32-character alphabet is 5 bits per symbol, **60 bits
of entropy** per code, formatted `XXXX-XXXX-XXXX`. Each symbol is drawn via
`crypto.randomInt` (rejection-sampled, unbiased CSPRNG), never `Math.random`.
Hashing reuses the same Argon2id parameters as OIDC client secrets
(memoryCost 19 MiB, timeCost 2, parallelism 1 - see
[OIDC Flow Hardening and Disclosure](/crypto/oidc-flow-hardening) and
[Hashing, HMAC, and Key Derivation](/crypto/hashing-hmac-and-kdfs)).

Redemption normalizes the input before comparing - strip whitespace and
separators, uppercase, and repair the handful of characters people commonly
substitute for the omitted ones (`I` and `L` to `1`, `O` to `0`, `U` to `V`) -
so a hand-transcribed code still matches:

```ts
// apps/minister/src/lib/recovery-codes.ts:51-59
export function normalizeRecoveryCode(input: string): string {
  return input.trim().toUpperCase().replace(/[\s-]+/g, "")
    .replace(/[IL]/g, "1").replace(/O/g, "0").replace(/U/g, "V");
}
```

`generateCode` never emits the substituted characters itself, so normalization
only ever repairs a transcription - it can't turn one valid code into a
different valid one. Verification checks the input against every unused row
for the account without short-circuiting on the first match, so there's no
positional timing signal, and Argon2's own `verify` is constant-time over the
encoded hash. A matched code is consumed atomically (`updateMany ... where
usedAt: null`), so two concurrent redemption attempts can't both succeed on
the same code. Redeeming one is AAL1 and lands a quarantined `recovered`
session.

## Weighted threshold badge recovery

If you've lost every credential, you recover the account by re-proving badges
you hold, live, until the accumulated weight crosses a threshold. One
government-document-grade badge clears it alone; a pile of weaker factors can
also add up to it.

```ts
// apps/minister/src/lib/assurance.ts:56,65-70
export const RECOVERY_THRESHOLD = 100;

export const BADGE_ASSURANCE_WEIGHT: Record<string, number> = {
  IAL0: 0, IAL1: 15, IAL2: 60, IAL3: 100,
};
```

Per-type overrides deviate from the bare IAL baseline: `tlsn-attestation`
sits at 100 (clears the threshold alone), `email-domain`/`email-exact` at
15, `invite-code` at 0 (one-shot, can't be re-proven), and `oauth-account` is
provenance-sensitive - Discord/Steam at 10, every other provider (GitHub,
Google, and the rest) at the default 20. In practice: one IAL3
government-document proof clears recovery by itself; recovering on OAuth
links alone takes five or more.

An attempt is a live ceremony, not a standing grant:

```ts
// apps/minister/src/lib/recovery-threshold.ts:55,60
const NONCE_BYTES = 24;
export const RECOVERY_ATTEMPT_TTL_MS = 15 * 60 * 1000; // 15 minutes
```

`startRecoveryAttempt` mints a 24-byte random nonce and a 15-minute TTL. Each
subsequent `recordReProof` call is **pure accounting** - it does not verify
any cryptographic proof itself. It trusts that the caller (a per-plugin live
re-proof step) already:

1. Ran the real live verification - a fresh OAuth round trip, a freshly
   clicked magic link, a fresh TLSNotary presentation. A stored `Badge.vcJwt`
   is never accepted as evidence; this engine never reads or accepts a VC
   JWT anywhere, so a leaked VC cannot replay into a recovery.
2. Bound that live proof to *this attempt's* nonce - the OAuth `state`, the
   magic-link token, or the TLSN submission token must derive from or equal
   the attempt nonce, so a proof captured for one attempt can't be replayed
   into a different one.
3. Confirmed the freshly proven real-world account matches one the target
   user actually holds a badge for, via the nullifier ledger rather than a
   renameable handle.

Given those caller obligations, `recordReProof` enforces attempt liveness,
type eligibility (`RECOVERY_ELIGIBLE_TYPES`: `oauth-account`, `email-domain`,
`email-exact`, `tlsn-attestation`), non-public badge holding, a
`@@unique(attemptId, badgeType)` no-double-count constraint, and an atomic
weight increment that flips the attempt to `satisfied` once it crosses 100.
`consumeSatisfiedAttempt` then does an atomic `satisfied -> consumed`
transition and mints a recovery ticket (below) - landing a quarantined,
reduced-assurance session, the same as a recovery-code redemption.

> Only non-public badges count toward the threshold. A public badge is
> attacker-enumerable, so it would let an attacker who merely knows what
> badges you hold (without holding any of them) rack up weight toward
> recovering your account.

## Dual-control account merge

Merging two Minister accounts into one requires proof of control over
*both*: the survivor drives the merge from an already-established AAL2
session, and a separate donor-proof ticket proves the same human also
controls the donor account.

```ts
// apps/minister/src/lib/merge-proof.ts:32-40
const ALG = "HS256";
const TYP = "minister-donor-proof";
const TTL_SECONDS = 5 * 60; // 5 minutes
```

The donor-proof ticket is an HS256 JWT - HMAC-SHA-256, RFC 7519, a keyed
fingerprint that anyone holding the same secret can check but nobody else can
forge - signed over `AUTH_SECRET`, not `OIDC_PAIRWISE_SECRET`, a different
secret entirely (see below). It carries `{ donorUserId, jti }` with a 5-minute TTL and a 24-byte
random `jti`. Binding `donorUserId` into the signed payload, not just
returning a bare "someone proved a donor" boolean, means a ticket minted for
one donor account can never be redirected to merge a different account in.
Single-use is enforced durably, cross-process, via a namespaced
`VerificationToken` row consumed with one atomic delete - a second
verification attempt finds nothing to delete and is rejected. `confirmMerge`
requires both: the caller's own AAL2 session, and a valid, unconsumed
donor-proof ticket naming the specific donor account being merged in.

### Freezing the donor's pairwise identity before the transaction

The hard problem merge solves: a pairwise `sub` is normally a pure function
of `(userId, clientId)`, so if the donor's `userId` simply disappeared, every
RP the donor used would compute a *different* `sub` for the survivor and
silently lose the donor's history there. `mergeAccounts` closes this by
pre-computing each donor pairwise sub, per RP, **before** the transaction
opens:

```text
// merge.ts:200-212 (derivation, before the tx opens)
for each RP the donor used:
  sub[clientId] = derivePairwiseSubForPersistence(donorUserId, clientId)

// then, inside the merge transaction:
write SubjectOverride { userId: survivor, clientId, sub[clientId] } per RP
```

Deriving outside the open transaction matters: it keeps a PRF network call
(the Signet seam, if `MINISTER_SUB_BACKEND` routes there) from happening
inside an open `prisma.$transaction`. The transaction re-reads the donor's
client set and aborts on any drift in that gap, so a token minted for a new
RP between derivation and commit can't slip through without an override.
After the merge, `resolveSub` (see
[Pairwise Subjects](/crypto/pairwise-subjects)) checks `SubjectOverride`
first, so the survivor keeps presenting the donor's historical `sub` to every
RP the donor already used - those RP-side accounts stay intact rather than
silently rebinding to a new identifier.

The merge transaction itself runs at Postgres `RepeatableRead`
(`Prisma.TransactionIsolationLevel.RepeatableRead`), not the engine default,
with bounded retry on isolation-conflict errors - the comment in `merge.ts`
frames this as closing an in-transaction token-drift race, not just a
performance choice.

The merge is reversible for a window, not immediate and permanent:

```ts
// apps/minister/src/lib/assurance.ts:45-46
export const MERGE_REVERSAL_DAYS = 7;
```

The donor account is tombstoned at merge and hard-deleted after seven days;
until then, reversal restores the donor's own rows, including its own prior
`SubjectOverride` entries.

Nullifiers need no analogous override: a badge's Sybil-dedup nullifier is
keyed on the anchor and badge type (plus the `clientId` for the per-RP
disclosed form), never on `userId`, so it's already merge-invariant by
construction. Donor ledger references are re-tagged
post-commit via a per-ref `reassignOwner`, not frozen through an override
table the way pairwise subs are. See
[The Badge Nullifier](/crypto/badge-nullifier).

> **Accepted stale-token gap.** `merge.ts` re-points model rows from donor to
> survivor, but predates the `OidcGrant` model, so a donor's `OidcGrant` rows
> aren't migrated on merge. Separately, a donor's `OidcAuthorizationCode`
> rows survive the merge and `/token` doesn't check the tombstone against
> them - a roughly 60-second window (bounded by the authorization code's own
> 60-second TTL) where a code issued to the donor just before merge could
> still redeem. Not a cross-account leak; accepted, tracked in `TODO.md`. See
> [Threat Model and Known Gaps](/crypto/threat-model).

## Briefly: the other HS256 artifacts

Three more constructions share the same key-handling shape - HS256 over
`AUTH_SECRET`, a namespaced single-use marker in `VerificationToken`, atomic
delete-on-consume - and are worth knowing about even though they're not the
main event on this page.

- **Session cookie.** Auth.js JWT-strategy session: an HMAC-signed JWT over
  `AUTH_SECRET`, verified by signature at the edge and revalidated
  server-side against `User.sessionGeneration`. 24-hour sliding TTL with a
  1-hour refresh; revoking a session bumps `sessionGeneration`.
- **Recovery sign-in ticket.** HS256, `typ:"minister-recovery-ticket"`,
  10-minute TTL, 24 random-byte `jti`, single-use via the same atomic-delete
  pattern as the donor-proof ticket, minted by both the recovery-code and
  threshold-recovery paths and handed straight to Auth.js's `recovery`
  credentials provider.
- **Share-link tokens.** Not HS256 - a bare 256-bit bearer token
  (`randomBytes(32).toString("base64url")`, 43 characters), server-enforced
  `expiresAt` (7-day default, 90-day max) and revocable. A share link
  discloses re-minted VCs under their own per-link pairwise sub/jti and
  deliberately gets **no nullifier** - it isn't part of the account-recovery
  or Sybil-dedup story at all.

## `AUTH_SECRET` is not `OIDC_PAIRWISE_SECRET`

Every construction on this page - the session cookie, both ticket types, the
donor-proof JWT - is keyed by `AUTH_SECRET`. The pairwise `sub`/`jti` HMAC and
the interim nullifier's HKDF root are keyed by the separate
`OIDC_PAIRWISE_SECRET` (see
[Pairwise Subjects](/crypto/pairwise-subjects) and
[The Badge Nullifier](/crypto/badge-nullifier)). Both are env-required at 32
or more characters. An older silent fallback from one to the other was
removed; treat them as two secrets with disjoint blast radii, not one secret
wearing two hats.

## Where to look in the source

- AAL/IAL constants and mappings: `apps/minister/src/lib/assurance.ts`
  (`aalForCredential`, `CREDENTIAL_QUARANTINE_MS`, `RECOVERY_THRESHOLD`,
  `BADGE_ASSURANCE_WEIGHT`, `RECOVERY_WEIGHT_BY_TYPE`, `MERGE_REVERSAL_DAYS`).
- Recovery codes: `apps/minister/src/lib/recovery-codes.ts` (`generateCode`,
  `normalizeRecoveryCode`).
- Threshold recovery accounting: `apps/minister/src/lib/recovery-threshold.ts`
  (`startRecoveryAttempt`, `recordReProof`, `consumeSatisfiedAttempt`).
- Donor-proof ticket: `apps/minister/src/lib/merge-proof.ts`
  (`issueDonorProof`).
- Recovery sign-in ticket: `apps/minister/src/lib/recovery-ticket.ts`
  (`issueRecoveryTicket`).
- The merge transaction, `SubjectOverride` writes, reversal:
  `apps/minister/src/lib/merge.ts` (`mergeAccounts`).
- Share-link tokens: `apps/minister/src/lib/share-links.ts`.
- The unenforced quarantine gap: `Minister/TODO.md`, "Account assurance /
  recovery - security follow-ups", and `apps/minister/src/server/credential-actions.ts`,
  `merge-actions.ts`, `recovery-code-actions.ts`.
