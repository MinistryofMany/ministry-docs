---
title: Pairwise Subjects and Unlinkability
description: How Minister keeps a user uncorrelatable across relying parties using two deliberately separate identifier namespaces: a per-RP pairwise sub and a re-minted pairwise badge subject.
order: 6
---

## The problem this solves

If every relying party (RP) saw the same subject identifier for the same user,
two RPs could collude, join their user tables on that identifier, and reconstruct
one profile that spans both apps. That defeats the point of an identity layer
whose whole pitch is selective, minimal disclosure.

Minister blocks that join structurally. A user gets a *different* identifier at
every RP, and the badges they disclose carry a subject that is likewise per-RP.
There is no shared identifier in anything an RP receives. This page explains the
two identifier namespaces, why they are kept separate, and how a correctly
written RP still binds a disclosed badge to the login in front of it.

## The pairwise `sub`

The `sub` claim in an id_token is a pairwise pseudonymous identifier, per
OIDC Core 1.0 §8.1. It is a keyed hash of the user and the client, so it is
stable for a given `(user, client)` pair but differs across clients.

From `apps/minister/src/lib/oidc-tokens.ts`:

```ts
export function pairwiseSub(userId: string, clientId: string): string {
  const secret = process.env.OIDC_PAIRWISE_SECRET ?? process.env.AUTH_SECRET;
  if (!secret) {
    throw new Error("OIDC_PAIRWISE_SECRET (or AUTH_SECRET fallback) must be set");
  }
  const mac = createHmac("sha256", secret).update(`${userId}:${clientId}`).digest();
  return mac.toString("base64url");
}
```

So `sub = base64url(HMAC-SHA256(secret, userId + ":" + clientId))`, keyed by
`OIDC_PAIRWISE_SECRET` (falling back to `AUTH_SECRET`). Properties that matter:

- Two RPs with different `clientId` values get different `sub` for the same user.
  They cannot join on it.
- The mapping is one-way. The RP never sees `userId`, and cannot invert the HMAC
  to recover it without the secret.
- It is deterministic, so the same user returning to the same RP keeps the same
  `sub` across logins. The RP can maintain a durable account keyed on it.

The access token carries the same `sub` and deliberately omits any raw `userId`;
`/oidc/userinfo` resolves the principal by looking up the `OidcAccessToken` row by
its `jti`, never by decoding a user id out of the token. Two RPs decoding their
access tokens see different `sub` and no shared underlying identifier.

The resulting id_token looks like this (from `Minister/CLAUDE.md`):

```json
{
  "iss": "https://ministry.id",
  "sub": "<pairwise pseudonymous id>",
  "aud": "<client_id>",
  "iat": 0,
  "exp": 0,
  "nonce": "...",
  "minister_badges": ["<vc jwt>", "<vc jwt>"]
}
```

## The badge subject is a separate namespace

A badge is a W3C JWT-VC. Its `credentialSubject.id` (and the JWT `sub`) is a DID,
not the OIDC pairwise `sub`. This is a second, deliberately distinct identifier
namespace. Minister never equates a badge subject DID with a pairwise `sub`; the
two are never cross-checked against each other.

There are two shapes in that DID namespace, and the distinction is the whole
unlinkability story for badges.

### Stored badge subject: stable, and never disclosed

When Minister issues a native badge, the stored VC (`Badge.vcJwt`) carries a
STABLE subject that identifies the Minister user across everything:

```ts
// packages/vc/src/did.ts
export function buildUserDid(domain: string, userId: string): string {
  return `did:web:${domain}:users:${userId}`;
}
```

So the stored subject is `did:web:<domain>:users:<userId>`. It is stable, it is
the same in every badge that user holds, and it is a different namespace from the
pairwise `sub`. Crucially, this stable subject is never handed to a relying party
over OIDC. It appears only in non-OIDC exit paths, where the recipient is a person
the user chose out of band, not a correlating app: a share link, or a
user-initiated VC export.

### Disclosed badge subject: pairwise, re-minted per RP

Handing an RP the stored VC verbatim would reintroduce the exact correlator the
pairwise `sub` removes. Two colluding RPs could ignore `sub` and instead join on
the badge's stable `credentialSubject.id`. So over OIDC, Minister does not
disclose the stored VC at all. It RE-MINTS each approved badge, rebinding the
subject onto a pairwise DID tied to the id_token `sub` for that RP:

```ts
// packages/vc/src/did.ts
export function buildPairwiseUserDid(domain: string, pairwiseSub: string): string {
  return `did:web:${domain}:u:${pairwiseSub}`;
}
```

Note the `:u:` marker, distinct from the stored `:users:` shape. The re-mint
(`loadApprovedBadgeJwts` in `apps/minister/src/lib/oidc-claims.ts`) sets, per
`(userId, clientId)`:

- `sub` and `credentialSubject.id` to `did:web:<domain>:u:<pairwiseSub>`, where
  `<pairwiseSub>` is the same value stamped as the id_token `sub`.
- `jti` to a per-RP value via `pairwiseJti(badgeId, clientId)` (an HMAC
  domain-separated from `pairwiseSub` by a `"jti:"` prefix), never the raw
  `Badge.id`. This removes `jti` as a cross-RP join key too.
- `iat`/`nbf` re-stamped to now, and `exp` presentation-shaped to
  `min(now + disclosure TTL, original exp, Badge.expiresAt)`. The original
  issuance-derived `exp` was a stable, high-entropy cross-RP correlator; the
  disclosed `exp` reflects only disclosure time.
- `iss`, `kid`, and every claim value unchanged.

`reMintVc` verifies the stored VC's signature against Minister's badge key before
re-signing, and the re-mint is scoped to rows whose `issuer` is Minister's own
DID, so neither a forged VC nor a future foreign-issuer import can be laundered
into a fresh Minister-signed credential through this path.

The upshot: the only badge subject that ever leaves Minister in a disclosed VC is
the pairwise `:u:<pairwiseSub>` form. The stable `:users:<userId>` form and the
pairwise `sub` remain two separate namespaces that Minister never reconciles.

## How a relying party binds a badge to the login

Because the disclosed badge subject is derived from the id_token `sub`, an RP can
prove a disclosed badge belongs to the user who just logged in, without any shared
global identifier. The SDK (`@ministryofmany/client`) does this in
`verifyMinisterBadges`: each badge's subject must equal
`did:web:<host>:u:<id_token sub>`.

```ts
// minister-client/src/did.ts
export function buildPairwiseSubjectDid(issuer: string, sub: string): string {
  return `${didFromIssuer(issuer)}:u:${sub}`;
}
```

`verifyMinisterBadges` computes that expected subject from the verified id_token's
`sub`, then pushes any badge whose subject does not match into `rejected` rather
than trusting it. A borrowed credential, a stale subject, or a badge minted for a
different RP fails closed and does not count.

Do not confuse this with the standalone `verifyMinisterBadge`. That function
certifies issuance and checks the VC-internal invariant
`credentialSubject.id === sub`, but it does NOT tie the VC to any login. A valid
Minister badge belonging to some other user (for example one received via a share
link) verifies successfully. Treating a standalone `verifyMinisterBadge` success
as "the current user holds this badge" is an authorization bug. Use the wrapper
for any access decision.

The issuer DID the SDK checks against is derived from the OIDC issuer host with no
override (`didFromIssuer`), which is why a deployment's `MINISTER_ISSUER` host must
equal Minister's issuer domain. Get it wrong and every badge lands in `rejected`.

## `sub` is never your email, and profile is never your upstream identity

Two leaks that an identity provider commonly springs, both closed here:

The subject is never an email. `sub` is the pairwise HMAC and nothing else. Email
is never used as a subject identifier for an RP.

The `profile` scope never falls back to the upstream login. When a user signs into
Minister with Google or GitHub, that provider's real name and avatar land on
`User.name` / `User.image`. Those are never disclosed. The claims resolver reads
only the user-curated `displayName` / `avatarUrl`:

```ts
// apps/minister/src/lib/oidc-claims.ts
export function resolveUserClaims(
  user: ClaimsUser,          // { displayName, avatarUrl } only
  profile: ProfileGrant,     // { name, avatar } consent booleans
  approvedBadgeJwts: string[],
): ResolvedUserClaims {
  const resolved: ResolvedUserClaims = { ministerBadges: approvedBadgeJwts };
  if (profile.name && user.displayName !== null) resolved.name = user.displayName;
  if (profile.avatar && user.avatarUrl !== null) resolved.picture = user.avatarUrl;
  return resolved;
}
```

`ClaimsUser` intentionally has no `User.name` / `User.image` fields, so the
upstream identity is not even a parameter and cannot leak by construction. When a
granted claim has no curated value, it is omitted entirely rather than falling
back or emitting a placeholder.

## The profile scope is consented per claim

`profile` is not an all-or-nothing grant. Name and avatar are independent toggles,
each default OFF. The consent decision is persisted as two separate booleans,
`profileName` and `profileAvatar`, on `OidcAuthorizationCode` and denormalized onto
`OidcAccessToken`. As the resolver above shows, `name` and `picture` are emitted
independently, so a user can share a display name without an avatar, or the
reverse. The RP-facing `profile` scope stays in the granted set if either
sub-claim was approved.

Both the id_token path (`/oidc/token`) and the `/oidc/userinfo` path run through
this one resolver, so the two return identical claims for the same grant by
construction.

## Account merge keeps you stable per app

Pairwise `sub` is normally a pure function of `(userId, clientId)`. That creates a
tension with account merge: if two Minister accounts become one, the survivor's
`userId` would produce a different `sub` at every RP the DONOR used, silently
breaking those accounts.

Merge resolves this with a `SubjectOverride` seam. The subject an RP sees is
resolved through `resolveSub`, which consults an override table before falling
back to the pure HMAC:

```ts
// apps/minister/src/lib/oidc-subject.ts
export async function resolveSub(userId: string, clientId: string): Promise<string> {
  const override = await prisma.subjectOverride.findUnique({
    where: { userId_clientId: { userId, clientId } },
    select: { sub: true },
  });
  if (override) return override.sub;
  return pairwiseSub(userId, clientId);
}
```

`SubjectOverride` is keyed `@@id([userId, clientId])` with a `sub` column. When
`mergeAccounts` runs (`apps/minister/src/lib/merge.ts`), it walks the RPs the donor
had token history with and, for each RP the survivor never used, writes an override
row carrying the donor's historical `pairwiseSub(donorUserId, clientId)`. After the
merge, the survivor keeps presenting the donor's old `sub` to every app the donor
already used, so those accounts stay intact.

For an RP that BOTH accounts used there is no lossless answer. One human logs in
once and gets one `sub`, so the donor's `sub` there is recorded as `stranded`
(carried for audit and UI, not written as an override). With no override present,
`resolveSub` is exactly `pairwiseSub`, so this seam is inert until a merge
populates it. The `sub` value that a merge preserves is also threaded through the
badge re-mint, so a disclosed badge's pairwise subject continues to bind to the
login even when an override makes `sub` differ from the raw HMAC.

## What an RP can and cannot correlate

- Within one RP: the pairwise `sub` is stable, so the RP keeps a durable account
  and can bind disclosed badges to it.
- Across two RPs, even colluding: no shared identifier. Different `sub`, different
  badge subject (`:u:<pairwiseSub>` differs per RP), different badge `jti`, and a
  disclosure-shaped `exp` that is not a stable correlator.
- The stable `:users:<userId>` DID and any email are never in what an RP receives.

## Where to look in the source

- Pairwise `sub` and per-RP `jti`: `apps/minister/src/lib/oidc-tokens.ts`
  (`pairwiseSub`, `pairwiseJti`).
- Merge override seam: `apps/minister/src/lib/oidc-subject.ts` (`resolveSub`),
  `apps/minister/src/lib/merge.ts` (`SubjectOverride` writes), and the
  `SubjectOverride` model in `apps/minister/prisma/schema.prisma`.
- Badge re-mint and profile claim resolution:
  `apps/minister/src/lib/oidc-claims.ts`.
- Subject DID shapes: `packages/vc/src/did.ts` (`buildUserDid`,
  `buildPairwiseUserDid`).
- RP-side binding and verification: `minister-client/src/did.ts`
  (`buildPairwiseSubjectDid`, `parsePairwiseSubjectDid`),
  `minister-client/src/verify-badges.ts`, and `minister-client/src/verify-badge.ts`.
