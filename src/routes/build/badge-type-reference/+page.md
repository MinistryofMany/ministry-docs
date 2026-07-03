---
title: Badge-Type Reference
description: The Minister badge vocabulary - slugs, scopes, credentialType mappings, and Zod claim schemas exposed by @ministryofmany/client/badges, plus the Minister-side registry it mirrors.
order: 7
---

## What this covers

Every Minister badge is a W3C verifiable credential of a known *type*. A type is a
stable slug (`email-domain`, `age-over-21`, ...), an OIDC scope you request it under
(`badge:email-domain`), a VC `credentialType` Minister stamps into the VC `type[]`
(`MinisterEmailDomainCredential`), and a Zod schema for the claims Minister signs into
`credentialSubject`.

Two copies of this vocabulary exist:

- **Provider side** - `Minister/packages/shared/src/badge-types.ts` (package
  `@minister/shared`). Authoritative. Also carries display metadata (labels, icon keys)
  and the coarse account-derived types.
- **Relying-party side** - `@ministryofmany/client/badges`, the `/badges` entry point of
  the SDK. A hand-maintained COPY carrying only what an RP needs.

If you are building an RP, you consume the SDK copy. The provider copy is documented here
so you know what Minister can actually issue, and where the two diverge.

## The `/badges` entry point

`@ministryofmany/client/badges` is dependency-light. It imports `zod` and nothing else -
`jose` (the JWT/JWKS machinery in the root and verifier entry points) is never pulled in.
Import it from a bundle, an edge function, or a config script without dragging in crypto.

```ts
import {
  BADGE_TYPES,
  badgeScope,
  badgeScopes,
  badgeTypeOf,
  getBadgeClaimSchema,
  knownBadgeTypes,
  slugForCredentialType,
  defineBadgeType,
  type BadgeTypeDef,
} from "@ministryofmany/client/badges";
```

It also re-exports the raw Zod schemas and the constant arrays (`EmailDomainClaims`,
`OAuthAccountClaims`, `AGE_THRESHOLDS`, `OAUTH_PROVIDERS`, ...) from `./schemas` if you want
to reach a schema directly instead of via `getBadgeClaimSchema`.

### The `BadgeTypeDef` shape

Every entry in the registry is a `BadgeTypeDef`:

```ts
interface BadgeTypeDef {
  slug: string;          // "email-domain"
  credentialType: string; // "MinisterEmailDomainCredential" - the VC type[] entry
  scope: string;          // "badge:email-domain" - the OIDC scope
  claims: z.ZodType<unknown>; // schema for credentialSubject (excluding `id`)
}
```

`BADGE_TYPES` is a `Record<slug, BadgeTypeDef>`. `scope` is always `badge:${slug}`;
`defineBadgeType({ slug, credentialType, claims })` derives it for you.

## Core types

These exist in both copies. Claim shapes below are the exact `credentialSubject` fields
(the `id` field - the holder's `did:web` URL - is added at issuance and is not part of
these schemas).

### `email-domain`

```ts
{ domain: string } // lowercased, must match /^[a-z0-9.-]+\.[a-z]{2,}$/
```

Holder controls an email address at the named domain. The email itself is never stored -
only the domain. credentialType `MinisterEmailDomainCredential`, scope
`badge:email-domain`.

### `email-exact`

```ts
{ email: string } // validated as an email, lowercased
```

Holder controls the exact address. Less private than `email-domain`, opt-in.
credentialType `MinisterEmailExactCredential`.

### `oauth-account`

```ts
{ provider: "github" | "google" | "discord"; accountId: string; handle?: string }
```

Holder controls a third-party account. `provider` is the `OAUTH_PROVIDERS` enum;
`handle` is optional. credentialType `MinisterOauthAccountCredential`.

### `invite-code`

```ts
{ label: string }
```

Holder redeemed an admin-minted invite code. `label` is the campaign/cohort name - the
code string itself never enters the VC. credentialType `MinisterInviteCodeCredential`.

### `tlsn-attestation`

```ts
{ domain: string; claim: string } // .strict() - unknown keys rejected
```

Generic TLSNotary attestation: one domain plus one structured claim. The schema is strict,
so extra keys are rejected rather than smuggled into a signed VC. credentialType
`MinisterTlsnAttestationCredential`.

## Age

Age is one type per threshold, not a single type with a numeric field. For each `N` in

```
16, 18, 21, 25, 30, 35, 40, 45, 55, 65   // AGE_THRESHOLDS
```

there is a slug `age-over-N` with:

```ts
{ threshold: N } // z.literal(N) - the value is pinned to the slug's N
```

credentialType `MinisterAgeOver${N}Credential` (for example `age-over-21` ->
`MinisterAgeOver21Credential`, scope `badge:age-over-21`). Requesting `badge:age-over-21`
discloses only that the holder is over 21 - not their birthdate, not a finer age.

## Residency

Three nested granularities, all keyed on an ISO 3166-1 alpha-2 country code (`country`
must match `/^[A-Z]{2}$/`):

```ts
// residency-country
{ country: string }
// residency-state
{ country: string; state: string }
// residency-city
{ country: string; state: string; city: string }
```

credentialTypes `MinisterResidencyCountryCredential`, `MinisterResidencyStateCredential`,
`MinisterResidencyCityCredential`. Request the coarsest one that satisfies your gate.

## Account-derived types (provider side only)

Minister's `github` plugin can issue three more types that attest facts about a connected
OAuth account without leaking the underlying values. They are **coarse buckets, never exact
figures** - the plugin picks the highest bucket the account satisfies, so disclosure
reveals only a lower bound.

```ts
// account-age  - "older than N months", never the creation date
{ provider: "github" | "google" | "discord"; olderThanMonths: 12 | 24 | 36 | 60 }
// two-factor   - bare presence; the badge's existence IS the claim
{ provider: "github" | "google" | "discord" }
// social-following - "at least N followers", never the exact count
{ provider: "github" | "google" | "discord"; followersAtLeast: 10 | 50 | 100 | 500 | 1000 }
```

All three schemas are `.strict()`.

**These are NOT in the SDK's `/badges` copy yet.** In today's SDK:

- `knownBadgeTypes()` does not list `account-age`, `two-factor`, or `social-following`.
- `getBadgeClaimSchema("account-age")` returns `undefined`.
- `badgeTypeOf([...])` returns `undefined` for their VC `credentialType`, so a verifier
  using the SDK vocabulary treats such a badge as an unknown type.

If your RP needs to gate on these, that is the concrete gap to close - see "Drift" below.

## Helpers

All from `@ministryofmany/client/badges`.

### `badgeScope(slug) / badgeScopes(slugs)`

Turn slugs into OIDC scope strings. Use this to build the `scope` param on your authorize
request - do not hand-write `badge:` prefixes.

```ts
badgeScope("age-over-21");            // "badge:age-over-21"
badgeScopes(["age-over-21", "oauth-account"]);
// ["badge:age-over-21", "badge:oauth-account"]

const scope = ["openid", "profile", ...badgeScopes(["age-over-21"])].join(" ");
// "openid profile badge:age-over-21"
```

### `badgeTypeOf(vcType: string[]) -> string | undefined`

Given a VC's `type` array, return the Minister slug it represents, or `undefined` if none
is a known Minister type. This is the reverse of `credentialType`.

```ts
badgeTypeOf(["VerifiableCredential", "MinisterEmailDomainCredential"]);
// "email-domain"
badgeTypeOf(["VerifiableCredential"]);         // undefined
badgeTypeOf(["VerifiableCredential", "MinisterAccountAgeCredential"]); // undefined (drift)
```

### `getBadgeClaimSchema(slug) -> z.ZodType<unknown> | undefined`

The Zod schema for a slug's `credentialSubject` claims, or `undefined` if the slug is
unknown to the SDK. Use it to validate or narrow claims you pulled off a disclosed VC.

```ts
const schema = getBadgeClaimSchema("residency-country");
const parsed = schema?.parse({ country: "US" }); // { country: "US" }
```

### `knownBadgeTypes() -> string[]`

Every slug the SDK knows (`Object.keys(BADGE_TYPES)`). Handy for validating a room policy's
badge types against the SDK vocabulary at config time.

### `slugForCredentialType(credentialType) -> string | undefined`

Lower-level: map a single `credentialType` string to its slug. `badgeTypeOf` is this
applied across a VC `type[]`.

```ts
slugForCredentialType("MinisterOauthAccountCredential"); // "oauth-account"
```

## credentialType mapping

The VC `type` array Minister stamps always contains `VerifiableCredential` plus one
Minister type. The Minister type is `Minister<PascalCaseSlug>Credential`:

| slug                | credentialType (VC `type[]`)          | scope                    |
| ------------------- | ------------------------------------- | ------------------------ |
| `email-domain`      | `MinisterEmailDomainCredential`       | `badge:email-domain`     |
| `email-exact`       | `MinisterEmailExactCredential`        | `badge:email-exact`      |
| `oauth-account`     | `MinisterOauthAccountCredential`      | `badge:oauth-account`    |
| `invite-code`       | `MinisterInviteCodeCredential`        | `badge:invite-code`      |
| `tlsn-attestation`  | `MinisterTlsnAttestationCredential`   | `badge:tlsn-attestation` |
| `residency-country` | `MinisterResidencyCountryCredential`  | `badge:residency-country`|
| `residency-state`   | `MinisterResidencyStateCredential`    | `badge:residency-state`  |
| `residency-city`    | `MinisterResidencyCityCredential`     | `badge:residency-city`   |
| `age-over-N`        | `MinisterAgeOver${N}Credential`       | `badge:age-over-N`       |

The account-derived types (`account-age`, `two-factor`, `social-following`) have no
SDK entry, so their credentialType strings are not part of the SDK vocabulary today.

## Drift: keep the two copies in sync

The `/badges` vocabulary is a **hand-maintained copy** of `@minister/shared`, not an
import - deliberately, so the SDK publishes standalone with no dependency on Minister's
internal packages. That means it can drift, and today it does:

- The account-derived types (`account-age`, `two-factor`, `social-following`) exist in
  `@minister/shared` but not in the SDK.
- Any future slug, provider enum change, or schema tweak in `@minister/shared` must be
  mirrored into `minister-client/src/badges/` by hand.

Adding a type to the SDK is one `defineBadgeType(...)` entry plus its schema; every helper,
scope, and the `credentialType -> slug` reverse index derive from `BADGE_TYPES`. The
`credentialType` literal you write must match Minister's `ministerCredentialType(slug)`
output exactly.

An automated drift-check asserting the SDK copy against `@minister/shared` is planned but
not yet in place. Until it lands, treat `@minister/shared` as the source of truth and the
SDK as a follower.

> TODO: expand once the drift-check test ships - link it here and note whether the
> account-derived types have been brought into the SDK copy.

## Naming note

The SDK is published as `@ministryofmany/client`; its `/badges` doc-comments refer to the
provider registry as `@ministryofmany/shared`, but that package's manifest name is still
`@minister/shared` (a rename from the `@minister/*` namespace to `@ministryofmany/*` is
in progress). Both names refer to the same registry at
`Minister/packages/shared/src/badge-types.ts`.
