---
title: Requesting Badge Scopes and Policies
description: Request the badge scopes your app needs and express OR/threshold requirements with the minister_policy authorize param.
order: 6
---

Your app tells Minister what it needs in two places on the authorize request: the
`scope` param names the badge types it may ask about, and an optional
`minister_policy` param structures those types into an OR/threshold requirement.
Minister minimizes the actual disclosure server-side, so you receive exactly one
minimal satisfying set no matter how you phrase the requirement.

Everything here uses the `@ministryofmany/client` SDK (the badge vocabulary lives
at the `@ministryofmany/client/badges` entry point). Nothing below invents an
endpoint or a param that Minister does not already validate.

## Request a badge by adding its scope

A badge type is requested as the OIDC scope `badge:<slug>`. The SDK builds that
string for you:

```ts
import { badgeScope, badgeScopes } from "@ministryofmany/client/badges";

badgeScope("age-over-21");
// => "badge:age-over-21"

badgeScopes(["age-over-21", "residency-state"]);
// => ["badge:age-over-21", "badge:residency-state"]
```

`badgeScopes` is just `slugs.map(badgeScope)`. Hand the result to the flow
client's `getAuthorizationUrl`, and prepend `openid` yourself. The SDK does not
inject `openid`, and Minister rejects any authorize request whose scope omits it
with `invalid_scope`.

```ts
import { createMinisterClient } from "@ministryofmany/client";
import { badgeScopes } from "@ministryofmany/client/badges";

const client = createMinisterClient({
  issuer: process.env.MINISTER_ISSUER!,      // e.g. "https://ministry.id"
  clientId: process.env.MINISTER_CLIENT_ID!,
  clientSecret: process.env.MINISTER_CLIENT_SECRET, // omit for public/PKCE-only clients
  redirectUri: process.env.MINISTER_REDIRECT_URI!,
});

const { verifier: codeVerifier, challenge } = await client.generatePkce();
const state = client.randomToken();
const nonce = client.randomToken();
// Persist { state, nonce, codeVerifier } keyed by state; consume delete-on-read
// at the callback. The SDK stores nothing.

const url = await client.getAuthorizationUrl({
  scopes: ["openid", ...badgeScopes(["age-over-21"])],
  state,
  nonce,
  codeChallenge: challenge,
});
```

Badge slugs are per-fact, not parameterized. Age is one slug per threshold
(`age-over-16`, `age-over-18`, `age-over-21`, and so on up to `age-over-65`), so
"over 21" is the scope `badge:age-over-21`, not `badge:age` with an argument. The
full slug list the SDK knows is `knownBadgeTypes()` from
`@ministryofmany/client/badges`.

### Two request paths

The auth-code + PKCE flow client above (`createMinisterClient`) is the path that
can carry a policy. The Auth.js adapter `ministerProvider` from
`@ministryofmany/client/auth-js` takes a `scopes` option too, but it has no
`minister_policy` hook, so use it for plain identity-or-flat-badge logins only:

```ts
import { ministerProvider } from "@ministryofmany/client/auth-js";

ministerProvider({
  issuer: process.env.MINISTER_ISSUER!,
  clientId: process.env.MINISTER_CLIENT_ID!,
  clientSecret: process.env.MINISTER_CLIENT_SECRET,
  scopes: ["openid", "profile"], // defaults to ["openid", "profile"] if omitted
});
```

Discreetly runs both: `ministerProvider` for the badge-free global header login,
and a dedicated `createMinisterClient` flow at its own routes for the per-room
disclosure that needs `minister_policy`.

## Requested scopes must be a subset of allowedScopes

Every OIDC client registered in Minister has an `allowedScopes` list (set in the
admin UI at `/admin/oidc-clients`). The authorize endpoint rejects any scope
outside it:

```
error=invalid_scope
error_description=client is not authorized for scope(s): badge:residency-city
```

Your app can never ask for a badge type it was not registered to request. Add the
scope to the client's `allowedScopes` first, then request it. This is the outer
gate: the `scope` param is checked against `allowedScopes`, and (below) the policy
is checked against the requested `scope`.

## Express OR/threshold requirements with minister_policy

A flat scope list is an implicit AND at the menu level: the consent screen offers
every requested badge type. When the real requirement is "any one of these" or
"any two of these," send a `minister_policy` authorize param carrying the
requirement tree. Minister then discloses only a minimal satisfying subset instead
of the whole menu.

The tree is a `PolicyNode`:

```ts
type PolicyNode =
  | { badge: { type: string; where?: Record<string, string | number | boolean>; maxAgeDays?: number } }
  | { allOf: PolicyNode[] }
  | { anyOf: PolicyNode[] }
  | { atLeast: { n: number; of: PolicyNode[] } };
```

- A **badge leaf** names one badge type. Optional `where` is an exact-match filter
  over the badge's attributes (every key must equal the badge's value). Optional
  `maxAgeDays` requires the badge to have been issued within that many days.
- `allOf` / `anyOf` are AND / OR over their children.
- `atLeast: { n, of }` requires `n` distinct satisfied children.

Example: "resident of NY, or any two of `{age-over-21, an email-domain badge, a
GitHub oauth-account}`":

```json
{
  "anyOf": [
    { "badge": { "type": "residency-state", "where": { "country": "US", "state": "NY" } } },
    {
      "atLeast": {
        "n": 2,
        "of": [
          { "badge": { "type": "age-over-21" } },
          { "badge": { "type": "email-domain" } },
          { "badge": { "type": "oauth-account", "where": { "provider": "github" } } }
        ]
      }
    }
  ]
}
```

Encode it as base64url JSON (no padding) and pass it through `extraParams`:

```ts
function encodeMinisterPolicy(policy: unknown): string {
  const json = JSON.stringify(policy);
  const b64 = Buffer.from(json, "utf8").toString("base64url"); // Node
  return b64; // in the browser: btoa + replace +/ with -_ and strip = padding
}

const url = await client.getAuthorizationUrl({
  scopes: ["openid", ...badgeScopes([
    "residency-state", "age-over-21", "email-domain", "oauth-account",
  ])],
  state,
  nonce,
  codeChallenge: challenge,
  extraParams: { minister_policy: encodeMinisterPolicy(policy) },
});
```

`extraParams` is appended after the standard params and can never overwrite one:
keys that collide with `response_type`, `client_id`, `redirect_uri`, `scope`,
`state`, `nonce`, `code_challenge`, or `code_challenge_method` are ignored.

Note the `where` example on `oauth-account`: the filter runs against the badge's
denormalized attributes, so `{ provider: "github" }` matches only a GitHub
oauth-account badge. `maxAgeDays` freshness is coarse (Minister derives age from a
month-granularity issuance bucket and fails closed), so treat it as "within N
months," not a sub-month gate.

## Every policy badge type must be within scope

The policy can only structure the menu you already requested. Minister enforces
that every badge `type` named anywhere in the tree is one of the requested
`badge:<type>` scopes:

```
error=invalid_scope
error_description=minister_policy references badge type not in scope: residency-city
```

Because the requested scope is itself already a subset of `allowedScopes`, the
policy sits inside two nested gates and can never widen what the RP is allowed to
ask about. In practice: request the union of every type your policy mentions as
`scope`, then send the policy to structure that union. (Discreetly derives the
union with `requiredScopes(policy)` and requests exactly that set.)

## How Minister validates and minimizes

Minister validates `minister_policy` fail-closed before it trusts a single byte of
it. On any failure the authorize request is rejected (redirected back to your
`redirect_uri` with an `error`), never silently downgraded:

- base64url + JSON decode (malformed => `invalid_request`)
- strict Zod schema, unknown keys rejected (=> `invalid_scope`)
- 4 KB byte cap on the decoded JSON (=> `invalid_request`)
- breadth caps: `atLeast.n <= 16`, `children per node <= 16`, `total nodes <= 64`
  (=> `invalid_request`)
- depth cap: `tree depth <= 8` (=> `invalid_request`)
- every badge type in the tree within the requested scope (=> `invalid_scope`)

For a satisfiable policy, Minister computes per-type holder counts and preselects
the **minimal satisfying set with the largest anonymity** (the disclosure whose
weakest-link anonymity set is largest, tie-broken by fewest badges). The consent
screen renders the requirement as a choice (radio for "one of," pick-n for "n of,"
checkboxes for "all of") with that set pre-ticked, and the user can override to
another satisfying set. Neither the user nor the RP sees the raw holder count.

The authoritative guard is server-side minimization on consent submit: whatever
the user ticks is trimmed to one minimal satisfying set before anything is
persisted, so a tampered POST that checks two satisfying branches (or extra badges
past `atLeast n`) can never land more than one minimal set in `minister_badges`.
With no policy this minimization is the identity, and consent falls back to the
flat per-scope menu.

## Match your RP-side gate to the same requirement

Send Minister the same requirement you enforce yourself. If your server-side gate
requires "any two of three," send that exact `atLeast{2, of: [...]}` as the
policy. Then Minister discloses one minimal satisfying set, and your gate accepts
that one set. A mismatch is what causes over-disclosure or a spurious denial:
request more than you gate on and the user reveals extra badges for nothing;
request less and Minister may disclose a set your gate rejects.

Discreetly is the reference for this: a room stores a `PolicyNode` access policy,
and at join time it mirrors that one policy into both places. `scopesToRequestForRoom(policy)`
produces `openid profile` plus the `badge:<type>` union of every type the policy
mentions (as the requested scope), and `encodeMinisterPolicy(policy)` sends the
same tree as `minister_policy`. The API re-verifies the disclosed badges against
the identical policy on the gated call. One policy object, three consistent uses,
one minimal satisfying set on the wire.

> Vocabulary sync caveat: the `@ministryofmany/client/badges` registry is a copy
> of Minister's authoritative `packages/shared` vocabulary, kept in sync by hand
> (an automated drift-check is planned but not yet in place). If you request a
> slug Minister does not know, the scope check rejects it; if the two registries
> disagree on a slug, trust Minister's `packages/shared`.
