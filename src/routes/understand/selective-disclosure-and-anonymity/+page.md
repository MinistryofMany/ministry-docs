---
title: Selective Disclosure and Anonymity
description: How Minister discloses the minimum a relying party needs and steers the user toward the most anonymous way to satisfy a requirement.
order: 5
---

## The principle

Minister's job at consent time is to disclose the least it can while still letting the
relying party (RP) make its access decision, and to nudge the user toward the disclosure
that identifies them the least. Two ideas do the work:

- **Per-action minimal disclosure.** An RP asks only for the badge types a specific action
  needs, and the user discloses only the specific badge VCs they choose. Nothing rides along.
- **Anonymity-aware selection.** When a requirement can be satisfied more than one way,
  Minister ranks the options by how many other users hold the same badge types, pre-selects
  the most anonymous minimal set, and shows the user a coarse hint so they can override.

The guarantees are enforced server-side, not in the UI. The consent screen's pre-selection
and override controls are advisory. The authoritative bound is a server-side minimization
step on consent submit that a tampered POST cannot get past.

## Scopes: the requested menu

An RP declares what it wants as OIDC scopes on the `/oidc/authorize` request:

- `openid` - required.
- `profile` - display name and avatar, each consented independently.
- `badge:<type>` - one scope per badge type, for example `badge:age-over-21` or
  `badge:oauth-account`.

The badge-type vocabulary (slugs, `credentialSubject` claim schemas, and the
`badge:<slug>` scope derivation) is defined provider-side in Minister's `@minister/shared`
and mirrored for RPs in the SDK's `@ministryofmany/client/badges` entry point. Current slugs
include `email-domain`, `email-exact`, `oauth-account`, `age-over-N`, `residency-country`,
`residency-state`, `residency-city`, `invite-code`, and `tlsn-attestation`.

The requested scope set is validated to be a subset of the client's registered
`allowedScopes` before anything else happens. So the RP can never request a badge type it
was not registered for, and the set of `badge:<type>` scopes on the request is the full menu
the user will be shown - the consent screen renders nothing beyond it.

Declining a badge does not abort the flow. The RP receives whatever the user approved and no
more.

## Structured requirements: `minister_policy`

A flat list of scopes says "these types are on the table" but not "here is what actually
satisfies the gate." Some actions need boolean structure: satisfy any one of these, or at
least two of these, or all of these. That structure travels in a separate authorize param,
`minister_policy`.

### The grammar

A policy is a small recursive tree. Leaves are badge requirements, interior nodes are boolean
combinators:

```ts
type PolicyNode = BadgeLeaf | AllOfNode | AnyOfNode | AtLeastNode;

interface BadgeLeaf {
  badge: {
    type: string;                              // a badge slug, e.g. "residency-state"
    where?: Record<string, string | number | boolean>; // attribute equality, e.g. { state: "MD" }
    maxAgeDays?: number;                        // badge must be issued within this window
  };
}

interface AllOfNode   { allOf: PolicyNode[]; }
interface AnyOfNode   { anyOf: PolicyNode[]; }
interface AtLeastNode { atLeast: { n: number; of: PolicyNode[] }; }
```

`allOf` needs every child, `anyOf` needs any one child, and `atLeast{n, of}` needs `n`
distinct children satisfied by `n` distinct badges (the evaluator computes a maximum
bipartite matching between branches and badges, so one badge cannot double-count across
overlapping branches).

The RP serializes this tree as JSON, base64url-encodes it, and sends it as the
`minister_policy` query param on `/oidc/authorize`. Discreetly is the live consumer: a room's
access requirement is exactly one of these subtrees, sent verbatim so the user discloses only
a minimal satisfying set. FreedInk, by contrast, requests `openid profile` only and sends no
policy at all.

The policy model is a deliberate copy of Discreetly's `policy` package, kept honest by a
drift test (`oidc-policy.drift.test.ts`) so the provider's and RP's evaluators agree.

### Validation is fail-closed and cannot widen the menu

`/oidc/authorize` validates `minister_policy` at every sub-step before it trusts the param
(`parseMinisterPolicy` in `oidc-authorize.ts`). Any failure rejects the request rather than
degrading to a looser interpretation:

- base64url decode, then `JSON.parse`; malformed input is `invalid_request`.
- a 4 KB byte cap on the decoded JSON (`MAX_POLICY_BYTES`).
- a strict Zod schema (`.strict()` objects, unknown keys rejected).
- breadth bounds: `MAX_ATLEAST_N` 16, `MAX_NODE_CHILDREN` 16, `MAX_POLICY_NODES` 64.
- a depth cap: `MAX_POLICY_DEPTH` 8.
- **every badge type named in the policy must be in the requested scope.**

The breadth and depth caps exist because byte size and depth alone do not bound the work: a
flat, shallow `atLeast{n, of: [many leaves]}` stays small and shallow yet would drive
combinatorial enumeration in selection. The caps make that explicit and reject it early.

The last check is the important one for the disclosure model. The requested scope is already
a subset of the client's `allowedScopes`, so requiring policy types to be a subset of the
requested scope means:

```text
policy badge types  ⊆  requested badge:<type> scopes  ⊆  client.allowedScopes
```

A policy can therefore only **structure** the already-permitted scope menu. It can turn a
flat menu into "any one of these" or "at least two of these," but it can never introduce a
badge type the RP was not authorized to ask about. The validated policy then rides into the
consent screen inside a signed request token, so the consent renderer trusts it without
re-parsing untrusted input.

## Anonymity-aware selection

Once the policy is trusted and the user is known, Minister figures out which of the user's
badges to pre-select. When more than one set satisfies the policy, it prefers the set that
identifies the user least.

### Holder counts

"Least identifying" is measured by anonymity-set size: for each badge type, how many distinct
users hold a badge of that type. More holders means disclosing that type narrows the crowd
less.

```sql
SELECT "type", COUNT(DISTINCT "userId") AS holders
FROM "Badge"
GROUP BY "type"
```

This is computed in `anonymity-sets.ts:holderCountsByType`, cached in-process for about 60
seconds, and used **server-side only**. It is a per-type aggregate, never a per-user value.
Staleness is harmless: the count only moves as badges are issued or deleted, and the RP's own
gate re-evaluates the full policy downstream regardless.

### Picking the minimal, most-anonymous set

`selectMinimalAnonymitySet` (in `oidc-policy.ts`) walks the policy tree and returns:

- `selectedBadgeIds` - the minimal satisfying set with the largest anonymity.
- `alternatives` - other minimal satisfying sets, for the override UI.
- `gaps` - required types the user cannot satisfy (drives the "you don't hold this" hint).

Ranking compares two candidate selections by their **weakest link first**. Each selection is
scored by the multiset of its per-type holder counts sorted ascending, compared
lexicographically, so the smallest anonymity set in the combination dominates (it is the most
identifying part of the disclosure). Ties break toward fewer disclosed badges, then a stable
type ordering for determinism. An `allOf` resolves each child to its best selection and unions
them; an `anyOf` offers each satisfiable child's best as a candidate; an `atLeast{n}` takes
the `n` most-anonymous satisfiable children.

### The coarse bucket the user sees

The consent screen renders the requirement as the matching control - a radio for "one of," a
pick-n for "n of," checkboxes for "all of" - with the minimal set pre-selected. Next to each
type it shows a coarse anonymity bucket, not the raw number (`anonymity-hint.ts`):

| Bucket       | Distinct holders |
| ------------ | ---------------- |
| `very-small` | fewer than 10    |
| `small`      | 10 to 99         |
| `medium`     | 100 to 999       |
| `large`      | 1000 or more     |

Everything under 10 collapses into one bucket on purpose: a live integer for a rarely held
type could itself become a slow identifying signal over time. The bucket gives the user enough
to make an informed override to another satisfying choice without leaking the count.

## Server-side minimization is the authoritative guard

The pre-selection and the override controls are UI. The real over-disclosure bound is applied
when consent is submitted, in `approveConsent` (`oidc-actions.ts`), via `minimizeToPolicy`
(`oidc-consent-minimize.ts`). The submitted badge ids pass through three server-side steps
before anything is persisted:

1. **Ownership drop.** Load the submitted ids scoped to the signed-in user. A badge id the
   user does not own falls out.
2. **Type filter.** Keep only badges whose type was actually requested via a `badge:<type>`
   scope. An owned-but-unrequested badge discloses nothing.
3. **Minimization.** With a policy present, `minimizeToPolicy` runs
   `selectMinimalAnonymitySet` over the surviving badges and keeps only the ids in the single
   chosen minimal satisfying set. The result is always a subset of what was submitted;
   minimization never fabricates or adds.

Because minimization re-derives the minimal set on the server, a tampered POST cannot emit
more than one minimal satisfying set. Ticking two satisfying `anyOf` branches, or extra badges
past `atLeast n`, gets trimmed back to one minimal set. If the submission does not satisfy the
policy at all, the minimal set is empty and nothing extra is disclosed - the RP's own gate is
the admission authority and will deny.

With no policy, `minimizeToPolicy` is the identity and consent falls back to the flat
per-scope menu, which is already bounded to owned-and-requested badges by steps 1 and 2. So
the flat path cannot over-disclose either.

The badges that survive minimization are the VC JWTs Minister embeds in the id_token's
`minister_badges` array:

```json
{
  "iss": "https://ministry.id",
  "sub": "<pairwise pseudonymous id>",
  "aud": "<client_id>",
  "nonce": "...",
  "minister_badges": ["<vc jwt>", "<vc jwt>"]
}
```

## What each party sees, and does not

- **The user** sees the requirement as a choice, the pre-selected minimal set, and a coarse
  anonymity bucket per type. The user never sees the raw holder count.
- **The relying party** receives only the minimized set of badge VCs plus the pairwise `sub`.
  It never sees the raw holder count and never sees a badge type outside the scopes it
  requested. The RP re-verifies and re-evaluates the disclosed badges against its own policy.
- **Minister** uses the raw holder counts internally, for ranking only, and never emits them.

Two more properties reinforce the anonymity story:

- The `sub` an RP receives is a **pairwise pseudonymous identifier**, different for every RP,
  so the same user cannot be correlated across relying parties by subject.
- A disclosed badge's issuance timestamp is **coarsened to the issuance-month start** before
  it feeds selection and before it lands in the VC (`toPolicyUserBadge`), so a fine-grained
  `iat` cannot become a cross-RP correlator. `maxAgeDays` is evaluated against that coarse
  bucket on both sides, so provider and RP reach the same decision.

## Where this lives

| Concern | Source |
| ------- | ------ |
| Policy grammar, evaluation, selection | `apps/minister/src/lib/oidc-policy.ts` |
| Authorize-param validation (`parseMinisterPolicy`) | `apps/minister/src/lib/oidc-authorize.ts` |
| Per-type holder counts | `apps/minister/src/lib/anonymity-sets.ts` |
| Coarse anonymity buckets | `apps/minister/src/lib/anonymity-hint.ts` |
| Server-side minimization (`minimizeToPolicy`) | `apps/minister/src/server/oidc-consent-minimize.ts` |
| Consent submit wiring (`approveConsent`) | `apps/minister/src/server/oidc-actions.ts` |
| Badge-type vocabulary (provider) | `packages/shared/src/badge-types.ts` |
| Badge-type vocabulary (RP SDK) | `@ministryofmany/client/badges` |

> TODO: expand with a worked end-to-end trace (a real `minister_policy` payload from a
> Discreetly room, its decoded tree, the holder counts, and the resulting minimized
> disclosure) once a stable fixture exists.
