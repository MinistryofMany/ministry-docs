---
title: Auth.js Integration
description: Drop Minister into an Auth.js (next-auth) app with the /auth-js adapter, no forking or pinning.
order: 5
---

## What this gives you

`@ministryofmany/client/auth-js` is a non-invasive adapter for Auth.js
(next-auth). It does not modify, fork, or pin Auth.js. Everything it exports is a
plain value or function you hand to Auth.js through its documented extension
points. `@auth/core` is a **types-only optional peer** (`^0.37.0`); it is used
solely for the `OIDCConfig` return type and is never imported at runtime.

Two exports:

- `ministerProvider(options)` returns a standard OIDC provider config object.
  Drop it into `NextAuth({ providers: [...] })`.
- `ministerBadgesFromProfile(profile, { issuer })` verifies the nested badge VCs
  carried by an already-verified id_token payload. Call it inside your own `jwt`
  (or `profile`) callback.

Auth.js owns the flow, session, cookies, and id_token verification. This adapter
only supplies the provider config and a badge verifier.

## Install

```sh
pnpm add @ministryofmany/client
```

`jose` and `zod` come along as runtime dependencies. `@auth/core` is an optional
peer; a next-auth app already has it transitively, so you install nothing extra.

The SDK is ESM-only and runs on Node 20+, Deno, and edge runtimes (it uses Web
Crypto and `fetch`, not `node:crypto`).

## Configure the provider

Pass `ministerProvider({ clientId, clientSecret?, issuer, scopes? })` into the
`providers` array. Build the scope list with `badgeScopes([...])` from the
`/badges` entry point.

```ts
// auth.ts
import NextAuth from "next-auth";
import { ministerProvider, ministerBadgesFromProfile } from "@ministryofmany/client/auth-js";
import { badgeScopes } from "@ministryofmany/client/badges";

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [
    ministerProvider({
      issuer: process.env.MINISTER_ISSUER!,
      clientId: process.env.MINISTER_CLIENT_ID!,
      clientSecret: process.env.MINISTER_CLIENT_SECRET, // omit for public/PKCE-only clients
      scopes: ["openid", "profile", ...badgeScopes(["age-over-18", "email-domain"])],
    }),
  ],
  // callbacks below
});
```

What `ministerProvider` returns (verbatim shape from the adapter source):

```ts
{
  id: "minister",
  name: "Minister",
  type: "oidc",
  issuer,        // your MINISTER_ISSUER
  clientId,
  clientSecret,  // undefined for public clients
  authorization: { params: { scope: scopes.join(" ") } },
  checks: ["pkce", "state", "nonce"],
}
```

Notes:

- The provider `id` is `"minister"`, which fixes the callback path to
  `/api/auth/callback/minister` (see registration below).
- `scopes` defaults to `["openid", "profile"]` when omitted. `openid` is
  required; the adapter does not add it for you, so include it when you pass a
  custom list.
- Minister publishes `/.well-known/openid-configuration`, so Auth.js discovers
  the authorize, token, userinfo, and JWKS endpoints from `issuer` alone.
- `checks: ["pkce", "state", "nonce"]` is enforced by Auth.js. PKCE is S256.

## Verify badges in your jwt callback

Auth.js verifies the id_token itself (EdDSA signature against Minister's JWKS,
`iss`, `aud`, `nonce`, `exp`). It does **not** know about the nested badge VCs in
the `minister_badges` claim. That is what `ministerBadgesFromProfile` is for:
hand it the `profile` (the already-verified id_token payload) and it verifies
each badge VC and binds it to this login.

```ts
callbacks: {
  async jwt({ token, account, profile }) {
    // `profile` and `account` are present only on the initial sign-in.
    if (profile) {
      const { badges, rejected } = await ministerBadgesFromProfile(profile, {
        issuer: process.env.MINISTER_ISSUER!,
      });
      // `badges` are signature-verified and holder-bound. Stash what you need.
      // Storing full badges (each carries the raw VC JWT) bloats the session
      // cookie; prefer the slugs unless you need the claims downstream.
      token.ministerBadges = badges.map((b) => b.type);

      // Keep the raw id_token if a downstream service must re-verify it.
      if (account?.id_token) token.idToken = account.id_token;

      // `rejected` holds badges that failed verification (bad signature,
      // wrong issuer, expired, or not bound to this login). Login still
      // succeeds; log/alert if a partner may be misconfigured.
    }
    return token;
  },
}
```

`ministerBadgesFromProfile(profile, { issuer, key? })` returns a
`BadgesResult`:

```ts
interface BadgesResult {
  badges: VerifiedBadge[];   // usable, signature-verified, holder-bound
  rejected: RejectedBadge[]; // failed, with the reason on `.error`
}
```

A `VerifiedBadge` looks like:

```ts
{
  type: "age-over-18",              // Minister badge slug
  claims: { threshold: 18 },        // schema-validated credentialSubject claims
  subject: "did:web:...:u:<sub>",   // per-RP pairwise holder DID, bound to id_token sub
  issuanceMonth: "2026-05",         // coarse "YYYY-MM" cohort bucket (optional)
  raw: "<vc-jwt>",                  // original VC JWT
}
```

**Holder binding.** The adapter requires each badge's pairwise subject to equal
`did:web:<issuer-host>:u:<id_token sub>`. Minister re-mints every disclosed badge
under the same pairwise pseudonym it stamps as the id_token `sub`, so a
borrowed or mismatched credential lands in `rejected` rather than counting.
Individual bad badges never throw; they are returned in `rejected`.

The `key` option is for tests only (inject Minister's public key or a JWKS
resolver). In production, omit it; the SDK fetches Minister's JWKS from the
issuer.

## Environment and client registration

Set these on your app (matching Auth.js and the SDK):

```sh
AUTH_SECRET="<openssl rand -base64 32>"   # Auth.js cookie/JWT secret
AUTH_URL="https://yourapp.example"        # your app origin
AUTH_TRUST_HOST=true                      # when behind a proxy/tunnel

MINISTER_ISSUER="https://ministry.id"     # Minister origin (OIDC issuer)
MINISTER_CLIENT_ID="your_client_id"
MINISTER_CLIENT_SECRET="<from Minister admin>"  # omit for public clients
```

Register the app as an OIDC client in Minister's admin
(`/admin/oidc-clients`). The redirect URI is the Auth.js callback for the
`minister` provider:

```
https://yourapp.example/api/auth/callback/minister
```

Because the provider `id` is `"minister"`, that path is fixed. If your
`MINISTER_CLIENT_SECRET` is set the client is confidential; leave it unset for a
public/PKCE-only client.

## Badge scopes and vocabulary

The `/badges` entry point (`@ministryofmany/client/badges`) is dependency-light
(no jose) and carries the badge vocabulary the RP needs: slugs, scope helpers,
and Zod claim schemas.

```ts
import { badgeScope, badgeScopes, knownBadgeTypes, getBadgeClaimSchema }
  from "@ministryofmany/client/badges";

badgeScope("age-over-21");          // "badge:age-over-21"
badgeScopes(["email-domain"]);       // ["badge:email-domain"]
knownBadgeTypes();                   // every slug this SDK knows
getBadgeClaimSchema("email-domain"); // Zod schema for the claims, or undefined
```

Known badge slugs (from the SDK registry):

| Slug | Claims |
| --- | --- |
| `email-domain` | `{ domain }` |
| `email-exact` | `{ email }` |
| `oauth-account` | `{ provider, accountId, handle? }` (`provider` in `github`, `google`, `discord`) |
| `residency-country` | `{ country }` (ISO 3166-1 alpha-2) |
| `residency-state` | `{ country, state }` |
| `residency-city` | `{ country, state, city }` |
| `invite-code` | `{ label }` |
| `tlsn-attestation` | `{ domain, claim }` |
| `age-over-<N>` | `{ threshold: N }` for N in 16, 18, 21, 25, 30, 35, 40, 45, 55, 65 |

This vocabulary is a deliberate copy of Minister's authoritative registry
(`@ministryofmany/shared`), not an import, so the SDK publishes standalone. The
copies can drift; a drift-check against `@ministryofmany/shared` is planned.

## How Discreetly uses it

Discreetly's Next.js web app (`apps/web`) signs users in with `ministerProvider`
from `@ministryofmany/client/auth-js`. Its global header login is
identity-only, requesting `["openid", "profile"]` with no badge scopes:

```ts
// Discreetly apps/web/src/auth.ts (abridged)
ministerProvider({
  issuer: process.env.MINISTER_ISSUER!,
  clientId: process.env.MINISTER_CLIENT_ID!,
  clientSecret: process.env.MINISTER_CLIENT_SECRET,
  scopes: ["openid", "profile"],
})
```

The tRPC API (`services/api`) is the sole verification authority: the browser
forwards the Minister id_token, and the API re-verifies it (and any disclosed
badge VCs) with `createMinisterVerifier` on every gated call. See the
"Verify on your backend" flow in the SDK README.

Two Discreetly specifics that are useful context but are not the general pattern:

- Discreetly runs the **database session strategy** (Prisma adapter). Under that
  strategy the `jwt` callback is not invoked, so it does not use
  `ministerBadgesFromProfile` in a jwt callback; instead the Prisma adapter
  persists the id_token on the `Account` row and the `session` callback reads it
  back for display. The `jwt`-callback pattern above is for the default JWT
  session strategy (no database adapter).
- Per-room **badge disclosure** does not ride the Auth.js global login. It runs
  the SDK auth-code + PKCE flow at dedicated RP routes
  (`/api/room-auth/start` + `/api/room-auth/callback`) that carry the
  `minister_policy` param and mint a fresh per-room id_token handed straight to
  the gate.

If you want badges on the Auth.js login itself, add badge scopes to
`ministerProvider` and verify them in the `jwt` callback as shown above; use the
default JWT strategy so the callback fires.

## Issuer-domain coupling (all badges rejected?)

The expected badge-VC issuer is derived as `did:web:<host-of-your-issuer>`, with
no override. Minister signs badge VCs with `did:web:<MINISTER_ISSUER_DOMAIN>`. If
the Minister deployment's `MINISTER_ISSUER_DOMAIN` host does not equal your OIDC
issuer host, **every badge fails verification** and lands in `rejected` with an
issuer mismatch. Login and id_token verification are unaffected; only badges
fail. If you see all badges rejected, check that Minister's
`MINISTER_ISSUER_DOMAIN` host matches its OIDC issuer host.
