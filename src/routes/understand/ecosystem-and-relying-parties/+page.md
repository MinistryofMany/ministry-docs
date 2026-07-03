---
title: The Ecosystem and Relying Parties
description: How Minister, the apps that rely on it, and the @ministryofmany/client SDK fit together at runtime over OIDC.
order: 2
---

## The shape of it

Minister is the identity provider (IdP). Everything else is a relying party (RP)
that authenticates users through it, or the SDK those RPs use to talk to it. The
only coupling between an RP and Minister is the OIDC protocol over HTTP - there
is no shared database, no shared runtime, no private API.

```
                Minister  (OIDC IdP / VC badge issuer)
                        |  OIDC (auth-code + PKCE/S256), discloses badge VCs
                        v
        FreedInk, Discreetly, Deforum, ...  (relying-party apps)
                        ^
                @ministryofmany/client  (the SDK those apps use)
```

## Minister, the identity provider

Minister runs the OIDC provider endpoints and holds the badge issuer key. An RP
sends users to Minister's `/oidc/authorize`, Minister authenticates the user and
shows a consent screen, and on approval it redirects back with an authorization
code the RP exchanges at `/oidc/token` for an `id_token`. The token carries a
pairwise `sub` and a `minister_badges` array of disclosed VCs. Minister
publishes standard discovery at `/.well-known/openid-configuration`, its keys at
`/.well-known/jwks.json`, and its DID document at `/.well-known/did.json`.

## `@ministryofmany/client`, the SDK

The SDK is the only externally consumable piece; it is what an RP imports to
speak to Minister. It has three entry points, each documented on its own page:

- **Root** (`@ministryofmany/client`) - `createMinisterClient` runs the
  auth-code + PKCE flow yourself, and a standalone verification layer
  (`createMinisterVerifier` / `verifyMinisterIdToken` / `verifyMinisterBadges` /
  `verifyMinisterBadge`) verifies a token and its badges on a backend. See
  [The Auth-Code + PKCE Flow](/build/auth-code-pkce-flow) and
  [Verifying Tokens and Badges on a Backend](/build/verifying-tokens-and-badges).
- **`@ministryofmany/client/auth-js`** - a non-invasive Auth.js adapter
  (`ministerProvider` + `ministerBadgesFromProfile`). See
  [Auth.js Integration](/build/auth-js-integration).
- **`@ministryofmany/client/badges`** - the client-side badge vocabulary (slugs,
  scope helpers, Zod claim schemas), dependency-light (no `jose`). See the
  [Badge-Type Reference](/build/badge-type-reference).

The SDK is framework-agnostic and stateless; the app owns its own flow-state
storage. It depends only on `jose` and `zod`, is ESM-only, and runs on Node 20+,
Deno, and edge runtimes.

## The relying parties

Three apps consume Minister today, each exercising a different slice of the
model:

- **FreedInk** - an anonymous collective-blogging platform gated by Semaphore
  zero-knowledge proofs. It authenticates via Minister (alongside passkeys,
  SIWE, and email) requesting `openid profile` only - identity, no badges. It is
  the SDK's first consumer, and shows the "sign in, no badge scopes" path.
- **Discreetly** - anonymous federated zero-knowledge group chat. It signs users
  in with the Auth.js adapter, and gates each room on a structured **badge
  policy**. A room's requirement travels to Minister as the `minister_policy`
  authorize param, and its tRPC API re-verifies the `id_token` and disclosed
  badges on every gated call with `createMinisterVerifier`. It is the reference
  for badge scopes + policies.
- **Deforum** - a badge-gated, anonymous-but-verified Reddit-shaped forum
  (deforum.space). Each sub-forum is gated by Minister badges; users get a stable
  per-sub-forum pseudonym and no global identity. It runs the SDK auth-code +
  PKCE flow directly.

Each RP is registered as an OIDC client in Minister's admin and holds its own
`MINISTER_ISSUER` / `MINISTER_CLIENT_ID` (+ secret for confidential clients). No
RP shares state with any other; they are correlated only through Minister, and
Minister is built specifically to prevent that correlation (see
[Pairwise Subjects and Unlinkability](/understand/pairwise-subjects-and-unlinkability)).

## The runtime flow, end to end

1. The RP redirects the user to Minister's `/oidc/authorize` with `openid`,
   optional `profile`, and any `badge:<type>` scopes (plus an optional
   `minister_policy`).
2. Minister authenticates the user, then renders a consent screen showing only
   the requested badge types and minimizing the disclosure.
3. On approval Minister redirects back with an authorization code.
4. The RP exchanges the code at `/oidc/token` (with its PKCE verifier) for an
   `id_token` carrying the pairwise `sub` and `minister_badges`.
5. The RP verifies the token and each badge, binds each badge to this login, and
   gates access on the resulting claims.

The SDK collapses steps 1, 4, and 5 into a few calls. What you never do is trust
a badge you have not verified, or assume a badge belongs to the current login
without checking its holder binding - both covered in the build track.

## The issuer-host coupling to remember

The SDK derives the expected badge-VC issuer DID (`did:web:<host>`) from the
OIDC issuer host, with no override. So a deployment's `MINISTER_ISSUER` host
**must equal** Minister's issuer domain (`MINISTER_ISSUER_DOMAIN`), or every
badge silently lands in `rejected` while login still works. This one mismatch is
the most common integration failure; it recurs across the build pages because it
bites at runtime, not at config time.
