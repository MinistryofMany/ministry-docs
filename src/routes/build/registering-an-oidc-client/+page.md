---
title: Registering an OIDC Client
description: Register a relying party in Minister's admin - confidential vs public clients, redirect URIs, allowed scopes, and the client secret.
order: 2
---

## Where registration happens

Relying parties are managed in Minister's admin UI at `/admin/oidc-clients`. You
register a client, edit its name, redirect URIs, and allowed scopes, rotate its
secret, or delete it (which revokes its outstanding tokens in the same
transaction). This is the management path - there is no self-service dynamic
registration endpoint, and the `scripts/seed-client.ts` bootstrap exists only to
seed the demo client under docker-compose.

## Confidential vs public

At registration you pick the client type, which decides whether Minister issues a
secret:

- **Confidential.** Minister generates a `client_secret`, **shown once** at
  creation (and on rotation). It is stored hashed at rest (Argon2id), so it
  cannot be recovered later - copy it then. Use this for a server-side app that
  can keep a secret.
- **Public / PKCE-only.** No secret. PKCE (S256) alone binds the authorization
  code to your app. Use this when there is no secure server to hold a secret (a
  SPA or native app).

Either way PKCE is mandatory and `S256`-only. A public client is not "less
secure" here - it just leans entirely on PKCE, `state`, `nonce`, and exact
redirect matching instead of also proving a secret at the token endpoint.

## Redirect URIs

You register one or more exact redirect URIs, one per line. Matching is exact
(RFC 6749 §3.1.2.2) - the callback's `redirect_uri` must be a
character-for-character match of a registered value, so register the precise URL
your app sends. Minister normalizes nothing beyond trimming whitespace.

Validation on registration:

- Must be an **absolute** URL. A relative path is rejected
  (`Not an absolute URL`).
- **No fragment.** A URL with a `#...` component is rejected.
- **`https` only**, except plain `http` is allowed on `localhost` or `127.0.0.1`
  for local development. Anything else is rejected (`Must be https (or http on
  localhost)`).

The exact URL depends on your integration surface:

- Hand-rolled flow (`createMinisterClient`): whatever you pass as
  `redirectUri`, for example `https://yourapp.example/auth/minister/callback`.
- Auth.js adapter (`ministerProvider`): the provider id is `minister`, so the
  callback path is fixed at `https://yourapp.example/api/auth/callback/minister`.

## Allowed scopes

Each client carries an `allowedScopes` list. This is the outer gate on what the
client may ever request: an authorize request whose `scope` is not a subset of
`allowedScopes` is rejected with `invalid_scope`. The valid scopes are:

- `openid` - **required**. The flow is meaningless without it, and registration
  rejects a scope set that omits it (`The openid scope is required`).
- `profile` - display name and avatar (each consented independently at the
  consent screen).
- `badge:<type>` - one per badge type you intend to request, for example
  `badge:age-over-21` or `badge:oauth-account`.

Any scope outside the known set (`openid`, `profile`, and the registered
`badge:<type>` vocabulary) is rejected as an unknown scope. Register the union of
every badge type your app will ever ask for; you can request a subset per login,
but never a superset of what is registered.

Scope containment nests: a `minister_policy` on an authorize request may only
reference badge types already in the requested `scope`, and the requested scope
must be a subset of `allowedScopes`. So:

```text
policy badge types  subset-of  requested badge:<type> scopes  subset-of  client.allowedScopes
```

A policy can therefore only structure the menu the client is already registered
for, never widen it. See
[Requesting Badge Scopes and Policies](/build/requesting-badges-and-policies).

## The client secret

For a confidential client, the secret is presented once at creation. If you lose
it, rotate it in the admin UI (which invalidates the old one and shows a new one
once). At the token endpoint your app authenticates with the client id and this
secret; the SDK sends it for you when you set `clientSecret` on the client
config. Leave `clientSecret` unset and the SDK treats the client as public and
relies on PKCE alone.

Never ship the secret to a browser or commit it. It belongs in server-side env
(`MINISTER_CLIENT_SECRET`) on a confidential client only.

## What you end up with

Registration gives you the values your app configures:

```sh
MINISTER_ISSUER=https://ministry.id            # Minister's origin (no path)
MINISTER_CLIENT_ID=...                          # the registered client id
MINISTER_CLIENT_SECRET=...                      # confidential only; omit for public
MINISTER_REDIRECT_URI=https://yourapp.example/auth/minister/callback
```

`MINISTER_ISSUER` is Minister's bare origin. Its host must equal Minister's
`MINISTER_ISSUER_DOMAIN`, because the SDK derives the expected badge-VC issuer
DID (`did:web:<host>`) from it with no override - a mismatch makes every badge
land in `rejected` at runtime while login still works.

## After registering

Wire the client with one of the integration surfaces:

- [Getting Started](/build/getting-started) - the shortest working flow.
- [The Auth-Code + PKCE Flow](/build/auth-code-pkce-flow) - run OIDC yourself.
- [Auth.js Integration](/build/auth-js-integration) - drop it into next-auth.
- [Requesting Badge Scopes and Policies](/build/requesting-badges-and-policies) -
  once you request badges.
