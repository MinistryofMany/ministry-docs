---
title: Getting Started
description: Prerequisites, registering an OIDC client, installing @ministryofmany/client, and the shortest working sign-in-with-Minister flow.
order: 1
---

## What you need

To wire an app to Minister as a relying party (RP) you need three things:

- A **Minister deployment** you can register a client on. That means access to
  its admin UI at `/admin/oidc-clients`, and its issuer origin (for example
  `https://ministry.id`).
- **Node 20+**. The SDK is ESM-only and uses Web Crypto and `fetch`, so it runs
  on Node 20+, Deno, and edge runtimes.
- A backend, or at least a server-side context, that can hold flow state and
  (for a confidential client) a secret. The SDK stores nothing itself.

You do not need a database schema from Minister, a shared library, or any
private API. The only coupling is OIDC over HTTP.

## Step 1 - register an OIDC client

In Minister's admin UI at `/admin/oidc-clients`, register your app. You choose:

- **Confidential** - Minister issues a `client_secret`, shown once. Use this for
  a server-side app.
- **Public / PKCE-only** - no secret; PKCE alone binds the code to your app. Use
  this when there is no secure server to hold a secret.

You also set the exact **redirect URI(s)** your app will use and the **scopes**
the client may request (`openid`, `profile`, and any `badge:<type>`). Minister
matches the callback `redirect_uri` exactly, so register the precise URL. Full
detail is on [Registering an OIDC Client](/build/registering-an-oidc-client).

You come away with these values:

```sh
MINISTER_ISSUER=https://ministry.id            # Minister's origin, no path
MINISTER_CLIENT_ID=...                          # from /admin/oidc-clients
MINISTER_CLIENT_SECRET=...                      # confidential clients only; omit for public
MINISTER_REDIRECT_URI=https://yourapp.example/auth/minister/callback
```

`MINISTER_ISSUER` must be a bare origin - scheme, host, optional port, no path,
query, or fragment. The SDK derives the badge issuer DID (`did:web:<host>`) from
this host, so a stray path fails at config time rather than silently rejecting
every badge later. Its host must equal Minister's `MINISTER_ISSUER_DOMAIN`, or
badges are rejected at runtime (see the caveat at the end).

## Step 2 - install the SDK

```sh
pnpm add @ministryofmany/client   # or: npm i / yarn add
```

`jose` and `zod` come with it; nothing else. There is no `@ministryofmany/client`
on npm yet in some setups - it may be consumed via a commit-pinned git URL - but
the import surface is the same either way.

Pick your integration surface:

- Running the flow yourself -> `createMinisterClient` (this page, and
  [The Auth-Code + PKCE Flow](/build/auth-code-pkce-flow)).
- Already on Auth.js -> the `@ministryofmany/client/auth-js` adapter
  ([Auth.js Integration](/build/auth-js-integration)).
- A different service runs the flow and you only verify tokens on a backend ->
  `createMinisterVerifier`
  ([Verifying Tokens and Badges on a Backend](/build/verifying-tokens-and-badges)).

## Step 3 - the shortest working flow

This is the minimum end-to-end with `createMinisterClient`: identity only, no
badge scopes. Create one client and reuse it - it caches Minister's discovery
document and JWKS after the first request.

```ts
// minister.ts
import { createMinisterClient } from "@ministryofmany/client";

export const minister = createMinisterClient({
  issuer: process.env.MINISTER_ISSUER!,
  clientId: process.env.MINISTER_CLIENT_ID!,
  clientSecret: process.env.MINISTER_CLIENT_SECRET, // omit for public clients
  redirectUri: process.env.MINISTER_REDIRECT_URI!,
});
```

**Start the login.** Generate a PKCE pair and CSRF/nonce tokens, build the
authorization URL, persist the flow state keyed by `state`, and redirect the
user:

```ts
import type { OidcFlowState } from "@ministryofmany/client";
import { minister } from "./minister";

export async function startLogin() {
  const { verifier, challenge } = await minister.generatePkce();
  const state = minister.randomToken();
  const nonce = minister.randomToken();

  const url = await minister.getAuthorizationUrl({
    scopes: ["openid", "profile"], // you MUST include "openid" yourself
    state,
    nonce,
    codeChallenge: challenge,
  });

  const flow: OidcFlowState = {
    state,
    nonce,
    codeVerifier: verifier,
    expiresAt: Date.now() + 10 * 60_000,
  };
  await saveFlow(state, flow); // YOUR storage (cookie, Redis, DB row)

  return url; // 302 the user here
}
```

**Handle the callback.** Consume the flow state atomically (delete-on-read),
then exchange the code. The SDK verifies the `id_token` and every disclosed
badge before returning:

```ts
import { MinisterTokenError } from "@ministryofmany/client";
import { minister } from "./minister";

export async function handleCallback(req: Request) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) throw new Error("missing code/state");

  const flow = await takeFlow(state); // atomic fetch-and-delete
  if (!flow || flow.expiresAt < Date.now()) {
    throw new Error("unknown or expired login flow");
  }

  try {
    const { claims, badges, rejected } = await minister.exchangeCode({
      code,
      codeVerifier: flow.codeVerifier,
      expectedNonce: flow.nonce,
    });

    // claims.sub is a pairwise pseudonym: stable for THIS user at YOUR app,
    // different from what every other RP sees. Key your user records on it.
    await upsertUser({ ministerSub: claims.sub, name: claims.name });
    // ... set your own session, redirect into the app ...
  } catch (err) {
    if (err instanceof MinisterTokenError) {
      return new Response("unauthorized", { status: 401 });
    }
    throw err;
  }
}
```

That is a complete sign-in. `claims.sub` is your durable, per-app user id;
`badges` is empty here because you requested no badge scopes.

## Add badges next

To gate on a fact, add badge scopes to the authorize request and read the
verified badges off the result:

```ts
import { badgeScopes } from "@ministryofmany/client/badges";

const url = await minister.getAuthorizationUrl({
  scopes: ["openid", "profile", ...badgeScopes(["age-over-21"])],
  state,
  nonce,
  codeChallenge: challenge,
});

// in the callback, after exchangeCode:
const isAdult = badges.some((b) => b.type === "age-over-21");
```

The badges in the result are already signature-verified and holder-bound to this
login; you do not re-verify them. For OR/threshold requirements, structured
policies, and the full badge vocabulary, see
[Requesting Badge Scopes and Policies](/build/requesting-badges-and-policies) and
the [Badge-Type Reference](/build/badge-type-reference).

## The one caveat that bites everyone

The SDK derives the expected badge issuer DID from your `MINISTER_ISSUER` host,
with no override. If that host does not equal Minister's `MINISTER_ISSUER_DOMAIN`
host, **login works but every badge lands in `rejected`** - the `id_token`
verifies against a different key, so the failure is silent. If you see badges
never counting, check that the two hosts match (a non-default port is
percent-encoded as `host%3Aport`).
