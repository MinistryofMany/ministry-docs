---
title: The Auth-Code + PKCE Flow
description: Run the authorization-code + PKCE (S256) flow yourself with createMinisterClient, owning the flow state.
order: 3
---

## When to use this

`@ministryofmany/client` gives you three ways to talk to Minister. This page covers the
first: run the OpenID Connect authorization-code flow with PKCE yourself, using
`createMinisterClient`. Reach for it when your app hand-rolls OIDC and you want full control
over the redirect and callback.

The other two surfaces are documented separately: `@ministryofmany/client/auth-js`
(`ministerProvider` + `ministerBadgesFromProfile`) if you already run Auth.js, and
`createMinisterVerifier` if a different service runs the flow and you only need to verify the
resulting `id_token` and badges on a backend.

The one thing to internalize up front: the SDK is stateless. It stores nothing between the
authorization redirect and the callback. You own that flow state, and how you persist and
consume it is what makes the flow safe.

## Prerequisites

Register your app as an OIDC client in Minister's admin UI at `/admin/oidc-clients`. You get
to choose:

- **Confidential** client - Minister issues a `client_secret`, shown once. Use this for a
  server-side app that can keep a secret.
- **Public / PKCE-only** client - no secret. PKCE alone binds the code to your app. Use this
  when there is no secure server to hold a secret.

Redirect URIs are validated on registration: absolute, fragment-free, and `https` except for
`localhost`. Minister matches the callback's `redirect_uri` exactly, so register the precise
URL you will send.

You will end up with these values, which map to the client config below:

```sh
MINISTER_ISSUER=https://ministry.id            # Minister's origin (no path)
MINISTER_CLIENT_ID=...                          # from /admin/oidc-clients
MINISTER_CLIENT_SECRET=...                       # confidential clients only; omit for public
MINISTER_REDIRECT_URI=https://yourapp.example/auth/minister/callback
```

## Install and create the client

```sh
pnpm add @ministryofmany/client
```

`jose` and `zod` come with it. ESM-only; runs on Node 20+, Deno, and edge runtimes (it uses
Web Crypto and `fetch`, not `node:crypto`).

Create one client and reuse it for the process lifetime. It caches Minister's discovery
document and JWKS after the first request, so a per-request client throws that cache away.

```ts
import { createMinisterClient } from "@ministryofmany/client";

export const minister = createMinisterClient({
  issuer: process.env.MINISTER_ISSUER!,        // Minister's origin, e.g. "https://ministry.id"
  clientId: process.env.MINISTER_CLIENT_ID!,
  clientSecret: process.env.MINISTER_CLIENT_SECRET, // omit for public/PKCE-only clients
  redirectUri: process.env.MINISTER_REDIRECT_URI!,
});
```

`issuer` must be an origin with no path, query, or fragment. The SDK derives the badge issuer
DID (`did:web:<host>`) from this host, so a stray path fails loudly at config time rather than
silently rejecting every badge later.

## The flow in three steps

```
start                          callback
  |                               |
  | generatePkce + randomToken    | consume flow state atomically (delete-on-read)
  | getAuthorizationUrl(...)       | exchangeCode(...)
  | persist { state, nonce,        |   -> { claims, badges, rejected }
  |           codeVerifier,        |
  |           expiresAt }          |
  v                               v
302 redirect user  ---> Minister consent ---> 302 back to your redirectUri
```

## Step 1 - start: PKCE, state, nonce, authorization URL

Generate a PKCE pair and two random tokens, then build the authorization URL. You pass the
scopes you want; the SDK does the OIDC discovery and assembles the query params.

```ts
import type { OidcFlowState } from "@ministryofmany/client";

export async function startLogin() {
  const { verifier, challenge } = await minister.generatePkce();
  const state = minister.randomToken();  // 128-bit URL-safe token
  const nonce = minister.randomToken();

  const url = await minister.getAuthorizationUrl({
    scopes: [
      "openid",                              // REQUIRED - the SDK does not add it for you
      "profile",
      minister.badgeScope("age-over-21"),    // -> "badge:age-over-21"
      minister.badgeScope("email-domain"),   // -> "badge:email-domain"
    ],
    state,
    nonce,
    codeChallenge: challenge,
  });

  const flow: OidcFlowState = {
    state,
    nonce,
    codeVerifier: verifier,
    expiresAt: Date.now() + 10 * 60_000, // 10 minutes
  };
  await saveFlow(state, flow); // YOUR storage - see step 2

  return url; // redirect the user here (302)
}
```

Details that matter:

- **You must include `openid` yourself.** `getAuthorizationUrl` joins your `scopes` verbatim
  into the `scope` param and never injects `openid`. Omit it and Minister does not treat the
  request as an OIDC authentication.
- **PKCE is S256, always.** `generatePkce()` returns `{ verifier, challenge }` where the
  challenge is the base64url SHA-256 of the verifier. The SDK sets
  `code_challenge_method=S256` on the URL. The `verifier` stays server-side; only the
  `challenge` goes on the wire.
- **`state` and `nonce` come from you.** `randomToken()` gives 16 bytes (128 bits) of
  URL-safe entropy by default; pass a byte count to change it. `state` is your CSRF token and
  your lookup key; `nonce` binds the eventual `id_token` to this request.
- The scopes you can request are bounded by what your client is allowed in
  `/admin/oidc-clients`. Badge scopes are `badge:<slug>` - use `minister.badgeScope(slug)` or
  the standalone `badgeScope` / `badgeScopes` helpers rather than hand-writing the prefix.

`getAuthorizationUrl` also takes an optional `extraParams` for authorize-request params the
SDK does not model, such as a Discreetly-style `minister_policy`. Keys that collide with a
standard param (`response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`,
`code_challenge`, `code_challenge_method`) are ignored, so `extraParams` can never clobber
them:

```ts
const url = await minister.getAuthorizationUrl({
  scopes: ["openid", minister.badgeScope("age-over-21")],
  state,
  nonce,
  codeChallenge: challenge,
  extraParams: { minister_policy: policyB64Url },
});
```

## Step 2 - own the flow state

The SDK stores nothing. Between the redirect and the callback you persist exactly one record,
keyed by `state`:

```ts
interface OidcFlowState {
  state: string;        // CSRF token, echoed back as the `state` query param; use as the key
  nonce: string;        // must equal the verified id_token's `nonce`
  codeVerifier: string; // PKCE verifier, replayed at token exchange
  expiresAt: number;    // epoch ms; the SDK does not enforce this - you do
}
```

Where you put it is your call. Any of these work, as long as the read in step 3 is atomic:

- **Signed, http-only cookie** - self-contained, no server store. Sign or encrypt it so the
  client cannot forge `state`/`nonce`, and clear the cookie on read so it is single-use.
- **Redis / KV** - store under `flow:<state>`, consume with a `GETDEL` so fetch-and-delete is
  one atomic op. Set the key TTL to your `expiresAt` window as a backstop.
- **DB row** - `DELETE ... WHERE state = $1 RETURNING *` reads and deletes in one statement.

The invariant, whichever you pick: a given `state`/`nonce`/`codeVerifier` can be redeemed at
most once.

## Step 3 - callback: consume the state atomically, then exchange

On the callback, read the `state` record and delete it in the same operation
(delete-on-read). Reject if it is missing or expired. This single-use consume is what defends
the flow against CSRF and replay; a returned `state` that is not in your store, or is already
consumed, or has expired, never proceeds to a token exchange.

```ts
export async function handleCallback(req: Request) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) throw new Error("missing code/state");

  // Atomic consume: fetch AND delete by `state` in one step.
  const flow = await takeFlow(state);
  if (!flow || flow.expiresAt < Date.now()) {
    throw new Error("unknown or expired login flow"); // -> 400
  }

  const { claims, badges, rejected } = await minister.exchangeCode({
    code,
    codeVerifier: flow.codeVerifier,
    expectedNonce: flow.nonce,
  });

  // claims.sub is a pairwise pseudonymous id - stable for THIS user at YOUR
  // client, different from what every other RP sees.
  // badges are already signature-verified and holder-bound to this login.
  const isAdult = badges.some((b) => b.type === "age-over-21");

  await upsertUser({
    ministerSub: claims.sub,
    name: claims.name,
    avatar: claims.picture,
    isAdult,
  });

  // ... set your own session, then redirect into the app ...
}
```

`exchangeCode` does the whole back half of the flow in one call: it POSTs
`grant_type=authorization_code` (with `code`, `redirect_uri`, `client_id`, your
`code_verifier`, and `client_secret` if the client has one) to the discovered token endpoint,
then verifies the returned `id_token` and every disclosed badge before handing anything back.

## What `exchangeCode` verifies

**The `id_token` (hard failure).** EdDSA signature against Minister's JWKS from the discovery
`jwks_uri`, plus:

- `iss` equals your configured issuer,
- `aud` equals your `clientId` (enforced fail-closed - a token minted for another RP is
  rejected),
- `nonce` equals the `expectedNonce` you passed,
- `exp` and `iat` are present and `exp` is not in the past (30s clock tolerance),
- `sub` is a non-empty string.

Any of these failing throws `MinisterTokenError`. The token is the trust root, so this is
fatal - map it to `401`.

**Each disclosed badge (soft failure).** EdDSA signature against Minister's badge public keys
(`${issuer}/.well-known/jwks.json`), issuer `did:web:<minister-host>`, JWT `typ`, an
unexpired `exp`, a well-formed VC envelope, claims that pass the badge's schema, and - the
part unique to a disclosure - holder binding: the badge's pairwise subject must equal
`did:web:<host>:u:<id_token sub>`. Minister re-mints each disclosed badge under the same
pairwise pseudonym it stamps as the `id_token` `sub`, so a borrowed or mismatched credential
presented alongside your login does not bind and is dropped.

A badge that fails any of these is not fatal. It is left out of `badges` and reported in
`rejected` with its reason, and login proceeds.

## Reading the result

`exchangeCode` returns `{ claims, badges, rejected }`.

```ts
interface MinisterClaims {
  sub: string;      // pairwise pseudonymous subject, stable per (issuer, clientId)
  name?: string;
  picture?: string;
  raw: string;      // the original id_token JWT, for forwarding/storage
}

interface VerifiedBadge {
  type: string;                    // the badge slug, e.g. "age-over-21"
  claims: Record<string, unknown>; // schema-validated credentialSubject claims
  subject: string;                 // pairwise subject DID, bound to this login
  issuanceMonth?: string;          // coarse "YYYY-MM" issuance bucket, if present
  raw: string;                     // the original VC JWT
}

interface RejectedBadge {
  raw: string;
  error: VcVerificationError;      // reason the badge was dropped
}
```

- **`claims.sub` is your stable, pseudonymous user id.** It is the same value every time this
  user logs in at your client, and different from the `sub` any other RP sees for the same
  person. Key your user records on it. It is not an email and carries no raw internal id.
- **`badges` are already signature-verified and holder-bound.** You do not re-verify them.
  Read `badge.type` and `badge.claims` and make your access decision. Do not derive badge age
  from the VC's `iat`/`exp` - those are disclosure-time values, re-minted per disclosure; use
  the coarse `issuanceMonth` if you need a freshness signal (`@ministryofmany/policy`'s
  `maxAgeDays` consumes it correctly).
- **`rejected` is informational.** Log or alert on it if a badge you expected did not survive
  verification (a common cause is a misconfigured partner), but it does not block login.

## Errors

| Error | When | What to do |
| --- | --- | --- |
| `MinisterTokenError` | Token exchange failed, or the `id_token` failed signature/`iss`/`aud`/`nonce`/`exp`. | Map to `401`. |
| `OidcError` | Non-token OIDC failure: bad client config, discovery failure, malformed token response. | `500`/`502`; it is a server-side or config problem. |
| `VcVerificationError` | A single badge failed verification. | Not thrown from `exchangeCode` - it arrives inside `rejected[].error`. |

```ts
import { MinisterTokenError } from "@ministryofmany/client";

try {
  const result = await minister.exchangeCode({ code, codeVerifier, expectedNonce });
} catch (err) {
  if (err instanceof MinisterTokenError) {
    return new Response("unauthorized", { status: 401 });
  }
  throw err;
}
```

## Testing without the network

`exchangeCode` accepts injectable key sources so tests never hit Minister: pass `idTokenKey`
(for the `id_token`) and `badgeKey` (for the badge VCs). Each takes a `KeyLike`, a raw `JWK`,
a `Uint8Array`, or a `jose` key-resolver function. The default is a remote JWKS fetched from
Minister.

```ts
const result = await minister.exchangeCode({
  code,
  codeVerifier,
  expectedNonce,
  idTokenKey: testPublicJwk, // no network in tests
  badgeKey: testPublicJwk,
});
```

## Pitfall: every badge lands in `rejected`

The expected badge issuer is derived as `did:web:<host-of-your-configured-issuer>`. Minister
signs badge VCs with `did:web:<MINISTER_ISSUER_DOMAIN>`. If the Minister deployment's
`MINISTER_ISSUER_DOMAIN` host does not equal your OIDC issuer host, every badge fails the
issuer check and lands in `rejected` - while `id_token` verification and login keep working,
because they use a different JWKS. If you see login succeed but no badge count, check that
Minister's `MINISTER_ISSUER_DOMAIN` host matches its OIDC issuer host (for a non-default port,
did:web percent-encodes the colon as `host%3Aport`).

## Badge vocabulary reference

Scopes are `badge:<slug>`. The slugs the SDK knows, with the claim shape each carries:

| Slug | Claims |
| --- | --- |
| `email-domain` | `{ domain }` |
| `email-exact` | `{ email }` |
| `oauth-account` | `{ provider, accountId, handle? }` (provider: `github`, `google`, `discord`) |
| `residency-country` | `{ country }` (ISO 3166-1 alpha-2) |
| `residency-state` | `{ country, state }` |
| `residency-city` | `{ country, state, city }` |
| `invite-code` | `{ label }` (the campaign label, never the code itself) |
| `tlsn-attestation` | `{ domain, claim }` |
| `age-over-<N>` | `{ threshold: N }` for N in 16, 18, 21, 25, 30, 35, 40, 45, 55, 65 |

Validate a badge's claims against its schema with `getBadgeClaimSchema(slug)`; list every
known slug with `knownBadgeTypes()`. This vocabulary is a copy of Minister's authoritative
registry in `@ministryofmany/shared` and can drift (a drift-check is planned), so treat
Minister's `packages/shared` as the source of truth if the two ever disagree.
