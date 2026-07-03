---
title: Verifying Tokens and Badges on a Backend
description: Verify a Minister id_token and its badges on a backend without running the OIDC flow, using createMinisterVerifier.
order: 4
---

## When to use the verifier

If your app already has a Minister `id_token` in hand, and you just need to check it, use the verifier. It does no redirect handling and holds no flow state. Typical cases:

- An OIDC library (or another service) ran the authorization-code flow, and your backend now receives the `id_token` as a Bearer token.
- You want to re-check the token on every request instead of trusting a server session.
- You received a single badge VC out of band (a Minister share link) and want to certify it.

For running the flow yourself (PKCE, state, nonce, code exchange), use `createMinisterClient` instead. That is a different page.

The package is `@ministryofmany/client`. It is ESM-only, runs on Node 20+, Deno, and edge runtimes, and depends on `jose` and `zod`.

## Create the verifier

Configure once, reuse everywhere. Build one verifier per (issuer, clientId) and share it.

```ts
import { createMinisterVerifier } from "@ministryofmany/client";

const minister = createMinisterVerifier({
  issuer: "https://ministry.id", // Minister's origin (the OIDC issuer)
  clientId: process.env.MINISTER_CLIENT_ID!, // your registered client id
});
```

- `issuer` is Minister's bare origin: scheme plus host, optional port, no path, no query, no fragment. A trailing slash is tolerated. A path-bearing issuer throws at verify time (badge issuer DID derivation is host-only and total).
- `clientId` is **required**. It is the expected `id_token` `aud`, enforced fail-closed. A verifier built without it would silently accept a token minted for another relying party (cross-RP impersonation), so the SDK guards this at runtime, not just in the type.
- `jwks` is optional. Omit it in production and each verifier fetches Minister's keys on demand. Inject it in tests to stay offline (see "Offline tests" below).

The returned object has three methods:

```ts
interface MinisterVerifier {
  verifyIdToken(idToken: string, opts?: { nonce?: string }): Promise<MinisterClaims>;
  verifyBadges(tokenOrPayload: string | JWTPayload): Promise<BadgesResult>;
  verifyBadge(vcJwt: string): Promise<VerifiedBadge>;
}
```

## Verify an id_token

```ts
import { MinisterTokenError } from "@ministryofmany/client";

try {
  const claims = await minister.verifyIdToken(idToken);
  // claims: { sub, name?, picture?, raw }
  // claims.sub is a pairwise pseudonymous id: stable for this user at YOUR
  // client, and different from what other RPs see. Never an email.
} catch (err) {
  if (err instanceof MinisterTokenError) {
    // signature, issuer, audience, expiry, or nonce failure -> map to 401
  }
  throw err;
}
```

`verifyIdToken` checks all of:

- **EdDSA signature** against Minister's JWKS at `<issuer>/.well-known/jwks.json`. `EdDSA` is the only accepted algorithm.
- `iss` equals the configured issuer.
- `aud` equals your `clientId`.
- `exp` and `iat` are present, with a 30-second clock tolerance, and `exp` is not in the past.
- `nonce` equals `opts.nonce` **only when you pass one**. On a stateless backend re-verifying a Bearer token you did not run the flow, so you usually omit `nonce` (you never held it). Pass it only if you carried the nonce through yourself.
- `sub` is a non-empty string.

On any failure it throws `MinisterTokenError`. On success it returns `MinisterClaims`:

```ts
interface MinisterClaims {
  sub: string;        // pairwise pseudonymous subject, stable per (issuer, clientId)
  name?: string;
  picture?: string;
  raw: string;        // the original id_token JWT, for forwarding or storage
}
```

### Re-verify per request (the Discreetly pattern)

Discreetly's tRPC API does not trust a server session for gated calls. It pulls the id_token from the `Authorization: Bearer` header and re-verifies it on every gated call, so the token itself is the trust root each time. It wraps the same verification functions in a small internal helper; the shape you would write directly is:

```ts
function bearer(header?: string): string | undefined {
  if (!header?.startsWith("Bearer ")) return undefined;
  return header.slice("Bearer ".length);
}

// per request
const idToken = bearer(req.headers.authorization);
if (!idToken) throw new Error("unauthorized");
const { sub } = await minister.verifyIdToken(idToken); // throws on a bad token
```

## Verify badges

`verifyBadges` reads the `minister_badges` claim (an array of VC JWT strings) and verifies each one, binding it to the login.

It accepts two input shapes:

```ts
// 1. A raw id_token STRING: the wrapper is verified first (aud enforced
//    fail-closed against your clientId), then its badges are read.
const { badges, rejected } = await minister.verifyBadges(idToken);

// 2. An already-verified PAYLOAD object (e.g. from Auth.js, or a prior
//    verifyIdToken): the wrapper is TRUSTED, and only the badge VCs are verified.
const { badges, rejected } = await minister.verifyBadges(verifiedPayload);
```

The result never throws on an individual bad badge. Good badges land in `badges`, failures land in `rejected` with a reason:

```ts
interface BadgesResult {
  badges: VerifiedBadge[];    // signature-verified, schema-validated, holder-bound
  rejected: RejectedBadge[];  // { raw: string, error: VcVerificationError }
}

interface VerifiedBadge {
  type: string;                       // Minister badge slug, e.g. "age-over-21"
  claims: Record<string, unknown>;    // credentialSubject claims, schema-validated
  subject: string;                    // did:web:<host>:u:<sub> (per-RP pairwise DID)
  issuanceMonth?: string;             // coarse "YYYY-MM" issuance bucket, when present
  raw: string;                        // the original VC JWT
}
```

Example:

```ts
const { badges, rejected } = await minister.verifyBadges(idToken);

const isAdult = badges.some((b) => b.type === "age-over-21");

if (rejected.length > 0) {
  // A disclosed badge failed verification (bad signature, expired, wrong
  // issuer, not bound to this login, ...). Login/verification still succeeded;
  // log or alert if a partner may be misconfigured. Do NOT reflect
  // error.message to untrusted output; it may carry VC-derived text.
}
```

### Holder binding

Each badge's `subject` must equal `did:web:<host>:u:<id_token sub>`. Minister re-mints every disclosed badge under the same pairwise pseudonym it stamps as the id_token `sub`, so a badge whose subject does not bind to **this** login (a borrowed or mismatched credential) is pushed to `rejected` rather than counted. If the wrapper has no usable `sub`, every badge is rejected (fail closed).

Passing the payload path (shape 2) trusts the wrapper's `aud`, so only hand it a payload you already verified.

## What each badge check enforces

For every VC in `minister_badges`, `verifyBadges` (via `verifyMinisterBadge`) requires:

- **EdDSA signature** against the issuer's DID assertion key. This is **not** the raw JWKS. Minister's JWKS at `/.well-known/jwks.json` serves both the badge signing key (`#key-2`) and the in-process token key (`#key-3`). The SDK resolves badge keys from `<issuer>/.well-known/did.json`, whose `assertionMethod` lists only `#key-2`, and rejects any `kid` not listed there. That stops a stolen or misused token key from ever attesting a badge.
- `iss` equals `did:web:<minister-host>`, derived from your configured issuer host (a port is percent-encoded, e.g. `did:web:localhost%3A3000`).
- JWT `typ` equals `vc+jwt`.
- `exp` is present and not in the past.
- A well-formed `vc` envelope: a `vc` object, a `type` string array, and a `credentialSubject` object.
- `credentialSubject.id` equals the VC's own JWT `sub` (the VC-internal holder-binding invariant).
- The VC `type` maps to a known Minister badge slug, and the claims validate against that slug's Zod schema. `id` and `issuanceMonth` are reserved keys, stripped before schema validation.

A badge failing any of these lands in `rejected`, never throws.

> Note on time: badge `iat`/`exp` are disclosure-shaped, not issuance-shaped. Minister re-mints at disclosure time, so `iat` is the disclosure instant and `exp` is a short presentation TTL. Never derive badge age from `iat`/`exp`. The only issuance signal is the coarse `issuanceMonth` ("YYYY-MM"); feed it to `@ministryofmany/policy`'s `maxAgeDays` for freshness checks.

## Verify a single VC out of band

`verifyBadge` certifies a single VC JWT received outside the flow (a Minister share link, a forwarded credential). It runs the same structural and signature checks as above, plus the VC-internal `credentialSubject.id === sub` invariant.

```ts
import { VcVerificationError } from "@ministryofmany/client";

try {
  const badge = await minister.verifyBadge(vcJwt);
  // badge.type    -> slug, e.g. "email-domain"
  // badge.claims  -> schema-validated, e.g. { domain: "example.com" }
  // badge.subject -> the holder's Minister DID (== credentialSubject.id)
} catch (err) {
  if (err instanceof VcVerificationError) {
    // invalid signature, wrong issuer, bad envelope, or subject mismatch
  }
  throw err;
}
```

**`verifyBadge` does NOT bind the VC to any login.** There is no id_token here, so nothing ties the VC to the user in front of you. A valid Minister badge belonging to some other user verifies successfully. Treating a standalone `verifyBadge` success as "the current user holds this badge" is an authorization bug. Use `verifyBadges` (the wrapper) for any access decision; use `verifyBadge` only to certify issuance of an out-of-band VC.

## Standalone functions

The three methods are thin wrappers over standalone functions that are also exported. Use them if you do not want to hold a verifier object; they take the same config inline per call.

```ts
import {
  verifyMinisterIdToken,
  verifyMinisterBadges,
  verifyMinisterBadge,
} from "@ministryofmany/client";

const claims = await verifyMinisterIdToken(idToken, {
  issuer: "https://ministry.id",
  clientId: "your-client-id",
  nonce,      // optional
  key,        // optional injected key; defaults to remote JWKS
});

const { badges, rejected } = await verifyMinisterBadges(idToken, {
  issuer: "https://ministry.id",
  clientId: "your-client-id", // required when passing a raw id_token string
  key,
});

const badge = await verifyMinisterBadge(vcJwt, {
  issuer: "https://ministry.id",
  key,        // defaults to the issuer DID assertionMethod key set
});
```

Note the option name differs: the verifier config field is `jwks`, the standalone options field is `key`. Both take the same `KeyInput` type. `createMinisterVerifier` just threads its `jwks` into `key` for all three.

## Offline tests: inject a key

By default the id_token verifier fetches the remote JWKS, and the badge verifier fetches the DID document. Each caches per issuer for the process lifetime, so expect at most one fetch per verifier per issuer. Note the id_token and badge caches are independent; they do not share a JWKSet.

For tests, inject the public key so verification never touches the network. `jwks` (config) / `key` (standalone) accepts a `KeyInput`:

```ts
type KeyInput = KeyLike | JWK | Uint8Array | JWTVerifyGetKey;
```

A bare public `JWK` is accepted; the SDK imports it internally, pinned to EdDSA. When you inject a key, all three operations use that exact key (both the id_token and the badges), so a test signs its fixtures with one keypair and verifies against its public half:

```ts
import { createMinisterVerifier } from "@ministryofmany/client";

const minister = createMinisterVerifier({
  issuer: "https://ministry.id",
  clientId: "test-client",
  jwks: publicJwk, // a public JWK, KeyLike, Uint8Array, or a jose resolver
});

const claims = await minister.verifyIdToken(signedIdToken);
```

## Config and the issuer-host coupling

A backend verifier needs two settings. Discreetly names them `MINISTER_ISSUER` and `MINISTER_CLIENT_ID`:

```
MINISTER_ISSUER="https://ministry.id"
MINISTER_CLIENT_ID="your-client-id"
```

**Watch the issuer-host coupling.** The SDK derives the expected badge VC issuer DID (`did:web:<host>`) from the OIDC issuer host, with no override. Minister signs badge VCs with `did:web:<MINISTER_ISSUER_DOMAIN>`. If the Minister deployment's `MINISTER_ISSUER_DOMAIN` host does not equal your configured issuer host, **every badge fails verification** and lands in `rejected` with an issuer mismatch. The id_token still verifies, so login works but no badge ever counts. If you see all badges rejected, check that Minister's `MINISTER_ISSUER_DOMAIN` host matches its OIDC issuer host.

To catch this at boot instead of at runtime, re-run the SDK's derivation against a stated expected DID (Discreetly does exactly this with an optional `MINISTER_VC_ISSUER`):

```ts
import { didFromIssuer } from "@ministryofmany/client";

const derived = didFromIssuer(process.env.MINISTER_ISSUER!); // e.g. "did:web:ministry.id"
if (process.env.MINISTER_VC_ISSUER && process.env.MINISTER_VC_ISSUER !== derived) {
  throw new Error(
    `Minister VC-issuer mismatch: SDK derives "${derived}" but expected ` +
      `"${process.env.MINISTER_VC_ISSUER}". Every badge would be rejected at runtime.`,
  );
}
```

## Badge vocabulary reference

`badge.type` is a Minister slug and `badge.claims` is validated against that slug's schema. The vocabulary is also exported standalone at `@ministryofmany/client/badges`. Current slugs and claim shapes:

| Slug | Claims |
| --- | --- |
| `email-domain` | `{ domain: string }` |
| `email-exact` | `{ email: string }` |
| `oauth-account` | `{ provider: "github" \| "google" \| "discord", accountId: string, handle?: string }` |
| `residency-country` | `{ country: string }` (ISO 3166-1 alpha-2) |
| `residency-state` | `{ country: string, state: string }` |
| `residency-city` | `{ country: string, state: string, city: string }` |
| `invite-code` | `{ label: string }` |
| `tlsn-attestation` | `{ domain: string, claim: string }` (strict, no extra keys) |
| `age-over-<N>` | `{ threshold: N }` for N in 16, 18, 21, 25, 30, 35, 40, 45, 55, 65 |

To validate or narrow claims yourself:

```ts
import { getBadgeClaimSchema, knownBadgeTypes } from "@ministryofmany/client";

const schema = getBadgeClaimSchema("email-domain");
const parsed = schema?.safeParse(badge.claims); // { success, data } | { success, error }
```

This vocabulary is a deliberate copy of Minister's authoritative registry (`@ministryofmany/shared`), kept in sync by hand. A drift-check between the two is planned but not yet shipped.

## Errors at a glance

- `MinisterTokenError` — an id_token failed verification (signature, issuer, audience, expiry, or nonce). Hard failure; thrown by `verifyIdToken`, and by `verifyBadges` when the wrapper string cannot be verified. Map to a 401.
- `VcVerificationError` — a single badge VC failed verification. `verifyBadge` throws it; `verifyBadges` never throws per badge, it collects these in `rejected`.

Both error messages may include token- or VC-derived text. Do not reflect them to untrusted output.
