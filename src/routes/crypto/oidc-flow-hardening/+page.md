---
title: OIDC Flow Hardening and Disclosure
description: The wire-level crypto of the authorization-code + PKCE flow - token construction, TTLs, single-use codes - and the fail-closed minimization that bounds badge disclosure at consent.
order: 9
---

## What this page is

[The Auth-Code + PKCE Flow](/build/auth-code-pkce-flow) shows you how to run
the flow as an RP. [Selective Disclosure and Anonymity](/understand/selective-disclosure-and-anonymity)
explains the disclosure model - scopes, `minister_policy`, anonymity-aware
selection - in full. This page does neither again. It's the auditor's view of
the same flow: what standard each token follows, what's checked before a code
or token is trusted, and where the actual security boundary sits for
disclosure minimization.

## PKCE: binding the code to the client that requested it

Minister requires PKCE S256 on every authorize request - no `plain`, no
skipping it. The construction (RFC 7636):

```text
code_challenge = base64url(SHA-256(code_verifier))
```

The RP sends `code_challenge` at `/oidc/authorize`; Minister stores it against
the issued authorization code. At `/oidc/token` the RP presents the raw
`code_verifier`, and Minister recomputes the digest and compares:

```ts
// apps/minister/src/lib/oidc-tokens.ts:54-63 (verifyPkceS256)
export function verifyPkceS256(codeVerifier: string, storedChallenge: string): boolean {
  const computed = createHash("sha256").update(codeVerifier).digest();
  const stored = Buffer.from(storedChallenge, "base64url");
  if (stored.length !== computed.length) return false;
  return timingSafeEqual(computed, stored);
}
```

Two details worth calling out because they're the kind of thing a naive
PKCE check gets wrong:

- `Buffer.from(_, "base64url")` never throws on malformed input - it silently
  drops any byte that doesn't fit the alphabet. A malformed stored challenge
  therefore decodes to some length, and the explicit length guard is what
  actually rejects it before the comparison runs.
- The comparison is `timingSafeEqual`, not `===`, after the length guard.
  `code_challenge` was visible to anyone who could see the `/authorize`
  redirect; `code_verifier` is the part that's supposed to stay secret to the
  RP. Constant-time comparison is defense in depth here, not the primary
  control - PKCE's real job is binding the code to whoever holds the
  verifier, and the RP's redirect URI is what's actually pinned server-side
  (see below).

## Tokens: two different signed artifacts, two different lifetimes

Both tokens are EdDSA (Ed25519) compact JWS, signed with `#key-3`, the
in-process token key - never KMS. See
[Signatures, Keys, and the DID](/crypto/signatures-and-signing-keys) for why
token signing can't use the KMS-backed badge key: an `id_token` carrying a
few disclosed badge VCs can exceed KMS's 4096-byte RAW-sign cap.

| Token | Standard | TTL | Carries | Signing key |
|---|---|---|---|---|
| `id_token` | OIDC Core, JWT | 600 s (10 min) | `sub` (pairwise), `aud`, `nonce`, optional `name`/`picture`, optional `minister_badges[]` | `#key-3`, EdDSA |
| access token | RFC 9068 (`typ:"at+jwt"`) | 3600 s (1 h) | `scope`, `client_id`, `token_use:"access"`, `jti` | `#key-3`, EdDSA |

```ts
// apps/minister/src/lib/oidc-tokens.ts:116-130 (mintAccessToken)
export async function mintAccessToken(issuer: Issuer, claims: AccessTokenClaims): Promise<string> {
  return new SignJWT({
    scope: claims.scopes.join(" "),
    client_id: claims.clientId,
    token_use: "access",
  })
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.token.kid, typ: "at+jwt" })
    .setIssuer(oidcIssuerUrl())
    .setSubject(claims.sub)
    .setAudience(oidcIssuerUrl())
    .setJti(claims.jti)
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TOKEN_TTL_SECONDS}s`)
    .sign(issuer.token.privateKey);
}
```

The access token deliberately carries no raw `userId`. `jti` is random and
keys an `OidcAccessToken` row; `/oidc/userinfo` resolves the calling
principal by looking up that row by `jti`, never by decoding an id out of
the JWT. Two RPs decoding their own access tokens see different `sub`
values and no shared identifier to join on - see
[Pairwise Subjects](/crypto/pairwise-subjects) for the full unlinkability
story.

There's no refresh token in this design. Sessions inside Minister itself are
a sliding HS256 JWT cookie (see
[Recovery, Assurance, and Account Merge](/crypto/recovery-and-merge)); an RP
that needs a new access token re-initiates the OIDC flow.

## Authorization codes, `state`, `nonce`, and the redirect URI

- **Authorization codes are single-use with a 60-second TTL**
  (`CODE_TTL_SECONDS = 60`, `server/oidc-actions.ts:38`). A code that's
  already been redeemed, or has aged out, fails token exchange.
- **`state` and `nonce` are both required**, not optional extras. `state` is
  the RP's CSRF token and flow-state lookup key; `nonce` gets echoed into the
  `id_token` and must match what the RP generated at the start of the flow.
  See [The Auth-Code + PKCE Flow](/build/auth-code-pkce-flow) for how an RP
  is expected to own and consume this state atomically.
- **Redirect URI is an exact string match**, not a prefix or path-relaxed
  match, against the client's registered `redirectUris`
  (`isRegisteredRedirectUri`, `oidc-clients.ts`).
- **No implicit flow, no resource-owner-password-credentials flow.**
  Authorization code + PKCE is the only grant Minister issues tokens for.

## Client credentials

```ts
// apps/minister/src/lib/oidc-clients.ts:31-37
export function generateClientId(): string {
  return `mc_${randomBytes(18).toString("base64url")}`;
}

export function generateClientSecret(): string {
  return randomBytes(32).toString("base64url");
}
```

`client_id` is `mc_` plus 18 random bytes, base64url-encoded - the `mc_`
prefix and charset (`^mc_[A-Za-z0-9_-]+$`) matter beyond naming: they're also
the guard that keeps the pairwise-`sub` input encoding collision-free (see
[Pairwise Subjects](/crypto/pairwise-subjects)). `client_secret` is 32 random
bytes, base64url. The secret is never stored in plaintext - it's hashed at
rest with Argon2id, the same OWASP-baseline parameters used for recovery
codes (memoryCost 19 MiB, timeCost 2, parallelism 1; see
[Hashing, HMAC, and Key Derivation](/crypto/hashing-hmac-and-kdfs)):

```ts
// apps/minister/src/lib/oidc-clients.ts:10-18
const ARGON_PARAMS = { memoryCost: 19 * 1024, timeCost: 2, parallelism: 1 } as const;

export async function hashClientSecret(plaintext: string): Promise<string> {
  return argonHash(plaintext, ARGON_PARAMS);
}
```

> Rate limiting on the OIDC endpoints is process-local, in-memory
> (`rate-limit.ts`) and keys on a client-IP header. It depends on the
> Cloudflare Tunnel in front of Minister actually stripping and
> re-setting that header - a deployment that lets a client set it directly
> would defeat the limiter. See
> [Threat Model and Known Gaps](/crypto/threat-model).

## Fail-closed minimization: the crypto-relevant caps

The disclosure model itself - scopes, the `minister_policy` grammar,
anonymity-aware selection, coarse holder-count buckets - is covered end to
end in [Selective Disclosure and Anonymity](/understand/selective-disclosure-and-anonymity).
What belongs here is the set of hard limits that make policy validation
fail-closed rather than best-effort, and where the actual security boundary
sits.

`minister_policy` arrives as `base64url(JSON)` on the authorize request. Before
Minister trusts any of it, `parseMinisterPolicy` (`oidc-authorize.ts`) runs it
through, in order:

1. base64url decode, then a **4096-byte cap** on the decoded JSON
   (`MAX_POLICY_BYTES`) before it's parsed.
2. `JSON.parse` - malformed input is rejected as `invalid_request`, not
   coerced.
3. a strict Zod schema - unknown keys rejected, not ignored (schema failures
   report `invalid_scope`).
4. breadth bounds: `MAX_ATLEAST_N = 16`, `MAX_NODE_CHILDREN = 16`,
   `MAX_POLICY_NODES = 64` across the whole tree (defined in
   `oidc-policy.ts`, enforced by `policyBoundsViolation`).
5. a depth cap, `MAX_POLICY_DEPTH = 8`.
6. **every badge type named in the policy must be a subset of the requested
   `badge:<type>` scopes** - which are themselves already a subset of the
   client's registered `allowedScopes`. A policy can only structure the menu
   the RP was already permitted to ask about; it can never widen it.

The breadth and depth caps exist together because byte size alone doesn't
bound the work a policy can demand: a small, shallow `atLeast{n, of: [...]}`
node with many leaves still drives combinatorial selection over its
branches. Capping node count and children per node closes that gap
independently of the byte cap.

Any failure at any step rejects the authorize request outright. There's no
degraded fallback path that trusts a partially-valid policy.

## The authoritative bound is server-side, at consent submit

The policy validation above bounds what an RP can *ask for*. It doesn't, by
itself, bound what a user's browser can *submit*. That's `minimizeToPolicy`'s
job, and it's the actual security boundary for over-disclosure:

```text
// server/oidc-consent-minimize.ts:70-80, called from approveConsent
submitted badge ids
  AND owned by the signed-in user       (ownership drop)
  AND requested via badge:<type> scope  (type filter)
  -> minimizeToPolicy -> the ONE minimal satisfying set
```

`approveConsent` (`server/oidc-actions.ts`) never trusts the consent form's
POST body as the final disclosure set. It re-derives the minimal satisfying
set server-side from the badges the user actually owns and actually
requested, and keeps only the ids inside that single minimal set. A tampered
POST that ticks two satisfying `anyOf` branches, or extra badges past an
`atLeast n`, gets trimmed back down. Minimization only ever removes ids from
what was submitted - it never adds or fabricates one. If the submission
doesn't satisfy the policy at all, the resulting set is empty; the RP's own
gate is the admission authority and denies from there.

> This is the load-bearing guarantee, not the consent screen's
> pre-selection or override UI. A client-side bug or a hand-crafted request
> to the consent-submit endpoint cannot over-disclose past this check.

One coarsening detail worth carrying over because it's a crypto-adjacent
correctness property, not just UX: a disclosed badge's issuance timestamp is
coarsened to the UTC month start (`issuanceMonthStartSeconds`, consumed as
`toPolicyUserBadge`) before it factors into selection and before it lands in
the re-minted VC. This keeps the provider-side minimization decision and an
RP's own `maxAgeDays` check evaluating the same coarse value, and stops a
fine-grained `iat` from becoming a correlator (see
[Verifiable Credentials and Holder Binding](/crypto/verifiable-credentials)).

The policy grammar and evaluator are a deliberate copy of Discreetly's
`policy` package, kept honest by a drift test
(`oidc-policy.drift.test.ts`) so the provider's and the RP's evaluators never
silently diverge.

> The badge-VC issuer DID is derived from the OIDC issuer host with no
> override. If an RP's `MINISTER_ISSUER` host doesn't exactly equal
> Minister's `MINISTER_ISSUER_DOMAIN`, `id_token` verification still
> succeeds but every disclosed badge lands in `rejected`. See
> [Trust and Security Model](/understand/trust-and-security-model) and
> [Threat Model and Known Gaps](/crypto/threat-model) - this page won't
> re-derive it.

## Where to look in the source

- PKCE verify, token minting, TTL constants:
  `apps/minister/src/lib/oidc-tokens.ts` (`verifyPkceS256`, `mintIdToken`,
  `mintAccessToken`).
- Authorize-request validation and `minister_policy` parsing:
  `apps/minister/src/lib/oidc-authorize.ts` (`parseMinisterPolicy`).
- Redirect URI matching, client id/secret generation, secret hashing:
  `apps/minister/src/lib/oidc-clients.ts`.
- Consent submit and the authoritative minimization guard:
  `apps/minister/src/server/oidc-actions.ts` (`approveConsent`),
  `apps/minister/src/server/oidc-consent-minimize.ts` (`minimizeToPolicy`).
- Claim resolution for both the `id_token` and `/oidc/userinfo` paths:
  `apps/minister/src/lib/oidc-claims.ts`.
- Policy grammar and selection: `apps/minister/src/lib/oidc-policy.ts`.
- Drift check against Discreetly's policy package:
  `oidc-policy.drift.test.ts`.
- Process-local rate limiting: `apps/minister/src/lib/rate-limit.ts`.
