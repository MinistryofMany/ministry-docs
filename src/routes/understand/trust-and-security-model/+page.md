---
title: Trust and Security Model
description: The trust anchors behind a Minister login - what a relying party must verify, why pairwise subjects hold, and the assertionMethod pinning that stops token-key badge forgery.
order: 7
---

## What you are trusting

A relying party (RP) that accepts a Minister login trusts exactly two signing
keys, both anchored in Minister's did:web identity (`did:web:ministry.id`):

- the **token key** (`#key-3`), which signs the `id_token`, resolved from the
  JWKS at `<issuer>/.well-known/jwks.json`;
- the **badge key** (`#key-2`), which signs badge VCs, resolved from the
  `assertionMethod` list in the DID document at
  `<issuer>/.well-known/did.json`.

Everything else - the pairwise pseudonym, the disclosed badges, the holder
binding - reduces to signatures under those two keys plus a set of structural
checks the RP performs itself. There is no shared secret between Minister and the
RP beyond the OIDC client credentials, and no callback to Minister at verify
time once the keys are cached. See
[Signing Keys and the DID](/understand/signing-keys-and-did) for the key model.

## What an RP must verify

Accepting a login means verifying two things: the token wrapper, then each badge
inside it. The [`@ministryofmany/client`](/build/verifying-tokens-and-badges) SDK
does all of this; the checks are listed here so you know what the trust rests on.

**The `id_token` (hard failure - reject the login on any miss):**

- EdDSA signature against Minister's JWKS (`EdDSA` is the only accepted
  algorithm).
- `iss` equals your configured issuer.
- `aud` equals your `clientId`, enforced fail-closed. A token minted for another
  RP must be rejected; a verifier built without a `clientId` would silently
  accept cross-RP tokens, so the SDK requires it at runtime.
- `exp` and `iat` present, `exp` not past (30s clock tolerance).
- `nonce` equals the value you sent, when you ran the flow and held one.
- `sub` is a non-empty string.

**Each disclosed badge (soft failure - drop the badge, keep the login):**

- EdDSA signature against the badge key resolved from the DID document's
  `assertionMethod` (see the pinning section below).
- `iss` equals `did:web:<minister-host>`.
- JWT `typ` is `vc+jwt`, `exp` not past, the `vc` envelope is well formed, and
  `credentialSubject.id === sub`.
- The `vc.type` maps to a known badge slug and the claims pass that slug's Zod
  schema.
- **Holder binding**: the badge's subject equals `did:web:<host>:u:<id_token sub>`.

A badge that fails any check lands in a `rejected` list with a reason; login
still succeeds. The RP makes its access decision on the badges that survived, and
re-evaluates them against its own gate - Minister's minimization is a privacy
aid, not the RP's authority.

## Pairwise subjects: the unlinkability anchor

The `sub` in an `id_token` is a **pairwise pseudonymous** identifier:
`base64url(HMAC-SHA256(OIDC_PAIRWISE_SECRET, userId || clientId))`. Two
properties fall out:

- It is stable for a given `(user, RP)` pair, so an RP keeps a durable account
  keyed on it.
- It differs across RPs for the same user, and it is one-way (the RP never sees
  `userId` and cannot invert the HMAC without the secret), so two colluding RPs
  cannot join their tables on it.

A disclosed badge's subject is re-minted onto `did:web:<host>:u:<pairwiseSub>`,
per RP, so the badge subject is *also* not a cross-RP correlator - and its `jti`,
`iat`, and `exp` are re-stamped so none of them is either. The `sub` is never an
email, and the `profile` scope never falls back to the upstream login identity.
The full treatment is in
[Pairwise Subjects and Unlinkability](/understand/pairwise-subjects-and-unlinkability).

## The H1 property: assertionMethod pinning

Minister serves both public keys in one JWKS, but only the badge key
(`#key-2`) is listed in the DID document's `assertionMethod`. The token key
(`#key-3`) attests nothing.

The pinning rule that makes this matter: **a badge verifier resolves the badge
signing key from the DID document's `assertionMethod`, not from the raw JWKS, and
rejects any badge whose `kid` is not listed there.** So a badge signed with the
token key does not verify, even though that key's public half is reachable in the
JWKS. A leaked, stolen, or misused token key cannot forge a Minister badge.

The failure mode to avoid: a verifier that instead trusts the raw JWKS and picks
a key by `kid` **would** accept a `#key-3`-signed badge, collapsing the
separation. The reference SDK pins to `assertionMethod` correctly. If you verify
badges by hand, you must resolve keys from `assertionMethod` and reject any
unlisted `kid` - do not select badge keys straight out of JWKS.

## Provider-side guarantees you inherit

Some of the trust is enforced inside Minister, so an RP gets it for free but
should know it exists:

- **Fail-closed disclosure minimization.** The consent screen's pre-selection is
  advisory; the authoritative bound is a server-side minimization on consent
  submit that trims the disclosure to one minimal satisfying set. A tampered
  consent POST cannot over-disclose. See
  [Selective Disclosure and Anonymity](/understand/selective-disclosure-and-anonymity).
- **Scope containment.** A requested scope must be a subset of the client's
  registered `allowedScopes`, and a `minister_policy` can only reference types
  already in the requested scope. A policy can structure the menu but never widen
  it.
- **OIDC hardening.** PKCE is mandatory and `S256`-only, `state` and `nonce` are
  required, authorization codes are single-use with a 60-second TTL, redirect
  URIs match exactly, client secrets are hashed at rest (Argon2id), and there is
  no implicit or password flow.
- **Re-mint integrity.** The disclosure-time badge re-mint verifies the stored
  VC's signature before re-signing and is scoped to Minister-issued rows, so a
  forged or foreign-issuer VC cannot be laundered into a fresh Minister-signed
  credential.

## The one operational trap

The SDK derives the expected badge-VC issuer DID (`did:web:<host>`) from the OIDC
issuer host, with **no override**. Minister signs badges with
`did:web:<MINISTER_ISSUER_DOMAIN>`. If a deployment's `MINISTER_ISSUER` host does
not equal Minister's `MINISTER_ISSUER_DOMAIN` host, every badge fails the issuer
check and lands in `rejected` - while the `id_token` still verifies against a
different key, so login works but no badge ever counts. It fails closed (no badge
is wrongly accepted), but it fails silently. If you see login succeed and every
badge rejected, check that those two hosts match (a non-default port is
percent-encoded as `host%3Aport`).

For the algorithm-level treatment - every primitive with its parameters and bit
strength, an assets/adversaries/controls table, and the register of known gaps
and why each is accepted - see the
[Cryptography and security](/crypto/overview) track, and in particular
[Threat Model and Known Gaps](/crypto/threat-model).
