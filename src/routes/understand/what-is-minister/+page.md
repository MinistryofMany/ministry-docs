---
title: What Is Minister
description: A privacy-preserving OpenID Connect identity provider and verifiable-credential badge issuer, and the problem it solves.
order: 1
---

## The one-line version

Minister is an OpenID Connect (OIDC) identity provider where a user holds
verifiable-credential **badges** attesting to facts about them, and discloses
only the specific badges a given app needs. An app logs users in with Minister
the same way it would with "Sign in with Google," but what comes back is a
pairwise pseudonym plus the minimum set of signed claims the user chose to
reveal.

## The problem

A conventional social login hands the relying party (RP) a durable identifier
and a pile of profile data. Two properties fall out of that, both bad for
privacy:

- **Correlation.** The same user shows the same subject id (often an email) to
  every app. Any two apps can join their user tables on it and reconstruct one
  profile spanning both.
- **Over-disclosure.** To prove one fact ("this user is over 21," "this user
  controls an email at `example.com`"), the RP typically learns far more: the
  full name, the address, the birthdate, the raw email.

Most gating needs a fact, not an identity. A forum sub that admits adults needs
"over 21," not a birthdate. A domain-gated space needs "controls an email at
this domain," not the email. Minister is built to disclose the fact and nothing
else.

## What a badge is

A badge is a W3C Verifiable Credential (VC), serialized as a signed JWT-VC and
signed with Ed25519 (`alg: EdDSA`) by Minister's issuer key. Each badge attests
one fact, for example:

- `email-domain` - the holder controls an email at a named domain (the domain,
  never the address).
- `age-over-21` - the holder is over 21 (the threshold, never the birthdate).
- `oauth-account` - the holder controls a named GitHub, Google, or Discord
  account.
- `residency-state` - the holder resides in a named country and state.

Minister derives a badge from a proof the user completes once (a magic-link
email check, an OAuth round trip, a TLSNotary attestation), then stores the
signed VC. It never stores the underlying PII: no birthdates, no street
addresses, no raw email for a domain badge. The full vocabulary is in the
[Badge-Type Reference](/build/badge-type-reference).

## What a relying party gets

When a user signs in and consents, the RP receives an OIDC `id_token`
containing:

- a **pairwise pseudonymous** `sub`: stable for this user at this one RP, and
  different from what every other RP sees for the same person, so two RPs cannot
  join on it.
- a `minister_badges` array: the JWT-VC strings for exactly the badges the user
  disclosed, each re-minted so its subject binds to this login and this RP.

The RP verifies the token and each badge (the
[`@ministryofmany/client`](/build/getting-started) SDK does this), reads the
badge claims, and makes its access decision. It never sees an email, a real
name it was not granted, or any identifier shared with another app.

## Two ideas do the work

- **Minimal, selective disclosure.** The user reveals a chosen subset of
  badges, and Minister minimizes even that server-side against the RP's stated
  requirement. See
  [Selective Disclosure and Anonymity](/understand/selective-disclosure-and-anonymity).
- **Unlinkability.** The `sub` is a per-RP keyed hash, and a disclosed badge's
  subject is re-minted onto a per-RP DID, so nothing an RP receives is a
  cross-RP correlator. See
  [Pairwise Subjects and Unlinkability](/understand/pairwise-subjects-and-unlinkability).

## What Minister is not

- Not a wallet you install; badges live in the user's Minister account, held
  server-side and disclosed over OIDC or a user-initiated share link.
- Not a general OAuth authorization server for API access; it is an
  authentication + selective-disclosure layer. It issues `id_token`s and a
  userinfo-backed access token, not scoped API grants for arbitrary resources.
- Not (yet) a zero-knowledge selective-disclosure scheme inside a single
  credential. A badge is disclosed whole; the minimization is over *which*
  badges, not over fields within one. Per-credential ZK (BBS+, SD-JWT) is a
  later topic.

## Where to go next

- [The Ecosystem and Relying Parties](/understand/ecosystem-and-relying-parties)
  - how Minister and the apps built on it fit together at runtime.
- [Badges and Verifiable Credentials](/understand/badges-and-verifiable-credentials)
  - the credential format and lifecycle.
- [Getting Started](/build/getting-started) - wire your own app to Minister.
