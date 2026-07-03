---
title: Badges and Verifiable Credentials
description: The W3C JWT-VC badge model - Ed25519 signing, the credential shape, and the issuance, holding, and disclosure lifecycle.
order: 3
---

## A badge is a verifiable credential

Every Minister badge is a W3C Verifiable Credential (VC Data Model 2.0),
serialized as a JWT-VC and signed with Ed25519 (`alg: EdDSA`) by Minister's
badge signing key. One badge attests exactly one fact - a domain the holder
controls, an age threshold they clear, an OAuth account they own. A VC is
self-contained: given the JWT and Minister's public key, anyone can verify the
signature and read the claim without calling back to Minister.

## The credential shape

A stored native badge VC looks like this (payload; the JWT also has a protected
header carrying the signing key's `kid`):

```json
{
  "iss": "did:web:ministry.id",
  "sub": "did:web:ministry.id:users:<userId>",
  "iat": 1715000000,
  "nbf": 1715000000,
  "exp": 1746536000,
  "jti": "<badge id>",
  "vc": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential", "MinisterEmailDomainCredential"],
    "credentialSubject": {
      "id": "did:web:ministry.id:users:<userId>",
      "domain": "example.com"
    }
  }
}
```

The pieces that matter:

- `iss` is Minister's issuer DID, `did:web:ministry.id`. A verifier resolves the
  signing key from that DID (see [Signing Keys and the DID](/understand/signing-keys-and-did)).
- `sub` and `credentialSubject.id` are the holder's DID. The two are always
  equal - that equality is a verified invariant. The `vc.type` array carries
  `VerifiableCredential` plus one Minister credential type
  (`MinisterEmailDomainCredential`), which maps to the badge slug
  (`email-domain`).
- `credentialSubject` carries the claim fields for that badge type, validated
  against a Zod schema before signing. For `email-domain` that is just
  `{ domain }` - the raw email is never in the credential.

The full slug-to-`credentialType`-to-claims mapping is in the
[Badge-Type Reference](/build/badge-type-reference).

## Issuance: proved once, then signed

Minister issues a native badge only after the user completes a proof for it. The
proof is per badge type - a plugin owns the flow:

- `email-domain` - the user enters an email, clicks a magic link, and Minister
  issues the badge for the domain. The address itself is not stored.
- `oauth-account` - an OAuth round trip with GitHub, Google, or Discord.
- `invite-code` - redeeming an admin-minted code; only the campaign `label`
  enters the VC, never the code string.
- `tlsn-attestation` - a TLSNotary presentation the user's browser produces,
  verified by a Minister sidecar.

On success Minister validates the derived claims against the badge type's schema,
mints the JWT-VC, and stores it. It records **no underlying PII**: for age, the
user proves once and Minister records eligibility rows for higher thresholds at
fuzzed future dates rather than storing a birthdate; for a domain badge it keeps
the domain, not the email.

## Holding: the badge lives in the account

Minister holds the signed VC server-side against the user's account, alongside
denormalized non-sensitive attributes used only for display and query. The
signed `vcJwt` is the authoritative artifact; the attributes are a convenience
copy. Badges are private by default - a badge appears on the public profile
(`/u/<userId>`) only if the user marks it public.

Minister can also hold **imported** credentials whose issuer is some external
DID. The credential's `iss` field tells a verifier whose key to check - Minister's
own, or the foreign issuer's - so an imported VC is never laundered into looking
Minister-signed.

## Disclosure: the VC is re-minted, not handed over verbatim

A VC leaves Minister only along a path the user chose: an `id_token` to an RP
they consented to, a share link they created, or a user-initiated export. The
OIDC path is the important one, and it does **not** disclose the stored VC as-is.

Handing an RP the stored VC would leak the stable `did:web:ministry.id:users:<userId>`
subject, which is the same across every badge and every RP - exactly the
cross-RP correlator the pairwise `sub` exists to remove. So at disclosure time
Minister **re-mints** each approved badge:

- `sub` and `credentialSubject.id` are rebound to a per-RP pairwise DID,
  `did:web:<domain>:u:<pairwiseSub>`, tied to the id_token `sub` for that RP.
- `jti` is replaced with a per-RP value, `iat`/`nbf` are re-stamped to now, and
  `exp` is shortened to a presentation TTL, so none of them survives as a
  cross-RP correlator.
- `iss`, the signing `kid`, and every claim value are unchanged, so the fact
  attested is identical.

The re-mint verifies the stored VC's signature before re-signing, and is scoped
to Minister-issued rows only. The full mechanics are in
[Pairwise Subjects and Unlinkability](/understand/pairwise-subjects-and-unlinkability).

## What a relying party verifies

A disclosed badge is only meaningful once verified. The RP (via the SDK) checks:

- the Ed25519 signature against Minister's badge key, resolved from the issuer
  DID's `assertionMethod` (not the raw JWKS - see
  [Trust and Security Model](/understand/trust-and-security-model)),
- `iss` equals `did:web:<minister-host>`,
- the JWT `typ` is `vc+jwt`, `exp` is not past, the `vc` envelope is well
  formed, and `credentialSubject.id === sub`,
- the `vc.type` maps to a known badge slug and the claims pass that slug's
  schema,
- **holder binding**: the badge's subject equals `did:web:<host>:u:<id_token sub>`,
  so the badge belongs to *this* login.

A badge that fails any check is dropped (into a `rejected` list), not trusted.
See [Verifying Tokens and Badges on a Backend](/build/verifying-tokens-and-badges)
for the code.

## On badge freshness

Because a disclosed badge is re-minted, its `iat`/`exp` reflect disclosure time,
not issuance time - do not derive a badge's age from them. The only issuance
signal that survives disclosure is a coarse `issuanceMonth` (`YYYY-MM`)
bucket, deliberately coarsened so a fine-grained timestamp cannot become a
correlator. Freshness policies (`maxAgeDays`) evaluate against that coarse
bucket on both sides.
