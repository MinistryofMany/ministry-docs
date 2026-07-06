---
title: Verifiable Credentials and Holder Binding
description: The badge VC as a cryptographic artifact - JWT-VC encoding, EdDSA signing under #key-2, the reMintVc integrity gate and reserved-claim stripping at disclosure, and the holder-binding rule an RP relies on.
order: 6
---

## The VC as a signed JWT

In plain terms, a badge is a signed claim: something like "this account
controls this email domain," wrapped so that anyone can check who issued it
and that nobody tampered with it, without calling Minister back to ask. A
Minister badge is a W3C Verifiable Credential (VC Data Model 2.0), but the
wire format is a JWT-VC: the `vc` envelope sits inside an ordinary JWT
payload, and the whole thing is a compact JWS. The protected header is
`{alg: "EdDSA", kid: "<issuer-did>#key-2", typ: "vc+jwt"}` - `EdDSA` per RFC
8032 (pure Ed25519, no prehash) over Ed25519 keys, and `typ: "vc+jwt"` is what
lets a verifier tell a badge apart from an `id_token` at a glance. The
signing key is always `#key-2`, the KMS-backed badge key described in
[Signatures, Keys, and the DID](/crypto/signatures-and-signing-keys) - never
the token key.

Because `jose`'s `SignJWT` takes only key material and has no pluggable
signer hook, and the KMS signing path needs one (it calls out to AWS over the
network instead of holding a private key locally), Minister builds the
compact JWS by hand:

```ts
// packages/vc/src/signer.ts:27-37
export async function signCompactJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signer: IssuerSigner,
): Promise<string> {
  const encodedHeader = base64url.encode(JSON.stringify(header));
  const encodedPayload = base64url.encode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64url.encode(signature)}`;
}
```

`base64url(header).base64url(payload).base64url(sig)`, exactly the compact-JWS
shape RFC 7515 defines, with the signature itself delegated to whichever
`IssuerSigner` is wired in - the in-process signer for `#key-3`, or the KMS
signer for `#key-2` in production. An Ed25519 signature is 64 bytes over a
32-byte public key, giving roughly 128-bit security regardless of which
signer produced it.

A stored badge's default lifetime is one year (`31_557_600` seconds -
`day * 365.25`, matching how `jose` computes a year - so the hand-rolled
signing path agrees with what `jose`'s `SignJWT` would have stamped).

## Issuance: `issueVc`

```ts
// packages/vc/src/issue.ts:21-54 (abridged)
export async function issueVc<TClaims extends Record<string, unknown>>(
  issuer: Issuer,
  badgeType: string,
  subjectId: string,
  claims: TClaims,
  options: IssueOptions = {},
): Promise<string> {
  const credentialSubject: CredentialSubject = { id: subjectId, ...claims };
  const vc: VerifiableCredentialClaim = {
    "@context": [VC_CONTEXT, ...(options.extraContexts ?? [])],
    type: [VC_BASE_TYPE, ministerCredentialType(badgeType)],
    credentialSubject,
  };
  // ...stamps iat/nbf/exp, then:
  const header = { alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" };
  return signCompactJwt(header, payload, issuer.signer);
}
```

`subjectId` here is the stable `did:web:<domain>:users:<userId>` shape (see
[Pairwise Subjects and Unlinkability](/understand/pairwise-subjects-and-unlinkability)
for why that DID never leaves Minister over OIDC). `ministerCredentialType`
maps a badge slug to its PascalCase VC type, so `email-domain` becomes
`MinisterEmailDomainCredential` in `vc.type`. The result is stored as
`Badge.vcJwt` - the authoritative artifact; nothing else about the badge is
authoritative over it.

## Disclosure: `reMintVc` never hands over the stored VC

Handing an RP the stored VC verbatim would leak the stable `:users:<userId>`
subject - the same value in every badge and every RP, exactly the cross-RP
correlator pairwise subjects exist to remove. So at disclosure time Minister
re-signs a fresh JWT-VC rather than forwarding the stored one, through
`reMintVc`. Three things about that function matter for anyone auditing it.

**It verifies before it re-signs.** The very first thing `reMintVc` does is
check the *stored* VC's own EdDSA signature against the issuer's public key,
and reject unless `typ` is `vc+jwt` and `iss` equals the issuer's own DID:

```ts
// packages/vc/src/issue.ts:219-231 (abridged)
const verified = await compactVerify(originalVcJwt, issuer.publicKey, {
  algorithms: ["EdDSA"],
});
if (verified.protectedHeader.typ !== "vc+jwt") {
  throw new Error(`unexpected typ ${String(verified.protectedHeader.typ)}`);
}
// ... decoded.iss !== issuer.did also throws
```

> Without this check, `reMintVc` would be a signing oracle over database
> contents: anyone who could write an arbitrary row to the `Badge` table (a
> compromised DB, or a future foreign-issuer import path) could get arbitrary
> claims re-signed under Minister's own key with a fresh, valid lifetime. The
> integrity gate and the scope-to-Minister's-own-`iss` check are what close
> that off - a badge whose `iss` names some other issuer is never re-minted
> as if it were Minister's.

**It strips reserved claim keys before re-stamping them.** `id`,
`issuanceMonth`, and `nullifier` are reserved names inside
`credentialSubject`. Every stored claim under those keys is dropped before the
result reaches any sanitizer hook, and the sanitizer's *output* is stripped of
the same three keys again afterward - so neither a stale stored field nor a
sanitizer that returns one of those names (accidentally or otherwise) can ride
through to the disclosure. Only then does `reMintVc` stamp its own fresh
values for all three: `id` becomes the re-bound subject (below), `nullifier`
is set only when a fresh one is supplied by the caller, and `issuanceMonth` is
a coarse `YYYY-MM` bucket derived from the *stored, signature-verified* `iat`
- never from an unsigned column, and never a fine-grained timestamp that
could itself become a cross-RP correlator.

**It rebinds the subject, replaces `jti`, and clamps the lifetime.**
`credentialSubject.id` and the JWT `sub` are both overwritten to the caller's
`subjectId` - the pairwise DID for this RP (next section). `jti` is replaced
with a per-RP value. `iat`/`nbf` are re-stamped to the current disclosure
time, and `exp` is computed as `min(now + disclosureTtl, original exp,
maxExpiresAt)` - the TTL defaults to one hour, and the clamp can only shorten
the lifetime relative to the stored VC, never extend it. `iss`, the signing
`kid`, and the non-reserved claim values are otherwise carried through
(optionally re-parsed by a caller-supplied sanitizer against the current
badge-type schema, which can drop a stale legacy field but never add one), so
the fact the badge attests is what was issued; only the identifiers and
timestamps around it are disclosure-scoped.

## Holder binding

A disclosed badge is only useful to a relying party if the RP can prove it
belongs to the person who just logged in, without Minister handing over any
shared identifier. Think of it like a wristband stamped at the door of a
show: it is tied to the person standing there when it was issued, not
something you can hand to someone else and have it still work. A disclosed
badge is stamped to the login that requested it, so it does not verify
against a different session, even a legitimate one, because the subject
baked into the badge will not match. The rule both Minister and the RP-side
SDK enforce is:

> a disclosed badge's subject must equal `did:web:<host>:u:<id_token sub>`.

`<host>` is the OIDC issuer host and `<id_token sub>` is the pairwise `sub`
from the id_token the RP just verified. Minister builds that subject at
re-mint time; `@ministryofmany/client` recomputes the same expected value on
the RP side and compares:

```ts
// minister-client/src/did.ts:39-41
export function buildPairwiseSubjectDid(issuer: string, sub: string): string {
  return `${didFromIssuer(issuer)}:u:${sub}`;
}
```

`verifyMinisterBadges` computes this expected subject from the already-verified
id_token, then pushes any badge whose subject doesn't match into a `rejected`
list rather than trusting it - a borrowed credential, a stale re-mint, or a
badge minted for a different RP fails closed and simply doesn't count. Here's
the trap: because `didFromIssuer` derives the DID from the issuer host with
no override, a deployment's `MINISTER_ISSUER` host must equal Minister's own
issuer domain, or every badge lands in `rejected` while login itself still
succeeds - the same coupling trap noted in
[Trust and Security Model](/understand/trust-and-security-model).

> Don't confuse this with the standalone `verifyMinisterBadge`, which only
> checks that a VC is authentically Minister-issued and that
> `credentialSubject.id === sub` internally - it does not tie the badge to any
> login. A badge received out-of-band (say, via a share link) verifies fine
> under `verifyMinisterBadge` without belonging to the current session.
> Treating that success as "the current user holds this badge" is an
> authorization bug; use `verifyMinisterBadges` for any access decision.

The full unlinkability argument - why the pairwise subject differs per RP and
what that buys you - is in
[Pairwise Subjects](/crypto/pairwise-subjects) and
[Pairwise Subjects and Unlinkability](/understand/pairwise-subjects-and-unlinkability).
The narrative, non-cryptographic view of issuance and disclosure lives in
[Badges and Verifiable Credentials](/understand/badges-and-verifiable-credentials).

## Where to look in the source

- Issuance: `packages/vc/src/issue.ts` (`issueVc`, `ministerCredentialType`).
- Disclosure re-mint, the integrity gate, and reserved-claim stripping:
  `packages/vc/src/issue.ts` (`reMintVc`, `RESERVED_CREDENTIAL_SUBJECT_KEYS`,
  `ISSUANCE_MONTH_CLAIM`, `NULLIFIER_CLAIM`, `stripReservedClaims`).
- Compact-JWS construction and the pluggable signer: `packages/vc/src/signer.ts`
  (`signCompactJwt`, `localSigner`).
- Subject DID shapes: `packages/vc/src/did.ts` (`buildUserDid`,
  `buildPairwiseUserDid`, `getDidDocument`).
- RP-side holder binding: `minister-client/src/did.ts`
  (`buildPairwiseSubjectDid`, `didFromIssuer`), `minister-client/src/verify-badges.ts`,
  `minister-client/src/verify-badge.ts`.
