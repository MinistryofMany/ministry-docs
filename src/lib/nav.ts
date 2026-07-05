// Site navigation, grouped into the two documentation tracks. Each page maps a
// slug to a route path; pages render within a track in ascending `order`.

export interface DocPage {
	slug: string;
	title: string;
	order: number;
	/** Absolute route path, e.g. "/build/auth-code-pkce-flow". */
	path: string;
}

export interface Track {
	/** Route + frontmatter track id. */
	id: 'understand' | 'build' | 'crypto';
	/** Sidebar section heading. */
	label: string;
	/** One-line summary used on the landing page. */
	blurb: string;
	pages: DocPage[];
}

function page(track: string, slug: string, title: string, order: number): DocPage {
	return { slug, title, order, path: `/${track}/${slug}` };
}

const trackList: Track[] = [
	{
		id: 'understand',
		label: 'Understand the ecosystem',
		blurb:
			'The privacy model behind Minister: what gets disclosed, how little of it, and why one user stays uncorrelatable across the apps that rely on it.',
		pages: [
			page('understand', 'what-is-minister', 'What Is Minister', 1),
			page('understand', 'ecosystem-and-relying-parties', 'The Ecosystem and Relying Parties', 2),
			page('understand', 'badges-and-verifiable-credentials', 'Badges and Verifiable Credentials', 3),
			page('understand', 'signing-keys-and-did', 'Signing Keys and the DID', 4),
			page('understand', 'selective-disclosure-and-anonymity', 'Selective Disclosure and Anonymity', 5),
			page('understand', 'pairwise-subjects-and-unlinkability', 'Pairwise Subjects and Unlinkability', 6),
			page('understand', 'trust-and-security-model', 'Trust and Security Model', 7)
		]
	},
	{
		id: 'build',
		label: 'Build on Minister',
		blurb:
			'Wire a relying party to Minister with @ministryofmany/client: run the flow yourself, verify tokens and badges on a backend, or drop it into Auth.js.',
		pages: [
			page('build', 'getting-started', 'Getting Started', 1),
			page('build', 'registering-an-oidc-client', 'Registering an OIDC Client', 2),
			page('build', 'auth-code-pkce-flow', 'The Auth-Code + PKCE Flow', 3),
			page('build', 'verifying-tokens-and-badges', 'Verifying Tokens and Badges on a Backend', 4),
			page('build', 'auth-js-integration', 'Auth.js Integration', 5),
			page('build', 'requesting-badges-and-policies', 'Requesting Badge Scopes and Policies', 6),
			page('build', 'badge-type-reference', 'Badge-Type Reference', 7)
		]
	},
	{
		id: 'crypto',
		label: 'Cryptography and security',
		blurb:
			'The algorithm-level reference for the whole ecosystem: every primitive with its name, parameters, and bit strength, how the pieces fit together, and the threat model. Written to be audited.',
		pages: [
			page('crypto', 'overview', 'Cryptographic Overview', 1),
			page('crypto', 'glossary', 'Glossary and Notation', 2),
			page('crypto', 'hashing-hmac-and-kdfs', 'Hashing, HMAC, and Key Derivation', 3),
			page('crypto', 'signatures-and-signing-keys', 'Signatures, Keys, and the DID', 4),
			page('crypto', 'pairwise-subjects', 'Pairwise Subjects', 5),
			page('crypto', 'verifiable-credentials', 'Verifiable Credentials and Holder Binding', 6),
			page('crypto', 'badge-nullifier', 'The Badge Nullifier', 7),
			page('crypto', 'signet-service', 'Signet: The Crypto-Core Service', 8),
			page('crypto', 'oidc-flow-hardening', 'OIDC Flow Hardening and Disclosure', 9),
			page('crypto', 'recovery-and-merge', 'Recovery, Assurance, and Account Merge', 10),
			page('crypto', 'relying-party-zero-knowledge', 'Zero-Knowledge in the Relying Parties', 11),
			page('crypto', 'threat-model', 'Threat Model and Known Gaps', 12)
		]
	}
];

// Pages render within a track in ascending `order`.
export const tracks: Track[] = trackList.map((track) => ({
	...track,
	pages: [...track.pages].sort((a, b) => a.order - b.order)
}));
