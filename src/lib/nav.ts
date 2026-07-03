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
	id: 'understand' | 'build';
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
			page('understand', 'selective-disclosure-and-anonymity', 'Selective Disclosure and Anonymity', 5),
			page('understand', 'pairwise-subjects-and-unlinkability', 'Pairwise Subjects and Unlinkability', 6)
		]
	},
	{
		id: 'build',
		label: 'Build on Minister',
		blurb:
			'Wire a relying party to Minister with @ministryofmany/client: run the flow yourself, verify tokens and badges on a backend, or drop it into Auth.js.',
		pages: [
			page('build', 'auth-code-pkce-flow', 'The Auth-Code + PKCE Flow', 3),
			page('build', 'verifying-tokens-and-badges', 'Verifying Tokens and Badges on a Backend', 4),
			page('build', 'auth-js-integration', 'Auth.js Integration', 5),
			page('build', 'requesting-badges-and-policies', 'Requesting Badge Scopes and Policies', 6),
			page('build', 'badge-type-reference', 'Badge-Type Reference', 7)
		]
	}
];

// Pages render within a track in ascending `order`.
export const tracks: Track[] = trackList.map((track) => ({
	...track,
	pages: [...track.pages].sort((a, b) => a.order - b.order)
}));
