<script lang="ts">
	import { tracks } from '$lib/nav';
</script>

<svelte:head>
	<title>Ministry of Many Documentation</title>
	<meta
		name="description"
		content="Documentation for the Ministry of Many ecosystem: how Minister discloses the minimum a relying party needs, and how to build apps on top of it."
	/>
</svelte:head>

<div class="prose">
	<section class="hero">
		<h1>Ministry of Many</h1>
		<p>
			Minister is an OpenID Connect identity provider where users hold
			verifiable-credential badges and disclose only what a relying party needs.
			These docs come in two tracks: read the first to understand the privacy
			model, the second to wire your own app to it.
		</p>
	</section>

	<div class="track-grid">
		{#each tracks as track (track.id)}
			<section class="track-card">
				<h2>{track.label}</h2>
				<p>{track.blurb}</p>
				<ul>
					{#each track.pages as doc, i (doc.path)}
						<li>
							<a href={doc.path}>
								<span class="num">{i + 1}</span>
								<span>{doc.title}</span>
							</a>
						</li>
					{/each}
				</ul>
			</section>
		{/each}
	</div>
</div>
