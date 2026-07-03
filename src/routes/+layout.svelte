<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { tracks } from '$lib/nav';
	import { page } from '$app/state';
	import { afterNavigate } from '$app/navigation';

	let { children } = $props();

	let menuOpen = $state(false);

	// Collapse the mobile nav after any navigation.
	afterNavigate(() => {
		menuOpen = false;
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<div class="mobile-bar">
	<a class="brand" href="/">Ministry of Many</a>
	<button
		class="menu-toggle"
		aria-expanded={menuOpen}
		onclick={() => (menuOpen = !menuOpen)}
	>
		{menuOpen ? 'Close' : 'Menu'}
	</button>
</div>

<div class="layout">
	<aside class="sidebar" data-open={menuOpen}>
		<a class="brand" href="/">Ministry of Many</a>
		<p class="brand-sub">Documentation</p>

		<nav aria-label="Documentation">
			{#each tracks as track (track.id)}
				<div class="nav-section">
					<p class="nav-heading">{track.label}</p>
					<ul class="nav-list">
						{#each track.pages as doc (doc.path)}
							<li>
								<a
									href={doc.path}
									aria-current={page.url.pathname === doc.path ? 'page' : undefined}
								>
									{doc.title}
								</a>
							</li>
						{/each}
					</ul>
				</div>
			{/each}
		</nav>
	</aside>

	<main class="content">
		<div class="content-inner">
			{@render children()}
		</div>
	</main>
</div>
