<script lang="ts">
	// mdsvex wraps every rendered markdown page in this component and passes the
	// page's YAML frontmatter (title, description, order) in as props.
	let {
		title,
		description,
		children
	}: {
		title?: string;
		description?: string;
		order?: number;
		children: import('svelte').Snippet;
	} = $props();
</script>

<svelte:head>
	<title>{title ? `${title} · Ministry of Many` : 'Ministry of Many Docs'}</title>
	{#if description}
		<meta name="description" content={description} />
	{/if}
</svelte:head>

<article class="prose">
	{#if title}
		<header class="doc-header">
			<h1>{title}</h1>
			{#if description}
				<p class="lead">{description}</p>
			{/if}
		</header>
	{/if}
	{@render children()}
</article>
