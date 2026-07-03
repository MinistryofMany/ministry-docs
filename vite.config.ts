import { mdsvex } from 'mdsvex';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import mdsvexConfig from './mdsvex.config.js';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for our own .svelte files. Leave mdsvex output
				// (.md/.svx) and node_modules in auto-detect: mdsvex emits legacy
				// `$$props`/`<slot>`, which is illegal under forced runes.
				runes: ({ filename }) => {
					if (filename.split(/[/\\]/).includes('node_modules')) return undefined;
					if (filename.endsWith('.md') || filename.endsWith('.svx')) return undefined;
					return true;
				}
			},
			adapter: adapter(),
			preprocess: [mdsvex(mdsvexConfig)],
			extensions: ['.svelte', '.svx', '.md']
		})
	]
});
