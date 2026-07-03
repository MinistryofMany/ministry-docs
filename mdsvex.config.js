import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineMDSveXConfig as defineConfig } from 'mdsvex';

const dir = path.dirname(fileURLToPath(import.meta.url));

// mdsvex uses the layout path both to read the file (fs.readFileSync) and as the
// emitted import specifier in each compiled page. A relative path or a `$lib`
// alias satisfies only one of those, and compiled pages live at varying route
// depths, so use an absolute path derived from this config's own location. It is
// resolved at build time, so it stays portable across machines.
const config = defineConfig({
	extensions: ['.svx', '.md'],
	layout: {
		_: path.join(dir, 'src/lib/DocLayout.svelte')
	}
});

export default config;
