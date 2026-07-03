# ministry-docs

Documentation site for the [Ministry of Many](https://github.com/MinistryofMany)
ecosystem. Static SvelteKit app, markdown authored with [mdsvex](https://mdsvex.pngwn.io/),
prerendered to plain HTML. No runtime, no database, no external network assets.

Content is organized into two tracks:

- **Understand the ecosystem** (`/understand/*`) - the privacy model behind Minister.
- **Build on Minister** (`/build/*`) - wiring a relying party with `@ministryofmany/client`.

## Stack

- SvelteKit 2 + Svelte 5 (runes), Vite
- `@sveltejs/adapter-static` - the whole site prerenders to static files
- `mdsvex` - renders `.md` route pages, each wrapped in `src/lib/DocLayout.svelte`
- TypeScript
- Node 20+

SvelteKit is configured inline in `vite.config.ts` (adapter, preprocess, extensions);
there is no separate `svelte.config.js`.

## Develop

```sh
npm install
npm run dev          # dev server on :5173
npm run build        # prerender to build/
npm run preview      # serve the production build locally
npm run check        # svelte-check type check
```

## Project layout

```
src/
  app.css                      global styles (light/dark, prose typography)
  lib/
    nav.ts                     the two tracks and their ordered pages
    DocLayout.svelte           mdsvex layout: renders frontmatter + content
  routes/
    +layout.svelte             sidebar shell + active-link highlighting
    +layout.ts                 prerender = true
    +page.svelte               landing page (both tracks)
    understand/<slug>/+page.md
    build/<slug>/+page.md
mdsvex.config.js               markdown extensions + layout wiring
```

## Add a page

1. Create `src/routes/<track>/<slug>/+page.md`, where `<track>` is `understand`
   or `build`. The route path is `/<track>/<slug>`.

2. Give it frontmatter:

   ```markdown
   ---
   title: Your Page Title
   description: One-line summary shown under the title and as the meta description.
   order: 8
   ---

   ## First heading
   ...
   ```

   `DocLayout.svelte` renders `title` and `description` as the page header, so the
   body should start at a section heading, not repeat the title.

3. Add the page to its track in `src/lib/nav.ts` so it shows in the sidebar and on
   the landing page. Pages sort by `order` within a track.

### Markdown gotchas (mdsvex)

mdsvex compiles each page as a Svelte component, so a bare `{` or `<` in prose is
parsed as a Svelte expression or tag and breaks the build. Inside backticks or
fenced code blocks these are escaped automatically, so wrap literal braces and
comparisons in code spans - e.g. write `` `atLeast.n <= 16` `` and
`` `{age-over-21, ...}` `` rather than leaving them bare in a sentence.

## Deploy

`npm run build` writes a static site to `build/`. Serve that directory from any
static host. No server runtime is required.
