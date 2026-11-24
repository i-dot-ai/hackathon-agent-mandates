# Frontend

Astro + Svelte UI for the mandate gateway. The approval page (`src/pages/approve/`) is where a person signs in to
approve or reject an agent's request for more access.

The old walkthrough (`src/pages/demo.astro`, calling the gateway's `/demo/*` routes) no longer works: the gateway's
`/demo` routes are off, and minting moved to the issuer service. Use the CLI in the root README instead.

`make run_frontend` from the repo root starts the dev server on `:4321`; `npm run lint` runs ESLint.
