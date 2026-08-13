# oneiron-web

The Oneiron web surface: the product app (console/workbench) and, later, whatever
else of the website wants to live in code rather than mocks.

- **Framework:** TanStack Start (Vite, TanStack Router, server functions opt-in).
  Chosen 2026-08-14 for interactivity-first defaults; research record in
  `oneiron-mocks` FLOWS.md and the session notes.
- **Design truth:** graduates from `oneiron-mocks` (Safelight system, FLOWS.md
  ruling ledger). The mocks repo stays the annotation bench until parity.
- **Future:** may fold into the `oneiron` engine repo as its web frontend. Not now.

## Run

```bash
bun install
bun run dev
```

## Layout

- `src/styles/safelight.css` — the Safelight token sheet (carried from the mocks).
- `public/fonts/` — vendored mono faces (Server Mono, Departure Mono).
- `src/routes/` — TanStack file routes.
