# Oneiron — agent instructions

Start with `AGENTS.md`. It states the vibe build rules (the merge bar, no tests, no backward
compatibility, no review rounds, the fix list) and how to find your way around the repo. This
file holds the consumer-boundary rule.

Oneiron is a **general-purpose memory engine** (Rust workspace; core crate `crates/oneiron`,
server `crates/oneiron-server`, bindings `crates/oneiron-napi`). It is consumer-agnostic and this
repo is public.

## Consumer boundary — the rule that keeps this repo generic

Products are built **on top of** the engine, never inside it. A downstream product:

- imports the crate, or runs `oneiron-server` and talks over the API;
- brings its own setup: **custom manifests, agent definitions, context lenses, and prompt/persona
  content** via the engine's configuration surfaces (policy manifests, agent-definition records,
  the lens system, prompt packages supplied at runtime);
- keeps ALL of its product-specific code, prompt text, persona blocks, wire-type conveniences, and
  API sugar **in its own repo**.

Consequences for any change in this repo:

1. **No product names in engine code, modules, constants, paths, or prompt files.** If a type or
   endpoint exists only to serve one downstream product, it belongs in that product's repo (or must
   be generalized until it doesn't).
2. **No hardcoded prompt/persona text in Rust.** User-facing or agent-facing text is configuration
   — it arrives through the prompt/lens/manifest system so hosts can override and localize it. If
   you find yourself writing an English sentence into a `const`, stop.
3. **Generic names for generic mechanisms.** A context board, resume flow, or companion surface that
   any consumer could use gets a consumer-neutral name and a config seam, not a product-branded
   module.
4. Names in *examples* (docs, test fixtures, run-id strings) are fine; modules, files, and shipped
   content are not.

## Where the docs live

Architecture docs and decisions live in the separate docs repo (bespoke Astro pages, compiled to
markdown mirrors). This repo's `docs/` folder holds the generated code map, operational runbooks
(`docs/ops/`), the checked-in architecture/deployment/storage diagrams, and a few research notes.
