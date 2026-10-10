---
name: oneiron.claude-seat
description: "A person's own Claude Code, signed in by them, run headless inside their vault as a seat. Installs Anthropic's tool from Anthropic's source at first use. Never holds a token."
version: 0.1.1
license: Apache-2.0
kind: capability
grants: ["run: the claude binary inside this vault's sandbox, as the seat's own user", "network: api.anthropic.com and claude.ai, for the login flow and the tool's own requests", "store: the seat's login directory on the vault volume, read and written only by the seat process"]
wakes: []
adapter: built-in:seat-headless
contact: "legal@oneiron.dev for removal requests, contact@oneiron.dev for everything else"
---

# claude-seat

This pack turns a person's own Claude subscription into a seat their vault can assign work to. It does three things and refuses three things.

## What it does

- **Installs the vendor's tool at first use.** The install step runs `npm install -g @anthropic-ai/claude-code` in the vault's sandbox, from Anthropic's registry, under Anthropic's terms. The hub never ships the binary.
- **Runs the vendor's own login.** The person signs in through Anthropic's flow. On a machine with no browser the flow shows a code; the person pastes it once into the seat process. The login store lands where Claude Code puts it, on the vault volume, owned by the seat's user.
- **Drives the tool through its documented headless surface.** A persistent `claude -p --input-format stream-json --output-format stream-json` session, with the vault's MCP server on the command line, or a native background session (`claude --bg`). The engine reads plan usage from the tool's own reports (`/usage`, the rate-limit fields on the status line) and shows it on the seat card. The seat's lease is plan percent; a spent seat parks with the reset time.

## What it never does

- Never reads, copies, refreshes or relays the login store or any token. The engine has no code path to it.
- Never hand-builds a request and never presents itself as Claude Code. The binary makes its own requests with its own identity.
- Never falls back to an API key silently. A key is a different seat.

## Permissions the card asks for

Under "Asks for permission": run the claude binary in this vault; reach api.anthropic.com and claude.ai; keep a login store on this vault's volume. The person's tap is the standing grant.

## When a vendor moves

If Anthropic changes what a subscription may do headless, this pack is archived and the connector shape carries on: the person's own Claude Code attached to the vault over MCP, work pushed through a channel, state read through hooks. Nothing in the engine changes.

## Terms and ship order

- **Terms.** Your login, your plan. Anthropic's terms apply.
- **Metering.** Headless use meters about 1.7x the interactive terminal per list dollar (Hermes plugin measurement, Pro plan, 2026-09-09). Oneiron's own bench replaces this number when it exists.
- **Ship order.** Opt-in. Never the cloud default.

## Requires

The engine's seat row (vendor, account, machine, login store, plan window) and the headless seat adapter. Until those ship, this folder is a manifest, not an installable pack.
