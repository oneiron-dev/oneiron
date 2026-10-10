---
name: oneiron.codex-seat
description: "A person's own Codex, signed in with their ChatGPT account, run headless inside their vault as a seat. Installs OpenAI's tool at first use. Identifies itself as Oneiron."
version: 0.1.1
license: Apache-2.0
kind: capability
grants: ["run: the codex binary and its app-server inside this vault's sandbox, as the seat's own user", "network: chatgpt.com and api.openai.com, for the device login and the tool's own requests", "store: the seat's Codex home on the vault volume, read and written only by the seat process"]
wakes: []
adapter: built-in:seat-headless
contact: "legal@oneiron.dev for removal requests, contact@oneiron.dev for everything else"
---

# codex-seat

This pack turns a person's own ChatGPT subscription into a seat their vault can assign work to, through Codex.

## What it does

- **Installs the vendor's tool at first use**, from OpenAI's registry, under its Apache-2.0 license, in the vault's sandbox.
- **Runs the vendor's own device login.** `codex login --device-auth` prints a link and a code; the person opens the link on any device, enters the code, approves. Nothing is pasted back. The credential lands in the seat's own Codex home on the vault volume.
- **Drives the tool through its app-server**, the JSON-RPC surface OpenAI documents for programmatic use. Where OpenAI asks harnesses to identify themselves, the seat says Oneiron.

## What it never does

- Never reads or relays the credential. Never builds a request of its own. Never presents itself as the Codex CLI.

## Permissions the card asks for

Under "Asks for permission": run codex in this vault; reach chatgpt.com and api.openai.com; keep a login store on this vault's volume. The person's tap is the standing grant.

## Terms and ship order

- **Terms.** Your login, your plan. OpenAI's terms apply.
- **Ship order.** Ships first, with the connector shape.

## Requires

The engine's seat row and the headless seat adapter. Until those ship, this folder is a manifest, not an installable pack.
