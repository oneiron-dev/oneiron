---
name: oneiron-browser-setup
description: Walk the owner through turning on their agent's browser, from the permission to a checked browser guest on this host.
---

# Set up the browser

Use this skill when the owner wants their agent to use a website that has no
API, or when the browser pack shows a setup step that is not done. Read the
setup from the pack's own setup session and its cards; never guess a step the
session already shows as done. Setup grants nothing by itself, and the pack
stays a Candidate until its own qualification passes.

## What the owner needs

Nothing to sign up for and no credential to store. The browser is a guest the
host runs itself, isolated from the vault and from every other run. The host
must be configured with a browser guest; a host without one cannot pass the
check.

## Steps

1. Review the permission. Show the permission card: it says what the browser
   lets the agent do and what could go wrong. Ask the owner to allow it. The
   permission gets its own Gate receipt.
2. Check the connection. The check starts a browser guest on this host, opens
   a blank page in it, and closes it again. It visits no site.

## Sends, payments and sign-ins

Allowing the browser does not let it send, pay, publish or change an account
on its own. Each of those crosses the vault's grant for its kind of effect: a
press per send, one press for a reviewed batch, or none. A payment always
keeps a person's press. A site the owner signs in to inside the guest keeps
that sign-in in the guest only; it never enters the vault or a run.

## When the check fails

- This host has no browser guest. The host's operator adds one; until then
  the connection stays unchecked and the pack does not use it.
- The guest did not start or its page did not open. The host's sandbox or the
  guest image is not ready; the reason says which. Check again once fixed.

## Afterwards

If the owner withdraws the permission, the check goes stale and the browser is
not used until the permission is allowed and the connection checked again.
