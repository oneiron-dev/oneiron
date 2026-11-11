---
name: oneiron-sheets-setup
description: Walk the owner through connecting Google Sheets to their agent, from the Google account to a checked connection.
---

# Set up Google Sheets

Use this skill when the owner wants their agent to read or write Google
Sheets, or when the Sheets pack shows a setup step that is not done. Read the
setup from the pack's own setup session and its cards; never guess a step the
session already shows as done. Setup grants nothing by itself, and the pack
stays a Candidate until its own qualification passes.

## What the owner needs

- A Google account or a Google Workspace account. A Workspace admin may have
  to allow third-party apps to use Google Sheets.

## Steps

1. Review the permissions first. Reading is required: every spreadsheet the
   account can open becomes readable by the agent. Writing is optional: allow
   it only when the agent must change spreadsheets. Show the permission card
   and ask the owner to allow each permission. Each one they allow gets its
   own Gate receipt.
2. Sign in with Google through the host's sign-in, on the host's agentic
   OAuth client: the Google client marked as an AI agent (`is_agentic`) in
   the Cloud console, never the client that imports mail or calendars. An
   owner who brings their own Google client marks a separate client as an AI
   agent for this. Ask for the Sheets scopes of the permissions the owner
   allowed, and no other Google access. Ask for offline access, so the grant
   carries a refresh token and the agent can keep using it after the first
   hour.
3. Store what the sign-in returns through the owner secrets form, under the
   name the card shows, bound for read to connector:google.sheets. Never ask
   for the owner's Google password, never ask for the grant in chat, and
   never repeat it back.
4. Check the connection. The check asks Google which account the grant
   belongs to and which scopes it holds, and passes only when those scopes
   are the permissions the owner allowed.

## How the agent uses it

- The agent calls `connector.call` with the name `google.sheets` and one of
  four tools: `spreadsheets.get`, `values.batchGet`, `values.batchUpdate` and
  `spreadsheets.batchUpdate`. In code mode,
  `connector["google.sheets"]["values.batchGet"](args)` sends the same call.
  `connector.schema` gives each tool's input.
- Any bound caller may call it: a code-mode run, an agent run, an agent's
  own credential, or the owner. A write from an anonymous off-record session
  is refused, as a secret grant is.
- A write runs only with `mutation` set to `explicit_mutation`. Without it,
  the call shows what it would write and writes nothing. Every write reads
  its ranges or sheets back, and leaves two Gate receipts: one before the
  send and one after.

## When the check fails

- Google refused the credential. The grant expired or was withdrawn in the
  Google account's security settings. Sign in again, store the new grant, and
  check again.
- The grant holds a scope the owner did not allow, or lacks one they allowed.
  Sign in again asking for exactly the allowed permissions, store that grant,
  and check again.

## Afterwards

If the owner withdraws access in their Google account, or withdraws a
permission here, the check goes stale and the agent cannot use Sheets until
it is checked again.
