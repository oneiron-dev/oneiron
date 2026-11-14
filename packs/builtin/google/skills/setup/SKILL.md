---
name: oneiron-google-setup
description: Walk the owner through connecting their Google files to their agent, from the Google account to a checked connection with the permissions they chose.
---

# Set up Google

Use this skill when the owner wants their agent to read or edit their Google
files in place, or when the Google pack shows a setup step that is not done.
Read the setup from the pack's own setup session and its cards; never guess a
step the session already shows as done. Setup grants nothing by itself, and
the pack stays a Candidate until its own qualification passes.

## What the owner needs

- A Google account or a Google Workspace account. A Workspace admin may have
  to allow third-party apps to use the account's Google files.

## Steps

1. Review the permissions first. Each app is its own permission, and every
   permission is optional: turn on only what the agent needs.
   - Sheets reading: every spreadsheet the account can open becomes readable
     by the agent.
   - Sheets writing: the agent may write cell values and change sheets. Allow
     it only when the agent must change spreadsheets.
   - Docs reading and Docs writing: the same for documents; writing edits a
     document in place.
   - Slides reading and Slides writing: the same for presentations; writing
     edits a deck in place.
   - Drive reading: the agent may find any file in the whole Drive, shared
     drives included, and see what changed: each file's name, type, folder,
     owners, dates and link. It never reads a file's content through Drive;
     content goes through the Sheets, Docs and Slides permissions.
   Show the permission card and ask the owner to allow each permission they
   want. Each one they allow gets its own Gate receipt.
2. Sign in with Google through the host's sign-in, on the host's agentic
   OAuth client: the Google client marked as an AI agent (`is_agentic`) in
   the Cloud console, never the client that imports mail or calendars. An
   owner who brings their own Google client marks a separate client as an AI
   agent for this. Ask for the scopes of the permissions the owner allowed,
   and no other Google access. Ask for offline access, so the grant carries a
   refresh token and the agent can keep using it after the first hour.
3. Store what the sign-in returns through the owner secrets form, under the
   name the card shows, bound for read to connector:google. Never ask for the
   owner's Google password, never ask for the grant in chat, and never repeat
   it back.
4. Check the connection. The check asks Google which account the grant
   belongs to and which scopes it holds, and passes only when those scopes
   are the permissions the owner allowed.

When the owner turns on another permission later, sign in again asking for
all the allowed scopes, store the new grant under the same name, and check
again.

## How the agent uses it

- Each app is one connector the agent calls with `connector.call`:
  - `google.sheets`: `spreadsheets.get`, `values.batchGet`,
    `values.batchUpdate` and `spreadsheets.batchUpdate`;
  - `google.docs`: `documents.get` and `documents.batchUpdate`;
  - `google.slides`: `presentations.get` and `presentations.batchUpdate`;
  - `google.drive`: `changes.getStartPageToken`, `changes.list` and
    `files.get`, reads only.
  In code mode, `connector["google.sheets"]["values.batchGet"](args)` sends
  the same call. The file stays in Google and is edited in place: read it,
  work out the change, send one batch, and read the result back. To find a
  file, or what changed since the last look, read Drive's change log: take a
  start token once, drain `changes.list` page by page, and keep the
  `newStartPageToken` the last page answers for the next drain. A change's
  file id is the id the Sheets, Docs and Slides tools take.
  `connector.schema` gives each tool's input, and `connector.list` shows the
  apps whose permissions the owner allowed.
- Any bound caller may call it: a code-mode run, an agent run, an agent's
  own credential, or the owner. A write from an anonymous off-record session
  is refused, as a secret grant is.
- A write runs only with `mutation` set to `explicit_mutation`. Without it,
  the call shows what it would write and writes nothing. Every write reads
  the file back, and leaves two Gate receipts: one before the send and one
  after.

## When the check fails

- Google refused the credential. The grant expired or was withdrawn in the
  Google account's security settings. Sign in again, store the new grant, and
  check again.
- The grant holds a scope the owner did not allow, or lacks one they allowed.
  Sign in again asking for exactly the allowed permissions, store that grant,
  and check again.

## Afterwards

If the owner withdraws access in their Google account, or withdraws a
permission here, the check goes stale and the agent cannot use that app until
it is checked again.
