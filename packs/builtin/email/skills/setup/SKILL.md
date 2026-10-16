---
name: oneiron-email-setup
description: Walk the owner through connecting a Gmail or Google Workspace mailbox to their agent, from the account to a checked connection.
---

# Set up email

Use this skill when the owner wants their agent to read a Gmail or Google
Workspace mailbox, or when the email pack shows a setup step that is not done.
Read the setup from the pack's own setup session and its cards; never guess a
step the session already shows as done. Setup grants nothing by itself, and
the pack stays a Candidate until its own qualification passes.

## What the owner needs

- A Google account or a Google Workspace mailbox. A Workspace admin may have to
  allow third-party apps to read Gmail.

## Steps

1. Review the permissions first. Reading mail is the highest risk this pack
   asks for: every message in the mailbox, private ones included, becomes
   readable by the agent. Show the permission card and ask the owner to allow
   each permission. Each one they allow gets its own Gate receipt.
2. Sign in with Google through the host's sign-in, and allow read access to
   Gmail only. Do not allow sending or deleting mail; this pack reads.
3. Store what the sign-in returns through the owner secrets form, under the
   name the card shows, bound for read to connector:gmail. Never ask for the
   owner's Google password, never ask for the grant in chat, and never repeat
   it back.
4. Check the connection. The check asks Gmail which mailbox the grant opens,
   and passes only when Gmail names it.

## When the check fails

- Google refused the credential. The grant expired or was withdrawn in the
  Google account's security settings. Sign in again, store the new grant, and
  check again.
- The mailbox named is not the one the owner meant. Sign in with the right
  account, store that grant, and check again.

## Afterwards

If the owner withdraws access in their Google account, or withdraws a
permission here, the check goes stale and the mailbox is not read until it is
checked again.
