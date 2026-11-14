---
name: oneiron-microsoft365-setup
description: Walk the owner through connecting their Microsoft 365 files to their agent, from the Microsoft account to a checked connection with the permissions they chose.
---

# Set up Microsoft 365

Use this skill when the owner wants their agent to read or edit their Excel
workbooks in place, or when the Microsoft 365 pack shows a setup step that is
not done. Read the setup from the pack's own setup session and its cards;
never guess a step the session already shows as done. Setup grants nothing by
itself, and the pack stays a Candidate until its own qualification passes.

## What the owner needs

- A Microsoft 365 work or school account. An organisation admin may have to
  consent before third-party apps can use the account's files.

## Steps

1. Review the permissions first. Each Microsoft app is its own permission,
   and every permission is optional: turn on only what the agent needs.
   - Excel: the agent may read every file in the account's OneDrive and
     write cell values, formulas and number formats in its workbooks. Allow
     it only when the agent must work in Excel workbooks.
   Show the permission card and ask the owner to allow each permission they
   want. Each one they allow gets its own Gate receipt.
2. Sign in with Microsoft through the host's sign-in. Ask for the scopes of
   the permissions the owner allowed, plus `User.Read`, which the check uses
   to name the account, and no other Microsoft access.
3. Store what the sign-in returns through the owner secrets form, under the
   name the card shows, bound for read to connector:microsoft365. Never ask
   for the owner's Microsoft password, never ask for the grant in chat, and
   never repeat it back. A Microsoft 365 mailbox the owner connects may name
   the same stored grant, so one sign-in serves their mail and their files.
4. Check the connection. The check asks Microsoft Graph which account the
   grant belongs to, and passes when Graph names one.

The engine presents the stored access token as it is: it does not refresh a
Microsoft grant yet. When the token expires, about an hour after the
sign-in, sign in again, store the new grant under the same name, and check
again.

## How the agent uses it

- Excel is the connector `microsoft.excel`, called with `connector.call`:
  `workbook.createSession`, `workbook.range.get`, `workbook.range.update`
  and `workbook.closeSession`. In code mode,
  `connector["microsoft.excel"]["workbook.range.get"](args)` sends the same
  call. The workbook stays in Microsoft 365 and is edited in place: open a
  session, read the range, work out the change, write it, and read the
  result back, all naming the session's id, then close the session.
  `connector.schema` gives each tool's input, and `connector.list` shows the
  apps whose permissions the owner allowed.
- Any bound caller may call it: a code-mode run, an agent run, an agent's
  own credential, or the owner. A write from an anonymous off-record session
  is refused, as a secret grant is.
- A range write runs only with `mutation` set to `explicit_mutation`.
  Without it, the call shows what it would write and writes nothing. Every
  write reads the range back, and leaves two Gate receipts: one before the
  send and one after.

## When the check fails

- Microsoft refused the credential. The token expired, or access was
  withdrawn in the account's settings. Sign in again, store the new grant,
  and check again.
- Graph named no account. The grant lacks `User.Read`; sign in again asking
  for it with the allowed permissions.

## Afterwards

If the owner withdraws access in their Microsoft account, or withdraws a
permission here, the check goes stale and the agent cannot use that app until
it is checked again.
