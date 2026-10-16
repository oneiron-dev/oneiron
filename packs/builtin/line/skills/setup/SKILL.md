---
name: oneiron-line-setup
description: Walk the owner through connecting a LINE Official Account to their agent, from the account to a checked connection.
---

# Set up LINE

Use this skill when the owner wants their agent on LINE, or when the LINE pack
shows a setup step that is not done. Read the setup from the pack's own setup
session and its cards; never guess a step the session already shows as done.
Setup grants nothing by itself, and the pack stays a Candidate until its own
qualification passes.

## What the owner needs

- A LINE Official Account. The owner can make one at entry.line.biz.
- The Messaging API turned on for that account in LINE Official Account
  Manager. Turning it on makes the account's channel in the LINE Developers
  Console.

## Steps

1. Review the permissions first. Show the permission card: each row says what
   the pack can do with the account and what could go wrong. Ask the owner to
   allow each one. Each permission they allow gets its own Gate receipt.
2. In the LINE Developers Console, open the account's channel. On its
   Messaging API tab, issue a long-lived channel access token. On its Basic
   settings tab, find the channel secret.
3. Store both values through the owner secrets form, under the names the card
   shows, each bound for read to connector:line. Never ask for either value in
   chat, never repeat one back, and never write one into a note or a card.
4. Set the webhook URL the host shows on the channel's Messaging API tab, and
   turn webhooks on, so messages reach the agent.
5. Check the connection. The check asks LINE which Official Account the access
   token belongs to, and passes only when LINE names it.

## When the check fails

- LINE refused the credential. The access token was copied wrong, reissued, or
  revoked. Issue a new one, store it, and check again.
- The check passes but no message arrives. The webhook is off or points
  elsewhere; the check proves the token, not delivery.

## Afterwards

If the owner reissues a value or withdraws a permission, the check goes stale
and the connection is not used until it is checked again.
