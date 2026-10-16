---
name: oneiron-linkedin-setup
description: Walk the owner through connecting LinkedIn to their agent through a signed-in session, with the risks of acting as them.
---

# Set up LinkedIn

Use this skill when the owner wants their agent to work their LinkedIn inbox,
or when the LinkedIn pack shows a setup step that is not done. Read the setup
from the pack's own setup session and its cards; never guess a step the
session already shows as done. Setup grants nothing by itself, and the pack
stays a Candidate until its own qualification passes.

## Say this first

The connector acts as the owner, through the owner's own signed-in session.
LinkedIn may limit or restrict an account it judges automated. Every message
and every connection request goes out under the owner's name. Make sure the
owner accepts that before going on.

## Steps

1. Review the permissions. Reading the inbox, sending messages and sending
   connection requests are each a high risk. Connection requests are optional;
   the owner may leave them off. Each permission they allow gets its own Gate
   receipt.
2. The owner signs in to LinkedIn in their own browser. The password stays with
   them; it never reaches the vault and never passes through chat.
3. Store the signed-in session cookie through the owner secrets form, under the
   name the card shows, bound for read to connector:linkedin. Never ask for it
   in chat and never repeat it back.
4. Check the connection. The check reads the signed-in member through the
   host's LinkedIn session. It never sends a message or a connection request.

## When the check fails

- The session ended. LinkedIn signs sessions out; sign in again, store the new
  cookie, and check again.
- This host has no LinkedIn check. The connection stays unchecked and the pack
  does not use it until a host that can check it does.

## Afterwards

If the owner signs out everywhere, rotates the cookie, or withdraws a
permission, the check goes stale and the connection is not used until it is
checked again.
