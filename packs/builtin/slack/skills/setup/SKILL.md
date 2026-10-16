---
name: oneiron-slack-setup
description: Walk the owner through connecting Slack to their agent, from the workspace and app to a checked connection.
---

# Set up Slack

Use this skill when the owner wants their agent on Slack, or when the Slack
pack shows a setup step that is not done. Read the setup from the pack's own
setup session and its cards; never guess a step the session already shows as
done. Setup grants nothing by itself, and the pack stays a Candidate until its
own qualification passes.

## What the owner needs

- A Slack workspace where they may install apps. A workspace admin may have to
  approve the app.
- About ten minutes, and a browser signed in to that workspace.

## Steps

1. Review the permissions first. Show the permission card: each row says what
   the app can do and what could go wrong. Ask the owner to allow each one; the
   app cannot work without them. Each permission they allow gets its own Gate
   receipt.
2. Make the app. At api.slack.com/apps the owner creates a new app from a
   manifest and pastes the manifest the host shows for the Slack adapter. The
   manifest asks for exactly the scopes on the permission card.
3. Install the app to the workspace. Slack then shows the Bot User OAuth Token
   on the app's OAuth and Permissions page, and the Signing Secret on its Basic
   Information page.
4. Store both values through the owner secrets form, under the names the card
   shows, each bound for read to connector:slack. Never ask for either value in
   chat, never repeat one back, and never write one into a note or a card.
5. Check the connection. The check asks Slack who the app is and which scopes
   it holds. It passes only when Slack names the workspace and the scopes match
   what the owner allowed, no more and no less.

## When the check fails

- Slack refused the credential. The value was copied wrong, or the app was
  reinstalled and Slack issued a new one. Store the current one and check again.
- The provider did not grant a scope. The app was installed before its manifest
  asked for it. Reinstall the app, store the new value, and check again.
- The credential holds a permission the pack never explained. Remove that scope
  from the app, reinstall it, and check again.

## Afterwards

If the owner later changes the app, rotates a value, or withdraws a permission,
the check goes stale and the connection is not used until it is checked again.
