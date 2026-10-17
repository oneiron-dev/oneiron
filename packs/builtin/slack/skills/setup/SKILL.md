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
   manifest and pastes the manifest the setup shows (`app_manifest`, also at
   `GET /v1/owner/packs/slack/manifest`). It already names this host's URLs:
   Event Subscriptions and Interactivity go to `/v1/hooks/slack/events`, and
   the OAuth redirect to `/v1/hooks/slack/oauth`, each after the host's public
   address. It asks for exactly the scopes on the permission card, and
   subscribes the bot to `app_mention` and `message.im`.
3. Store the app's Client ID, Client Secret and Signing Secret, from its Basic
   Information page, through the owner secrets form, under the names the card
   shows, each bound for read to connector:slack. Never ask for any value in
   chat, never repeat one back, and never write one into a note or a card.
4. Install the app. `POST /v1/owner/packs/slack/install` returns a link; the
   owner opens it in the browser signed in to the workspace and approves. Slack
   sends them back to the host, which stores the bot token and checks the
   connection. The link works once, for ten minutes.
5. The check asks Slack who the app is and which scopes it holds. It passes
   only when Slack names the workspace and the scopes match what the owner
   allowed, no more and no less. The install page says whether it passed; the
   owner can check again from the setup.
6. Once the check passes, the host answers Slack's events within a minute. If
   Slack showed the Request URL as unverified when the app was made, press
   Retry on the app's Event Subscriptions page. Each event is verified with the
   Signing Secret before it is kept.

## When the check fails

- Slack refused the credential. The app was reinstalled and Slack issued a new
  one, or the token was revoked. Install again from a new install link.
- The provider did not grant a scope. The app was installed before its manifest
  asked for it. Install again from a new install link.
- The credential holds a permission the pack never explained. Remove that scope
  from the app, reinstall it, and check again.

## Afterwards

If the owner later changes the app, rotates a value, or withdraws a permission,
the check goes stale and the connection is not used until it is checked again.
