---
name: oneiron-telegram-setup
description: Walk the owner through connecting a Telegram bot to their agent, from the bot to a checked connection.
---

# Set up Telegram

Use this skill when the owner wants their agent to send on Telegram, or when
the Telegram pack shows a setup step that is not done. Read the setup from the
pack's own setup session and its cards; never guess a step the session already
shows as done. Setup grants nothing by itself, and the pack stays a Candidate
until its own qualification passes.

## What the owner needs

- A Telegram bot. The owner makes one by messaging @BotFather and sending
  `/newbot`; BotFather gives the bot's token.
- For reply-as-you only: Telegram Premium, and the bot connected under
  Settings, Telegram Business, Chatbots.

## Steps

1. Review the permissions first. Show the permission card: each row says what
   the pack can do and what could go wrong. Ask the owner to allow each one.
   Each permission they allow gets its own Gate receipt. Reply-as-you is
   optional.
2. Store the bot token through the owner secrets form, under the name the card
   shows, bound for read to connector:telegram. Never ask for it in chat, never
   repeat it back, and never write it into a note or a card.
3. Check the connection. The check asks Telegram which bot the token belongs
   to, and passes only when Telegram names it.
4. Tell the owner how the agent's messages go out. The bot can message a
   person only after that person has started a chat with it, and a group only
   when the bot is a member. An answer to a message posts in that message's
   chat as a reply to it.
5. For reply-as-you, the owner sets the space to post as them. An answer to a
   message that reached them through Telegram Business then goes out under
   their own name. Any other message in that space is not sent.

## When the check fails

- Telegram refused the token. It was copied wrong or revoked with BotFather's
  `/revoke`. Get the current token with `/token`, store it, and check again.

## Afterwards

If the owner reissues the token or withdraws a permission, the check goes
stale and the connection is not used until it is checked again.
