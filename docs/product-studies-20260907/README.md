# Product studies, 2026-09-07 — Grok Bot and Squad

Two headless grok legs (xAI grok CLI, first-party pages + X, retrieved 7 Sep 2026), run
because the owner asked whether the chat-with-agents idea should follow Grok Bot / squad.so.
Raw reports, unedited apart from stripping the CLI's narration line:

- `grok-grokbot-product.md` — Grok Bot by xAI (launched 11 Aug 2026).
- `grok-squad-product.md` — Squad, ex-MissionControlHQ (renamed Aug 2026, "vs Grok Bot" push 3 Sep 2026).

## What both say, in one screen

- Both are **chat-first, not chat-only.** Grok Bot: chat → skill → routine → Routines panel,
  plus Edit Profile / Settings → Plugins. Squad: Lead chat → dashboard (mission board, tickets,
  runs ledger, docs, settings). Progressive disclosure is the category norm already.
- **Setup by conversation is shipping** at Squad: the Lead interviews you for 10–15 minutes,
  proposes named roles, creates the specialists, sets the first schedules. Grok Bot is a form
  for identity (name, title, description, avatar) and chat for the work.
- **Where consent lives is the real split.** Grok Bot: "never send without approval" is copy in
  the bot description, approvals interrupt the transcript, no approval inbox. Squad: a "Needs
  you" ticket column, draft-for-review enforced at send time, daily send caps, pause.
- **Where finished work lands.** Grok Bot: in the thread (the transcript is the status board).
  Squad: cards, Done column, per-agent inbox at 07:00, end-of-day digest, per-run receipts.
- **Credentials.** Grok Bot: one cloud computer per user, every bot shares its logins ("do not
  use separate Bots as a security boundary"). Squad: one machine per customer, browser profile
  per agent, vault that never echoes into chat.
- **Neither has a product API, voice setup, or per-agent scoped skills.**
- "Normie tier" for Grok Bot is not a sourced nickname; reviewers say "iMessage to Slack"
  (Mo Bitar, 25 Aug) and "Chief of AI agents" (Gergely Orosz, 7 Sep).

## Read for Oneiron

Oneiron's inbox, vault and consent gates are exactly the pieces both verdicts say to steal from
Squad and that Grok Bot lacks. The missing piece on our side is the chat door: a named roster
you can talk to, group chat as visible handoff, and set-up-by-conversation that opens the
existing agent form beneath it. Finished work should keep landing in the inbox as a card, not
as a speech bubble. Canon pages in oneiron-docs get minted only on the owner's go.

## 09-08 addendum: prior art on concurrent sessions and subagents

Raw Grok leg in `prior-art-concurrency-ui.md` (Paperclip, T3 Code, Cursor, Devin; the Codex, Claude Code and messenger sub-questions returned no claims block). Cross-cut: no product lists subagents as top-level rows; they live inside the parent session (T3 right-panel Agents surface, Cursor in-session cards, Devin subagent panel, Paperclip run cards). Sessions or threads are the top-level list, grouped by state (T3: pinned / active / snoozed / settled; Devin: kanban by status). Steering and stop go to the parent thread or run, never to a child.
