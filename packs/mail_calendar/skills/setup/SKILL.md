---
name: oneiron-mail-calendar-setup
description: Connect a personal mailbox, a group address or a calendar to the shared vault, and set what each one keeps.
---

# Set up mail and calendars

Use this skill when a person wants a mailbox or a calendar in the vault, or
wants to change what a connected one keeps. Read the person's connected
sources first (`vault.mail.sources.list`); never connect a source twice.

## Which kind of source

- **A personal mailbox** (`owen@example.com`): the person connects it
  themselves, and it reads to them alone. Never connect someone else's
  personal mailbox for them.
- **A group address** (`hello@`, `legal@`, `billing@`, `team@`): an Owner or
  an Admin connects it once, as the group, and names the people who read it.
  A copy of group mail delivered to someone's personal mailbox belongs to that
  personal mailbox; it does not make the group's members its readers.
- **A calendar**: the person connects their own. The vault sees when they are
  busy or free; the event details stay theirs unless they share the calendar
  in detail.

## What a mailbox keeps

Ask once, at connect, and say what each choice means:

- **Keep a copy of my mail.** All mail is the default and what the owner
  prefers. Recent months only keeps the newest mail. Search only keeps the
  mail a search fetched, and the headers of what it found.
- **When I delete at the provider.** Keep in memory is the default: the
  message leaves the live inbox and stays as a labelled source-deleted copy.
  Forget too forgets it in the vault as well.

A big mailbox copies slowly; say so once. A Google Takeout export to the
person's Google Drive speeds it up.

## Credentials

The credential is stored through the owner secrets form under a custody name.
Pass only that name to the connect call. Never ask for a password or a token
in chat, and never repeat one back.
