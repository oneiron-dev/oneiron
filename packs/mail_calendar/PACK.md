---
name: oneiron.mail_calendar
description: Mail and calendars in one shared vault: personal mailboxes private to their owner, group addresses read by their members, calendars busy/free to the vault and in detail only when shared
version: 0.1.0
license: Apache-2.0
kind: capability
---

# Mail & Calendar

This pack connects mailboxes and calendars into the vault (owner ruling
MAIL-SHARE, MAIL-DELETE, MAIL-PROVIDERS and MAIL-VIEW = A, 2026-11-03). It is
a pack, not engine core: install it to connect a source; a vault without it
connects none.

## Who reads what

- **A personal mailbox reads only to its owner.** The person who connects it
  is its owner. Its messages, their attachments and every fact learned from
  them read to that person and to their own agents alone. The vault's Owner
  and its Admins do not read it by their role.
- **A group address is connected once, as the group.** An Owner or an Admin
  connects `hello@` or `legal@` and names its members. The members read it;
  a member removed reads none of it from then on.
- **A thread is shared only by an explicit act.** A person who reads a thread
  may share it with another person. The share reaches that thread alone,
  never the mailbox, and the person who shared it, or any reader of the
  source, may withdraw it.
- **Calendars show busy and free to the vault.** An event's details read only
  to the calendar's owner unless the owner shares the calendar in detail.
- **Org compliance search is the org admin's setting, off by default.** While
  it is on, an Owner or an Admin may search across mailboxes, and every use
  is logged before anything is answered.

## What a mailbox keeps

- **Keep a copy of my mail:** all mail (the default), the recent months only,
  or search only.
- **When I delete at the provider:** keep it in memory (the default) or forget
  it too. Kept, a deleted message leaves the live inbox and stays as a
  labelled source-deleted copy; the facts drawn from it are checked again.
- Trash and spam are never ingested.

## Providers

Staged as ruled: Google Workspace first, then other Google accounts,
Microsoft 365, IMAP, and CalDAV or ICS calendars.

## Skills

| skill | loads when |
|---|---|
| `setup` | someone connects a mailbox, a group address or a calendar, or changes what it keeps |
| `mail-calendar` | an agent reads, searches or answers mail, or reads a calendar |
