---
name: oneiron-mail-calendar-setup
description: Connect a personal mailbox, a group address or a calendar to the shared vault, and set what each one keeps.
---

# Set up mail and calendars

Use this skill when a person wants a mailbox or a calendar in the vault, or
wants to change what a connected one keeps. Read the person's connected
sources first (`vault.mail.sources.list`); never connect a source twice.

## Which kind of source

- **A personal mailbox** (`oleksii@antevon.com`): the person connects it
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

The Owner stores every credential, and says whom it is for in the scopes of
its bindings (each `connector:` binding the pack reads through):

- The Owner's own mailbox or calendar: `read` only.
- A member's: `read` and `actor:` with the member's PERSON id, for example
  `actor:0123456789abcdef0123456789abcdef`. Only that member's sources take it,
  whoever connects them.
- A group address: `read` and `group-address`.

All the bindings of one credential name the same holder. A source refuses a
credential stored for someone else, and stops reading if the Owner rebinds it
to someone else later.

## An IMAP mailbox

For a mailbox that is not Google or Microsoft 365 (Fastmail, iCloud, a
company server), connect it with provider `imap`:

- The person stores, through the owner secrets form, a JSON credential for
  effector `connector:imap`: `host` (the IMAP server, for example
  `imap.fastmail.com`), `security` (`tls`, the default: TLS from the first
  byte, port 993; or `starttls`: the server's plain port, port 143, upgraded
  to TLS before anything else is sent, and refused if the server does not
  upgrade), `port` (only when the server uses another), `username`, and
  either `password` (an app password where the provider offers one) or
  `access_token` (OAuth, `XOAUTH2`).
- For drafted replies to send, the same credential also names the mailbox's
  submission server: `submission`, an object with `host` (for example
  `smtp.fastmail.com`), `security` (`starttls`, the default, port 587; or
  `tls`, port 465) and `port` (only when the server uses another). The same
  username and password, or token, sign in there. The person binds the
  credential to effector `connector:smtp` as well: a credential bound only to
  `connector:imap` reads mail and sends none.
- The provider account is `<username>@<host>`, exactly as stored: a credential
  for another account never fills the source.
- Every folder is read but drafts; trash and junk are only looked in.
  Folders become labels. A message moved to trash, or expunged, is deleted at
  the provider and follows the delete setting.
- An mbox export of the same mailbox, imported before or after, lands each
  message once.

## A CalDAV calendar

For a calendar on iCloud, Fastmail, Nextcloud or another CalDAV server,
connect it with provider `caldav` and kind `calendar`:

- The person stores, through the owner secrets form, a JSON credential for
  effector `connector:caldav_calendar`: `url` (the CalDAV server over HTTPS,
  for example `https://caldav.icloud.com/` or `https://caldav.fastmail.com/`),
  `username`, `password` (an app password where the provider offers one),
  and `calendar` (the calendar's name as the person sees it; the first
  calendar that holds events when absent).
- The provider account is `<username>@<host>`, the host the URL's, exactly as
  stored.
- One source reads one calendar. Connect another source for each other
  calendar the person wants counted.
