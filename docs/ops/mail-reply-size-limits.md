# Mail reply size limits

A drafted mail reply may carry files: pinned versions of artifacts the drafter
reads. The engine writes the whole message once, at draft, and sends exactly
those bytes. Each send rail has one size limit. The limit applies to the
complete message, not to the sum of the files.

## What is counted

The counted message is the exact RFC 5322 message the engine froze at draft:
every header, the text and HTML body, every MIME boundary, and each file's
base64 lines with their CRLF line ends. The engine never splits, shrinks or
sends again a message that is over its limit. It refuses the whole draft or
the whole send.

## The three rails

| Rail | Mailbox | Unit | Limit |
|---|---|---|---|
| Gmail `users.messages.send` | Google | The message octets, before Gmail's own base64url | 36,700,160 octets (35 MiB) |
| Graph MIME `sendMail` | Microsoft 365 | The POST body: the standard padded base64 of the message | 4,000,000 bytes (at most 3,000,000 message octets) |
| SMTP submission | IMAP | The message octets: CRLF MIME, not the dot-stuffed data, not the final `.<CRLF>` | The server's advertised `SIZE`, else `mail.smtp.max_message_octets_unadvertised` |

Gmail and Graph limits are fixed. No upload session, remote draft or second
message is used for a larger reply.

## SMTP: the advertised SIZE and the host setting

An SMTP server names its limit in its `EHLO` answer over TLS (RFC 1870). A
positive number after `SIZE` is the limit. If `SIZE` is absent, has no number
or is 0, the server names no limit. The host setting then applies.

An advertised `SIZE` always wins over the host setting, larger or smaller.

The host setting is in the server config file:

```toml
[mail.smtp]
max_message_octets_unadvertised = 36700160   # the default (35 MiB)
```

The value must be at least 1. It is host policy, not an SMTP or provider
limit. A host that installs no mail settings uses the default.

## When the SMTP limit is checked

1. **At draft.** Before any file is read, the engine opens a session to the
   mailbox's submission server with the mailbox's own submission credential:
   TLS, `EHLO`, `AUTH`, the limit read, `QUIT`. It never sends `MAIL`, `RCPT`
   or `DATA`. The frozen message must fit the limit before the draft lands and
   the owner is asked. If the check cannot be made, the draft is refused.
   Each step has a deadline: the host name's resolution, the connection, TLS
   and `EHLO` share the SMTP client's connect deadline; `AUTH` and `QUIT` each
   have its command deadline. The server must answer `QUIT`. A step past its
   deadline, or an unanswered `QUIT`, refuses the check.
2. **Before the press.** The engine asks the server again. If the message no
   longer fits, or the check cannot be made, the press is refused and nothing
   is approved. The draft view shows the limit (`smtp_limit_octets`) and when
   it was read (`smtp_limit_read_at`). That record is information for the
   reviewer, not a lasting permission.
3. **At the send.** The sending session reads `SIZE` again after TLS. Above
   that session's limit, or above the host setting when the server names
   none, the send is refused before `MAIL`. When the server offers `SIZE`,
   `MAIL FROM` declares the message octets (`SIZE=<N>`).

A reply without files is not checked at any of these steps. It is submitted
as before: no limit is checked before `MAIL`, and `MAIL FROM` declares no
`SIZE`.

## What a check is bound to

Each check records what it was read from:

- the mailbox source;
- the custody record that holds the mailbox's credential, and that record's
  value generation;
- the submission server (host and port) that the credential names;
- the host setting it applied, when the server named no limit.

The draft is published, and the press is made, in one write each. That write
reads the mailbox source and its credential record as they are at that time.
It uses the check only if the source still names the same credential record,
the record is still at the same generation, and, for a server that named no
limit, the host setting is unchanged. The submission server comes from the
credential's value, so the same record at the same generation names the same
server. The exact frozen message must then fit the check's limit.

If any of these changed, for example the mailbox was reconnected with
another credential, the credential was rotated or the setting was changed,
the write is refused. Nothing is published, asked or approved. Draft again,
or approve again: each call asks the server again before its write.

The press write also keeps its new check only over the check the draft held
when that press read the draft. If another press recorded a check in
between, this press is refused. Approve again: the next press asks the
server again. No timestamp decides which check is newer.

The check runs inside the caller's own call, with the caller's own handle and
the mailbox's own credential, and with no store transaction open. A served
vault runs it on the server's blocking hop, so it holds no async runtime
worker. A host that installs no blocking runner (an embedded vault, a CLI, a
test) never runs the check. There, an IMAP reply with files is refused at
draft and at the press, before any file is read and before anything is
published. It is never drafted or pressed unchecked.

## A late refusal

A server can still refuse the message after `MAIL`, for example when it
lowers its limit. That refusal is a failed send, recorded by the outbound
ledger as any refused send is. The engine does not retry, does not send a
smaller message and does not send a second one. The owner drafts again.
