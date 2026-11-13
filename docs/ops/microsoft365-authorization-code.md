# Microsoft 365 authorization-code exchange

`POST /v1/owner/packs/microsoft365/exchange` exchanges a Microsoft sign-in's
authorization code and stores a normal `microsoft365.oauth` credential for
the `oneiron.microsoft365` pack. It authenticates the owner. It is not a
keyless OAuth callback and does not start a browser sign-in or issue OAuth
state. It has the same shape as the Gmail exchange
(`docs/ops/gmail-authorization-code.md`).

The host that starts Microsoft sign-in must validate its own OAuth state
before passing the completed authorization to this door. Register the app's
exact redirect URI in the Microsoft Entra admin center, and pass that same
URI in the exchange. Ask for the scopes of the permissions the owner allowed
in the pack's setup (`https://graph.microsoft.com/Files.ReadWrite` for
Excel), `User.Read` for the connection check, and `offline_access`, without
which Microsoft issues no refresh token. A host that used PKCE also supplies
the matching verifier.

## Values enter only through the wiping secrets door

Use `POST /v1/owner/secrets/register` to register two opaque credentials with
a `connector:microsoft365` read binding. Use that endpoint's existing
encoded-value transport, not the pack setup answer or the exchange request
body.

- The client credential is JSON with `client_id`, `tenant`, and the
  `client_secret` of a web application (leave it out for a public client).
  `tenant` is the directory the sign-in ran against: `organizations` for any
  work or school account, `common` to take personal accounts as well,
  `consumers` for personal accounts only, or one directory's id or domain.
  Any other character in it is refused before anything is sent.
- The authorization credential is JSON with `code`, `redirect_uri`, and an
  optional `code_verifier`.

The exchange body contains their custody **names** only:

```json
{
  "client_secret": "microsoft.web-client",
  "authorization_secret": "microsoft.completed-authorization",
  "class": "custody-portable",
  "device_only": false,
  "rung": 0,
  "replace_existing": false
}
```

`source` optionally selects the pack's exact setup source. Storage settings
and `replace_existing` are explicit caller choices, as in the Gmail exchange.
The owner must prepare the pack's setup and allow the desired permissions
through the existing setup flow; exchanging a code grants no engine
authority.

The exchange reads both values through the native credential doors, calls
only the tenant's token endpoint on Microsoft's fixed sign-in origin
(`https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`), and stores
the access token, any returned refresh token, the client id and secret, the
tenant and the scopes Microsoft granted, as `microsoft365.oauth` bound for
read to `connector:microsoft365`. It then pins that credential through
`secret_stored` and runs the `microsoft365.me` check. The reply holds the
setup view and `refreshable`, never credential bytes. A refused exchange
names Microsoft's error code (such as `invalid_grant`), never its
description.

## Refresh

Each use of a stored grant that carries a refresh token, its client and its
tenant first gets a fresh access token from the tenant's token endpoint,
inside the credential door: the Excel connection's sends, the
`microsoft365.me` check, and the Graph mail, calendar and reply-send wires
of a Microsoft 365 mailbox source that names the record. The mail wires keep
one fresh token per source for a wire's life. Nothing fresh is stored.

Microsoft returns a newer refresh token with each refresh, and the engine
drops it: the stored grant keeps the refresh token its sign-in returned
(ASK MICROSOFT365-REFRESH-WRITEBACK). Microsoft's refresh tokens expire 90
days after they are issued, so a connection needs a new sign-in within 90
days. The check fails when Microsoft refuses the refresh: sign in again and
run the exchange with `replace_existing: true`.

A grant that names a tenant is never sent to Google's token endpoint, and a
Google grant names none, so it is never sent to Microsoft's.

## Mail and calendar

A Microsoft 365 mailbox source may name `microsoft365.oauth`, so one sign-in
serves mail and Excel (RULING L3-17-EXCEL-CONNECTION = B). Request the mail
scopes in the same sign-in. A calendar source reads through
`connector:microsoft365_calendar`; add that binding to the record through
the owner's secret binding door before a calendar source names it.

The two input custody records are not deleted by the exchange. Retire them
through the existing owner credential controls when no longer needed. No
code, verifier, token reply, client secret or provider error body is
returned or logged by this endpoint.
