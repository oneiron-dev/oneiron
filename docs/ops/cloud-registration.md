# Cloud registration: pins, link, refresh, logout

The engine links a vault to the owner's Oneiron cloud account (G7). The
owner approves the link on the issuer's page, over the RFC 8628 device
grant. The engine keeps the token family in its own custody. Every act is
the owner's: login, status, refresh and logout. Nothing runs on a timer.

One client serves one open vault. `oneiron account` drives it on a stopped
vault. A running server answers the same acts at
`/v1/owner/cloud-registration/*` (start, poll, status, refresh, logout).

## Pins

Trust comes from the operator's pins file alone. Nothing is discovered
into trust: discovery only locates the endpoints, the `jwks_uri` is never
fetched, and no token carries a key.

The file is public JSON:

```json
{"issuer": "https://issuer.example", "audience": "https://issuer.example/oauth/registration", "keys": [
  {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "...", "n": "...", "e": "..."}
]}
```

The issuer is a canonical https origin. The audience is the issuer plus
`/oauth/registration`. Each key is an RSA public signing key: `kty` RSA,
`alg` RS256, `use` sig, a nonempty unique `kid`, base64url `n` of at
least 3072 bits, and base64url `e`. Any private member refuses the file.

The path is `--cloud-registration-pins`, an absolute path, on `serve`
and on every `account` command. The server reads the file once at start.
Each `account` command reads it at its own start. A file absent,
unreadable or invalid leaves this feature alone `not_configured`, with
the reason. Serve, other auth and the anonymous training window go on.

## Commands

`oneiron account` works on a stopped vault. Holding the vault's writer
lease is the owner proof. Each command prints its result as JSON on
stdout. No token or code goes to argv, a log or stdout.

- `login [--replace]` starts a login. It prints the verification address
  and the code on stderr, apart, and polls at the issuer's pace until the
  login is approved, denied or expired. The code lives at most 600
  seconds. `--replace` lets a different cloud account replace the
  current link. Without it, another account's approval stores nothing
  and revokes the new tokens.
- `status [--refresh]` shows where the link stands. It reads only: it
  never rotates a family. `--refresh` refreshes first.
- `refresh` rotates the token family once, then checks it online.
- `logout [--erase]` stops the link here and asks the cloud to revoke
  it. `--erase` erases every token this vault kept for it first.

Status is one of: `signed_out`, `registered`, `needs_refresh`,
`needs_login`, `unavailable`, `failed`, `not_configured`, or `erasing`.
`erasing` still keeps value-free rows; `complete` false is pending, never
failed.

## Lifecycle

Login is a device flow. Discovery reads the issuer's `auth.md` locator,
checks its metadata against the pins, and takes the endpoints only when
each is an https URL on the issuer's own origin. The owner opens the
verification address, enters the code there, and approves. The approved
tokens are verified against the pins before anything is stored. The
cloud subject has the form `cp-owner:<account>:<revision>`.

Refresh is explicit and serialized: one rotation at a time under the
family lock and this process's writer lease. The link is reserved first,
the refresh token leaves once, and a verified successor commits with
its generation. A lost or uncertain answer, `invalid_grant`, an answer
off the wire or the pins, or a changed subject stops the link at
`needs_login`: the owner logs in again. No spent token is ever sent
twice. Any 503 is `unavailable`, with the issuer's description verbatim.

Logout copies the refresh token out first, stops the local binding,
then tries the RFC 7009 revoke with that copy. `logout --erase` is the
owner's erase: every slot fenced and crypto-shredded first, under every
issuer when no pins name one, and the revoke tried after. The local
result and the revoke's own result are reported apart. A delete keeps
the tokens. Switching the feature off does nothing to them.

## Key rollover

Rollover is a new pins file plus a restart. The client reads the pins
once at start and holds no other key source. A token whose `kid` the
pins do not hold is rejected. There is no automatic key transport.

## What the client wipes

Every form is encoded into one buffer, and every answer body is read
into one. Each buffer is sized before it is written, and wiped on drop.
Token replies, codes and held tokens are wiped the same way. The HTTP
stack's own buffers still hold copies: reqwest's body chunks, hyper's
and TLS's. Nothing here wipes those.
