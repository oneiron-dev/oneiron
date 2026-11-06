# Gmail authorization-code exchange

`POST /v1/owner/packs/gmail/exchange` exchanges a Google **web application**
client's authorization code and stores a normal `gmail.oauth` credential.
It authenticates the owner. It is not a keyless OAuth callback and does not
start a browser sign-in or issue OAuth state.

The host that starts Google sign-in must validate its own OAuth state before
passing the completed authorization to this door. Configure the client's
exact redirect URI in Google Cloud. Pass that same URI in the exchange,
including an HTTP localhost URI when Google permits it for that client.
Request the setup's allowed Gmail scopes. Request offline access if the host
needs a refresh token; Google may omit one on a later authorization. A host
that used PKCE also supplies the matching verifier. A public-client-only
PKCE flow is not assumed by this endpoint.

## Values enter only through the wiping secrets door

Use `POST /v1/owner/secrets/register` to register two opaque credentials with a
`connector:gmail` read binding. Use that endpoint's existing encoded-value
transport, not the pack setup answer or the exchange request body.

- The client credential is JSON with `client_id` and `client_secret`.
- The authorization credential is JSON with `code`, `redirect_uri`, and an
  optional `code_verifier`.

These are credential **values**, not ordinary request examples to log or
place in a URL. The exchange body contains their custody **names** only:

```json
{
  "client_secret": "google.web-client",
  "authorization_secret": "google.completed-authorization",
  "class": "custody-portable",
  "device_only": false,
  "rung": 0,
  "replace_existing": false
}
```

`source` optionally selects the email pack's exact setup source. All storage
settings and `replace_existing` are explicit caller choices, with no new
storage defaults. The example chooses portable, replicating, doored custody.
The owner must prepare the email setup and allow the desired permissions
through the existing setup flow; exchanging a code grants no engine authority.

The exchange reads both values through the native credential doors, calls
only Google's fixed token endpoint, and stores its access token, any returned
refresh token, and the client metadata as `gmail.oauth`. It then pins that
credential through `secret_stored` and runs the normal Gmail profile check.
The reply contains the setup view and `refreshable`, never credential bytes.
A failed profile check stays visible in the setup view; the stored grant can
be checked again through the normal setup door.

With `replace_existing: false`, native name-collision behavior leaves a live
`gmail.oauth` unchanged. With `true`, the owner explicitly asks the native
custody rotation door to replace that credential. Rotation retains the live
record's custody policy. The exchange never appends an old refresh token to a
new authorization: it might belong to a different Google account. If Google
returns access only, `refreshable` is false, including after an explicitly
requested replacement. Request a new offline consent grant if a refresh token
is needed. A Google code is single-use; if custody storage fails after Google
accepts it, the host must obtain a fresh authorization before retrying.

The two input custody records are not deleted by the exchange. Retire them
through the existing owner credential controls when no longer needed. No
code, verifier, token reply, client secret or provider error body is returned
or logged by this endpoint. Provider scopes do not authorize Gmail sends.

Existing bare access tokens and stored access/refresh grants keep their
existing verification, read and send paths. This addition does not implement
browser sign-in, an engine-issued Google callback, or uncertain-send retries.
