# Recipient-bound shared brief links

`vault.shares.issue_view_link` issues a pairing link for one existing, admitted
brief share. The caller must be that share's issuer or the vault's live owner.
The link fixes the recipient from the share; the caller does not supply a new
recipient. It also fixes an explicit `actor_class` (`human`, `agent` or `system`)
and the requested `slip_lifetime_secs`, subject to the existing credential policy.
There is no new lifetime default or approval step.

Call `POST /v1/core/facade/vault.shares.issue_view_link` with the authenticated
caller's usual holder proof and this input:

```json
{"share_ref":"<share id>","actor_class":"human","slip_lifetime_secs":3600}
```

The answer is the ordinary pairing link (`code`, `expires_at`, checkpoint `pin`
when present, and `comm`). Deliver it to the recipient through a private channel.
The example lifetime is caller input, not a new engine default.

The recipient redeems through the existing pairing flow. Their own connection
key signs the code, holder and checkpoint-pin transcript. The same writer checks
the share is still live and belongs to that holder, mints the credential, and
consumes the code. It does not create a resident identity or enrol a machine.
The existing pairing-code lifetime, signature, host-key and pin checks remain.

The signed credential names this share in `share_ref`. Its only verbs are
`vault.shares.view` and `vault.notes.follow_citation`. It carries neither `read`
nor `core:read`; ordinary memory reads and general raw-record reads do not accept
it. A delegated or attenuated credential cannot remove the share binding or add
a general read verb. It is not an owner, support or federation-grant credential.

The two share doors use a private rendering lane under the same verified holder
proof. Each use checks the live admitted share, its recipient, expiry and deletion
state. The existing share evaluator applies the current maximum, request narrowing
and live read policy. The existing renderer keeps its pin selection, source
permissions, secret masking, redacted citations and born-with travel choice.
No raw NOTE document, pin metadata or private rendering key is returned.
Revoking or deleting the share stops its view credential as well.

Existing resident views and credentials without `share_ref` keep their original
read lane. This is the current credential/wire format; no migration or old-format
reader is included.
