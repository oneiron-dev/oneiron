# Shared invitation acceptance with HTTPS source context

The Rust SDK's `OneironClient::accept_shared_invitation_https` calls the same
`vault.members.accept_with_credential` facade verb as ordinary acceptance. It
uses the existing remote HTTP client, credential headers, holder proof, request
limits, invocation hooks and reply decoder. It does not add a transport or a
second acceptance writer.

Use an invitee's invitation credential on a connected HTTPS home. The returned
`HttpsSharedInvitationAcceptance` retains:

- the intended normalized home and exact acceptance URL;
- the selected shared vault, invitation and requested credential expiry;
- the logical invocation and the recipient's binding key;
- the complete successful native receipt and member credential.

The value has private fields and no deserialization constructor. It is created
only after a successful call over the SDK's built-in HTTPS wire. An embedded
handle, an in-process transport, cleartext loopback or an arbitrary decoded
receipt cannot create it. These checks run before the acceptance is submitted.
Ordinary invitation acceptance remains available unchanged on those other
backends.

If a runtime hook returns `PENDING_ASK`, use
`retry_shared_invitation_https` with that refusal and the same request and
invitation credential. It reuses the pending invocation. A generic decoded
retry response is not an HTTPS acceptance value.

`reply()` preserves the successful receipt. `member_client()` creates an
ordinary facade client using the returned member token and the same recipient
key, home and HTTP wire. The home admits every later call under the current
member grant. If creating that client fails, the successful acceptance reply
remains available; there is no claim that the committed membership rolled back.

This is source context, not permission to import a replica. Token decoding alone
does not authenticate authority or widen a scope. Native signed-history/refold,
first-grant/holder/token checks, all six current scope axes, the selected window
and fresh request binding still need to succeed before an atomic local bootstrap
publishes authority or content. This API does not open or register a dedicated
local environment, write a credential file, create an owner or machine identity,
or open the owner's full-replication `/ws` door.
