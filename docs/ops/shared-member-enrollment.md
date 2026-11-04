# Accepting a shared-vault invitation with a credential

`vault.members.accept_with_credential` is the explicit credential-producing
sibling of `vault.members.accept`. Plain acceptance keeps its existing request
and receipt and does not require a host signing key.

## Request and result

The new request has three required fields:

- `vault_id`: the shared vault ID as a decimal string.
- `invitation`: the invitee's invitation ID.
- `expires_at`: the expiry to use for the new member slip. The caller chooses
  it; this operation adds no default or maximum lifetime.

Call the operation as the invited person with the holder-signed credential for
that invitation. The host uses its existing slip issuer. The public binding key
comes from the verified invitation request, not from a request-body key or a
replacement owner credential. The invitee keeps the corresponding private key.

The result contains `receipt` and a nonoptional `credential`. The credential
contains `slip_id`, `slip`, and `expires_at`. Acceptance, the new membership grant,
the member slip mint, and the acceptance receipt use the same acting writer.
If any part fails, the writer does not commit acceptance alone. A host without
the required issuer or request proof reports the missing capability rather than
returning an empty credential after accepting.

## Using the returned credential

Use the returned slip through the normal holder-signed request path with the
same private key. Native verification binds it to the actual live membership
grant and meets its effective Scope with the grant's current six-axis Scope.
Role changes, withdrawal, deletion and expiry do not grant continuing authority
to an older cached proof. See [member-credentials.md](member-credentials.md) for
the native verification contract.

A shared-vault Admin grant may include `org:*` verbs without naming an
organization. Those verbs do not invalidate its ordinary read/write/admin
transport authority. They also do not grant organization API powers: those
still require an explicitly organization-bound credential. The member token's
grant Scope and its absent organization reference are not rewritten.

## Remaining enrollment work

This operation returns a member credential; it does not create a local shared
replica, choose a local vault directory, write the invitee's credential file,
open a shared environment, or insert it into the running host registry.
Dedicated environment bootstrap and insertion remain separate work. The normal
full-replication owner endpoint is not a member-bootstrap endpoint.

Update the engine/server and generated clients together to use this new verb.
There is no configuration, storage-format, dependency or migration change.
