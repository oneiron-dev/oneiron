# Embedded shared-vault membership revocation

The embedded `vault.members.change`, `vault.members.remove` and
`vault.members.leave` calls use the install's own host slip issuer when the
caller supplies none. The existing person and named admin-power checks still
authorize the membership change. The host's signature records its execution,
not owner authority.

The engine checks that issuer against the authority roster in the same write
transaction as the membership change. The vault must have a root, that root
must not be conflicted, and the issuer must still be a live host. If the install
holds no live issuer, the membership change keeps its existing no-issuer path.
An explicitly supplied issuer keeps its existing behavior.

A lower-ranked role, removal or leave revokes the member's held capability
slips. When that change drops a grant created by a signed GitPush or owner-agent
mint, the host records its signed withdrawal too. Those records, the grant
changes and the existing receipt commit together. The receipt lists the revoked
slips, and credential-revocation listeners are notified after commit.

These calls cannot change an Owner's role. Ownership transfer and Owner removal
still use their existing shared acts and signed `OwnerHandover` records. This
change adds no group rekey, approval, wait, receipt field or configuration.
