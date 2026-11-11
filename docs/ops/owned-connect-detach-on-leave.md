# Connect detach on member leave

An owner minting a Connect guest grant can attach a local release setting,
`detach_on_member_leave`, naming one shared vault. When the person named in
the setting genuinely leaves that shared vault, this vault withdraws the
Connect grant here. The setting selects which grants a leave releases; it
proves nothing about the peer vault and grants no authority.

The served Owner mint stores the actual owner the writer revalidated,
never a caller person id. Its shared-vault creation and Owner roster check
stay unchanged. Without the setting the grant keeps generic shared Connect
behavior and its body encodes exactly as before. The setting rides a Connect
guest grant only.

The native `Vault::mint_connect_grant` also accepts a distinct member's
`ConnectMemberLeaveConsent`: a shared-vault id and that person's existing
`AuthenticatedOwner` proof, alongside the original minting Owner proof. The
mint still requires Owner authority and the original scope ceiling. In the
same writer it revalidates the member as a live person of this vault's open,
checks the actual shared creation, and requires current member standing,
including grant expiry, row liveness and pact activation. A scoped Guest or
Delegate alone is not membership. The persisted setting names that actual
person, never the synthetic Connect guest actor or a peer key.

This is a local release choice jointly presented to the native mint. It
proves no personal ownership or kind of the remote vault. The existing HTTP,
facade and SDK Owner-self setting is unchanged; it presents the same Owner
proof for both roles. Distinct-member authentication and consent transport
for those remote doors are not implemented by the native parameter.

A genuine leave is a self leave, a member removal, a recovery that moves the
prior owner out, or an ownership transfer or removal whose kept role is none.
A downgrade to another role, an owner addition and any keeps-some-role
handover release nothing. Shared writings and property bytes stay untouched.

The leave attempts to withdraw each bound grant, including inert grants behind
outstanding offers. Each attempt uses its own nested savepoint and the existing
guest-revoke effect: pact disconnects, slip revokes, the signed grant revoke,
the grant withdrawal, the row delete and the withdrawal row. A successful
withdrawal also prevents an outstanding offer from activating. One grant's refusal rolls
back alone and is listed truthfully; the membership still progresses. With no
host issuer in the writer, every bound grant is listed as refused for it.

The durable receipt reports the local outcome only: the grants actually
withdrawn and the per-grant typed remainder still standing. Withdrawn grant ids join the receipt's grant list; revoked slip ids join its
revoked-slip list, so credential listeners fire after commit. Ownership handovers truthfully include the new local effect in their
affected ids. A local withdrawal is not peer delivery, courtesy deletion or
erasure of retained copies.

PART scope: Connect grants remain Owner-authorized. A distinct member can
supply the local release consent through the native API; a person-tier grant
mint bypass is not added. Remote distinct-member consent transport, companion
and account integrations, personal-vault ownership proof, and any remote
erasure remain open.
