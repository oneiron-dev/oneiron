# Owned Connect detach on member leave

An owner minting a Connect guest grant can attach a local release setting,
`detach_on_member_leave`, naming one shared vault. When the owner named in
the setting genuinely leaves that shared vault, this vault withdraws the
Connect grant here. The setting selects which grants a leave releases; it
proves nothing about the peer vault and grants no authority.

The mint stores the actual owner the writer revalidated, never a caller
input: the shared vault's creation must name the vault, and the actor must
hold a live Owner grant there in the same writer. Without the setting the
grant keeps generic shared Connect behavior and its body encodes exactly as
before. The setting rides a Connect guest grant only.

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

PART scope: owner-minted Connect attachments only. Non-owner attachment,
companion and account integrations, and any remote erasure stay out.
