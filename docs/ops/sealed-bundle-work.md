# Sealed residence bundle work

A residence publisher uploads the bundle and pads in parts, then sends
`residence.bundle.commit`. A commit is a durable execution attempt, not a
publication acknowledgement. Its `workId` is known and persisted by the client
before the first commit send, including automatic publication without an owner
request. The address binds the immutable input and both sealed object lengths
and digests. A client whose home proof has not synced yet uses the explicit
unknown-home address form; the server still binds the actual vault/home and
proved publisher. Automatic attempts use the selected endpoint's address digest,
so a proof becoming known does not orphan pending work. An address never grants
authority.

## Replies and reconnect

Commit replies use `{ "work": ... }`. The work states are `pending`,
`committed`, `needsRebase` and `refused`. Only `committed` carries the full
published generation entry. Pending work never enacts an owner's request and
never causes another upload. A parent that moved is reported as `needsRebase`;
the home never silently changes the saved parent.

`residence.bundle.commit.status` selects exactly one of:

- `workId`: reads the exact attempt and attaches a live write-authorized driver
  when it is pending. Its reply is `{ "work": ... }`, or `work: null` when no
  attempt was accepted. A client with a saved attempt resends the same begin
  after a null, without reassembling or reuploading first.
- `request`: reads only the original owner-request publication receipt, plus
  pending work metadata. This selector does not execute work or imply Write
  admission. No publication receipt is not evidence that accepted work is absent.

A reconnect proves the machine and presents current Read and Write authority.
The work address is not a bearer token, and an old socket or credential is not
required. The driver checks current authority again between phases and in the
publication writer. A stopped driver leaves durable pending progress. Socket
close, caller cancellation and host stop do not delete an accepted attempt.
Terminal metadata has no expiry or count cap; replay does not publish again even
if the original generation has since retired.

## Storage and accounting

Each ordinary stage header contains an immutable 16-byte part identity. Acceptance
detaches both active stage handles in one transaction. The next upload, even with
the same generation and digests, cannot overwrite or idle-collect the detached
source. Identity reservations remain until all physical cleanup finishes, so a
nonce collision cannot adopt a partially cleaned source.

Work metadata and generation/identity reservations use prefixed keys in the
existing commit-receipt family. They do not replace owner-request receipt rows.
There is no migration or old-format reader. Stage headers are 96 bytes; upload
part keys are `identity:offset`.

The driver validates the same strict sealed frames on a tracked blocking phase,
then copies one existing 4 MiB stored-part page per turn. Generation metadata stays
invisible until a final transaction checks authority, exact bindings, parent,
clock, root and publisher turn. That transaction publishes the generation,
optional owner-request receipt and committed work outcome together. The existing
retention and pad-access retirement rules stay in force.

Whole-object strict validation and the existing generation-retirement transaction
remain indivisible. This interface does not promise constant-time validation,
a bounded retention transaction, or measured latency. The socket itself keeps
serving frames while a worker runs; its work attachments do not consume the
ordinary verb-RPC count allowance. Shutdown joins admitted blocking phases.

The existing memory row charges driver metadata and phase buffers. The machine
memory floor admits allocations before they begin. The existing disk-floor
ledger transfers the same upload claims to work ownership, counts prepared
bytes, and restores pending claims at startup. A capacity wait leaves the work
pending, never silently admitted under a zero reservation. Written source and
cleanup bytes remain real disk use until deleted. Terminal cleanup is paged,
recorded durably and included in the host's existing tracked housekeeping pass;
maintenance never executes a pending publication without caller authority.

The 256 KiB upload/read part sizes, 4 MiB stored part size, ordinary stage idle
period, publisher lease, two-copy disk provision and generation-retention rules
are unchanged. No new object-size ceiling, timeout, TTL, retry cap or consent
step is introduced.
