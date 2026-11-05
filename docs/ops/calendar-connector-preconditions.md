# Calendar connector retained preconditions

The calendar cursor and write outbox keep an exact sealed copy of their own
href, ETag, and provider receipt. Readable row fields remain nonsecret
projections. A missing projection is not evidence that a provider resource or
ETag was absent. Fresh writes and Prepared resumes use the authenticated
operation's sealed values, not those projections.

## Operation binding

Opening requires the current authenticated owner and installed registration.
The carrier binds its row kind, stable key, instance, immutable intent, and UID.
Its scope includes the endpoint and the complete immutable configuration,
excluding only the `seat_ref` label. Equivalent labels may continue the same
resource under their own current owner, installed-seat, and credential checks.
Different credentials or any other configuration difference do not share it.
This same-operation scope is an Engine call, subject to owner revision; it is
not a general custody reveal or a new transport grant.

Outbox and cursor carriers have separate purpose-derived ConnectorResume refs.
Each fresh instance comes from StoreClock. Codec version is 1, custody generation
is 0, and only AEAD ciphertext is encoded as integer words 256 through 511. This
encoding is not available to plaintext. Other row metadata keeps the normal
Authored scan; metadata-pattern refusals remain outside this slice.

## Lifetime and settlement

A replacement retires the prior different instance in the same writer, using
the existing post-commit custody finisher. State changes, Committed, and a seat
kill do not retire the current carrier. Exact-carrier checks prevent a stale
settlement from resealing a deleted or newer outbox reference. Before replacing
a settlement cursor, its writer checks the same current RemoteApplied carrier.
Truthful recording after admitted I/O adds no fresh owner or credential gate.

Outbound RemoteApplied settlement publishes its cursor, passport admissions and
supersessions, UID index, and final Committed outbox row in one writer. Passport
and subject reads include that writer's pending rows. The existing Active-only
passport comparison and admitted-or-local UID index rule remain distinct.

A stale carrier guard or final outbox compare-and-swap discards this settlement's
staged rows and returns the already-admitted provider receipt. A claim, signing,
or store error also rolls back this settlement; the outbox stays retryable.
Retirement finishing runs only after the outer commit. This does not serialize
provider I/O or other inbound operations. There is no migration or old masked-row
reader.

## Archived-vault activation

Activation collects every current outbox and remote-object cursor, including
Committed outbox evidence. It plans only each carrier's purpose-derived resume
ref at generation 0 before forking custody. A retired instance removes only its
own row through the existing archive prune. A row already unavailable because
its source key is absent, custody planning fails, or its row cannot decode stays
sealed and unavailable; it does not veto other activation work. No replacement
key or empty transport precondition is substituted.

Before lifting the archive mark, activation opens each source-live carrier under the
new fork's transaction binding and validates the same ciphertext encoding and
envelope bindings as ordinary operation reads. This validation returns no
literal and admits no transport work. A source-live carrier that fails this
forked readback rolls back activation, retaining the old binding and archive
mark; it is never silently dropped or blessed as pending. A later source
retirement is not revived; a subsequent activation plans its proved retirement.
This does not change credential, owner, or installed-seat admission. Side-restore
parity is not established by this slice.
