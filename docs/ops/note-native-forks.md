# Native NOTE forks and review landing

A local NOTE fork keeps the admitted Loro document, including the proposer's
operation identities, inherited pins and authenticated authorship. The actual
program edit is recorded under the allocated fork ID. Its actor is the verified
writer's stamp token, not a reviewer or an actor copied from request text.
Stamp-token uses are recorded under the NOTE in the same transaction, including
while the fork waits for review.

## Admission and landing

Proposal text, title and inherited quote data still pass the existing privacy
checks before storage. If masking changes the text or title, storage keeps a
history-free value instead. It does not keep the operations that held the secret.
A non-rewrite value fork records its exact parent text and admitted target as its
recovery merge basis.

Merge still requires the fork's parent to be the current head. Other edits of
that same head do not replace its identity. A native merge imports the stored
proposer operations into that head. The conservative semantic edit runs on a
disposable copy to make the existing citation-review decision. The actual
imported candidate passes the pin, reverse-pin, privacy, markdown, wire-size,
persistence and title-index checks before it lands.

The reviewer is recorded in the landing receipt. The merge does not manufacture
a reviewer-authored content edit in place of the proposer operations. A reviewed
semantic edit can still produce the existing Proposed outcome without landing
the fork. Reconstructed forks retain their value-merge path. Explicit Switch and
Reject remain distinct choices, and a seal continues to protect the live head.

## Value exports and erasure

Ordinary window carriers export proposal text, not its pins, operation authority
or historical merge basis. This projection reads the host's actual stored
proposal. Incoming carriers still use the strict value-only decoder.

Canonical recovery also carries values rather than raw fork history. Before
reconstruction, it reads the exact base at the fork's saved opening frontier
from that same stored proposal. The fork and its waiting bundle copy carry the
same resulting value basis. Recovery does not guess the base from today's head.

Citation erasure removes affected stored quotes before they can escape through
retained heads. Before an affected stored snapshot becomes StateOnly, any native
fork basis it needs is materialized in the same writer, together with its bundle
copy. The same transaction also scrubs the original and registered retired
canonical slots left by Switch. Each slot's snapshot and all its pending updates
are replayed before the affected pin is removed. Its clean snapshot replaces the
old snapshot and updates. Authored text and surviving pins stay intact.
Unaffected snapshots keep their original bytes and history.

Owner-selected history purge also applies the selected version-vector cut to
each stored proposal or retained-head snapshot of that NOTE. It also covers the
original and registered retired canonical slots that Switch left behind. Each
cut is bounded by that snapshot's actual oplog and keeps an already higher
shallow floor. Unrelated histories are unchanged. A
native base that the cut would remove is materialized before the cut; the purge
does not discard all retained history merely to remove the selected prefix.

New local births use the anonymous raw-birth representation described in
[note-birth-authorship.md](note-birth-authorship.md). Later authenticated edits
continue to name stamp tokens. These changes do not claim that verbatim replica
imports or older raw snapshots have been globally scrubbed. They add no legacy
reader, migration, new consent step, numeric limit or background timer.
