# Conflict settlement reverts

`Memory::settle_conflict` keeps one standing member, holds both, or dismisses
an open conflict. `Memory::revert_conflict_settlement` reopens the marker for
the owner. The original marker and closed claims remain audit history.

A Dreamer MACHINE claim whose signed history cannot reopen is restored as a
fresh claim. The settlement revert writes its actual conflict marker into
that copy's write provenance in the same transaction as the copy. The normal
reverted-conflict history reader includes those Dreamer-authored copies as
members at their actual ids. The owner can keep a restored copy, and keeping
another member supersedes each active restored copy through the same native
lifecycle and responder checks as the original members. Repeating Keep and
Revert carries the same marker into each fresh generation; no original id is
reused or reopened. Retained alternatives and their staged import reviews keep
their existing behavior.

A generic Dreamer-change revert or a maintenance revert does not acquire a
conflict marker merely because it makes a copy. Marker membership does not
approve a claim, grant review authority, or replace the existing subject,
source, lifecycle, confirmation, and Gate checks. This covers the normal
retained settlement history, not a claim that every partial-erasure or
history-removal path reconstructs membership.

Scoped evidence attachments store their support edge's `created_at` and
provenance claim's `learned_at` in Unix seconds, converted once from the same
`DreamerRunContext.now_ms`. Strength observations and run/attempt timestamps
remain in milliseconds. Existing stored-attachment replay checks are unchanged;
there is no old-format reader or timestamp repair pass.
