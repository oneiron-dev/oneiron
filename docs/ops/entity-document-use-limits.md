# Entity-document write use limits

Entity-document user writes use the same named-write restriction as ordinary record puts, in the write transaction and before loading or copying the live document.

This covers anchored text edits, whole-text updates (including timeout and review forks), metadata edits, proposal opening, Merge and Switch settlement, and scope-summary editor memos. A later restricted member aborts the whole proposal transaction.

A C6 restriction requires both a `PrivacyEraseKept` marker and a standing hold that retains the record. A bare hold does not activate this restriction. A marker with no retaining hold does not activate it either. The same native predicate also honors a recipient's explicit cooperative-review use restriction; it does not treat every courtesy-copy choice as a restriction.

Anchored edits preflight every editor's existing authority and shared-record scope before checking the restriction. Authorized actor-bearing operations return the existing native refusal unchanged: a visible host-order bound can produce `use_restricted`; a silent order, customer hold, or cooperative restriction can produce absence. An empty anchored-edit call has no editor proof and returns absence when restricted; a nonrestricted empty call keeps its prior behavior. Owner authorization and standing grants do not bypass a current use restriction.

Reject still uses its existing authorization checks and removes the pending fork snapshot and dependencies. It does not publish a replacement, so the added write check does not block it. Raw persistence, checkpoint reconstruction, recovery, deletion, and sync maintenance are unchanged. This does not claim that every document read, retained-history export, or sync path is covered.
