# Use-limited records and omission counts

C6 keeps a record after a refused privacy erase only for the legal purpose
that kept it. The existing read gate withholds that record from ordinary
reads, including the owner's, while a retaining hold still stands.

A withheld record must not reappear through its omission metadata:

- `ScopedRead::admit_in` excludes use-limited rows from suppressed counts after
  all existing world, credential, room, device, TASK/facet and countability
  checks. Code-memory payload suppression uses this classifier. Tagging turn
  and mention receipts already report zero omissions and keep doing so.
  Visible reads and ordinary policy-denial counts are unchanged. The classifier
  also follows the existing generic use-limit predicate for an explicit
  cooperative-review restriction.
- MCP TASK-board omission counts preserve the existing connector and slip
  world/facet checks, then omit a C6-limited row from `scope_omitted`. This uses
  the existing public `Vault::legal_hold_use_limit` door. Like the surrounding
  MCP metadata helpers, it opens its own read transaction; it does not claim
  a single snapshot across board admission and omission counting.

A bare hold without a privacy-erase-kept use-limit marker is not this state.
No requester ask or general courtesy non-delete choice alone creates this C6
condition. The MCP change covers C6 only, not every cooperative-review or
retained-copy omission path.

Internal `record_scope` reads remain available to authorization. No payload
admission, legal-purpose read, refusal, grant, owner exemption, limit, default,
storage format, SDK, route or config changes. The remaining FIX 1496 families
and unqualified archived-row count paths are not declared complete here.
