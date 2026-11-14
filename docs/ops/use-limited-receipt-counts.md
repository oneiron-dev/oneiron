# Use-limited records and omission counts

A recipient's explicit cooperative-review use restriction withholds a record
from ordinary reads, including the owner's, while it stands. A refused
privacy erasure no longer keeps a record for a legal purpose: the hold-based
C6 use limit is gone, and no hold retains a record.

A withheld record must not reappear through its omission metadata:

- `ScopedRead::admit_in` excludes use-limited rows from suppressed counts after
  all existing world, credential, room, device, TASK/facet and countability
  checks. Code-memory payload suppression uses this classifier. Tagging turn
  and mention receipts already report zero omissions and keep doing so.
  Visible reads and ordinary policy-denial counts are unchanged.
- MCP TASK-board omission counts preserve the existing connector and slip
  world/facet checks. No hold-limited row exists to omit from
  `scope_omitted`.

No requester ask or general courtesy non-delete choice alone creates a use
restriction.

Internal `record_scope` reads remain available to authorization. No payload
admission, legal-purpose read, refusal, grant, owner exemption, limit, default,
storage format, SDK, route or config changes. The remaining FIX 1496 families
and unqualified archived-row count paths are not declared complete here.
