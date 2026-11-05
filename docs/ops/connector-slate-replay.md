# Connector slate settings during outbound replay

Pending sends under a connector key read the tool's current `never allow`
setting before transport. This applies to ordinary connector sends as well as
scoped MCP calls. A key without its own or a derived catalog slate keeps the
existing `auto` behavior. The reader also preserves the key holder's existing
narrowing rules.

A matching `never allow` uses the existing `ConnectorSlateNeverAllow` terminal.
It does not change the frozen request, acquire a new grant, clear delivery
knowledge, or send a request. Completed, deferred, and abandoned ledger rows
still replay their recorded result before pending-send governance runs.

The check is the last observed in-process setting, not an atomic lock with a
remote provider. The existing send-boundary check repeats it before retry
permission, the dedupe touch, and transport. No default, timeout, budget, or
slate-setting value changes.

Scoped MCP `always ask` keeps its existing exact-call approve-once flow.
Ordinary connector `always ask` replay remains an open part of FIX 990; this
change does not add a hold without an approve-once path. It does not change
prepare, consent, the recovery driver, or a provider's transport.
