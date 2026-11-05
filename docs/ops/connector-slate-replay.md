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
Supported ordinary communication, calendar, feedback HTTP-bundle, non-mirror
Linear and native campaign targets use the exact-call owner question and
approve-once paths described in [ordinary outbound approvals](ordinary-outbound-approval.md).
Other ordinary formats remain an open part of FIX 990; no hold is added without
an approve-once path. Recovery drivers and provider transports are retained.
