# Blocked reports from an attached live run

A native host's live-run binding keeps the executor ID and the original
dispatcher's transcript label. Re-entering that binding restores both values.
`self.report_blocked` uses them for its speech-position scan, witnessed MESSAGE
and Coach report. The attempt still binds the report's receipt and lease.

Standalone leased bindings without an executor transcript label keep the
attempt-derived label. A dispatcher with no executor binding also keeps its
attempt-based speech identity. Neither route changes the report's authority,
completes its task, or clears the condition it reports.
