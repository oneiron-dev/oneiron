# Blocked reports from an attached live run

`self.report_blocked` on an attached live run keeps the executor run ID sealed in
that attachment. Its speech-position scan, witnessed MESSAGE and Coach report use
that executor ID instead of substituting the attempt ID. The attempt still binds
the report's receipt and lease. The dispatcher's run-reference label is unchanged.

A standalone leased dispatcher with no executor binding keeps its attempt-based
speech identity. Neither route changes the report's authority, completes its task,
or clears the condition it reports.
