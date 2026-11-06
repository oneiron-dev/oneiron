# Scoped finding fold receipts

A fold store can name a scoped child of the same parent run. Its primary
input must name the fold source occurrence, and its delegated range must be
inside the fold source range. The receipt keeps the actual task, finding,
state, shortfall reason and delegated primary range. A guessed task or a
child of another parent does not supply a finding.

A scoped child may complete after storing a literal finding without reading
any input. Its completion therefore does not establish byte coverage of its
primary source. Scoped ranges do not contribute to the receipt's `read`
coverage or to the short-read ranges subtracted from `unread`. A scoped
partial finding still keeps its actual reason in `partial`. Here `unread`
means the source range not covered by the receipt; it does not assert that
no scoped code ever read those bytes.

Read children keep their existing completed-range and partial-range rules.
The host still computes coverage from its own job records, never from guest
coverage claims. Source admission, occurrence ownership, finding resolution,
cutoff, summary-tree reads, recipe and checkpoint publication keep their
existing paths. This adds no capability or authority to the receipt.

The fold inherits the primary source's and actual finding's occurrence marks
through the existing native store path. Additional producing inputs can be
named through the existing `store` option `sources`; their existing read and
mark checks remain. Merely lending another input neither proves it was read
nor adds a new read gate for that unused input. This change does not replace
the scoped child's own source-mark propagation or claim that every loaned
input was used.

The receipt is a record of the fold, not a new per-byte read audit. Exact
scoped byte coverage needs its own native witness; this slice does not add
one. There is no new public input field, stored format, limit, timeout or
compatibility reader.
