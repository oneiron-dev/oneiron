# Scoped finding fold receipts

A fold store can name a scoped child of the same parent run. Its primary
input must name the fold source occurrence, and its delegated range must be
inside the fold source range. The receipt keeps the actual task, finding,
state, shortfall reason and delegated primary range. A guessed task or a
child of another parent does not supply a finding.

A scoped child may complete after storing a literal finding without reading
any input. Its completion or its finding therefore proves no byte coverage
of its primary source. The host keeps a delivery witness on the child's job
instead (FIX 7735). When a `slice` reply shows the child bytes of its
primary source (`src`), the host adds that byte range to the witness. It
adds the range only after the reply passes its taint, secret and live-cutoff
checks, and only while the job is live at the claim it runs under. Each
claim starts with an empty witness, and the job's settlement freezes it. A
job that settles from its queue keeps no witness.

A fold counts a done scoped child's witness ranges in `read`, and a partial
one's as short-read ranges, each cut to the child's delegated range. Cards,
asked ranges, `chunks` pages, `search` and `query` replies, lent inputs and
findings add nothing. A scoped partial finding still keeps its actual reason
in `partial`. Here `unread` means the source range that no counted range
covers; it does not assert that no scoped code ever read those bytes.

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

## Usage pattern

1. The host lends the child its source as `src` (`ScopedChildLoan::from_parent`)
   and queues it (`ReaderJobs::spawn_scoped`).
2. The child reads `src` with `slice` and follows `next` until `done`. A
   `chunks` page only names ranges: the child reads each chunk ref with
   `slice`.
3. The child reports its finding with `tasks.update`.
4. The parent waits with `tasks.wait`, then calls
   `store(value, name, { receipt: { source, tasks }, sources })`. `source`
   names the fold source and `tasks` the children. `sources` names the other
   results the value was made from, so the value inherits their marks.
5. The store's card, and `describe` of the stored value, show the receipt's
   `read`, `unread` and `partial`. The host computes them from the jobs it
   names. No receipt input carries a coverage claim.

The receipt is a record of the fold, not a per-byte read audit. The witness
is new data on the job row; the stored receipt keeps its format. There is no
new public input field, limit, timeout, refusal or compatibility reader.
