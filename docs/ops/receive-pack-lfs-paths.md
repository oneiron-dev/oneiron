# Receive-pack LFS path identity

The receive-pack door keeps two views of a tip record's path:

- The original textual Git label goes to the existing blob scanner and secret-mark logic.
- The LFS attribution callback decodes Git C quoting to the exact repository path bytes.

LFS pointer paths are bytes, not UTF-8 strings. The same bytes pass through the pushed
pointer, the LFS path classifier, the durable operation journal, the outcome evidence,
and the per-ref tree walk. The tree walk splits on the byte `/` and compares each
component with the tree entry's raw name. Invalid UTF-8 is not replaced or dropped.
Only the displayed missing-object reason uses a lossy text view, followed by the
existing printable-name filter. That display is never used for identity or policy.

The current journal stores byte-valued pointer paths and an explicit pointer-position
list for every ref. An omitted list in a live door report is expanded to all current
pointer positions when the journal is written. An explicit empty list stays empty.
Outcome evidence stores each path in a MessagePack binary value. There are no readers
for older text-path evidence or journals missing per-ref lists.

This does not change hook framing, history labels, scanner predicates, secret marks,
LFS object admission, ref publication, retention, or the default path classification.
Git-quoted non-UTF-8 names are supported on the LFS attribution lane. The separate
checkout changed-path grant reader and raw non-UTF-8 hook headers are not covered.
