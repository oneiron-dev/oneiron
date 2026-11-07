# Reader-child terminal output

A reader child returns its finding through `self.reader.report`. Its bound door
continues to reject speech and other writes outside the child contract.

The executor does not select or recover an automatic terminal speech bubble for
a run bound with `with_reader_child`. The final code step and its replay record
commit normally, and the server sees a normal `Complete` outcome. No implicit
speech intent, attachment, marker or transcript row is needed for that finish.

This does not change explicit guest calls. An explicit `self.speak` still goes
through the existing read-only admission and keeps its denied outcome. Ordinary
runs retain trailing-text selection, same-text suppression, result attachments,
checkpoint recovery and retry-safe bubble delivery.

The child runner no longer treats `HostRefused(reader_child_read_only)` as proof
that a run completed. Real executor errors follow the existing failure handling;
the normal completed path and finding-based settlement stay unchanged.
