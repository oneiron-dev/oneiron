# PDF preparation framing and page trees

PDF preparation reads the complete leading trailer or xref-stream dictionary.
The framing scanner has no fixed byte or nesting limit. It preserves the outer
`<<` offset, string escapes, comments, hex strings, delimiter matching and the
absolute consumed offset. Leading PDF whitespace is not passed to the narrower
content-stream whitespace parser. Dictionary and literal contents are unchanged.
The dictionary operand uses the section's existing admitted decoder.

The page-tree walk uses an explicit depth-first worklist. It preserves Kids
order and inherited page attributes. It rejects repeated object IDs and checks
each Pages node's Count after visiting all its children. Empty and malformed
page trees keep their existing errors.

Object-stream members use the same direct signature checks through an iterative
worklist admitted by their parse stage. Later document-level checks are unchanged.

On an admitted inspection, these worklists reserve backing memory through the
same inspection host. A replacement is admitted while the old allocation is
still live; the old admission is released after replacement. The final vector
is freed before its backing admission. An inspection without host memory keeps
ordinary allocation behavior. No new budget, timeout, configuration or default
limit is introduced.

Visual-resource copying also uses an explicit worklist. Indirect objects keep
their leaf-first output IDs, and shared resource maps keep their cached member
IDs. Stream admission, dictionary/member order, direct-member promotion and
Type 3 glyph checks retain their existing order. There is no fixed copy or
glyph-array depth limit. Active-path cycle checks allow repeated acyclic
references; malformed graphs still fail. Glyph streams keep their per-stream
codec bounds, and content/operator checks are unchanged.

Visual copying still uses ordinary unadmitted preparation allocations. The
existing reference resolver and codec/format limits remain. These changes do
not prove whole-parse memory coverage, arbitrary-depth preparation,
cryptographic validity or a runtime signing result. Use a matching
engine/server build; no schema, client, storage ABI or organ-protocol change
is required for these worklists.
