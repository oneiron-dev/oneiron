# Query pages for oversized selections

`read_result` with the `query` facet can page one selected value that does
not fit the inline reply. This includes a projected JSON object and one
JSON-lines, CSV or TSV row. Code-run callers still use their existing spill
sink for a new oversized selection.

An untransformed document value keeps its existing source-range reply:
`paged.ref` is a range of the immutable parent, and `slice` reads its next
byte page.

A re-encoded selection has no such range in the source. Its `paged` object
instead contains `start`, `end`, `bytes`, `text` and `done`. These byte offsets
belong to the selected JSON value, not to the original result. It has no
`paged.ref`, `paged.next` or source-line numbers. Do not use these offsets
with `slice` on the original result.

For a re-encoded selection, repeat the **same query** on the same result,
putting the top-level reply's `next` into the query input's `cursor`:

```json
{"path":"items[*]","columns":["body"],"cursor":{"skip":0,"within":260000}}
```

Use the actual emitted cursor, not the illustrative offset above. The
`within` offset continues the selected value's UTF-8 JSON bytes. A table's
cursor also includes its logical row's `offset` and `row`; `skip` identifies
a path-picked value within that row. Completing a value advances to its next
sibling before advancing to the next row. For documents, `skip` remains the
existing picked-value ordinal before filtering.

Append byte pages while `paged.done` is false. It describes the current
value; the top-level `done` describes the query. A response with `paged`
describes one selected value, including on a byte continuation; do not count
its continuation pages as additional query values. A completed value may
still return `next` without `within` to continue the query.

Every continuation re-derives the selection from the same result under the
normal read, taint, secret, source-standing and scan/reply checks. It retains
no page cache, creates no result occurrence and grants no new read authority.
An explicit byte continuation remains a page even for a code-run caller with
a spill sink. Numeric limits and the original raw-JSON range path are
unchanged.
