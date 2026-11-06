# DOCX paragraph questions in native stories

A paragraph question can name one native story with `units.scope`. The selected
`blocks` are paragraph ids local to that story, as returned by `docx.read`. An
omitted scope keeps the existing document-body selection. Never use a body id
as a replacement for a missing story id.

For a footnote, the selection fragment is:

```json
{
  "kind": "paragraphs",
  "scope": { "kind": "footnote", "id": "1" },
  "blocks": ["story_p1"]
}
```

This is only the selection fragment. Supply the existing author, display labels,
question and artifact fields as usual. Copy the actual note id and paragraph id
from that document's native read; the example does not identify an arbitrary
package. Header and footer scopes also carry their actual part name and band.

The ask pins the whole live document, reads only the selected story's live
paragraphs for its decisions, and quotes the same story's native head version
when it creates each Word comment. Its judgment records that scope, the native
head text hash, the version and the live pin. The receipt check compares the
scope with the actual `comment_create` operation, not just its bare block id.
One request and its judgments name one scope.

Keep compares the selected paragraphs at the same pinned and exported frontiers.
It carries unchanged judgments back to that same native story. A withdrawal and
its re-ask retain the scope. Standing questions use it for both version arrivals
and live edits that have not been exported. Other stories with an identical
paragraph id are not the same unit.

Native range markers in comment content are non-conformant under ISO/IEC
29500-1, section 17.13.4. A native create targeting a comment content story returns
`UnsupportedEdit`; it never redirects the marker to the body. Imported comments,
existing reads, replies, resolution and deletion keep their current behavior.

The source supports top-level paragraphs and direct table-cell paragraphs in
one named story. For a cell, copy its actual paragraph id from that story's
`cells[].paragraphs[]` native read; do not use the table id, grid address or joined
cell text as a paragraph identity. The native lookup keeps the same story and
uses the paragraph's guard and existing quote/marker splice. The native cell
lock and enclosing table lock still apply. The same whole-document live pin
covers top-level and direct cell paragraphs for reads and change comparisons.
BODY table cells and nested table paragraphs remain outside this source slice.

Header/footer marker serialization follows the native story serializer; Word's
handling of those file-authored ranges has not been proved. No Word run,
compiler result, whole-story fidelity result or full FIX 14487 completion is
claimed by this source change. Existing BODY behavior and numeric policies are
unchanged.


## Native nested-cell comment lookup

Native named-story `CommentCreate` also accepts an imported paragraph id inside
nested table cells. It keeps existing top-level and direct-cell lookup priority,
uses the same ancestor-status and quoted-range guards, and does not address
vertical-merge continuation cells. Body lookup is unchanged. This native lookup
extension does not add nested paragraphs to ParagraphAsk or live-pin inventories;
those consumers still require their own source-qualified integration (FIX 14487).
