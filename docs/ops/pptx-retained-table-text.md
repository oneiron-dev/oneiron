# Native PPTX table text preservation

`NativeEdit::SetTableCell` checks `expected` against the cell's current text:
DrawingML `a:t` descendants in document order, with newlines between paragraphs.
The edit then maps the requested text onto the retained XML.

The cell mapping counts text inside an unknown paragraph child as one opaque
item. If that item lies outside the changed span, its complete XML survives.
This includes its attributes, namespaces and nested compatibility content.
Known runs outside the span keep their original properties and bytes too.
An unchanged opaque paragraph no longer forces another edited paragraph to
rebuild the entire cell.

If the changed span covers an opaque item whole, the requested replacement may
remove it. If the change cuts inside it, the existing cell rebuild remains the
fallback. This does not add a refusal. Whole-field cuts still report only the
actual `a:fld` types that were removed.

This is a cell-only mapping. Generic deck text mapping, merge checks, the
optimistic `expected` check and the stored package transaction are unchanged.
The reader still counts the same `a:t` descendants. It does not choose between
Markup Compatibility branches or claim to match a renderer's displayed text.

No API, schema, dependency, setting or deployment configuration changes are
required. Source preservation is not a PowerPoint rendering proof.
