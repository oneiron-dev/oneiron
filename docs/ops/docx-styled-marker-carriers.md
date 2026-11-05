# Structural markers in styled whole-paragraph replacements

A styled whole-paragraph replacement keeps existing bookmarks, comment range
boundaries and comment references once, at their original native inline
positions and statuses. Existing Normal markers stay Normal; prior inserted or
deleted markers keep their own revision rather than being made current. The
old text keeps the existing deletion or stacked-deletion status; replacement
text stays Inserted.

Rejecting the replacement restores the original text around those same markers.
Accepting it removes the old text, so an interior range collapses to the boundary
before the replacement text. The engine does not guess a range in new prose or
clone a bookmark/comment identity into both deleted and inserted content.
The Direct path uses the same native acceptance projection.

This fixes the whole-paragraph materializer used by mixed text/format body
replacements and styled header/footer replacements. It changes no native wire
shape, version, authority check or text-edit refusal. Marker-free replacements,
opaque/hard-break references and own/cross-author pending-insertion text retain
their existing behavior. This does not close story paragraph-question support,
structural paragraph-mark edits or every Office marker mapping case.

The evidence is source inspection and a production compile when recorded for
the submitted head or merge train. It is not a Word-runtime comparison. No tests
were written, changed, compiled or run for this change.
