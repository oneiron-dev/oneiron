# Frozen task-type parents on dispatch receipts

Native agent dispatch captures the type-tree parents in the same transaction and
from the same tree value that produces its placement. It stores the nearest parent
first, through the root, beside the existing type reference in the dispatch payload.
A later tree split, merge, or project-tree change does not change this capture.

The terminal attempt pack receipt copies that stored array to `fields["typeParents"]`.
The existing `typeRef`, scalar type fields, project, receipt identity, and settlement
paths remain unchanged. The reliability projector already reads this optional array.
The parent list is evidence for learning, not a read grant or a task-parent chain.

An absent capture is unknown and does not get reconstructed from the current tree.
A captured root placement has an empty array. Undecodable optional capture data stays
unknown without refusing the dispatch. Low-level frozen dispatch inputs without an
actual placement tree also leave the capture unknown.

This covers native dispatch and its terminal attempt pack receipt. TASK lifecycle
receipts and other context-pack assembly callers remain separate work.
