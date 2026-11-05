# Artifact append and HTML annotation hooks

Checked append doors return either a landed version or the actual retained proposal.
A proposed append does not change HEAD or re-anchor comments. A later authorized
Keep remains a separate operation. The HTTP append door builds the caller's read
lane only when a retained named envelope has sources beyond its writer. Landed
appends and writer-only envelopes do not acquire read authority. Named source
admission and its existing credential errors remain unchanged.

Direct retention preserves the artifact's already-valid file name, including a
whitespace-only name. Organ-submitted outputs keep their existing nonblank-name
and nonempty-byte requirements.

A direct append that changes an HTML artifact's HEAD re-anchors its live,
non-drifted HTML comments in the same write transaction. The sweep starts at the
previous HEAD, even when the appended version explicitly forks from an older
ancestor. First versions and ordinary byte-deduplication returns have no sweep.
HTML media types use the existing case-insensitive, charset-tolerant classifier.
Other media types and other locator formats keep their existing behavior.

The hook reuses the existing HTML part identity and span mapping. A surviving
span moves to the new version. A deleted or ambiguous span drifts, stays pinned
to its earlier version, and keeps its existing Unattached recovery record. Invalid
UTF-8 or unreadable HTML content follows that same drift behavior rather than
adding an append-format refusal. Storage or annotation-write errors roll back
the transaction with the append.

Keep and Office settlement do not take the direct hook. They keep their existing
re-anchor behavior and reported outcomes, including Office's operation-carrying
sweep and restore's exact-identity recovery. This change does not add an HTML
sweep to native-output Keep.

FIX 12520 remains partial. This direct hook does not establish a whole-operation
deadline, cancellation, or parse-memory bound. The HTML parser and span mapper do
not currently consume an explicit caller context; creating a fresh no-deadline
document resource port would not provide that contract.

Edit proposal manifests use the existing current schema version, 2. The old
schema-1 reader exception is removed. Current constructors already emit schema 2;
there is no legacy reader, migration, or version bump. The document-organ outer
contract and nested deck schema are separate formats.
