//! Purposes of notes (`crates/oneiron/src/note`).

purposes! {}

legacy_purposes! {
    /// A note import batch's content hash (`note::import::content_hash`), bound into the
    /// owner's approval of the batch and into its one decision slot, which the vault stores
    /// and compares, so it keeps its bytes (K, PLAN-UC-04 6.2). BLAKE3 of the JSON of the
    /// folder, each note (path, kind, title, written-at, its Markdown's BLAKE3 in lowercase
    /// hex, its original's media type and hash), each link and each name-only file.
    IMPORT_CONTENT = (Blake3, NotHashed, "oneiron.note.import_content.v1");

    /// A queued note request's input (`note::pending_request`): plain BLAKE3 of the
    /// operation's encoding as its caller gives it (`NoteOperation::encode`, JSON), with no
    /// tag written; the tag is the registry name only. The queue envelope holds it, and a
    /// retry under the same id with another digest is refused.
    PENDING_REQUEST_INPUT = (Blake3, NotHashed, "oneiron.note.pending_request.input.v1");
}
