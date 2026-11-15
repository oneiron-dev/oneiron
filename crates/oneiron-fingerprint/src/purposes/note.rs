//! Purposes of notes (`crates/oneiron/src/note`).

purposes! {}

legacy_purposes! {
    /// A queued note request's input (`note::pending_request`): plain BLAKE3 of the
    /// operation's encoding as its caller gives it (`NoteOperation::encode`, JSON), with no
    /// tag written; the tag is the registry name only. The queue envelope holds it, and a
    /// retry under the same id with another digest is refused.
    PENDING_REQUEST_INPUT = (Blake3, NotHashed, "oneiron.note.pending_request.input.v1");
}
