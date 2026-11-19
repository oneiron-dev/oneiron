//! Purposes of connectors (`crates/oneiron/src/connector_key`, `ingest::connector_*`,
//! `outbound_consent`, `outbound::reply_job`, `linear_sync`).

purposes! {}

legacy_purposes! {
    /// A Linear webhook delivery (`linear_sync::mirror_event`): plain BLAKE3, the tag's
    /// bytes, then the delivery id as a u64 little-endian length and its bytes. Its mirror
    /// event row's key, and the delivery's side of its binding to its body.
    LINEAR_MIRROR_DELIVERY = (Blake3, HashedFirst, "oneiron:linear-mirror-delivery:v1");

    /// A Linear mapping edit's mirror event key: plain BLAKE3, the tag's bytes, then the
    /// TASK and the intent key, each a u64 little-endian length and its bytes.
    LINEAR_MIRROR_MAPPING = (Blake3, HashedFirst, "oneiron:linear-mirror-mapping:v1");

    /// A public title edit's mirror event key: plain BLAKE3, the tag's bytes, then the
    /// TASK, the actor and the qualified report key, each a u64 little-endian length and
    /// its bytes.
    LINEAR_MIRROR_TASK_EDIT = (Blake3, HashedFirst, "oneiron:linear-mirror-task-edit:v1");

    /// The request a mapping or title edit is compared by on a replay
    /// (`linear_sync::mirror_event::request_digest`): plain BLAKE3, the bytes
    /// `oneiron:linear-mirror-body:v1` unframed, then each part as a u64 little-endian
    /// length and its bytes. The edit's mirror event row stores its hex; a replay with
    /// another digest is refused. Those bytes are also the context of a body occurrence's
    /// id (`linear_sync::custody`), and two purposes never share a string, so the site
    /// writes them itself and this tag is the registry name only.
    LINEAR_MIRROR_EDIT_REQUEST = (Blake3, NotHashed, "oneiron:linear-mirror-edit-request:v1");
}
