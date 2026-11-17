//! Doors for `tests/side_key_pins.rs` (UC-06 PR 2 K-proof): one fixture key of each
//! crate-private side-table key type that PR 2 derives, with the reader of its type. Compiled
//! only under `--cfg oneiron_test_support`; never API.

use crate::entity_id::EntityId;
use crate::side_table::SideKey;

/// One fixture key: the bytes it spells after its table prefix, and what its type reads from
/// any bytes (the key read, spelled again; `None` where the type refuses them).
pub struct Pin {
    pub spelled: Vec<u8>,
    pub read: fn(&[u8]) -> Option<Vec<u8>>,
}

impl Pin {
    pub fn of<K: SideKey>(key: &K) -> Self {
        Self {
            spelled: spell(key),
            read: |bytes: &[u8]| K::decode_key(bytes).map(|key| spell(&key)),
        }
    }
}

fn spell<K: SideKey>(key: &K) -> Vec<u8> {
    let mut out = Vec::new();
    key.encode_into(&mut out);
    out
}

/// `workspace_roster::codec::MemberIntentKey`: the workspace ref, NUL, the raw person id.
pub fn member_intent_key(workspace_ref: &str, person_ref: EntityId) -> Pin {
    crate::workspace_roster::member_intent_key_pin_for_test(workspace_ref, person_ref)
}

/// `workspace_roster::records::RosterMemberKey`: the workspace ref, NUL, the person id in hex.
pub fn roster_member_key(workspace_ref: &str, person_ref: EntityId) -> Pin {
    crate::workspace_roster::roster_member_key_pin_for_test(workspace_ref, person_ref)
}

/// `workspace_roster::rooms::participation::FactKey`: room, thread, subject kind and id, cause
/// kind and id. `subject` is a kind byte and id that `FactSubject` reads.
pub fn fact_key(
    room: EntityId,
    branch: [u8; 16],
    subject: (u8, [u8; 16]),
    cause: (u8, [u8; 16]),
) -> Pin {
    crate::workspace_roster::fact_key_pin_for_test(room, branch, subject, cause)
}

/// `origin::document_ingress::ProvenanceRefKey`: the provenance id, `:`, the ref name hash.
pub fn provenance_ref_key(provenance: EntityId, ref_name_hash: [u8; 32]) -> Pin {
    crate::origin::provenance_ref_key_pin_for_test(provenance, ref_name_hash)
}

/// `origin::export::RepoRevisionKey`: the repo identity hex, `:`, the raw revision id.
pub fn repo_revision_key(repo_hex: &str, revision: EntityId) -> Pin {
    crate::origin::export::repo_revision_key_pin_for_test(repo_hex, revision)
}

/// `origin::lfs::store::LfsRefKey`: the repo id, NUL, the ref name, NUL, the object id.
pub fn lfs_ref_key(repo_id: EntityId, ref_name: &str, oid: [u8; 32]) -> Pin {
    crate::origin::lfs::lfs_ref_key_pin_for_test(repo_id, ref_name, oid)
}

/// `origin::smart_http::intent::ReceivePackIntentKey`: the repo identity hex, then the raw
/// operation id, with no separator.
pub fn receive_pack_intent_key(repo_identity_hex: &str, operation_id: EntityId) -> Pin {
    crate::origin::smart_http::receive_pack_intent_key_pin_for_test(repo_identity_hex, operation_id)
}

/// `origin::smart_http::intent::ReceivePackProgressKey`: an intent key, then the batch number
/// as eight big-endian bytes.
pub fn receive_pack_progress_key(
    repo_identity_hex: &str,
    operation_id: EntityId,
    batch: u64,
) -> Pin {
    crate::origin::smart_http::receive_pack_progress_key_pin_for_test(
        repo_identity_hex,
        operation_id,
        batch,
    )
}
