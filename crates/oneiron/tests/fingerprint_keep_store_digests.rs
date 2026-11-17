//! K-proof for store legacy digests at c715a39b45b5: existing stored, sent and
//! compared identities keep main's bytes through the fingerprint K door.
//!
//! A tested revision stores its code-tree inventory digest and an import
//! manifest stores the blob-only inventory's hex; both are compared when read
//! back. The authority log stores a critical confirm's effect digest and
//! confirm id; CRITICAL_CONFIRM_INDEX is keyed by the id, and the gate compares
//! it. Erasable key ref rows store the drafter and grant-scope key
//! incarnations. A custody drain stores its operation id in the fence, an ack
//! sends the drain origin's hex, which is compared, and the target set history
//! stores the ack digest's hex. An owner-answer obligation stores its item
//! hash. ROW_BIRTH stores a birth's content hash and write-door params hash. An
//! off-record session's body directory is named by its spill name. A skill
//! source carrier's row id is its truncated digest, compared on read.
//!
//! The base modules copy exact main lines. Inline hash lines have hand-written
//! headers and returns. Stand-ins hold only what main's lines read: a pending
//! consent's decision id, diff handle and read frontier; the skill content
//! hash's bytes; an ack's encoded bytes; a birth process's params hash.
//! `drain_operation_id`, `drain_origin` and `RowBirth::content_hash_of` are
//! public, so the test calls them directly.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_store_digests`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron::EntityId;
use oneiron::store::code_revision_record::{CodeCommitMetadata, CodeRevision, CodeTreeBlob};
use oneiron::store::custody_protocol::{
    CustodyPosition, TargetId, drain_operation_id, drain_origin, hex,
};
use oneiron::store::row_birth::RowBirth;
use oneiron::test_doors::fingerprint_keep_store_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use oneiron_store::code_document_values::CodeDocumentFrontier;

#[cfg(unix)]
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_spill {
    // main c715a39b45b5: crates/oneiron/src/store/body_store.rs:756-758
    fn session_spill_name(session_ref: &str) -> String {
        blake3::hash(session_ref.as_bytes()).to_hex().to_string()
    }
    pub(crate) fn name(session_ref: &str) -> String {
        session_spill_name(session_ref)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_tree {
    use std::collections::BTreeMap;
    use oneiron::store::code_revision_record::{CodeRevision, CodeTreeBlob};
    use oneiron_store::code_document_values::CodeDocumentFrontier;
    type Result<T> = std::result::Result<T, &'static str>;
    fn invalid(reason: &'static str) -> &'static str {
        reason
    }
    // main c715a39b45b5: crates/oneiron/src/store/code_revision_record/tree_inventory.rs:69-89
        pub(crate) fn digest(revision: &CodeRevision) -> Result<[u8; 32]> {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"oneiron:code-tree-inventory:v1");
            let documents: BTreeMap<&str, &CodeDocumentFrontier> = revision
                .file_frontiers
                .values()
                .map(|frontier| (frontier.path.as_str(), frontier))
                .collect();
            hasher.update(&(documents.len() as u64).to_be_bytes());
            for (path, frontier) in documents {
                let encoded = rmp_serde::to_vec_named(frontier)
                    .map_err(|_| invalid("tested tree document encode"))?;
                for part in [path.as_bytes(), encoded.as_slice()] {
                    hasher.update(&(part.len() as u64).to_be_bytes());
                    hasher.update(part);
                }
                hasher.update(&document_mode(revision, &frontier.document_id).to_be_bytes());
            }
            hash_blobs(&mut hasher, &revision.blob_frontiers);
            Ok(*hasher.finalize().as_bytes())
        }
    // main c715a39b45b5: crates/oneiron/src/store/code_revision_record/tree_inventory.rs:94-100
        pub(crate) fn blob_digest(blobs: &BTreeMap<String, CodeTreeBlob>) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"oneiron:code-tree-inventory:v1");
            hasher.update(&0_u64.to_be_bytes());
            hash_blobs(&mut hasher, blobs);
            *hasher.finalize().as_bytes()
        }
    // main c715a39b45b5: crates/oneiron/src/store/code_revision_record/tree_inventory.rs:104-115
    fn hash_blobs(hasher: &mut blake3::Hasher, blobs: &BTreeMap<String, CodeTreeBlob>) {
        hasher.update(&(blobs.len() as u64).to_be_bytes());
        for (path, blob) in blobs {
            for part in [path.as_bytes(), blob.git_oid.as_bytes()] {
                hasher.update(&(part.len() as u64).to_be_bytes());
                hasher.update(part);
            }
            hasher.update(&blob.content_hash);
            hasher.update(&blob.size_bytes.to_be_bytes());
            hasher.update(&blob.mode.to_be_bytes());
        }
    }
    // main c715a39b45b5: crates/oneiron/src/store/code_revision_record/tree_inventory.rs:153-158
    pub(crate) fn document_mode(revision: &CodeRevision, document: &[u8; 32]) -> u32 {
        revision
            .commit_metadata
            .as_ref()
            .and_then(|metadata| metadata.file_modes.get(document))
            .copied()
            .unwrap_or(oneiron::store::code_snapshot::DEFAULT_CODE_FILE_MODE)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_confirm {
    use oneiron::EntityId;
    // main c715a39b45b5: crates/oneiron/src/store/critical_confirm_record.rs:9-10
    use oneiron_authority::authority::CRITICAL_WRITE_CONFIRM_DOMAIN;
    use sha2::{Digest, Sha256};
    // Stand-in: the gate decision id, as GateDecisionId::as_bytes returns it.
    pub(crate) struct DecisionId(pub(crate) [u8; 16]);
    impl DecisionId {
        pub(crate) fn as_bytes(&self) -> [u8; 16] {
            self.0
        }
    }
    // Stand-in: the three pending-consent fields main's lines read.
    pub(crate) struct Pending {
        pub(crate) decision_id: DecisionId,
        pub(crate) diff_handle: Vec<u8>,
        pub(crate) read_frontier_hash: [u8; 32],
    }
    pub(crate) fn effect(claim_id: &EntityId, pending: &Pending) -> [u8; 32] {
        // main c715a39b45b5: crates/oneiron/src/store/critical_confirm_record.rs:48-54
            let mut digest = blake3::Hasher::new();
            digest.update(b"oneiron:critical-confirm:v1");
            digest.update(claim_id.as_bytes());
            digest.update(&pending.decision_id.as_bytes());
            digest.update(&pending.diff_handle);
            digest.update(&pending.read_frontier_hash);
            let effect_digest = *digest.finalize().as_bytes();
        effect_digest
    }
    pub(crate) fn confirm_id(
        claim_id: &EntityId,
        pending: &Pending,
        effect_digest: [u8; 32],
        nonce: [u8; 16],
        expires_at: u64,
    ) -> [u8; 32] {
        // main c715a39b45b5: crates/oneiron/src/store/critical_confirm_record.rs:64-71
            let mut confirm = Sha256::new();
            confirm.update(CRITICAL_WRITE_CONFIRM_DOMAIN);
            confirm.update(pending.decision_id.as_bytes());
            confirm.update(claim_id.as_bytes());
            confirm.update(effect_digest);
            confirm.update(pending.read_frontier_hash);
            confirm.update(nonce);
            confirm.update(expires_at.to_be_bytes());
        confirm.finalize().into()
    }
    pub(crate) fn tag() -> &'static [u8] {
        CRITICAL_WRITE_CONFIRM_DOMAIN
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_drafter {
    // main c715a39b45b5: crates/oneiron/src/store/drafter_custody.rs:34-34
    const DRAFTER_INCARNATION_CONTEXT: &str = "oneiron/drafter-artifact/erasable-incarnation/v1";
    // main c715a39b45b5: crates/oneiron/src/store/drafter_custody.rs:83-85
    fn incarnation(artifact: &[u8; 16]) -> [u8; 32] {
        blake3::derive_key(DRAFTER_INCARNATION_CONTEXT, artifact)
    }
    pub(crate) fn digest(artifact: &[u8; 16]) -> [u8; 32] {
        incarnation(artifact)
    }
    pub(crate) fn tag() -> &'static str {
        DRAFTER_INCARNATION_CONTEXT
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_grant {
    // main c715a39b45b5: crates/oneiron/src/store/grant_scope_custody.rs:27-27
    const GRANT_INCARNATION_CONTEXT: &str = "oneiron/grant-scope/erasable-incarnation/v1";
    // main c715a39b45b5: crates/oneiron/src/store/grant_scope_custody.rs:30-35
    fn incarnation(pact_id: &[u8; 32], epoch: u64) -> [u8; 32] {
        let mut material = [0u8; 40];
        material[..32].copy_from_slice(pact_id);
        material[32..].copy_from_slice(&epoch.to_be_bytes());
        blake3::derive_key(GRANT_INCARNATION_CONTEXT, &material)
    }
    pub(crate) fn digest(pact_id: &[u8; 32], epoch: u64) -> [u8; 32] {
        incarnation(pact_id, epoch)
    }
    pub(crate) fn tag() -> &'static str {
        GRANT_INCARNATION_CONTEXT
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_drain {
    use oneiron::store::custody_protocol::{CustodyPosition, TargetId};
    // main c715a39b45b5: crates/oneiron-store/src/key_custody/protocol/drain.rs:29-29
    pub const OPERATION_CONTEXT: &str = "oneiron/custody-drain/operation/v1";
    // main c715a39b45b5: crates/oneiron-store/src/key_custody/protocol/drain.rs:31-31
    pub const ORIGIN_CONTEXT: &str = "oneiron/custody-drain/origin/v1";
    // main c715a39b45b5: crates/oneiron/src/store/key_custody/protocol/drain.rs:27-37
    #[must_use]
    pub fn drain_operation_id(
        target: &TargetId,
        revision: u64,
        position: &CustodyPosition,
    ) -> [u8; 32] {
        let mut material = position.to_bytes().to_vec();
        material.extend_from_slice(&revision.to_be_bytes());
        material.extend_from_slice(target.as_str().as_bytes());
        blake3::derive_key(OPERATION_CONTEXT, &material)
    }
    // main c715a39b45b5: crates/oneiron/src/store/key_custody/protocol/drain.rs:40-45
    #[must_use]
    pub fn drain_origin(position: &CustodyPosition) -> [u8; 32] {
        let mut material = position.vault.as_bytes().to_vec();
        material.extend_from_slice(position.namespace.as_bytes());
        blake3::derive_key(ORIGIN_CONTEXT, &material)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_drain_ack {
    // Stand-ins: the set history's evidence field; the ack's encoding (here the
    // encoded bytes themselves); the custody hex.
    pub(crate) struct DrainEvidence {
        pub(crate) ack_digest: String,
    }
    fn encode(ack: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(ack.to_vec())
    }
    fn hex(bytes: &[u8]) -> String {
        oneiron::store::custody_protocol::hex(bytes)
    }
    pub(crate) fn evidence(ack: &[u8]) -> Result<DrainEvidence, ()> {
        Ok(DrainEvidence {
            // main c715a39b45b5: crates/oneiron/src/store/key_custody/targets/drain.rs:222-222
                            ack_digest: hex(blake3::hash(&encode(ack)?).as_bytes()),
        })
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_owner_item {
    // main c715a39b45b5: crates/oneiron/src/store/pending_gate_consent/obligation.rs:36-41
    pub(crate) fn owner_answer_item_hash(diff_handle: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:owner-answer-item:v1");
        hasher.update(diff_handle);
        *hasher.finalize().as_bytes()
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_row_birth {
    use sha2::{Digest, Sha256};
    pub(crate) struct RowBirth;
    impl RowBirth {
        // main c715a39b45b5: crates/oneiron/src/store/row_birth.rs:250-258
            #[must_use]
            pub fn content_hash_of(parts: &[&[u8]]) -> String {
                let mut hasher = blake3::Hasher::new_derive_key("oneiron made_by content_hash v1");
                for part in parts {
                    hasher.update(&(part.len() as u64).to_le_bytes());
                    hasher.update(part);
                }
                hasher.finalize().to_hex().to_string()
            }
    }
    // Stand-in: the birth process field main's lines write.
    pub(crate) struct Process {
        pub(crate) params_hash: String,
    }
    pub(crate) fn params_hash_in_written() -> String {
        Process {
            // main c715a39b45b5: crates/oneiron/src/store/row_birth.rs:227-227
                                params_hash: format!("{:x}", Sha256::digest([])),
        }
        .params_hash
    }
    pub(crate) fn params_hash_in_room() -> String {
        Process {
            // main c715a39b45b5: crates/oneiron/src/store/row_birth.rs:380-380
                                params_hash: format!("{:x}", Sha256::digest([])),
        }
        .params_hash
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_carrier {
    use oneiron::EntityId;
    use sha2::{Digest, Sha256};
    // Stand-in: the skill content hash's bytes.
    pub(crate) struct SkillContentHash(pub(crate) [u8; 32]);
    impl SkillContentHash {
        pub(crate) fn as_bytes(&self) -> &[u8; 32] {
            &self.0
        }
    }
    // main c715a39b45b5: crates/oneiron/src/store/skill_source_carrier.rs:11-11
    const DOMAIN: &[u8] = b"oneiron.hub-source.asset.v1\0";
    pub(crate) fn id_bytes(holder: &EntityId, hash: &SkillContentHash) -> [u8; 16] {
        // main c715a39b45b5: crates/oneiron/src/store/skill_source_carrier.rs:14-18
            let digest = Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(holder.as_bytes())
                .chain_update(hash.as_bytes())
                .finalize();
        digest[..16].try_into().expect("16 digest bytes")
    }
    pub(crate) fn tag() -> &'static [u8] {
        DOMAIN
    }
}

fn id(n: u8) -> EntityId {
    let mut bytes = [0x5a; 16];
    bytes[0] = n;
    EntityId::from_bytes(bytes).expect("unreserved entity id")
}

fn texts() -> Vec<String> {
    vec![
        String::new(),
        "ordinary".into(),
        "é 日本 α".into(),
        "a\0b".into(),
        "../escape".into(),
        "長x".repeat(600),
    ]
}

fn byte_rows() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0],
        b"ab".to_vec(),
        "é 日本".as_bytes().to_vec(),
        b"\x83\xa7version\x01".to_vec(),
        "長x".repeat(600).into_bytes(),
        vec![0xa5; 70_000],
    ]
}

fn frontier(path: &str, seed: u8) -> CodeDocumentFrontier {
    CodeDocumentFrontier {
        document_id: [seed; 32],
        repo: "repo".into(),
        path: path.into(),
        version: vec![(1, i32::from(seed))],
        op_fold: [seed ^ 0x11; 32],
        text_hash: [seed ^ 0x22; 32],
        file_presence: None,
    }
}

fn blob(git_oid: &str, seed: u8, mode: u32) -> CodeTreeBlob {
    CodeTreeBlob {
        git_oid: git_oid.into(),
        content_hash: [seed; 32],
        size_bytes: u64::from(seed) * 1000,
        mode,
    }
}

fn blob_sets() -> Vec<BTreeMap<String, CodeTreeBlob>> {
    vec![
        BTreeMap::new(),
        BTreeMap::from([
            ("src/lib.rs".to_owned(), blob("8f3e", 1, 0o100_644)),
            ("vendor/dep".to_owned(), blob("a0b1", 2, 0o160_000)),
        ]),
        BTreeMap::from([("ab".to_owned(), blob("c", 3, 0o100_755))]),
        BTreeMap::from([("a".to_owned(), blob("bc", 3, 0o100_755))]),
    ]
}

fn position(vault: u8, namespace: u8, seq: u64) -> CustodyPosition {
    let mut bytes = [0_u8; 96];
    bytes[..32].fill(vault);
    bytes[32..48].fill(namespace);
    bytes[48..56].copy_from_slice(&3_u64.to_be_bytes());
    bytes[56..64].copy_from_slice(&seq.to_be_bytes());
    bytes[64..].fill(0x7e);
    CustodyPosition::from_bytes(&bytes).expect("96-byte position")
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    // tree_inventory.rs:71, critical_confirm_record.rs:49, obligation.rs:38 and
    // row_birth.rs:252 write their tags inline; their bytes are written out here.
    let recipes: [(LegacyPurpose, LegacyHash, TagMode, &[u8]); 13] = [
        (
            purposes::store::CODE_TREE_INVENTORY,
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            b"oneiron:code-tree-inventory:v1",
        ),
        (
            purposes::store::CRITICAL_CONFIRM_EFFECT,
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            b"oneiron:critical-confirm:v1",
        ),
        (
            purposes::store::CRITICAL_WRITE_CONFIRM,
            LegacyHash::Sha256,
            TagMode::HashedFirst,
            base_confirm::tag(),
        ),
        (
            purposes::store::CUSTODY_DRAIN_ACK,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.store.custody_drain_ack.v1",
        ),
        (
            purposes::store::CUSTODY_DRAIN_OPERATION,
            LegacyHash::Blake3,
            TagMode::DeriveKeyContext,
            base_drain::OPERATION_CONTEXT.as_bytes(),
        ),
        (
            purposes::store::CUSTODY_DRAIN_ORIGIN,
            LegacyHash::Blake3,
            TagMode::DeriveKeyContext,
            base_drain::ORIGIN_CONTEXT.as_bytes(),
        ),
        (
            purposes::store::DRAFTER_INCARNATION,
            LegacyHash::Blake3,
            TagMode::DeriveKeyContext,
            base_drafter::tag().as_bytes(),
        ),
        (
            purposes::store::GRANT_INCARNATION,
            LegacyHash::Blake3,
            TagMode::DeriveKeyContext,
            base_grant::tag().as_bytes(),
        ),
        (
            purposes::store::MADE_BY_CONTENT,
            LegacyHash::Blake3,
            TagMode::DeriveKeyContext,
            b"oneiron made_by content_hash v1",
        ),
        (
            purposes::store::OWNER_ANSWER_ITEM,
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            b"oneiron:owner-answer-item:v1",
        ),
        (
            purposes::store::SESSION_SPILL_DIR,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.store.session_spill_dir.v1",
        ),
        (
            purposes::store::SKILL_SOURCE_CARRIER,
            LegacyHash::Sha256,
            TagMode::HashedFirst,
            base_carrier::tag(),
        ),
        (
            purposes::store::WRITE_DOOR_PARAMS,
            LegacyHash::Sha256,
            TagMode::NotHashed,
            b"oneiron.store.write_door_params.v1",
        ),
    ];
    for (purpose, hash, mode, tag) in recipes {
        assert_eq!(purpose.tag().as_bytes(), tag);
        assert_eq!(purpose.hash(), hash);
        assert_eq!(purpose.tag_mode(), mode);
    }
    // The confirm id's tag is still the domain the authority crate exports.
    assert_eq!(
        purposes::store::CRITICAL_WRITE_CONFIRM.tag().as_bytes(),
        oneiron_authority::authority::CRITICAL_WRITE_CONFIRM_DOMAIN
    );
}

#[cfg(unix)]
#[test]
fn session_spill_names_keep_main_s_bytes() {
    let mut names = BTreeSet::new();
    for session_ref in texts() {
        let head = door::session_spill_name(&session_ref);
        assert_eq!(head, base_spill::name(&session_ref));
        assert_eq!(head.len(), 64);
        names.insert(head);
    }
    assert_eq!(names.len(), texts().len());
}

#[test]
fn code_tree_inventories_keep_main_s_bytes() {
    let a = frontier("src/a.rs", 1);
    let b = frontier("src/b.rs", 2);
    let b_moved = frontier("z/b.rs", 2);
    let document_sets = [vec![], vec![a.clone()], vec![a.clone(), b], vec![b_moved]];
    let metadata = |file_modes: BTreeMap<[u8; 32], u32>| CodeCommitMetadata {
        author: None,
        message: "message".into(),
        file_modes,
    };
    let mode_sets = [
        None,
        Some(metadata(BTreeMap::new())),
        Some(metadata(BTreeMap::from([(a.document_id, 0o100_755)]))),
    ];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for documents in &document_sets {
        for modes in &mode_sets {
            for blobs in blob_sets() {
                let mut revision = CodeRevision::commit(id(1), id(2), 7);
                revision.file_frontiers = documents
                    .iter()
                    .map(|document| (document.document_id, document.clone()))
                    .collect();
                revision.commit_metadata = modes.clone();
                revision.blob_frontiers = blobs;
                let head = door::code_tree_inventory(&revision).expect("inventory digest");
                assert_eq!(Ok(head), base_tree::digest(&revision));
                digests.insert(head);
                rows += 1;
            }
        }
    }
    // An unlisted mode is 100644, so no metadata and empty modes digest alike,
    // and a's listed mode moves only the trees that hold a: 6 per blob set.
    assert_eq!((rows, digests.len()), (48, 24));
}

#[test]
fn blob_inventories_keep_main_s_bytes() {
    let mut digests = BTreeSet::new();
    for blobs in blob_sets() {
        let head = door::code_tree_blob_inventory(&blobs);
        assert_eq!(head, base_tree::blob_digest(&blobs));
        // The same bytes as a document-free revision's inventory.
        let mut revision = CodeRevision::commit(id(1), id(2), 7);
        revision.blob_frontiers = blobs;
        assert_eq!(
            head,
            door::code_tree_inventory(&revision).expect("inventory digest")
        );
        digests.insert(head);
    }
    assert_eq!(digests.len(), 4);
}

#[test]
fn critical_confirm_effects_keep_main_s_bytes() {
    let diff_handles = [vec![], b"ab".to_vec(), b"a".to_vec(), vec![0xd1; 70_000]];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for claim_id in [id(1), id(2)] {
        for decision_id in [[0x10; 16], [0x11; 16]] {
            for diff_handle in &diff_handles {
                for read_frontier_hash in [[0; 32], [0xf0; 32]] {
                    let head = door::critical_confirm_effect(
                        &claim_id,
                        decision_id,
                        diff_handle,
                        read_frontier_hash,
                    );
                    let pending = base_confirm::Pending {
                        decision_id: base_confirm::DecisionId(decision_id),
                        diff_handle: diff_handle.clone(),
                        read_frontier_hash,
                    };
                    assert_eq!(head, base_confirm::effect(&claim_id, &pending));
                    digests.insert(head);
                    rows += 1;
                }
            }
        }
    }
    assert_eq!((rows, digests.len()), (32, 32));
}

#[test]
fn critical_write_confirm_ids_keep_main_s_bytes() {
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for decision_id in [[0x10; 16], [0x11; 16]] {
        for claim_id in [id(1), id(2)] {
            for effect_digest in [[0xe0; 32], [0xe1; 32]] {
                for read_frontier_hash in [[0; 32], [0xf0; 32]] {
                    for nonce in [[0x10; 16], [0x4e; 16]] {
                        for expires_at in [0, 1, u64::MAX] {
                            let head = door::critical_write_confirm_id(
                                decision_id,
                                &claim_id,
                                effect_digest,
                                read_frontier_hash,
                                nonce,
                                expires_at,
                            );
                            let pending = base_confirm::Pending {
                                decision_id: base_confirm::DecisionId(decision_id),
                                diff_handle: Vec::new(),
                                read_frontier_hash,
                            };
                            assert_eq!(
                                head,
                                base_confirm::confirm_id(
                                    &claim_id,
                                    &pending,
                                    effect_digest,
                                    nonce,
                                    expires_at,
                                )
                            );
                            digests.insert(head);
                            rows += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!((rows, digests.len()), (96, 96));
}

#[test]
fn key_incarnations_keep_main_s_bytes() {
    let artifacts = [
        [0; 16],
        [1; 16],
        [0xff; 16],
        [0x5a; 16],
        *id(3).as_bytes(),
        *id(4).as_bytes(),
    ];
    let mut digests = BTreeSet::new();
    for artifact in &artifacts {
        let head = door::drafter_incarnation(artifact);
        assert_eq!(head, base_drafter::digest(artifact));
        digests.insert(head);
    }
    assert_eq!(digests.len(), 6);
    let mut digests = BTreeSet::new();
    for pact_id in [[0; 32], [7; 32], [0xff; 32]] {
        for epoch in [0, 1, u64::MAX] {
            let head = door::grant_incarnation(&pact_id, epoch);
            assert_eq!(head, base_grant::digest(&pact_id, epoch));
            digests.insert(head);
        }
    }
    assert_eq!(digests.len(), 9);
}

#[test]
fn custody_drain_identities_keep_main_s_bytes() {
    let targets = ["folder:nas", "cloud:b2-1", "folder:a.b_c"]
        .map(|target| TargetId::new(target).expect("target id"));
    let positions = [position(1, 2, 0), position(9, 2, 0), position(1, 2, 41)];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for target in &targets {
        for revision in [0, 1, u64::MAX] {
            for position in &positions {
                let head = drain_operation_id(target, revision, position);
                assert_eq!(
                    head,
                    base_drain::drain_operation_id(target, revision, position)
                );
                digests.insert(head);
                rows += 1;
            }
        }
    }
    assert_eq!((rows, digests.len()), (27, 27));
    let origins: BTreeSet<[u8; 32]> = positions
        .iter()
        .map(|position| {
            let head = drain_origin(position);
            assert_eq!(head, base_drain::drain_origin(position));
            head
        })
        .collect();
    // The origin reads only the vault and namespace: positions 0 and 2 share it.
    assert_eq!(origins.len(), 2);
}

#[test]
fn custody_drain_acks_keep_main_s_bytes() {
    let rows = byte_rows();
    let mut digests = BTreeSet::new();
    for encoded in &rows {
        let head = door::custody_drain_ack(encoded);
        let evidence = base_drain_ack::evidence(encoded).expect("stand-in encode");
        assert_eq!(hex(&head), evidence.ack_digest);
        digests.insert(head);
    }
    assert_eq!(digests.len(), rows.len());
}

#[test]
fn owner_answer_items_keep_main_s_bytes() {
    let rows = byte_rows();
    let mut digests = BTreeSet::new();
    for diff_handle in &rows {
        let head = door::owner_answer_item(diff_handle);
        assert_eq!(head, base_owner_item::owner_answer_item_hash(diff_handle));
        digests.insert(head);
    }
    assert_eq!(digests.len(), rows.len());
}

#[test]
fn row_birth_hashes_keep_main_s_bytes() {
    let part_lists: Vec<Vec<Vec<u8>>> = vec![
        vec![],
        vec![vec![]],
        vec![b"a".to_vec()],
        vec![b"ab".to_vec(), b"c".to_vec()],
        vec![b"a".to_vec(), b"bc".to_vec()],
        vec![vec![], vec![]],
        vec![vec![0x6c; 70_000]],
    ];
    let mut hashes = BTreeSet::new();
    for list in &part_lists {
        let parts: Vec<&[u8]> = list.iter().map(Vec::as_slice).collect();
        let head = RowBirth::content_hash_of(&parts);
        assert_eq!(head, base_row_birth::RowBirth::content_hash_of(&parts));
        hashes.insert(head);
    }
    assert_eq!(hashes.len(), part_lists.len());
    let params = door::write_door_params_hash();
    assert_eq!(params, base_row_birth::params_hash_in_written());
    assert_eq!(params, base_row_birth::params_hash_in_room());
    // SHA-256 of no bytes.
    assert_eq!(
        params,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn skill_source_carriers_keep_main_s_bytes() {
    let mut ids = BTreeSet::new();
    for holder in [id(1), id(2), id(0xee)] {
        for content_hash in [[0; 32], [0x11; 32], [0xff; 32]] {
            let head = door::skill_source_carrier(&holder, content_hash).expect("carrier id");
            assert_eq!(
                *head.as_bytes(),
                base_carrier::id_bytes(&holder, &base_carrier::SkillContentHash(content_hash))
            );
            ids.insert(*head.as_bytes());
        }
    }
    assert_eq!(ids.len(), 9);
}
