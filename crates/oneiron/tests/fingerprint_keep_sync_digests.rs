//! K-proof for sync legacy digests at 62d2d72f5c1b: existing stored, sent and
//! compared identities keep main's bytes through the fingerprint K door.
//!
//! HomeMove stores the signed, sealed election basis. sync_queue stores maintenance
//! quota keys and OfficeProposals/TypedBodyRows quarantine dedup identities.
//! PEER_ORIGIN bytes 32..64 store the logical ASSET identity. Residence search pages
//! send revision hex and compare it for search_changed. Sealed-bundle WORK stores
//! the work id, which clients precompute and the server compares. Settlement sends
//! the opaque revision to the owner and compares the exact replacement approval.
//! Window-pad Pending.id is compared with continuation frame ids. NOTE receipts
//! compare command_hash with the encoded operation's digest.
//!
//! The base modules copy exact main lines. Election and ASSET stand-ins contain
//! only fields the private argument types expose to the hash. Inline hash blocks
//! have hand-written headers/returns; the window-pad field expression alone is
//! written by hand as `*blake3::hash(header).as_bytes()`, as permitted for that row.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_sync_digests`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeSet;

use loro::VersionVector;
use oneiron::EntityId;
use oneiron::memory::ReadFilterInput;
use oneiron::origin::RepoProjectionHoldCause;
use oneiron::sync::residence::{
    ResolvedRecallSelection, ResolvedRecallWorlds, SealedBundleCommitInput,
};
use oneiron::sync::types::WindowKey;
use oneiron::test_doors::fingerprint_keep_sync_digests as door;
use oneiron::world_keys::{RecoveryRootId, SealedBundleGeneration};
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use oneiron_records::note::operations::{NoteChange, NoteOperation};

// Main's copied search function names this public filter path.
mod memory {
    pub(crate) use oneiron::memory::ReadFilterInput;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_election {
    use oneiron::EntityId;
    use oneiron::dreamer_runner::{DreamerHomeNodeDesignation, DreamerHomeNodeClass};
    // main 62d2d72f5c1b: crates/oneiron/src/sync/home_handoff/delivery.rs:40-40
    const BASIS_DOMAIN: &[u8] = b"oneiron/home-handoff/election-basis/v1\0";
    #[derive(Clone, Copy)]
    struct MoveRequest { from: Option<u64>, to: Option<u64> }
    struct HomeIdentity { machine: EntityId, node_id: u64 }
    // main 62d2d72f5c1b: crates/oneiron/src/sync/home_handoff/delivery.rs:247-271
    fn election_basis(
        vault_id: &[u8; 32],
        request: Option<MoveRequest>,
        home: Option<&DreamerHomeNodeDesignation>,
        target: &HomeIdentity,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BASIS_DOMAIN);
        hasher.update(vault_id);
        let nodes = [
            request.and_then(|request| request.from),
            request.and_then(|request| request.to),
            home.map(|home| home.node_id),
        ];
        for node in nodes {
            match node {
                Some(node) => hasher.update(&[1]).update(&node.to_be_bytes()),
                None => hasher.update(&[0]),
            };
        }
        hasher.update(&home.map_or(0, |home| home.elected_at).to_be_bytes());
        hasher.update(target.machine.as_bytes());
        hasher.update(&target.node_id.to_be_bytes());
        *hasher.finalize().as_bytes()
    }
    pub(crate) fn basis(vault_id: &[u8; 32], nodes: [Option<u64>; 3], elected_at: u64, target_machine: &[u8; 16], target_node: u64) -> [u8; 32] {
        let request = Some(MoveRequest { from: nodes[0], to: nodes[1] });
        let home = nodes[2].map(|node_id| DreamerHomeNodeDesignation { node_id, class: DreamerHomeNodeClass::CloudAttached, elected_at });
        let target = HomeIdentity { machine: EntityId::from_bytes(*target_machine).expect("public entity id"), node_id: target_node };
        election_basis(vault_id, request, home.as_ref(), &target)
    }
    pub(crate) fn tag() -> &'static [u8] { BASIS_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_quota {
    // main 62d2d72f5c1b: crates/oneiron/src/sync/quota.rs:20-20
    const MAINTENANCE_INGEST_QUOTA_PEER_DOMAIN: &[u8] = b"oneiron/maintenance-ingest-quota/v1/peer";
    struct MaintenanceIngestPeerKey([u8; 32]);
    // main 62d2d72f5c1b: crates/oneiron/src/sync/quota.rs:285-307
    pub(super) fn peer_key_from_redaction_pubkey(pubkey: &[u8; 32]) -> MaintenanceIngestPeerKey {
        peer_key_from_signature_key(b"ed25519", pubkey)
    }

    /// Quota bucket for replicated type-76 identity-topology events. The
    /// stream carries no per-record signature material yet (lease attestation
    /// is a flagged follow-up), so ingest is bounded per lease-scoped stream
    /// rather than per signer.
    pub(super) fn peer_key_from_identity_topology_stream(
        lease_vault_id: u64,
    ) -> MaintenanceIngestPeerKey {
        peer_key_from_signature_key(b"identity-topology-stream", &lease_vault_id.to_be_bytes())
    }

    fn peer_key_from_signature_key(suite: &[u8], public_key: &[u8]) -> MaintenanceIngestPeerKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MAINTENANCE_INGEST_QUOTA_PEER_DOMAIN);
        hasher.update(&[0]);
        hasher.update(suite);
        hasher.update(&[0]);
        hasher.update(public_key);
        MaintenanceIngestPeerKey(*hasher.finalize().as_bytes())
    }
    pub(crate) fn peer(suite: &[u8], public_key: &[u8]) -> [u8; 32] { peer_key_from_signature_key(suite, public_key).0 }
    pub(crate) fn redaction(public_key: &[u8; 32]) -> [u8; 32] { peer_key_from_redaction_pubkey(public_key).0 }
    pub(crate) fn topology(lease_vault_id: u64) -> [u8; 32] { peer_key_from_identity_topology_stream(lease_vault_id).0 }
    pub(crate) fn tag() -> &'static str { std::str::from_utf8(MAINTENANCE_INGEST_QUOTA_PEER_DOMAIN).unwrap() }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_office {
    // main 62d2d72f5c1b: crates/oneiron/src/sync/office_proposals.rs:62-62
    const DIVERGENCE_CONTEXT: &str = "oneiron.office_proposals.divergence.v1";
    pub(crate) fn divergence(held: &[u8], bytes: &[u8]) -> oneiron::Result<[u8; 32]> {
        let held = held.to_vec();
        // main 62d2d72f5c1b: crates/oneiron/src/sync/office_proposals.rs:335-342
            let mut copies = [held.as_slice(), bytes];
            copies.sort_unstable();
            let mut hasher = blake3::Hasher::new_derive_key(DIVERGENCE_CONTEXT);
            for copy in copies {
                hasher.update(&u64::try_from(copy.len()).unwrap_or(u64::MAX).to_le_bytes());
                hasher.update(copy);
            }
            Ok(*hasher.finalize().as_bytes())
    }
    pub(crate) fn tag() -> &'static str { DIVERGENCE_CONTEXT }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_asset {
    use oneiron::batch::ENTITY_METADATA_HEADER_LEN;
    struct AssetBodyFacts { blake3: [u8; 32], len: u64, xxh32: u32 }
    // main 62d2d72f5c1b: crates/oneiron/src/sync/ingest/peer_import.rs:67-74
    fn asset_digest(blob: &[u8], facts: &AssetBodyFacts) -> [u8; 32] {
        let mut digest = blake3::Hasher::new();
        digest.update(&blob[..ENTITY_METADATA_HEADER_LEN]);
        digest.update(&facts.blake3);
        digest.update(&facts.len.to_be_bytes());
        digest.update(&facts.xxh32.to_be_bytes());
        *digest.finalize().as_bytes()
    }
    pub(crate) fn asset(header: &[u8], blake3: &[u8; 32], len: u64, xxh32: u32) -> [u8; 32] {
        asset_digest(header, &AssetBodyFacts { blake3: *blake3, len, xxh32 })
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_search {
    use oneiron::EntityId;
    use oneiron::sync::residence::ResolvedRecallSelection;
    use oneiron::sync::types::WindowKey;
    // main 62d2d72f5c1b: crates/oneiron/src/memory/resolved_recall_scope.rs:20-63
    pub fn recall_scope_transcript(scope: Option<&ResolvedRecallSelection>) -> Vec<u8> {
        fn ids(out: &mut Vec<u8>, ids: &[EntityId]) {
            out.extend_from_slice(&(ids.len() as u64).to_be_bytes());
            for id in ids {
                out.extend_from_slice(id.as_bytes());
            }
        }
        let Some(scope) = scope else {
            return vec![0];
        };
        let mut out = vec![1];
        match &scope.worlds {
            None => out.push(0),
            Some(worlds) => {
                out.push(1);
                out.push(u8::from(worlds.include_base));
                ids(&mut out, &worlds.world_ids);
            }
        }
        ids(&mut out, &scope.project_ids);
        match &scope.conversation_ids {
            None => out.push(0),
            Some(conversations) => {
                out.push(1);
                ids(&mut out, conversations);
            }
        }
        match &scope.facet {
            None => out.push(0),
            Some(facet) => {
                out.push(1);
                out.extend_from_slice(facet.as_bytes());
            }
        }
        match &scope.kinds {
            None => out.push(0),
            Some(kinds) => {
                out.push(1);
                out.extend_from_slice(&(kinds.len() as u64).to_be_bytes());
                out.extend_from_slice(kinds);
            }
        }
        out
    }
    // main 62d2d72f5c1b: crates/oneiron/src/sync/residence/search.rs:23-60
    const READ_FILTER_FIELD_TAG: &[u8] = b"oneiron.residence.search.read_filter.v1";

    /// A caller's retrieval filter as the one field a residence search signs and
    /// hashes (FIX 3977): its tag, then each field in order, a presence byte
    /// before each value: the entity types as a big-endian `u64` count and their
    /// bytes, the band and staleness as one byte each, and the minima as their
    /// big-endian `f32` bits. A search without a filter has no such field, so
    /// its bytes are the ones it always had.
    fn read_filter_transcript(filter: &crate::memory::ReadFilterInput) -> Vec<u8> {
        let mut field = READ_FILTER_FIELD_TAG.to_vec();
        match &filter.entity_types {
            Some(types) => {
                field.push(1);
                field.extend((types.len() as u64).to_be_bytes());
                field.extend(types.iter().copied());
            }
            None => field.push(0),
        }
        for byte in [
            filter.max_sensitivity_band,
            filter.include_stale.map(u8::from),
        ] {
            match byte {
                Some(byte) => field.extend([1, byte]),
                None => field.push(0),
            }
        }
        for minimum in [filter.min_confidence, filter.min_salience] {
            match minimum {
                Some(minimum) => {
                    field.push(1);
                    field.extend(minimum.to_bits().to_be_bytes());
                }
                None => field.push(0),
            }
        }
        field
    }
    pub(crate) fn page(fields: &[&[u8]], hits: &[(EntityId, WindowKey)]) -> String {
        // main 62d2d72f5c1b: crates/oneiron/src/sync/residence/search.rs:192-203
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"oneiron.residence.search.page.v1");
            for field in fields {
                hasher.update(&(field.len() as u64).to_be_bytes());
                hasher.update(field);
            }
            for (id, window) in hits {
                hasher.update(id.as_bytes());
                hasher.update(&(window.as_str().len() as u64).to_be_bytes());
                hasher.update(window.as_str().as_bytes());
            }
            hasher.finalize().to_hex().to_string()
    }
    // main 62d2d72f5c1b: crates/oneiron/src/sync/residence/search.rs:168-204
    pub fn residence_search_revision(
        query: &str,
        limit: usize,
        selector_wire: &[u8],
        scope: Option<&ResolvedRecallSelection>,
        as_of: u64,
        filter: Option<&crate::memory::ReadFilterInput>,
        hits: &[(EntityId, WindowKey)],
    ) -> String {
        let limit = (limit as u64).to_be_bytes();
        let scope = recall_scope_transcript(scope);
        let as_of = as_of.to_be_bytes();
        let filter = filter.map(read_filter_transcript);
        let mut fields: Vec<&[u8]> = Vec::with_capacity(6);
        fields.extend([
            query.as_bytes(),
            limit.as_slice(),
            selector_wire,
            scope.as_slice(),
            as_of.as_slice(),
        ]);
        if let Some(filter) = &filter {
            fields.push(filter.as_slice());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.residence.search.page.v1");
        for field in fields {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        for (id, window) in hits {
            hasher.update(id.as_bytes());
            hasher.update(&(window.as_str().len() as u64).to_be_bytes());
            hasher.update(window.as_str().as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_work {
    use oneiron::EntityId;
    use oneiron::sync::residence::SealedBundleCommitInput;
    // main 62d2d72f5c1b: crates/oneiron/src/sync/residence/bundle/work.rs:34-34
    const WORK_ID_CONTEXT: &str = "oneiron sealed bundle commit work v1";
    // main 62d2d72f5c1b: crates/oneiron/src/sync/residence/bundle/work.rs:211-239
    pub fn sealed_bundle_work_id(
        home: Option<EntityId>,
        executor: EntityId,
        input: SealedBundleCommitInput,
        objects: [(u64, [u8; 32]); 2],
    ) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key(WORK_ID_CONTEXT);
        hash.update(&[u8::from(home.is_some())]);
        if let Some(home) = home {
            hash.update(home.as_bytes());
        }
        hash.update(executor.as_bytes());
        hash.update(&input.generation.to_bytes());
        hash.update(&[u8::from(input.parent.is_some())]);
        if let Some(parent) = input.parent {
            hash.update(&parent.to_bytes());
        }
        for value in [input.root.map(|root| root.0), input.request] {
            hash.update(&[u8::from(value.is_some())]);
            if let Some(value) = value {
                hash.update(&value);
            }
        }
        for (len, digest) in objects {
            hash.update(&len.to_be_bytes());
            hash.update(&digest);
        }
        *hash.finalize().as_bytes()
    }
    pub(crate) fn tag() -> &'static str { WORK_ID_CONTEXT }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_settlement {
    use loro::VersionVector;
    use oneiron::EntityId;
    use oneiron::origin::RepoProjectionHoldCause;
    // main 62d2d72f5c1b: crates/oneiron/src/sync/selector/secret_projection/documents/settlement.rs:38-38
    const SETTLEMENT_REVIEW_DOMAIN: &str = "oneiron.repo-sync-settlement.review.v1";
    struct Review { revision: [u8; 32] }
    impl Review {
        fn approval_for(&self, replacement: &str) -> [u8; 32] {
            // main 62d2d72f5c1b: crates/oneiron/src/sync/selector/secret_projection/documents/settlement.rs:95-99
                    let mut hasher = blake3::Hasher::new_derive_key(SETTLEMENT_REVIEW_DOMAIN);
                    hasher.update(&self.revision);
                    hasher.update(&(replacement.len() as u64).to_be_bytes());
                    hasher.update(replacement.as_bytes());
                    *hasher.finalize().as_bytes()
        }
    }
    pub(crate) fn approval(revision: &[u8; 32], replacement: &str) -> [u8; 32] { Review { revision: *revision }.approval_for(replacement) }
    // main 62d2d72f5c1b: crates/oneiron/src/sync/selector/secret_projection/documents/settlement.rs:271-311
    fn revision_hash(
        source: &EntityId,
        incarnation: &str,
        text: &str,
        source_vv: &VersionVector,
        stamp: &[u8; 32],
        blob: &[u8; 32],
        lineage_vv: &VersionVector,
        submitted: &str,
        cause: RepoProjectionHoldCause,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(SETTLEMENT_REVIEW_DOMAIN);
        hasher.update(source.as_bytes());
        hasher.update(&(incarnation.len() as u64).to_be_bytes());
        hasher.update(incarnation.as_bytes());
        hasher.update(&(text.len() as u64).to_be_bytes());
        hasher.update(text.as_bytes());
        canonical_vv(&mut hasher, source_vv);
        hasher.update(stamp);
        hasher.update(blob);
        canonical_vv(&mut hasher, lineage_vv);
        hasher.update(&(submitted.len() as u64).to_be_bytes());
        hasher.update(submitted.as_bytes());
        let cause_str = cause.as_str();
        hasher.update(&(cause_str.len() as u64).to_be_bytes());
        hasher.update(cause_str.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// The canonical hash of `vv`: its `(peer, counter)` pairs sorted, count then
    /// each pair (`u64` then `i32`, both BE). `VersionVector::encode` ordering is
    /// NOT assumed deterministic, so the pairs are sorted before hashing.
    fn canonical_vv(hasher: &mut blake3::Hasher, vv: &VersionVector) {
        let mut pairs: Vec<(u64, i32)> = vv.iter().map(|(peer, counter)| (*peer, *counter)).collect();
        pairs.sort_unstable();
        hasher.update(&(pairs.len() as u64).to_be_bytes());
        for (peer, counter) in pairs {
            hasher.update(&peer.to_be_bytes());
            hasher.update(&counter.to_be_bytes());
        }
    }
    pub(crate) fn revision(source: &EntityId, incarnation: &str, text: &str, source_vv: &VersionVector, stamp: &[u8; 32], blob: &[u8; 32], lineage_vv: &VersionVector, submitted: &str, cause: RepoProjectionHoldCause) -> [u8; 32] {
        revision_hash(source, incarnation, text, source_vv, stamp, blob, lineage_vv, submitted, cause)
    }
    pub(crate) fn tag() -> &'static str { SETTLEMENT_REVIEW_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_typed {
    // main 62d2d72f5c1b: crates/oneiron/src/sync/typed_body_rows.rs:92-92
    const DIVERGENCE_CONTEXT: &str = "oneiron.typed_body_rows.divergence.v1";
    // main 62d2d72f5c1b: crates/oneiron/src/sync/typed_body_rows.rs:709-718
    fn divergence_digest(held: &[u8], carried: &[u8]) -> [u8; 32] {
        let mut copies = [held, carried];
        copies.sort_unstable();
        let mut hasher = blake3::Hasher::new_derive_key(DIVERGENCE_CONTEXT);
        for copy in copies {
            hasher.update(&u64::try_from(copy.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(copy);
        }
        *hasher.finalize().as_bytes()
    }
    pub(crate) fn divergence(held: &[u8], carried: &[u8]) -> [u8; 32] { divergence_digest(held, carried) }
    pub(crate) fn tag() -> &'static str { DIVERGENCE_CONTEXT }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_envelope {
    // Hand-written equivalent of parts.rs:215's field expression: it reads only this slice.
    pub(crate) fn id(header: &[u8]) -> [u8; 32] { *blake3::hash(header).as_bytes() }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_note {
    use oneiron_records::note::operations::NoteOperation;
    pub(crate) fn hash(operation: &NoteOperation) -> oneiron::Result<[u8; 32]> {
        // main 62d2d72f5c1b: crates/oneiron/src/sync/documents/note_requests.rs:129-129
                    let digest = blake3::hash(&operation.encode()?);
        Ok(*digest.as_bytes())
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
        " \t\n".into(),
        "長x".repeat(600),
    ]
}

fn divergence_rows() -> Vec<(Vec<u8>, Vec<u8>)> {
    let long = "長x".repeat(600).into_bytes();
    vec![
        (vec![], vec![]),
        (vec![], b"a".to_vec()),
        (b"a".to_vec(), vec![]),
        (b"a".to_vec(), b"a".to_vec()),
        (b"ab".to_vec(), b"c".to_vec()),
        (b"c".to_vec(), b"ab".to_vec()),
        (b"a".to_vec(), b"bc".to_vec()),
        (b"bc".to_vec(), b"a".to_vec()),
        ("é 日本".as_bytes().to_vec(), long.clone()),
        (long.clone(), "é 日本".as_bytes().to_vec()),
        (long.clone(), long),
    ]
}

fn hit_rows() -> Vec<Vec<(EntityId, WindowKey)>> {
    let a = (id(1), WindowKey::new("1970-01"));
    let b = (id(2), WindowKey::for_world(u64::MAX, id(3)));
    vec![
        vec![],
        vec![a.clone()],
        vec![b.clone()],
        vec![a.clone(), b.clone()],
        vec![b, a.clone()],
        vec![a.clone(), a],
    ]
}

fn vector_rows() -> Vec<VersionVector> {
    vec![
        VersionVector::new(),
        [(0u64, 0i32)].into_iter().collect(),
        [(u64::MAX, i32::MAX)].into_iter().collect(),
        [(0, i32::MIN), (u64::MAX, i32::MAX), (7, 1)]
            .into_iter()
            .collect(),
    ]
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    let recipes: [(LegacyPurpose, TagMode, &str); 8] = [
        (
            purposes::sync::MAINTENANCE_INGEST_QUOTA_PEER,
            TagMode::HashedFirst,
            base_quota::tag(),
        ),
        (
            purposes::sync::OFFICE_PROPOSAL_DIVERGENCE,
            TagMode::DeriveKeyContext,
            base_office::tag(),
        ),
        (
            purposes::sync::PEER_ASSET_ORIGIN,
            TagMode::NotHashed,
            "oneiron.sync.peer_asset_origin.v1",
        ),
        (
            purposes::sync::RESIDENCE_SEARCH_PAGE,
            TagMode::HashedFirst,
            "oneiron.residence.search.page.v1",
        ),
        (
            purposes::sync::SEALED_BUNDLE_WORK_ID,
            TagMode::DeriveKeyContext,
            base_work::tag(),
        ),
        (
            purposes::sync::SETTLEMENT_REVIEW,
            TagMode::DeriveKeyContext,
            base_settlement::tag(),
        ),
        (
            purposes::sync::TYPED_BODY_DIVERGENCE,
            TagMode::DeriveKeyContext,
            base_typed::tag(),
        ),
        (
            purposes::sync::WINDOW_PAD_ENVELOPE_ID,
            TagMode::NotHashed,
            "oneiron.sync.window_pad_envelope_id.v1",
        ),
    ];
    for (purpose, mode, tag) in recipes {
        assert_eq!(purpose.tag(), tag);
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), mode);
    }
    let election = purposes::sync::ELECTION_BASIS;
    assert_eq!(election.tag().as_bytes(), base_election::tag());
    assert_eq!(election.tag().as_bytes().last(), Some(&0));
    assert_eq!(election.hash(), LegacyHash::Blake3);
    assert_eq!(election.tag_mode(), TagMode::HashedFirst);
}

#[test]
fn election_basis_keeps_main_s_bytes() {
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for from in [None, Some(0), Some(u64::MAX)] {
        for to in [None, Some(0), Some(u64::MAX)] {
            for home in [None, Some(0), Some(u64::MAX)] {
                let times: &[u64] = if home.is_some() { &[0, u64::MAX] } else { &[0] };
                for &elected_at in times {
                    for vault in [[0; 32], [255; 32]] {
                        for machine in [id(1), id(255)] {
                            for target in [0, u64::MAX] {
                                let nodes = [from, to, home];
                                let head = door::election_basis(
                                    &vault,
                                    nodes,
                                    elected_at,
                                    machine.as_bytes(),
                                    target,
                                );
                                assert_eq!(
                                    head,
                                    base_election::basis(
                                        &vault,
                                        nodes,
                                        elected_at,
                                        machine.as_bytes(),
                                        target
                                    )
                                );
                                hashes.insert(head);
                                rows += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!((rows, hashes.len()), (360, 360));
}

#[test]
fn maintenance_ingest_quota_peer_keeps_main_s_bytes() {
    let values = texts();
    let mut hashes = BTreeSet::new();
    for suite in &values {
        for key in &values {
            let head = door::maintenance_ingest_quota_peer(suite.as_bytes(), key.as_bytes());
            assert_eq!(head, base_quota::peer(suite.as_bytes(), key.as_bytes()));
            hashes.insert(head);
        }
    }
    assert_eq!(hashes.len(), 36);
    assert_ne!(
        door::maintenance_ingest_quota_peer(b"ab", b"c"),
        door::maintenance_ingest_quota_peer(b"a", b"bc")
    );
    for key in [[0; 32], [255; 32], [0x5a; 32]] {
        assert_eq!(
            door::maintenance_redaction_peer(&key),
            base_quota::redaction(&key)
        );
        assert_eq!(
            door::maintenance_redaction_peer(&key),
            door::maintenance_ingest_quota_peer(b"ed25519", &key)
        );
    }
    for vault in [0, 1, u64::MAX] {
        assert_eq!(
            door::maintenance_identity_topology_peer(vault),
            base_quota::topology(vault)
        );
        assert_eq!(
            door::maintenance_identity_topology_peer(vault),
            door::maintenance_ingest_quota_peer(b"identity-topology-stream", &vault.to_be_bytes())
        );
    }
}

#[test]
fn office_proposal_divergence_keeps_main_s_bytes() {
    let rows = divergence_rows();
    let mut hashes = BTreeSet::new();
    for (held, carried) in &rows {
        let head = door::office_proposal_divergence(held, carried);
        assert_eq!(
            head,
            base_office::divergence(held, carried).expect("main digest")
        );
        assert_eq!(head, door::office_proposal_divergence(carried, held));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (11, 7));
    assert_ne!(
        door::office_proposal_divergence(b"ab", b"c"),
        door::office_proposal_divergence(b"a", b"bc")
    );
}

#[test]
fn peer_asset_origin_keeps_main_s_bytes() {
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for header in [
        vec![0; oneiron::batch::ENTITY_METADATA_HEADER_LEN],
        vec![255; oneiron::batch::ENTITY_METADATA_HEADER_LEN],
    ] {
        for body in [[0; 32], [255; 32]] {
            for len in [0, u64::MAX] {
                for xxh32 in [0, u32::MAX] {
                    let head = door::peer_asset_origin(&header, &body, len, xxh32);
                    assert_eq!(head, base_asset::asset(&header, &body, len, xxh32));
                    hashes.insert(head);
                    rows += 1;
                }
            }
        }
    }
    assert_eq!((rows, hashes.len()), (16, 16));
}

#[test]
fn residence_search_revision_keeps_main_s_bytes() {
    let long = "長x".repeat(600);
    let fields: Vec<Vec<&[u8]>> = vec![
        vec![],
        vec![b""],
        vec![b"a"],
        vec![b"ab", b"c"],
        vec![b"a", b"bc"],
        vec!["é 日本".as_bytes()],
        vec![long.as_bytes()],
        vec![b"", b""],
    ];
    let hits = hit_rows();
    let mut hashes = BTreeSet::new();
    for fields in &fields {
        for hits in &hits {
            let head = door::search_page_revision(fields, hits);
            assert_eq!(head, base_search::page(fields, hits));
            assert_eq!(head.len(), 64);
            hashes.insert(head);
        }
    }
    assert_eq!(hashes.len(), 48);
    let scope = ResolvedRecallSelection {
        worlds: None,
        project_ids: vec![],
        conversation_ids: None,
        facet: None,
        kinds: None,
    };
    let narrowed = ResolvedRecallSelection {
        worlds: Some(ResolvedRecallWorlds {
            include_base: true,
            world_ids: vec![id(3)],
        }),
        project_ids: vec![id(4)],
        conversation_ids: Some(vec![id(5)]),
        facet: Some(id(6)),
        kinds: Some(vec![1, 2]),
    };
    let filter = ReadFilterInput::default();
    let narrowed_filter = ReadFilterInput {
        entity_types: Some([1, 2].into_iter().collect()),
        max_sensitivity_band: Some(3),
        include_stale: Some(false),
        min_confidence: Some(0.0),
        min_salience: Some(1.0),
    };
    let mut public_hashes = BTreeSet::new();
    let mut public_rows = 0;
    for query in texts() {
        for limit in [0, usize::MAX] {
            for as_of in [0, u64::MAX] {
                for scope in [None, Some(&scope), Some(&narrowed)] {
                    for filter in [None, Some(&filter), Some(&narrowed_filter)] {
                        let head = door::residence_search_revision(
                            &query,
                            limit,
                            b"selector",
                            scope,
                            as_of,
                            filter,
                            &hits[3],
                        );
                        assert_eq!(
                            head,
                            base_search::residence_search_revision(
                                &query,
                                limit,
                                b"selector",
                                scope,
                                as_of,
                                filter,
                                &hits[3]
                            )
                        );
                        public_hashes.insert(head);
                        public_rows += 1;
                    }
                }
            }
        }
    }
    assert_eq!((public_rows, public_hashes.len()), (216, 216));
}

#[test]
fn sealed_bundle_work_id_keeps_main_s_bytes() {
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for home in [None, Some(id(1))] {
        for executor in [id(2), id(255)] {
            for generation in [[0; 24], [255; 24]] {
                for parent in [None, Some([0; 24]), Some([255; 24])] {
                    for root in [None, Some([0; 32]), Some([255; 32])] {
                        for request in [None, Some([0; 32]), Some([255; 32])] {
                            for objects in [
                                [(0, [0; 32]), (u64::MAX, [255; 32])],
                                [(u64::MAX, [255; 32]), (0, [0; 32])],
                            ] {
                                let input = SealedBundleCommitInput {
                                    generation: SealedBundleGeneration::from_bytes(&generation)
                                        .expect("generation"),
                                    parent: parent.map(|raw| {
                                        SealedBundleGeneration::from_bytes(&raw).expect("parent")
                                    }),
                                    root: root.map(RecoveryRootId),
                                    request,
                                };
                                let head = door::sealed_bundle_work_id(
                                    home, executor, generation, parent, root, request, objects,
                                );
                                assert_eq!(
                                    head,
                                    base_work::sealed_bundle_work_id(
                                        home, executor, input, objects
                                    )
                                );
                                hashes.insert(head);
                                rows += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!((rows, hashes.len()), (432, 432));
}

#[test]
fn settlement_approval_keeps_main_s_bytes() {
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for revision in [[0; 32], [255; 32], [0x5a; 32]] {
        for replacement in texts() {
            let head = door::settlement_approval(&revision, &replacement);
            assert_eq!(head, base_settlement::approval(&revision, &replacement));
            hashes.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, hashes.len()), (18, 18));
}

#[test]
fn settlement_revision_keeps_main_s_bytes() {
    let long = "長x".repeat(600);
    let strings = [
        ("", "", ""),
        ("ab", "c", ""),
        ("a", "bc", ""),
        ("é", "日本", "α\0β"),
        (long.as_str(), "", ""),
        ("", long.as_str(), ""),
        ("", "", long.as_str()),
    ];
    let vectors = vector_rows();
    let mut hashes = BTreeSet::new();
    let mut rows = 0;
    for cause in [
        RepoProjectionHoldCause::SealedFileEdited,
        RepoProjectionHoldCause::ProjectionEditConflict,
    ] {
        for (incarnation, text, submitted) in strings {
            for source_vv in &vectors {
                for lineage_vv in &vectors {
                    for (source, stamp, blob) in
                        [(id(1), [0; 32], [255; 32]), (id(2), [255; 32], [0; 32])]
                    {
                        let head = door::settlement_revision(
                            &source,
                            incarnation,
                            text,
                            source_vv,
                            &stamp,
                            &blob,
                            lineage_vv,
                            submitted,
                            cause,
                        );
                        assert_eq!(
                            head,
                            base_settlement::revision(
                                &source,
                                incarnation,
                                text,
                                source_vv,
                                &stamp,
                                &blob,
                                lineage_vv,
                                submitted,
                                cause
                            )
                        );
                        assert_ne!(head, door::settlement_approval(&head, submitted));
                        hashes.insert(head);
                        rows += 1;
                    }
                }
            }
        }
    }
    assert_eq!((rows, hashes.len()), (448, 448));
    let left: VersionVector = [(9u64, 3i32), (1, 2)].into_iter().collect();
    let right: VersionVector = [(1u64, 2i32), (9, 3)].into_iter().collect();
    assert_eq!(
        door::settlement_revision(
            &id(1),
            "",
            "",
            &left,
            &[0; 32],
            &[0; 32],
            &left,
            "",
            RepoProjectionHoldCause::SealedFileEdited
        ),
        door::settlement_revision(
            &id(1),
            "",
            "",
            &right,
            &[0; 32],
            &[0; 32],
            &right,
            "",
            RepoProjectionHoldCause::SealedFileEdited
        )
    );
}

#[test]
fn typed_body_divergence_keeps_main_s_bytes() {
    let rows = divergence_rows();
    let mut hashes = BTreeSet::new();
    for (held, carried) in &rows {
        let head = door::typed_body_divergence(held, carried);
        assert_eq!(head, base_typed::divergence(held, carried));
        assert_eq!(head, door::typed_body_divergence(carried, held));
        assert_ne!(head, door::office_proposal_divergence(held, carried));
        hashes.insert(head);
    }
    assert_eq!((rows.len(), hashes.len()), (11, 7));
    assert_ne!(
        door::typed_body_divergence(b"ab", b"c"),
        door::typed_body_divergence(b"a", b"bc")
    );
}

#[test]
fn window_pad_envelope_id_keeps_main_s_bytes() {
    let mut headers = texts()
        .into_iter()
        .map(String::into_bytes)
        .collect::<Vec<_>>();
    headers.extend([
        vec![0; oneiron::sync::transport::WINDOW_PAD_HEADER_BYTES],
        vec![255; oneiron::sync::transport::WINDOW_PAD_HEADER_BYTES],
    ]);
    let mut hashes = BTreeSet::new();
    for header in &headers {
        let head = door::window_pad_envelope_id(header);
        assert_eq!(head, base_envelope::id(header));
        hashes.insert(head);
    }
    assert_eq!((headers.len(), hashes.len()), (8, 8));
}

#[test]
fn note_operation_hash_keeps_main_s_bytes() {
    use oneiron_records::note::document::{NotePin, NoteScalarEdit};
    let mut operations = texts()
        .into_iter()
        .map(|title| NoteOperation {
            request_id: id(1),
            change: NoteChange::SetTitle { title },
        })
        .collect::<Vec<_>>();
    operations.push(NoteOperation {
        request_id: id(2),
        change: NoteChange::Edit {
            base: vec![],
            edits: vec![],
        },
    });
    operations.push(NoteOperation {
        request_id: id(2),
        change: NoteChange::Edit {
            base: vec![0, 255],
            edits: vec![
                NoteScalarEdit {
                    start: 0,
                    delete: usize::MAX,
                    insert: "é 日本".into(),
                },
                NoteScalarEdit {
                    start: usize::MAX,
                    delete: 0,
                    insert: "長x".repeat(600),
                },
            ],
        },
    });
    operations.push(NoteOperation {
        request_id: id(3),
        change: NoteChange::Cite {
            pin: NotePin {
                claim: id(4),
                document: id(5),
                frontier: vec![],
                start_cursor: vec![0],
                end_cursor: vec![255],
                quote_hash: [255; 32],
                quote_text: "é 日本".into(),
            },
        },
    });
    let mut hashes = BTreeSet::new();
    for operation in &operations {
        let head = operation.hash().expect("operation hash");
        assert_eq!(
            head,
            base_note::hash(operation).expect("main operation hash")
        );
        let decoded =
            NoteOperation::decode(&operation.encode().expect("JSON")).expect("public decoder");
        assert_eq!(decoded.hash().expect("round-trip hash"), head);
        hashes.insert(head);
    }
    assert_eq!((operations.len(), hashes.len()), (9, 9));
}
