//! K-proof door for sync digests that existing records store, send or compare.
//! Compiled only under `oneiron_test_support`; never part of the engine API.
#![cfg(oneiron_test_support)]

use loro::VersionVector;

use crate::EntityId;
use crate::memory::ReadFilterInput;
use crate::origin::RepoProjectionHoldCause;
use crate::sync::residence::ResolvedRecallSelection;
use crate::sync::types::WindowKey;
use crate::sync::{self, residence};
use crate::world_keys::{RecoveryRootId, SealedBundleGeneration};

/// The election evidence stored in the signed and sealed HomeMove.
#[must_use]
pub fn election_basis(
    vault_id: &[u8; 32],
    nodes: [Option<u64>; 3],
    elected_at: u64,
    target_machine: &[u8; 16],
    target_node: u64,
) -> [u8; 32] {
    sync::home_handoff::election_basis_for_test(
        vault_id,
        nodes,
        elected_at,
        target_machine,
        target_node,
    )
}

/// The peer identity stored in local maintenance-ingest quota keys.
#[must_use]
pub fn maintenance_ingest_quota_peer(suite: &[u8], public_key: &[u8]) -> [u8; 32] {
    sync::quota::peer_key_from_signature_key_for_test(suite, public_key)
}

/// The redaction wrapper's quota key.
#[must_use]
pub fn maintenance_redaction_peer(public_key: &[u8; 32]) -> [u8; 32] {
    sync::quota::peer_key_from_redaction_pubkey_for_test(public_key)
}

/// The identity-topology stream wrapper's quota key.
#[must_use]
pub fn maintenance_identity_topology_peer(lease_vault_id: u64) -> [u8; 32] {
    sync::quota::peer_key_from_identity_topology_stream_for_test(lease_vault_id)
}

/// The OfficeProposals quarantine identity of two copies.
#[must_use]
pub fn office_proposal_divergence(held: &[u8], carried: &[u8]) -> [u8; 32] {
    sync::office_proposals::divergence_of_for_test(held, carried)
}

/// The logical ASSET origin stored beside its exact wire digest.
#[must_use]
pub fn peer_asset_origin(header: &[u8], blake3: &[u8; 32], len: u64, xxh32: u32) -> [u8; 32] {
    sync::asset_digest_for_test(header, blake3, len, xxh32)
}

/// The exact lowercase-hex page revision of already constructed field transcripts.
#[must_use]
pub fn search_page_revision(fields: &[&[u8]], hits: &[(EntityId, WindowKey)]) -> String {
    residence::search_page_revision_for_test(fields, hits)
}

/// The public search-revision path, including scope and filter transcript construction.
#[must_use]
pub fn residence_search_revision(
    query: &str,
    limit: usize,
    selector_wire: &[u8],
    scope: Option<&ResolvedRecallSelection>,
    as_of: u64,
    filter: Option<&ReadFilterInput>,
    hits: &[(EntityId, WindowKey)],
) -> String {
    residence::residence_search_revision(query, limit, selector_wire, scope, as_of, filter, hits)
}

/// The caller-known work id used as the durable sealed-bundle work key.
#[must_use]
pub fn sealed_bundle_work_id(
    home: Option<EntityId>,
    executor: EntityId,
    generation: [u8; 24],
    parent: Option<[u8; 24]>,
    root: Option<[u8; 32]>,
    request: Option<[u8; 32]>,
    objects: [(u64, [u8; 32]); 2],
) -> [u8; 32] {
    let input = residence::SealedBundleCommitInput {
        generation: SealedBundleGeneration::from_bytes(&generation).expect("24-byte generation"),
        parent: parent
            .map(|bytes| SealedBundleGeneration::from_bytes(&bytes).expect("24-byte parent")),
        root: root.map(RecoveryRootId),
        request,
    };
    residence::sealed_bundle_work_id(home, executor, input, objects)
}

/// The exact replacement token the settlement writer compares.
#[must_use]
pub fn settlement_approval(revision: &[u8; 32], replacement: &str) -> [u8; 32] {
    sync::selector::secret_projection::approval_token_for_test(revision, replacement)
}

/// The opaque settlement revision sent to the owner and compared on replacement.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn settlement_revision(
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
    sync::selector::secret_projection::revision_hash_for_test(
        source,
        incarnation,
        text,
        source_vv,
        stamp,
        blob,
        lineage_vv,
        submitted,
        cause,
    )
}

/// The TypedBodyRows quarantine identity of two copies.
#[must_use]
pub fn typed_body_divergence(held: &[u8], carried: &[u8]) -> [u8; 32] {
    sync::typed_body_rows::divergence_digest_for_test(held, carried)
}

/// The header identity compared against continuation frame ids.
#[must_use]
pub fn window_pad_envelope_id(header: &[u8]) -> [u8; 32] {
    sync::transport::WindowPadAssembly::envelope_id_for_test(header)
}
