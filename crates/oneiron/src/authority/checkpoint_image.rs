//! The portable authority checkpoint v2 image (OF-469): the exact fold a vault
//! builds of its covered history, in one canonical encoding, and the unsigned
//! id an attestation names.
//!
//! An image commits an exact ancestor-closed covered set, its frontier, the
//! fold state at each frontier row and the merged fold, the safety indexes a
//! fold past it reads, the unresolved closure it holds back, its archive
//! manifests, the fold schema, and the root policy it was built under
//! (identity.md, "Resumable checkpoints and cold authority history"). A
//! decoded image is checked, never trusted: trust is a quorum attestation and
//! an adoption, both elsewhere.
//!
//! Receiver-local facts stay out: first-seen times, sequence floors, vouches,
//! the observation policy, the install pin, no-vouch deadlines, and every
//! clock or anti-rollback receipt. The image fold runs with no clock; each
//! approval the stale-roster window could still expire is declared unresolved
//! rather than decided, and a build that a local sequence floor would decide
//! refuses. Covered rows a later fold reads whole travel as their canonical
//! signed bytes: the signed wire codec has no serde form.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use serde::{Deserialize, Serialize};

use super::revoke_proof::RevokeFacts;
use super::*;
use crate::error::{Error, RecordError, Result};
use crate::{EntityId, HostingPrivacyPosture, Vault};

/// The fold-state schema an image encodes. A decoder refuses any other.
pub const AUTHORITY_CHECKPOINT_FOLD_SCHEMA: u32 = 1;
/// The domain every encoded image starts with.
pub const AUTHORITY_CHECKPOINT_V2_DOMAIN: &[u8] = b"oneiron/authority/checkpoint/v2";
/// The context of an image's id over its encoded bytes.
pub const AUTHORITY_CHECKPOINT_V2_ID_CONTEXT: &str = "oneiron/authority/checkpoint-v2/id/v1";
/// The largest encoded image a vault writes or decodes.
pub const AUTHORITY_CHECKPOINT_V2_MAX_BYTES: usize = 64 * 1024 * 1024;

/// One covered row, as a fold past the image reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointRow {
    pub signer: AuthorityKey,
    pub seq: u64,
    /// The parents, in the signed row's order.
    pub parents: Vec<AuthorityEntryHash>,
    /// The world of a side-branch row.
    pub world: Option<EntityId>,
    /// Whether the row is a slip op (a mint, a slip revocation or a
    /// consumption): a store door counts a slip issuer's slip ops toward no
    /// bound.
    pub slip_op: bool,
    /// The canonical signed body of a row a fold or a store door past the
    /// image reads whole (an approval, a binding, a confirm, a revocation, a
    /// handoff, an enrollment, the genesis, a root record, a machine profile,
    /// a world edit or a world-key record); None for every other row.
    #[serde(with = "body_bytes")]
    pub body: Option<Vec<u8>>,
}

/// Whether an image carries the canonical signed body of a covered row of
/// `op`'s kind: each row a fold past the image reads whole
/// ([`super::fold_resume::is_projected`]: an approval, a binding, a confirm,
/// a device revocation, a handoff, a machine profile, a world-key record),
/// and each row a store door past it reads whole to judge a new row: the
/// genesis and each device enrollment the consent structure rests on, the
/// root records that name owner anchors, the actor revocations a signer's
/// revocations count, and the world edits that may be a stranger's.
pub(super) fn carries_body(op: &AuthorityOp) -> bool {
    super::fold_resume::is_projected(op)
        || matches!(
            op,
            AuthorityOp::Genesis { .. }
                | AuthorityOp::EnrollDevice { .. }
                | AuthorityOp::OwnerRoot(_)
                | AuthorityOp::RevokeActor { .. }
                | AuthorityOp::WorldPrivacy(_)
        )
}

/// The fold the image commits: the settled once fold before any install's
/// stale-roster window, with no receiver-local field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointAggregate {
    /// The hosting posture the fold judged under.
    pub(super) posture: HostingPrivacyPosture,
    /// The admitted peers' consent roots the fold read (FED-01 evidence).
    pub(super) peers: BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    /// The merge of every surviving state, before any restrictive fact.
    pub(super) merged: FoldState,
    /// The projected once fold. Its install bound and pin are empty: what the
    /// building install held back is in [`AuthorityCheckpointUnresolved`].
    pub(super) fold: AuthorityFold,
}

/// The sequence, fork, actor, slip and confirm indexes a fold past the image
/// reads beside the merged state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointSafety {
    /// Sequence: the slip issuers, the slip rows the ancestry budget does
    /// not count, the ancestor pairs and counted pairs, and per frontier row
    /// its ancestors and counted ancestors.
    pub(super) issuers: BTreeSet<AuthorityKey>,
    pub(super) uncounted: BTreeSet<AuthorityEntryHash>,
    pub(super) pairs: u64,
    pub(super) counted_pairs: u64,
    pub(super) frontier_ancestry: BTreeMap<AuthorityEntryHash, (u64, u64)>,
    /// Fork and slip: the restrictive facts proved on their own branches
    /// (actor revocations, slip withdrawals and burns, machine removals),
    /// the retired keys, the closed handoffs, whether a handoff is
    /// unsettled, the settlement's issues, the parents no folded row is, and
    /// the owner-held roster marks before custody is judged.
    pub(super) revoke_facts: RevokeFacts,
    pub(super) retired_keys: BTreeSet<AuthorityKey>,
    pub(super) closed_handoffs: BTreeSet<AuthorityEntryHash>,
    pub(super) unsettled: bool,
    pub(super) issues: Vec<AuthorityFoldIssue>,
    pub(super) missing_parents: BTreeSet<AuthorityEntryHash>,
    pub(super) marks: Vec<(AuthorityEntryHash, AuthorityKey)>,
    /// Actor: the final merge's revocations, every binding any state holds,
    /// and the keys a main state holds a live binding for.
    pub(super) revocations: BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>>,
    pub(super) writers: BTreeMap<AuthorityKey, BTreeSet<(EntityId, String)>>,
    pub(super) bound_keys: BTreeSet<AuthorityKey>,
    /// Confirm: the federation confirm ids and nonces across every state, and
    /// every confirmation id seen for each critical-write nonce, which the
    /// projected fold drops.
    pub(super) confirm_ids: BTreeSet<[u8; 32]>,
    pub(super) confirm_nonces: BTreeSet<[u8; 16]>,
    pub(super) nonce_provenance: BTreeMap<[u8; 16], BTreeSet<[u8; 32]>>,
}

/// What the image holds back, typed and never omitted. Each list ascends.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointUnresolved {
    /// Held rows outside `covered`: an ancestor of each is not held here.
    pub held: Vec<AuthorityEntryHash>,
    /// The parents held rows name that no held row is.
    pub missing: Vec<AuthorityEntryHash>,
    /// Covered handoffs in conflict: no successor stands until one settles.
    pub unsettled_handoffs: Vec<AuthorityEntryHash>,
    /// Covered machine revisions and world edits the building install held
    /// back to restriction only.
    pub held_back: Vec<AuthorityEntryHash>,
    /// Covered approvals resting on a key revoked since: whether each has
    /// expired turns on the reader's own first-seen clock, still pending.
    pub stale_approvals: Vec<AuthorityEntryHash>,
}

/// One cold archive that holds covered rows' original signed scaffold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityArchiveManifest {
    /// The archive's content id.
    pub archive: [u8; 32],
    /// The covered rows it holds, ascending.
    pub rows: Vec<AuthorityEntryHash>,
}

/// A portable authority checkpoint image (OF-469, checkpoint v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointV2 {
    pub fold_schema: u32,
    pub vault_id: AuthorityVaultId,
    /// The authority genesis row's hash.
    pub genesis: AuthorityEntryHash,
    /// Every covered row, ascending: each covered row's parents are covered.
    pub covered: Vec<AuthorityEntryHash>,
    /// The covered rows no covered row names as a parent, ascending.
    pub frontier: Vec<AuthorityEntryHash>,
    /// Each covered row's summary, keyed as `covered`.
    pub rows: BTreeMap<AuthorityEntryHash, AuthorityCheckpointRow>,
    /// The fold state at each frontier row, keyed as `frontier`; None for a
    /// frontier row the fold holds no state for (a rejected row).
    pub(super) per_parent: BTreeMap<AuthorityEntryHash, Option<FoldState>>,
    pub(super) aggregate: CheckpointAggregate,
    pub(super) safety: CheckpointSafety,
    pub unresolved: AuthorityCheckpointUnresolved,
    /// Empty while no cold archive exists.
    pub archive_manifests: Vec<AuthorityArchiveManifest>,
    /// The root policy the image was built under. A verifier takes its
    /// policy from its own pin, never from here.
    pub root_policy: CheckpointRootPolicy,
    /// The owner-root pin of the install that built the image: its fold
    /// counted world keys and local reads under that pin. An adopter's own
    /// pin must equal it.
    pub building_pin: Option<PinnedRoot>,
    /// The previous image's id in this vault's local chain.
    pub parent: Option<[u8; 32]>,
}

/// The coverage an image's bytes name, read alone.
#[derive(Deserialize)]
struct CoveredOnly {
    covered: Vec<AuthorityEntryHash>,
}

fn refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

fn ascending(hashes: &[AuthorityEntryHash]) -> bool {
    hashes.windows(2).all(|pair| pair[0] < pair[1])
}

/// The id of an encoded image: what an attestation names. Signatures never
/// enter it (SLH-DSA is randomized).
pub(super) fn checkpoint_image_id(encoded: &[u8]) -> [u8; 32] {
    blake3::derive_key(AUTHORITY_CHECKPOINT_V2_ID_CONTEXT, encoded)
}

/// The covered hashes an image's bytes name, read without the rest of the
/// image and without trusting it: naming a hash as history to fetch is not
/// trust.
pub(super) fn covered_of(bytes: &[u8]) -> Result<Vec<AuthorityEntryHash>> {
    let body = bytes
        .strip_prefix(AUTHORITY_CHECKPOINT_V2_DOMAIN)
        .filter(|_| bytes.len() <= AUTHORITY_CHECKPOINT_V2_MAX_BYTES)
        .ok_or_else(|| refused("checkpoint image framing"))?;
    let coverage: CoveredOnly =
        rmp_serde::from_slice(body).map_err(|_| refused("checkpoint image coverage"))?;
    if !ascending(&coverage.covered) {
        return Err(refused("checkpoint image coverage"));
    }
    Ok(coverage.covered)
}

impl AuthorityCheckpointV2 {
    /// The canonical bytes: the v2 domain, then named MessagePack, after the
    /// shape check. An image past the size cap does not encode.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let mut bytes = AUTHORITY_CHECKPOINT_V2_DOMAIN.to_vec();
        rmp_serde::encode::write_named(&mut bytes, self)
            .map_err(|_| refused("checkpoint image does not encode"))?;
        if bytes.len() > AUTHORITY_CHECKPOINT_V2_MAX_BYTES {
            return Err(refused("checkpoint image exceeds its size cap"));
        }
        Ok(bytes)
    }

    /// Strict decoding: the size cap, the domain, the whole body consumed,
    /// the shape check, and canonical re-encoding. A decoded image is
    /// checked, not trusted.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > AUTHORITY_CHECKPOINT_V2_MAX_BYTES {
            return Err(refused("checkpoint image exceeds its size cap"));
        }
        let body = bytes
            .strip_prefix(AUTHORITY_CHECKPOINT_V2_DOMAIN)
            .ok_or_else(|| refused("checkpoint image domain"))?;
        let mut cursor = Cursor::new(body);
        let image: Self = rmp_serde::decode::from_read(&mut cursor)
            .map_err(|_| refused("checkpoint image does not decode"))?;
        if cursor.position() != body.len() as u64 {
            return Err(refused("checkpoint image trailing bytes"));
        }
        if image.encode()? != bytes {
            return Err(refused("checkpoint image is not canonical"));
        }
        Ok(image)
    }

    /// The unsigned image id signatures name.
    pub fn id(&self) -> Result<[u8; 32]> {
        Ok(checkpoint_image_id(&self.encode()?))
    }

    /// The projected fold the image commits.
    #[must_use]
    pub fn fold(&self) -> &AuthorityFold {
        &self.aggregate.fold
    }

    fn shape(&self) -> Result<()> {
        if self.fold_schema != AUTHORITY_CHECKPOINT_FOLD_SCHEMA {
            return Err(refused("checkpoint image fold schema"));
        }
        if self.vault_id == [0; 32] || self.genesis != self.vault_id {
            return Err(refused("checkpoint image vault"));
        }
        self.shape_rows()?;
        self.shape_state()?;
        self.shape_held_back()?;
        self.root_policy.canonical_bytes()?;
        Ok(())
    }

    /// Covered, frontier and rows: sorted, unique, ancestor-closed from the
    /// genesis, and each carried body the row it summarizes.
    fn shape_rows(&self) -> Result<()> {
        if !ascending(&self.covered)
            || !ascending(&self.frontier)
            || !self.rows.keys().eq(self.covered.iter())
            || !self.per_parent.keys().eq(self.frontier.iter())
        {
            return Err(refused("checkpoint image coverage"));
        }
        if self
            .rows
            .get(&self.genesis)
            .is_none_or(|genesis| !genesis.parents.is_empty())
        {
            return Err(refused("checkpoint image genesis"));
        }
        let mut named = BTreeSet::new();
        for (hash, row) in &self.rows {
            for parent in &row.parents {
                if !self.rows.contains_key(parent) {
                    return Err(refused("checkpoint image coverage is not ancestor-closed"));
                }
                named.insert(*parent);
            }
            if let Some(body) = &row.body {
                row_body_matches(hash, row, body)?;
            }
        }
        if !self
            .rows
            .keys()
            .filter(|hash| !named.contains(*hash))
            .eq(self.frontier.iter())
        {
            return Err(refused("checkpoint image frontier"));
        }
        Ok(())
    }

    /// The fold states name this vault and only covered rows, carry no
    /// receiver-local field, and agree with the safety indexes.
    fn shape_state(&self) -> Result<()> {
        let covered = |hash: &AuthorityEntryHash| self.rows.contains_key(hash);
        let aggregate = &self.aggregate;
        let safety = &self.safety;
        if aggregate.merged.vault_id != self.vault_id
            || aggregate.fold.vault_id != Some(self.vault_id)
            || self
                .per_parent
                .values()
                .flatten()
                .any(|state| state.vault_id != self.vault_id)
        {
            return Err(refused("checkpoint image fold vault"));
        }
        if aggregate.fold.install != InstallBound::default()
            || aggregate.fold.pinned_root.is_some()
            || CheckpointPosture::from(aggregate.posture) != self.root_policy.posture
        {
            return Err(refused("checkpoint image carries an install's own facts"));
        }
        if !aggregate.fold.valid_entries.iter().all(covered)
            || !safety.uncounted.iter().all(covered)
            || !safety.closed_handoffs.iter().all(covered)
            || !safety
                .frontier_ancestry
                .keys()
                .all(|hash| self.per_parent.contains_key(hash))
            || safety.nonce_provenance != aggregate.merged.critical_write_confirm_nonce_provenance
        {
            return Err(refused("checkpoint image safety indexes"));
        }
        Ok(())
    }

    /// The unresolved closure and the archive manifests: sorted, unique, and
    /// each list on the side of `covered` it names.
    fn shape_held_back(&self) -> Result<()> {
        let covered = |hash: &AuthorityEntryHash| self.rows.contains_key(hash);
        let unresolved = &self.unresolved;
        let lists = [
            &unresolved.held,
            &unresolved.missing,
            &unresolved.unsettled_handoffs,
            &unresolved.held_back,
            &unresolved.stale_approvals,
        ];
        if lists.iter().any(|list| !ascending(list))
            || unresolved
                .held
                .iter()
                .chain(&unresolved.missing)
                .any(covered)
            || unresolved
                .missing
                .iter()
                .any(|hash| unresolved.held.binary_search(hash).is_ok())
            || !unresolved
                .unsettled_handoffs
                .iter()
                .chain(&unresolved.held_back)
                .chain(&unresolved.stale_approvals)
                .all(covered)
        {
            return Err(refused("checkpoint image unresolved closure"));
        }
        if self
            .archive_manifests
            .windows(2)
            .any(|pair| pair[0].archive >= pair[1].archive)
            || self.archive_manifests.iter().any(|manifest| {
                manifest.rows.is_empty()
                    || !ascending(&manifest.rows)
                    || !manifest.rows.iter().all(covered)
            })
        {
            return Err(refused("checkpoint image archive manifests"));
        }
        Ok(())
    }
}

/// A carried body is the canonical signed row its summary names, and a row
/// the image carries whole.
fn row_body_matches(
    hash: &AuthorityEntryHash,
    row: &AuthorityCheckpointRow,
    body: &[u8],
) -> Result<()> {
    let entry = decode_authority_log_entry_body(body)?;
    if authority_entry_hash(&entry)? != *hash
        || entry.signer_key() != &row.signer
        || entry.seq != row.seq
        || entry.parent_hashes != row.parents
        || super::world_privacy::side_world(&entry.op) != row.world
        || super::log_budget::is_slip_op(&entry.op) != row.slip_op
        || !carries_body(&entry.op)
    {
        return Err(refused("checkpoint image row body"));
    }
    Ok(())
}

/// One held row: its signed entry and its stored canonical body.
type HeldRow = (AuthorityLogEntry, Vec<u8>);

/// The held rows whose every ancestor is held, the held rows outside them,
/// and the parents held rows name that no held row is.
fn covered_closure(
    held: &BTreeMap<AuthorityEntryHash, HeldRow>,
) -> (
    BTreeSet<AuthorityEntryHash>,
    BTreeSet<AuthorityEntryHash>,
    BTreeSet<AuthorityEntryHash>,
) {
    let mut children = BTreeMap::<AuthorityEntryHash, Vec<AuthorityEntryHash>>::new();
    let mut waiting = BTreeMap::<AuthorityEntryHash, usize>::new();
    let mut ready = Vec::new();
    let mut missing = BTreeSet::new();
    for (hash, (entry, _)) in held {
        let parents: BTreeSet<_> = entry.parent_hashes.iter().copied().collect();
        for parent in &parents {
            if !held.contains_key(parent) {
                missing.insert(*parent);
            }
            children.entry(*parent).or_default().push(*hash);
        }
        if parents.is_empty() {
            ready.push(*hash);
        } else {
            waiting.insert(*hash, parents.len());
        }
    }
    let mut covered = BTreeSet::new();
    while let Some(hash) = ready.pop() {
        if !covered.insert(hash) {
            continue;
        }
        for child in children.get(&hash).into_iter().flatten() {
            if let Some(count) = waiting.get_mut(child) {
                *count -= 1;
                if *count == 0 {
                    waiting.remove(child);
                    ready.push(*child);
                }
            }
        }
    }
    let uncovered = held
        .keys()
        .filter(|hash| !covered.contains(*hash))
        .copied()
        .collect();
    (covered, uncovered, missing)
}

impl Vault {
    /// This vault's checkpoint v2 image of the history it holds, from one
    /// read snapshot. Unlinked: [`Vault::write_authority_checkpoint_v2`] sets
    /// its parent and keeps it.
    pub fn build_authority_checkpoint_v2(&self) -> Result<AuthorityCheckpointV2> {
        let txn = self.store.env.read_txn()?;
        self.build_authority_checkpoint_v2_in_txn(&txn)
    }

    /// [`Vault::build_authority_checkpoint_v2`] in the caller's snapshot.
    pub(super) fn build_authority_checkpoint_v2_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<AuthorityCheckpointV2> {
        let store = &self.store;
        let posture = self.privacy_posture();
        let mut held = BTreeMap::new();
        for (_, body) in super::readonly_fold::authority_log_rows_in_txn(store, txn)? {
            let entry = decode_authority_log_entry_body(&body)?;
            held.insert(authority_entry_hash(&entry)?, (entry, body));
        }
        let (covered, uncovered, missing) = covered_closure(&held);
        let entries = covered
            .iter()
            .map(|hash| held.get(hash).map(|(entry, _)| entry.clone()))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(invalid_authority)?;
        let named: BTreeSet<_> = entries
            .iter()
            .flat_map(|entry| entry.parent_hashes.iter().copied())
            .collect();
        let frontier: BTreeSet<_> = covered
            .iter()
            .filter(|hash| !named.contains(*hash))
            .copied()
            .collect();
        // A local floor is an anti-rollback receipt: an image never carries
        // what one decided.
        let observations = authority_local_observations_in_txn(store, txn, &entries)?;
        if entries.iter().zip(&covered).any(|(entry, hash)| {
            observations
                .sequence_floors
                .get(hash)
                .is_some_and(|floor| entry.seq < *floor)
        }) {
            return Err(refused(
                "a local sequence floor decides a covered authority row",
            ));
        }
        let peers = crate::federation::admitted_peer_consent_roots_in_txn(self, txn)?;
        let pin = super::pinned_root::read_pinned_root_in_txn(store, txn)?;
        let capture = super::fold_resume::FoldCapture::for_image(frontier.clone());
        let (consent, local) = super::fold_engine::own_log_inputs(posture, pin.as_ref());
        // No first-seen time and no clock: nothing time-dependent is decided.
        let fold = super::fold_engine::fold_authority_log_inner(
            &entries,
            &BTreeMap::new(),
            None,
            &peers,
            consent,
            super::fold_engine::FoldLocalInputs {
                observations: Some(&observations),
                capture: Some(&capture),
                ..local
            },
        );
        let vault_id = fold
            .vault_id
            .filter(|_| !fold.vault_root_is_conflicted())
            .ok_or_else(|| refused("the covered authority history has no settled root"))?;
        let super::fold_resume::ImageFold {
            per_parent,
            merged,
            fold: mut once,
            safety,
        } = *capture
            .take_image()
            .ok_or_else(|| refused("the covered authority history left no image"))?;
        if once.vault_id != Some(vault_id)
            || held
                .get(&vault_id)
                .is_none_or(|(entry, _)| genesis_vault_id(entry).ok() != Some(vault_id))
        {
            return Err(refused("the covered authority history has no settled root"));
        }
        let mut unsettled_handoffs: Vec<_> = safety
            .issues
            .iter()
            .filter_map(|issue| match issue {
                AuthorityFoldIssue::UnsettledHandoff(hash) => Some(*hash),
                _ => None,
            })
            .collect();
        unsettled_handoffs.sort_unstable();
        unsettled_handoffs.dedup();
        let unresolved = AuthorityCheckpointUnresolved {
            held: uncovered.into_iter().collect(),
            missing: missing.into_iter().collect(),
            unsettled_handoffs,
            held_back: std::mem::take(&mut once.install.held_back)
                .into_iter()
                .collect(),
            stale_approvals: super::stale_roster::stale_roster_subject_approvals(&entries, &once)
                .into_iter()
                .collect(),
        };
        once.install = InstallBound::default();
        once.pinned_root = None;
        let rows = covered
            .iter()
            .map(|hash| {
                let (entry, body) = held.get(hash).ok_or_else(invalid_authority)?;
                let row = AuthorityCheckpointRow {
                    signer: entry.signer_key().clone(),
                    seq: entry.seq,
                    parents: entry.parent_hashes.clone(),
                    world: super::world_privacy::side_world(&entry.op),
                    slip_op: super::log_budget::is_slip_op(&entry.op),
                    body: carries_body(&entry.op).then(|| body.clone()),
                };
                Ok((*hash, row))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let image = AuthorityCheckpointV2 {
            fold_schema: AUTHORITY_CHECKPOINT_FOLD_SCHEMA,
            vault_id,
            genesis: vault_id,
            covered: covered.into_iter().collect(),
            frontier: frontier.into_iter().collect(),
            rows,
            per_parent,
            aggregate: CheckpointAggregate {
                posture,
                peers,
                merged,
                fold: once,
            },
            safety,
            unresolved,
            archive_manifests: Vec::new(),
            root_policy: self.checkpoint_root_policy_in_txn(txn)?,
            building_pin: pin,
            parent: None,
        };
        // One serde round trip normalizes what a decoder would (an empty
        // scope set is the bottom), so the image re-encodes to its own bytes.
        let normalized: AuthorityCheckpointV2 = rmp_serde::from_slice(
            &rmp_serde::to_vec_named(&image)
                .map_err(|_| refused("checkpoint image does not encode"))?,
        )
        .map_err(|_| refused("checkpoint image does not decode"))?;
        normalized.encode()?;
        Ok(normalized)
    }
}

/// A row body as one MessagePack byte string.
mod body_bytes {
    use serde::de::{Error, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        body: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match body {
            Some(bytes) => serializer.serialize_some(&Bin(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Ok(Option::<BinBuf>::deserialize(deserializer)?.map(|body| body.0))
    }

    struct Bin<'a>(&'a [u8]);

    impl Serialize for Bin<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }

    struct BinBuf(Vec<u8>);

    impl<'de> Deserialize<'de> for BinBuf {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_byte_buf(BinVisitor)
        }
    }

    struct BinVisitor;

    impl Visitor<'_> for BinVisitor {
        type Value = BinBuf;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a row body byte string")
        }

        fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            Ok(BinBuf(bytes.to_vec()))
        }

        fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            Ok(BinBuf(bytes))
        }
    }
}
