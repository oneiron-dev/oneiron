//! Durable typed child proposals and their live root write fence.
use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::super::ConsolidationBucketKey;
use super::super::support::invalid_consolidation;
use super::{Root, bucket_key, pin_reference, reference, require_readable};
mod recovery;
use crate::attempt_queue::AttemptId;
use crate::claim::ScopedRead;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, decode_dreamer_attempt_payload,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::consolidation_frontier::{
    ConsolidationBucketAccounting, ConsolidationChildFrontier, ConsolidationChildReceipt,
    ConsolidationFrontierRequest, ConsolidationReference, ConsolidationRootBucket,
    ConsolidationRootEvidence,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::{Result, Vault};
pub(super) use recovery::GrantedClose;

/// The bridge attempt type. Queued on the existing Micro kind
/// (`DreamerConsolidationScope::Micro.attempt_kind()`), so wake preparation
/// skips its non-partition input by decode failure and the partition window
/// excludes it by attempt type; the inner executor arm runs it.
pub(in crate::dreamer_consolidation) const ATTEMPT: &str = "dreamer.consolidation.root_bridge";

/// Domain of the per-payload dedupe-children digest (dedupe key segment).
const DEDUPE_DOMAIN: &[u8] = b"oneiron:root-bridge-dedupe:v1";
/// Domain of `RootBinding` identity.
const BINDING_IDENTITY_DOMAIN: &[u8] = b"oneiron:root-bridge-binding:v1";

/// Private queue schema (NOT the public frontier schema): one bucket group of
/// newly-accepted children, with their ORIGINAL typed frontiers. Judgement
/// values stay JSON-native here; no JSON->rmpv conversion of proposals happens
/// before the final candidate (Root owns `json_to_rmpv` at candidate build).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::dreamer_consolidation) struct RootPayload {
    /// Side-table root id (hex). Excluded from read-context entity ids.
    /// Fields are `pub` for the root executor; effective visibility stays
    /// consolidation-only through the struct.
    pub root_ref: String,
    /// Owner hex FOR ERASURE ONLY. Never authority, never actor.
    pub owner: String,
    /// Audit lineage only (LMDB revision at pin). NEVER a content version.
    pub revision: u64,
    pub bucket: ConsolidationRootBucket,
    pub bucket_hash: [u8; 32],
    /// Canonical child_ref-ordered; each evidence sorted/deduped.
    pub children: Vec<ConsolidationChildFrontier>,
    /// Every original selector/source/ancestor/MESSAGE this payload depends on.
    /// Captured by the producer, so source erasure needs no surviving root.
    pub dependencies: Vec<String>,
}

impl RootPayload {
    /// Keep the public judgement's JSON representation inside the queue's
    /// MessagePack string; no intermediate value coercion changes its digest.
    pub(in crate::dreamer_consolidation) fn encode(&self) -> Result<Value> {
        serde_json::to_string(self)
            .map(Value::from)
            .map_err(|_| invalid_consolidation("root bridge payload does not encode"))
    }

    pub(in crate::dreamer_consolidation) fn decode(input: &Value) -> Result<Self> {
        let json = input
            .as_str()
            .ok_or_else(|| invalid_consolidation("root bridge input is not a root payload"))?;
        serde_json::from_str(json)
            .map_err(|_| invalid_consolidation("root bridge input is not a root payload"))
    }

    /// Stable dedupe key: type + root + bucket + digest over the canonical
    /// children bytes. `serde_json` struct field order is deterministic, the
    /// same stability the child-receipt judgement hash already relies on.
    /// Shape mirrors `person_about` (`type:hex:hex`, colons legal); ~195 bytes,
    /// under the 512-byte dedupe cap.
    pub(in crate::dreamer_consolidation) fn dedupe_key(&self) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DEDUPE_DOMAIN);
        hasher.update(&(self.children.len() as u64).to_be_bytes());
        for child in &self.children {
            let bytes = serde_json::to_vec(child)
                .map_err(|_| invalid_consolidation("root bridge child does not encode"))?;
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
        }
        Ok(format!(
            "{}:{}:{}:{}",
            ATTEMPT,
            self.root_ref,
            bytes_to_hex_lower(&self.bucket_hash),
            bytes_to_hex_lower(hasher.finalize().as_bytes()),
        ))
    }

    /// Entity ids a read context for `input` covers: the bucket selectors
    /// (subject/world/facet/project/relationship set) plus every evidence
    /// source (and claim) id. EXCLUDES the side-table `root_ref` and the
    /// opaque `child_ref` strings. `None` when the input is not a decodable
    /// bridge payload. The executor feeds this into the native
    /// `declare_attempt_reads`/`record_attempt_reads` read-set doors.
    pub(in crate::dreamer_consolidation) fn about(input: &Value) -> Option<Vec<EntityId>> {
        let payload = Self::decode(input).ok()?;
        let key = bucket_key(&payload.bucket).ok()?;
        let mut ids = BTreeSet::new();
        ids.insert(key.subject);
        ids.extend(key.world);
        ids.extend(key.facet);
        ids.insert(key.project);
        if let Some(rel) = key.rel.as_ref() {
            ids.extend(rel.iter().copied());
        }
        for dependency in &payload.dependencies {
            ids.insert(EntityId::from_hex(dependency).ok()?);
        }
        for child in &payload.children {
            for entry in &child.evidence {
                ids.insert(EntityId::from_hex(&entry.source_id).ok()?);
                if let Some(claim) = entry.claim_id.as_deref() {
                    ids.insert(EntityId::from_hex(claim).ok()?);
                }
            }
        }
        Some(ids.into_iter().collect())
    }
}

/// WHOLE-child support: true only when EVERY evidence citation passes ALL of:
/// (a) existing `reference()` shape validity (claim xor range) plus a live
fn child_supported(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pinned: &BTreeMap<&ConsolidationReference, &ConsolidationRootEvidence>,
    child: &ConsolidationChildFrontier,
) -> Result<bool> {
    for entry in &child.evidence {
        let parsed = reference(entry)?;
        let kind = vault.get_entity_type_in_txn(txn, &parsed.source_id)?;
        let shape_kind = match (parsed.claim_id.is_some(), parsed.byte_range.is_some(), kind) {
            (true, false, Some(ENTITY_TYPE_CLAIM)) => true,
            (false, true, Some(ENTITY_TYPE_TURN)) => true,
            _ => false,
        };
        if !shape_kind {
            return Ok(false);
        }
        let pin = pinned
            .get(entry)
            .copied()
            .ok_or_else(|| invalid_consolidation("accepted child citation is not pinned"))?;
        if !pin.corroborates || pin.refusal.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Enqueue one bridge attempt per bucket group over ONLY newly-accepted,
/// supported children. Runs inside `frontier_frozen`'s SAME writer txn, after
pub(super) fn enqueue_new_bridges_in_txn(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &mut heed::RwTxn<'_>,
    root_id: EntityId,
    root: &Root,
    new_accepted: &[(usize, ConsolidationChildReceipt)],
    input: &ConsolidationFrontierRequest,
) -> Result<Vec<AttemptId>> {
    if new_accepted.is_empty() {
        return Ok(Vec::new());
    }
    let originals: BTreeMap<&str, &ConsolidationChildFrontier> = input
        .children
        .iter()
        .map(|child| (child.child_ref.as_str(), child))
        .collect();
    let mut groups: BTreeMap<usize, Vec<&ConsolidationChildReceipt>> = BTreeMap::new();
    for (index, receipt) in new_accepted {
        groups.entry(*index).or_default().push(receipt);
    }
    let now = vault.now_recorded_at();
    let store = DreamerRunnerStore::new(vault);
    let mut ids = Vec::new();
    for (index, receipts) in &groups {
        let bucket: &ConsolidationBucketAccounting = root
            .accounting
            .buckets
            .get(*index)
            .ok_or_else(|| invalid_consolidation("root bridge bucket index out of range"))?;
        let pinned: BTreeMap<&ConsolidationReference, &ConsolidationRootEvidence> = bucket
            .pinned
            .iter()
            .map(|row| (&row.reference, row))
            .collect();
        let mut children = Vec::new();
        for receipt in receipts {
            let original = originals.get(receipt.child_ref.as_str()).ok_or_else(|| {
                invalid_consolidation("accepted child has no typed frontier in this writer")
            })?;
            let mut evidence = original.evidence.clone();
            evidence.sort();
            evidence.dedup();
            if evidence.is_empty() || evidence != receipt.evidence {
                return Err(invalid_consolidation(
                    "accepted child evidence is not canonical",
                ));
            }
            if !child_supported(vault, txn, &pinned, original)? {
                // NOTE-only/MIXED-NOTE/non-corroborating: the WHOLE child
                // stays accounting-only and skips the queue. The receipt and
                // every citation already landed; nothing is dropped.
                continue;
            }
            children.push(ConsolidationChildFrontier {
                child_ref: receipt.child_ref.clone(),
                bucket_hash: bucket.bucket_hash,
                judgement: original.judgement.clone(),
                evidence,
            });
        }
        if children.is_empty() {
            continue;
        }
        children.sort_by(|left, right| left.child_ref.cmp(&right.child_ref));
        let used: BTreeSet<_> = children.iter().flat_map(|child| &child.evidence).collect();
        let selected_pins: Vec<_> = used
            .into_iter()
            .map(|entry| {
                pinned
                    .get(entry)
                    .map(|pin| (*pin).clone())
                    .ok_or_else(|| invalid_consolidation("root bridge citation is not pinned"))
            })
            .collect::<Result<_>>()?;
        // A frontier's snapshot may predate an erase. Never publish copied
        // judgement text after its current source authority or pins withdrew.
        // The already-accepted accounting receipt still stands on its own.
        match fresh_pins_match_after_closes(
            vault,
            read,
            read,
            txn,
            &bucket_key(&bucket.bucket)?,
            &selected_pins,
            &BTreeMap::new(),
        ) {
            Ok(()) => {}
            Err(
                crate::Error::EntityNotFound
                | crate::Error::InvalidClaimBody(_)
                | crate::Error::Record(_),
            ) => continue,
            Err(error) => return Err(error),
        }
        let dependencies = binding_source_ids(&bucket_key(&bucket.bucket)?, &selected_pins)?
            .iter()
            .map(EntityId::to_hex)
            .collect();
        let payload = RootPayload {
            root_ref: root_id.to_hex(),
            owner: root.owner.to_hex(),
            revision: root.accounting.revision,
            bucket: bucket.bucket.clone(),
            bucket_hash: bucket.bucket_hash,
            children,
            dependencies,
        };
        let attempt = DreamerAttemptPayload {
            attempt_type: ATTEMPT.to_owned(),
            input: payload.encode()?,
            parent_attempt: None,
        };
        let outcome = store.enqueue_kind_in_txn(
            txn,
            DreamerConsolidationScope::Micro.attempt_kind(),
            attempt.clone(),
            Some(payload.dedupe_key()?),
            None,
            now,
        )?;
        let status = match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status) => status,
            EnqueueDreamerAttemptOutcome::Existing(status) => {
                // Native FULL equality: same input bytes, same type, same
                // (absent) parent. Mirrors the consolidation dedupe guard.
                if status.payload != attempt {
                    return Err(invalid_consolidation(
                        "root bridge dedupe cannot change payload or parent",
                    ));
                }
                status
            }
        };
        ids.push(status.attempt.id);
    }
    Ok(ids)
}

/// Sweep this owner's bridge payloads from the SAME root-erase txn, even when
/// no ROOTS row survives (root already gone). The predicate decodes with the
pub(super) fn erase_owner_bridges_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    let owner_hex = owner.to_hex();
    crate::attempt_queue::erase_kind_payloads_in_txn(
        store,
        txn,
        DreamerConsolidationScope::Micro.attempt_kind(),
        |raw| {
            let Ok(payload) = decode_dreamer_attempt_payload(raw) else {
                return false;
            };
            if payload.attempt_type != ATTEMPT {
                return false;
            }
            RootPayload::decode(&payload.input).is_ok_and(|bridge| bridge.owner == owner_hex)
        },
    )
}

/// A hard-erased source takes every bridge copy of its judgement with it,
/// including archived attempt rows and run snapshots handled by the native
/// kind-payload eraser. The captured ids survive removal of the root row.
pub(crate) fn erase_source_bridges_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    crate::attempt_queue::erase_kind_payloads_in_txn(
        &vault.store,
        txn,
        DreamerConsolidationScope::Micro.attempt_kind(),
        |raw| {
            let Ok(payload) = decode_dreamer_attempt_payload(raw) else {
                return false;
            };
            if payload.attempt_type != ATTEMPT {
                return false;
            }
            RootPayload::decode(&payload.input).is_ok_and(|bridge| {
                bridge
                    .dependencies
                    .iter()
                    .any(|id| EntityId::from_hex(id).ok().as_ref() == Some(source))
            })
        },
    )
}

/// Selector + source ids a binding must hold readable: the bucket selectors
/// plus every pinned source, ancestor and message (mirrors `pinned_buckets`
/// selectors + `source_ids`).
fn binding_source_ids(
    key: &ConsolidationBucketKey,
    pins: &[ConsolidationRootEvidence],
) -> Result<Vec<EntityId>> {
    let mut ids = BTreeSet::new();
    ids.insert(key.subject);
    ids.extend(key.world);
    ids.extend(key.facet);
    ids.insert(key.project);
    if let Some(rel) = key.rel.as_ref() {
        ids.extend(rel.iter().copied());
    }
    for pin in pins {
        ids.insert(EntityId::from_hex(&pin.reference.source_id)?);
        for ancestor in &pin.ancestors {
            ids.insert(EntityId::from_hex(&ancestor.source_ref)?);
        }
        for message in &pin.messages {
            ids.insert(EntityId::from_hex(&message.message_ref)?);
        }
    }
    Ok(ids.into_iter().collect())
}

fn pin_bytes(pin: &ConsolidationRootEvidence) -> Result<Vec<u8>> {
    serde_json::to_vec(pin).map_err(|_| invalid_consolidation("root pin metadata does not encode"))
}

/// Every expected pin still fresh-pins byte-identical under the SAME read:
/// source hash, trust, ancestors, messages, refusal, project and axes (the
/// last two refuse inside `pin_reference` itself). Byte comparison avoids
/// widening native public types for PartialEq.
fn fresh_pins_match_after_closes(
    vault: &Vault,
    live: &ScopedRead<'_>,
    recorded: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    key: &ConsolidationBucketKey,
    expected: &[ConsolidationRootEvidence],
    closed: &BTreeMap<EntityId, super::super::resources::RowRevision>,
) -> Result<()> {
    let ids = binding_source_ids(key, expected)?;
    let (closed_ids, live_ids): (Vec<_>, Vec<_>) =
        ids.into_iter().partition(|id| closed.contains_key(id));
    require_readable(live, txn, &live_ids)?;
    require_readable(recorded, txn, &closed_ids)?;
    for id in &closed_ids {
        if super::super::resources::RowRevision::read_in(vault, txn, id)?.as_ref() != closed.get(id)
        {
            return Err(invalid_consolidation("root's granted prior changed"));
        }
    }
    let read = if closed.is_empty() { live } else { recorded };
    for pin in expected {
        let mut fresh = pin_reference(vault, read, txn, key, &pin.reference)?;
        let source = EntityId::from_hex(&pin.reference.source_id)?;
        if closed.contains_key(&source) {
            // The native grant changed this exact source revision, not its
            // evidence basis. The fence holds it to that grant's own revision.
            fresh.source_revision = pin.source_revision;
            fresh.content_hash = pin.content_hash;
            if fresh.refusal
                == Some(crate::dreamer_promotion::PromotionEvidenceReason::NotSurfaceable)
            {
                fresh.refusal = pin.refusal;
                fresh.corroborates = pin.corroborates;
            }
        }
        for ancestor in &mut fresh.ancestors {
            let id = EntityId::from_hex(&ancestor.source_ref)?;
            if closed.contains_key(&id)
                && let Some(original) = pin
                    .ancestors
                    .iter()
                    .find(|old| old.source_ref == ancestor.source_ref)
            {
                ancestor.source_revision = original.source_revision;
            }
        }
        if pin_bytes(&fresh)? != pin_bytes(pin)? {
            return Err(invalid_consolidation("root pin changed under its binding"));
        }
    }
    Ok(())
}

fn binding_identity(
    root_id: &EntityId,
    bucket_hash: &[u8; 32],
    accepted: &[(String, [u8; 32])],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BINDING_IDENTITY_DOMAIN);
    hasher.update(root_id.as_bytes());
    hasher.update(bucket_hash);
    hasher.update(&(accepted.len() as u64).to_be_bytes());
    for (child_ref, digest) in accepted {
        hasher.update(&(child_ref.len() as u64).to_be_bytes());
        hasher.update(child_ref.as_bytes());
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

fn judgement_hash(
    judgement: &crate::memory::consolidation_frontier::ConsolidationJudgement,
) -> Result<[u8; 32]> {
    let encoded = serde_json::to_vec(judgement)
        .map_err(|_| invalid_consolidation("child judgement does not encode"))?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

/// The private root binding: one payload's accepted-receipt SUBSET plus the
/// pinned subset its references need, bound to the root's immutable captures
#[derive(Debug, Clone)]
pub(in crate::dreamer_consolidation) struct RootBinding {
    root_id: EntityId,
    owner: EntityId,
    revision: u64,
    key: ConsolidationBucketKey,
    bucket_hash: [u8; 32],
    accepted: Vec<ConsolidationChildReceipt>,
    pins: Vec<ConsolidationRootEvidence>,
    identity: [u8; 32],
    closed: BTreeMap<EntityId, GrantedClose>,
}

impl RootBinding {
    /// Bind `payload` against the live root row: owner/revision/bucket identity,
    /// every child receipt present with its ORIGINAL typed judgement hash and
    /// exact predicate/confidence/shapes, every referenced pin present AND
    /// fresh-pinning byte-identical under the caller's (Dreamer) read. The
    /// binding covers the payload's accepted SUBSET only, so children landed
    /// concurrently neither break it nor join it silently.
    pub(in crate::dreamer_consolidation) fn load(
        vault: &Vault,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        payload: &RootPayload,
        actor: crate::WriteActor,
        attempt: AttemptId,
    ) -> Result<Self> {
        if payload.children.is_empty() {
            return Err(invalid_consolidation("root bridge payload has no children"));
        }
        let root_id = EntityId::from_hex(&payload.root_ref)?;
        let owner = EntityId::from_hex(&payload.owner)?;
        let root = super::ROOTS
            .get(&vault.store, txn, &root_id)?
            .ok_or_else(|| invalid_consolidation("no evidence root has that ref"))?;
        if root.owner != owner {
            return Err(invalid_consolidation(
                "evidence root belongs to another owner",
            ));
        }
        if root.accounting.revision != payload.revision {
            return Err(invalid_consolidation("root bridge revision changed"));
        }
        let bucket = root
            .accounting
            .buckets
            .iter()
            .find(|bucket| bucket.bucket_hash == payload.bucket_hash)
            .ok_or_else(|| invalid_consolidation("root bridge names an unpinned bucket"))?;
        let key = bucket_key(&bucket.bucket)?;
        if key.bucket_hash() != payload.bucket_hash || bucket.bucket != payload.bucket {
            return Err(invalid_consolidation("root bridge bucket identity changed"));
        }
        let pinned: BTreeMap<&ConsolidationReference, &ConsolidationRootEvidence> = bucket
            .pinned
            .iter()
            .map(|row| (&row.reference, row))
            .collect();
        let mut accepted = Vec::with_capacity(payload.children.len());
        let mut references = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for child in &payload.children {
            EntityId::from_hex(&child.child_ref)?;
            if child.bucket_hash != payload.bucket_hash || !seen.insert(&child.child_ref) {
                return Err(invalid_consolidation(
                    "root bridge child bucket or identity changed",
                ));
            }
            if !child.judgement.confidence.is_finite()
                || !(0.0..=1.0).contains(&child.judgement.confidence)
                || child.evidence.is_empty()
            {
                return Err(invalid_consolidation(
                    "invalid child judgement or empty frontier",
                ));
            }
            crate::claim::validate_predicate(&child.judgement.predicate, false)?;
            if crate::claim::predicate_root(&child.judgement.predicate)
                != bucket.bucket.predicate_root
            {
                return Err(invalid_consolidation("child judgement crossed its bucket"));
            }
            let receipt = bucket
                .children
                .iter()
                .find(|row| row.child_ref == child.child_ref)
                .ok_or_else(|| invalid_consolidation("root bridge child is not accepted"))?;
            if receipt.judgement_hash != judgement_hash(&child.judgement)? {
                return Err(invalid_consolidation("root bridge judgement changed"));
            }
            let mut evidence = child.evidence.clone();
            evidence.sort();
            evidence.dedup();
            if evidence != receipt.evidence {
                return Err(invalid_consolidation("root bridge child evidence changed"));
            }
            references.extend(evidence);
            accepted.push(receipt.clone());
        }
        accepted.sort_by(|left, right| left.child_ref.cmp(&right.child_ref));
        let references: Vec<ConsolidationReference> = references.into_iter().collect();
        // Whole children retain the root's original corroboration and ancestry bounds.
        let mut pins = Vec::with_capacity(references.len());
        for entry in &references {
            let pin = pinned
                .get(entry)
                .copied()
                .ok_or_else(|| invalid_consolidation("root bridge citation is not pinned"))?;
            if !pin.corroborates || pin.refusal.is_some() {
                return Err(invalid_consolidation(
                    "root bridge citation does not corroborate",
                ));
            }
            pins.push(pin.clone());
        }
        let dependencies: Vec<_> = binding_source_ids(&key, &pins)?
            .iter()
            .map(EntityId::to_hex)
            .collect();
        if payload.dependencies != dependencies {
            return Err(invalid_consolidation("root bridge dependencies changed"));
        }
        let subset: Vec<(String, [u8; 32])> = accepted
            .iter()
            .map(|row| (row.child_ref.clone(), row.judgement_hash))
            .collect();
        let mut binding = Self {
            root_id,
            owner,
            revision: payload.revision,
            key,
            bucket_hash: payload.bucket_hash,
            accepted,
            pins,
            identity: binding_identity(&root_id, &payload.bucket_hash, &subset),
            closed: BTreeMap::new(),
        };
        binding.load_closes(&root, actor, attempt);
        binding.validate_in_txn(vault, read, txn)?;
        Ok(binding)
    }

    pub(in crate::dreamer_consolidation) fn key(&self) -> &ConsolidationBucketKey {
        &self.key
    }

    pub(in crate::dreamer_consolidation) fn pins(&self) -> &[ConsolidationRootEvidence] {
        &self.pins
    }

    pub(in crate::dreamer_consolidation) fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// Re-read the root row and re-verify the whole binding in the caller's
    /// (output writer's) txn AFTER awaits: root still present (a root missing
    /// after erase cannot write), owner/revision/bucket identity unchanged,
    /// every accepted receipt and pin still byte-identical, every pin still
    /// fresh-pinning identical under the SAME read. Concurrent later children
    /// neither break nor join this subset.
    pub(in crate::dreamer_consolidation) fn validate_in_txn(
        &self,
        vault: &Vault,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        if self.closed.is_empty() {
            self.validate_after_closes_in_txn(vault, read, read, txn, &BTreeMap::new())
        } else {
            let key = self
                .closed
                .values()
                .next()
                .expect("root close")
                .reader_key()?;
            let recorded = vault
                .scoped_read(key)
                .with_claim_status(crate::claim::ClaimReadStatus::Recorded);
            self.validate_after_closes_in_txn(vault, read, &recorded, txn, &self.closed_revisions())
        }
    }

    pub(in crate::dreamer_consolidation) fn validate_after_closes_in_txn(
        &self,
        vault: &Vault,
        live: &ScopedRead<'_>,
        recorded: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        closed: &BTreeMap<EntityId, super::super::resources::RowRevision>,
    ) -> Result<()> {
        let root = super::ROOTS
            .get(&vault.store, txn, &self.root_id)?
            .ok_or_else(|| invalid_consolidation("root bridge root is gone"))?;
        self.validate_closes(&root)?;
        if root.owner != self.owner {
            return Err(invalid_consolidation(
                "evidence root belongs to another owner",
            ));
        }
        if root.accounting.revision != self.revision {
            return Err(invalid_consolidation("root bridge revision changed"));
        }
        let bucket = root
            .accounting
            .buckets
            .iter()
            .find(|bucket| bucket.bucket_hash == self.bucket_hash)
            .ok_or_else(|| invalid_consolidation("root bridge names an unpinned bucket"))?;
        let key = bucket_key(&bucket.bucket)?;
        if key != self.key {
            return Err(invalid_consolidation("root bridge bucket identity changed"));
        }
        for row in &self.accepted {
            let live = bucket
                .children
                .iter()
                .find(|live| live.child_ref == row.child_ref)
                .ok_or_else(|| invalid_consolidation("root bridge child is not accepted"))?;
            if live.judgement_hash != row.judgement_hash || live.evidence != row.evidence {
                return Err(invalid_consolidation("root bridge child changed"));
            }
        }
        for pin in &self.pins {
            let live = bucket
                .pinned
                .iter()
                .find(|live| live.reference == pin.reference)
                .ok_or_else(|| invalid_consolidation("root bridge citation is not pinned"))?;
            if pin_bytes(live)? != pin_bytes(pin)? {
                return Err(invalid_consolidation("root pin changed under its binding"));
            }
            if !live.corroborates || live.refusal.is_some() {
                return Err(invalid_consolidation(
                    "root bridge citation does not corroborate",
                ));
            }
        }
        fresh_pins_match_after_closes(vault, live, recorded, txn, &key, &self.pins, closed)
    }
}
