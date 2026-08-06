//! ED-09 (ONE-1765, ARCH-0056 §10–11): the SFT/DPO reservoir — every amendment
//! the decider made, projected into a training pair and exported through one
//! owner-triggered, consent-scoped door.
//!
//! # The pair
//!
//! ED-00 retains both ends of a proposal's edit window ([`FinalizedProposalText`]:
//! `proposed_text` as drafted, `final_text` as the decider left it). Those two
//! strings ARE the preference pair — `rejected` and `chosen` — and they exist
//! nowhere else, which is why ED-00's retention is a contract rather than a
//! convenience. An artifact whose two texts are EQUAL projects no pair: an
//! untouched approval amended nothing, and a rejection finalized nothing, so
//! there is no preference to learn. That filter is exact, not heuristic.
//!
//! SFT and DPO are two views of one pair — `chosen` alone is the supervised
//! target, the pair is the preference sample — so this module ships ONE schema
//! and no second exporter.
//!
//! # Off-record exclusion is CONSTRUCTIVE, and the assert is the backstop
//!
//! The ONE-1570 ruling is that a fenced turn is PIPELINE-INERT: no derived row
//! is produced from it, so there is nothing downstream to filter. Exclusion
//! therefore happens at the enumeration SOURCE — the scan cannot see a fenced
//! session's work because that work never became a row. There is no filter
//! here to disable and no flag to flip.
//!
//! What IS here is a belt-and-suspenders tripwire. Every artifact the scan
//! enumerates carries a persisted [`FinalizedProposalText::source_turn_ref`],
//! and each one is probed against the SAME durable per-entity fence
//! (`off_record_fence_active`) the retrieval filter consults. A hit means an
//! upstream inertness bug put a fenced turn's work into the pipeline, so the
//! export ABORTS with a typed error — loudly, never as a silent skip, because a
//! silent skip would let the bug ship a corpus while looking healthy. The probe
//! is durable-only by necessity: session refs are in-process-only and evaporate
//! at close, so no check may phrase itself against a live session record.
//!
//! `source_turn_ref = None` passes: a proposal with no turn source has no fence
//! surface to violate, and treating absence as suspicion would deny every
//! non-turn-sourced pair for a fence that cannot exist.
//!
//! There is deliberately **no off-record override**: no argument, no scope
//! field, no builder method admits fenced content. Opting in after the fact is
//! the one thing the fence exists to make impossible, so the surface simply
//! does not exist — enforced by [`tests::no_override_api_on_the_export_surface`].
//!
//! # The door
//!
//! [`export_reservoir`] is a DOOR, never a cron: nothing schedules it, and an
//! export is content leaving the vault, so it rides the house disclosure
//! consent rail ([`crate::consent`]) exactly as any other outbound hop does —
//! a standing `audience × class × envelope` grant must cover
//! [`RESERVOIR_EXPORT_AUDIENCE`] before a byte is resolved, and revocation is
//! immediate because the grant set is read live.
//!
//! It is TWO-PHASE. Phase 1 takes the consent decision, enumerates, runs the
//! fence tripwire, resolves every pair and serializes the whole corpus into
//! memory, writing nothing. Phase 2 hands those finished bytes to the sink.
//! A caller therefore never sees a partially-written export that failed on
//! CONTENT: past the first byte the only remaining failure is the sink's own
//! I/O.
//!
//! # Rebuildable index, snapshot artifact
//!
//! The candidate index is derived state (CID-7): [`rebuild_reservoir_index`]
//! reconstructs it from the artifacts and tag rows alone, so it can be dropped
//! at any time. The exported JSONL is a point-in-time SNAPSHOT — receipted, and
//! never read back as truth by anything in this engine.

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize};

use super::{FinalizedProposalText, PROPOSAL_ARTIFACT_KEY_PREFIX, decode_finalized_proposal_text};
use crate::Vault;
use crate::consent::{
    AudienceBound, DisclosureClass, DisclosureEnvelope, GrantBound, MAX_CONSENT_REF_LEN,
};
use crate::edit_distance::attribution::amendment_evidence;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::off_record::off_record_fence_active;
use crate::receipt::{MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptQuery, ReceiptRecord};

// ---------------------------------------------------------------------------
// Keyspace + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` prefix of the rebuildable candidate index, keyed by the
/// proposal artifact's entity id — so the index inherits the artifact
/// keyspace's ordering, and an export is one ordered walk.
const CANDIDATE_KEY_PREFIX: &[u8] = b"edit_distance/reservoir_candidate/v1\0";

/// `vault_meta` prefix of the export-receipt ledger, keyed by receipt id.
const EXPORT_RECEIPT_KEY_PREFIX: &[u8] = b"edit_distance/reservoir_export/v1\0";

/// `receipt_id` namespace of an export receipt.
const EXPORT_RECEIPT_ID_PREFIX: &str = "reservoir_export:";

/// Only accepted schema version for any row this module stores.
const ROW_VERSION: u8 = 1;

const CANDIDATE_ROW_LABEL: &str = "reservoir candidate row";
const EXPORT_RECEIPT_ROW_LABEL: &str = "reservoir export receipt row";

/// The audience a reservoir export discloses to.
///
/// Pinned rather than caller-supplied: the door takes no audience argument, so
/// a caller cannot widen the room by naming a different one. Granting this
/// audience IS the owner's decision to let training pairs leave the vault.
pub const RESERVOIR_EXPORT_AUDIENCE: &str = "audience:training_reservoir";

/// The disclosure data class a reservoir export rides.
///
/// A grant covering some other class does not cover this one — the whole point
/// of the class axis is that clearance for one kind of content is not clearance
/// for training corpora.
pub const RESERVOIR_DISCLOSURE_CLASS: &str = "training_corpus";

/// The envelope selector naming the reservoir itself.
pub const RESERVOIR_ENVELOPE_SELECTOR: &str = "reservoir:training_pairs";

/// Receipt field: how many pairs the export wrote.
pub const FIELD_EXPORT_PAIRS: &str = "reservoir_pairs";
/// Receipt field: blake3 of the exported JSONL, lower hex.
pub const FIELD_EXPORT_CONTENT_HASH: &str = "reservoir_content_hash";
/// Receipt field: the task-class filter, comma-joined; absent means unscoped.
pub const FIELD_EXPORT_TASK_CLASSES: &str = "reservoir_task_classes";
/// Receipt field: the `since` floor in Unix seconds; absent means unbounded.
pub const FIELD_EXPORT_SINCE: &str = "reservoir_since";

/// Longest accepted task class — the ED lane's scope bound, shared with
/// `edit_distance::attribution` and `edit_distance::routing` so one scope
/// string means one thing lane-wide.
const MAX_TASK_CLASS_LEN: usize = MAX_CONSENT_REF_LEN;

const TASK_CLASS_SEPARATOR: char = ',';

// ---------------------------------------------------------------------------
// The pair
// ---------------------------------------------------------------------------

/// One preference pair: what the model drafted, and what the decider kept.
///
/// Every tag is optional and its absence is EXPLICIT. Old rows predate the tag
/// ledgers, and a mandatory `String` would force the projection to choose
/// between dropping a usable pair and inventing a sentinel — both of which
/// corrupt a training corpus more quietly than a missing tag ever could.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrainingPair {
    /// The proposal as drafted — the DPO `rejected` side.
    pub rejected: String,
    /// The proposal as the decider left it — the `chosen` side, and the SFT
    /// target on its own.
    pub chosen: String,
    /// The kind of work this pair came from (`AmendmentEvidence::scope`).
    pub task_class: Option<String>,
    /// The skill the amended proposal rode, when it rode one.
    #[serde(serialize_with = "serialize_opt_entity_hex")]
    pub skill: Option<EntityId>,
    /// The model recorded on the pair's own receipt — never the model serving
    /// NOW, which would be a guess about history.
    pub model_id: Option<String>,
    /// The proposal artifact's durable handle: the id ED-00 mints, the key its
    /// retention row lives under, and the id the tag ledgers join on.
    #[serde(serialize_with = "serialize_entity_hex")]
    pub receipt_ref: EntityId,
}

/// Ids cross the wire as lower hex, the one spelling every other receipt field
/// in this engine uses — a consumer joining an exported pair back to its
/// artifact compares strings, never byte encodings.
fn serialize_entity_hex<S: serde::Serializer>(
    id: &EntityId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
}

fn serialize_opt_entity_hex<S: serde::Serializer>(
    id: &Option<EntityId>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match id {
        Some(id) => serializer.serialize_some(&id.to_hex()),
        None => serializer.serialize_none(),
    }
}

/// What an export asks for. Both filters are optional; both narrow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReservoirScope {
    /// Keep only pairs tagged with one of these task classes. `None` keeps
    /// every class INCLUDING untagged pairs; naming classes excludes untagged
    /// ones, because an untagged pair cannot be shown to be in the set.
    pub task_classes: Option<Vec<String>>,
    /// Keep only pairs observed at or after this Unix second.
    pub since: Option<u64>,
}

/// What an export produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportManifest {
    /// Pairs written to the sink.
    pub pairs: usize,
    /// blake3 of the exported JSONL bytes, lower hex. Stable across re-exports
    /// of the same scope over unchanged rows.
    pub content_hash: String,
    /// The export receipt recording scope, count and hash.
    pub receipt: EntityId,
}

// ---------------------------------------------------------------------------
// The door
// ---------------------------------------------------------------------------

/// Exports the reservoir as JSONL, one [`TrainingPair`] per line.
///
/// Owner-triggered: nothing in the engine calls this on a schedule.
///
/// TWO-PHASE by contract. Phase 1 clears consent, enumerates, runs the
/// off-record tripwire, resolves every pair and serializes the whole corpus
/// with ZERO bytes written. Phase 2 writes those finished bytes. A failure
/// after the first byte can therefore only be the sink's — content selection
/// never leaves a partial export behind.
///
/// The export is a point-in-time snapshot. It is receipted and handed to the
/// caller; nothing stores it as truth.
///
/// # Errors
///
/// * [`Error::ConsentGrantNotFound`] when no standing disclosure grant covers
///   the reservoir audience — fail-closed, and revocation is immediate.
/// * [`Error::InvariantViolation`] when a candidate's `source_turn_ref` is
///   off-record fenced. That is an upstream inertness bug, and it aborts the
///   export rather than skipping the row.
/// * [`Error::InvalidConsentBound`] on an unusable task-class filter.
/// * [`Error::CorruptedIndex`] on an undecodable row; storage and I/O errors.
pub fn export_reservoir(
    vault: &Vault,
    scope: ReservoirScope,
    out: &mut dyn io::Write,
) -> Result<ExportManifest> {
    let scope = normalized_scope(scope)?;

    // ── phase 1: decide, resolve, serialize. Nothing is written. ──────────
    authorize_export(vault)?;
    let pairs = resolve_candidates(vault, &scope)?;
    let mut body = Vec::new();
    for pair in &pairs {
        serde_json::to_writer(&mut body, pair)
            .map_err(|_| Error::InvariantViolation("training pair JSONL encode failed"))?;
        body.push(b'\n');
    }
    let content_hash = blake3::hash(&body).to_hex().to_string();
    let receipt = record_export(vault, &scope, pairs.len(), &content_hash)?;

    // ── phase 2: the only failure left is the sink's own I/O. ─────────────
    out.write_all(&body)?;

    Ok(ExportManifest {
        pairs: pairs.len(),
        content_hash,
        receipt,
    })
}

/// Rebuilds the candidate index from the artifacts and tag rows alone.
///
/// The index is derived state (CID-7): every row it holds is recomputable, so
/// dropping it costs nothing but the walk. This is the door that pays that
/// walk, and it is the SAME resolution [`export_reservoir`] runs — one
/// enumeration path, so a rebuilt index and an export can never disagree about
/// what a candidate is.
///
/// Stale rows are deleted rather than left: an artifact whose two texts stopped
/// differing, or that no longer resolves, is not a candidate, and an index that
/// remembered it would answer for a pair the export does not carry.
///
/// # Errors
///
/// Storage errors; the same tripwire and decode errors as [`export_reservoir`].
pub fn rebuild_reservoir_index(vault: &Vault) -> Result<()> {
    let pairs = resolve_candidates(vault, &ReservoirScope::default())?;
    let rebuilt = pairs
        .iter()
        .map(|pair| Ok((candidate_key(pair.receipt_ref), encode_candidate(pair)?)))
        .collect::<Result<BTreeMap<Vec<u8>, Vec<u8>>>>()?;

    // Errors are collected BEFORE the staleness filter, never through it: a
    // filter over `Result`s drops the `Err` arm as "not stale" and swallows the
    // storage failure that produced it.
    let stale = {
        let rtxn = vault.store.env.read_txn()?;
        let keys = vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, CANDIDATE_KEY_PREFIX)?
            .map(|entry| Ok(entry?.0.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        keys.into_iter()
            .filter(|key| !rebuilt.contains_key(key))
            .collect::<Vec<_>>()
    };

    vault.with_write_txn(|wtxn| {
        for key in &stale {
            vault.store.vault_meta.delete(wtxn, key)?;
        }
        for (key, value) in &rebuilt {
            vault.store.vault_meta.put(wtxn, key, value)?;
        }
        Ok(())
    })
}

/// The candidate pairs `scope` selects, in artifact-id order.
///
/// The read door behind both [`export_reservoir`] and
/// [`rebuild_reservoir_index`], public so a caller can inspect what an export
/// WOULD carry without producing an artifact.
///
/// # Errors
///
/// As [`export_reservoir`], minus the consent decision — this reads, it does
/// not disclose.
pub fn reservoir_candidates(vault: &Vault, scope: ReservoirScope) -> Result<Vec<TrainingPair>> {
    let scope = normalized_scope(scope)?;
    resolve_candidates(vault, &scope)
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Enumerates, tripwires, tags and filters — the one candidate path.
///
/// Ordering is the artifact keyspace's own, which is entity-id order, so two
/// exports of one scope over unchanged rows serialize identically. That is what
/// makes [`ExportManifest::content_hash`] a stable identity rather than a
/// coincidence.
fn resolve_candidates(vault: &Vault, scope: &ReservoirScope) -> Result<Vec<TrainingPair>> {
    let mut records = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for entry in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, PROPOSAL_ARTIFACT_KEY_PREFIX)?
        {
            let (_key, raw) = entry?;
            let record = decode_finalized_proposal_text(&raw)?;

            // THE TRIPWIRE, at the enumeration source and ahead of every
            // filter. Probing before the pair and scope filters is deliberate:
            // a filter that ran first could hide an inertness bug behind a
            // narrow scope, and a fence violation is not a row to skip — it is
            // an export to refuse.
            if let Some(turn) = record.source_turn_ref
                && off_record_fence_active(&vault.store, &rtxn, &turn)?
            {
                return Err(Error::InvariantViolation(
                    "reservoir candidate is sourced from an off-record fenced turn; \
                     fenced turns are pipeline-inert and must produce no derived rows",
                ));
            }
            records.push(record);
        }
    }

    let models = export_models(vault)?;
    let mut pairs = Vec::new();
    for record in records {
        // An untouched approval and a rejection both leave the two ends equal:
        // no amendment, so no preference to learn.
        if record.proposed_text == record.final_text {
            continue;
        }
        let (pair, observed_at) = tagged_pair(vault, &record, &models)?;
        if selects(scope, &pair, observed_at) {
            pairs.push(pair);
        }
    }
    Ok(pairs)
}

/// Joins the tag ledgers onto one artifact, with the instant the amendment was
/// observed (the `since` axis, which is a tag fact rather than a pair fact and
/// so never rides [`TrainingPair`]).
///
/// The join key is the artifact's ref hex: it is the only durable id ED-00
/// mints, so it is the id an ED-00-sourced amendment's evidence is recorded
/// under. A miss is not a failure — it yields a pair with every tag `None`,
/// which is the Notes contract (absence explicit, never guessed).
fn tagged_pair(
    vault: &Vault,
    record: &FinalizedProposalText,
    models: &BTreeMap<String, String>,
) -> Result<(TrainingPair, Option<u64>)> {
    let artifact = record.artifact_ref.entity_id();
    let evidence = amendment_evidence(vault, &artifact.to_hex())?;
    let pair = TrainingPair {
        rejected: record.proposed_text.clone(),
        chosen: record.final_text.clone(),
        task_class: evidence.as_ref().map(|row| row.scope.clone()),
        skill: evidence.as_ref().and_then(|row| row.skill),
        model_id: models.get(&artifact.to_hex()).cloned(),
        receipt_ref: artifact,
    };
    Ok((pair, evidence.map(|row| row.at)))
}

/// Whether `scope` keeps this pair.
///
/// Both filters exclude UNTAGGED pairs on purpose, and for one reason: the
/// caller asked for a named set, and a pair that cannot be SHOWN to be in it is
/// not in it. Admitting untagged rows into a narrowed export would quietly
/// widen every scope the owner drew.
fn selects(scope: &ReservoirScope, pair: &TrainingPair, observed_at: Option<u64>) -> bool {
    if let Some(classes) = &scope.task_classes {
        let Some(task_class) = &pair.task_class else {
            return false;
        };
        if !classes.iter().any(|wanted| wanted == task_class) {
            return false;
        }
    }
    if let Some(since) = scope.since {
        let Some(observed_at) = observed_at else {
            return false;
        };
        if observed_at < since {
            return false;
        }
    }
    true
}

/// `receipt_id → model` for every receipt that recorded one.
///
/// ONE bounded receipt query serves the whole export rather than one lookup per
/// candidate — the join is a map build, not a fan-out. The model is read from
/// the receipt's OWN recorded field, never recomputed from the model serving
/// now: which generation drafted a two-year-old proposal is history, and
/// history is recorded or it is absent.
fn export_models(vault: &Vault) -> Result<BTreeMap<String, String>> {
    let mut models = BTreeMap::new();
    for receipt in vault.receipts(ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN))? {
        if let Some(model) = receipt_model(&receipt) {
            models.insert(receipt.receipt_id, model);
        }
    }
    Ok(models)
}

fn receipt_model(receipt: &ReceiptRecord) -> Option<String> {
    receipt.context_receipt_fields()?.model
}

// ---------------------------------------------------------------------------
// The consent rail
// ---------------------------------------------------------------------------

/// The bound an export needs: the reservoir audience, the training-corpus data
/// class, the reservoir envelope.
fn export_grant_bound() -> Result<GrantBound> {
    GrantBound::disclosure(
        AudienceBound::singleton(RESERVOIR_EXPORT_AUDIENCE)?,
        DisclosureClass::new(RESERVOIR_DISCLOSURE_CLASS)?,
        DisclosureEnvelope::new([RESERVOIR_ENVELOPE_SELECTOR.to_owned()])?,
    )
}

/// Clears the export against the house disclosure rail.
///
/// This re-implements nothing: it builds the required bound and asks the SAME
/// standing-grant set every other outbound hop is checked against. Only ACTIVE
/// rows are returned, so a revoked grant stops authorizing the instant it is
/// revoked. Fails closed — no covering grant, no export.
fn authorize_export(vault: &Vault) -> Result<()> {
    let required = export_grant_bound()?;
    if vault
        .active_standing_consent_grants()?
        .iter()
        .any(|grant| grant.bound().contains(&required))
    {
        return Ok(());
    }
    Err(Error::ConsentGrantNotFound)
}

// ---------------------------------------------------------------------------
// The export receipt
// ---------------------------------------------------------------------------

/// What one export recorded. Scope, count and hash — enough to say what left
/// and to recognize the artifact again, and deliberately not the content.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredExport {
    v: u8,
    pairs: u64,
    content_hash: String,
    task_classes: Option<Vec<String>>,
    since: Option<u64>,
    at: u64,
}

fn record_export(
    vault: &Vault,
    scope: &ReservoirScope,
    pairs: usize,
    content_hash: &str,
) -> Result<EntityId> {
    let id = EntityId::now();
    let row = StoredExport {
        v: ROW_VERSION,
        pairs: pairs as u64,
        content_hash: content_hash.to_owned(),
        task_classes: scope.task_classes.clone(),
        since: scope.since,
        at: crate::unix_seconds_now(),
    };
    let encoded = encode_row(&row, EXPORT_RECEIPT_ROW_LABEL)?;
    let key = export_receipt_key(id);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })?;
    Ok(id)
}

/// Projects the export receipts.
///
/// A [`ReceiptKind::ScopedRead`] projector in the house shape: its own store,
/// its own field class, no kind of its own — an export IS a scoped read that
/// left the vault, and minting a kind for it would split a family that answers
/// one question.
///
/// Reads on the dispatcher's SHARED transaction rather than opening its own:
/// `receipt::receipts` already holds a read txn by the time the `ScopedRead`
/// family projects, and a second one on the same thread is an LMDB
/// `BadRslot`.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage errors.
pub(crate) fn reservoir_export_receipts(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(rtxn, EXPORT_RECEIPT_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        let record = export_receipt_record(&export_receipt_key_id(&key)?, &decode_export(&raw)?);
        if query.matches(&record) {
            out.push(record);
        }
    }
    Ok(out)
}

fn export_receipt_record(id: &EntityId, row: &StoredExport) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        (FIELD_EXPORT_PAIRS.to_owned(), row.pairs.to_string()),
        (
            FIELD_EXPORT_CONTENT_HASH.to_owned(),
            row.content_hash.clone(),
        ),
    ]);
    if let Some(classes) = &row.task_classes {
        fields.insert(
            FIELD_EXPORT_TASK_CLASSES.to_owned(),
            classes.join(&TASK_CLASS_SEPARATOR.to_string()),
        );
    }
    if let Some(since) = row.since {
        fields.insert(FIELD_EXPORT_SINCE.to_owned(), since.to_string());
    }
    ReceiptRecord {
        receipt_id: format!("{EXPORT_RECEIPT_ID_PREFIX}{}", id.to_hex()),
        receipt_kind: ReceiptKind::ScopedRead,
        occurred_at: row.at,
        actor: None,
        on_behalf_of: None,
        outcome: "exported".to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec!["edit_distance.reservoir.export".to_owned()],
        fields,
    }
}

// ---------------------------------------------------------------------------
// Validation + codec
// ---------------------------------------------------------------------------

/// Normalizes and vets a scope.
///
/// Task classes are trimmed, deduped and SORTED, so two spellings of one filter
/// produce one export with one hash. An empty class list is rejected rather
/// than read as "everything": the two readings are opposite, and a caller that
/// meant everything has [`Option::None`] to say it with.
fn normalized_scope(scope: ReservoirScope) -> Result<ReservoirScope> {
    let task_classes = scope
        .task_classes
        .map(|classes| {
            let mut classes = classes
                .into_iter()
                .map(|class| {
                    let trimmed = class.trim();
                    if trimmed.is_empty() || trimmed.len() > MAX_TASK_CLASS_LEN {
                        return Err(Error::InvalidConsentBound(
                            "a reservoir task class must be non-empty and within the \
                             consent-ref bound",
                        ));
                    }
                    Ok(trimmed.to_owned())
                })
                .collect::<Result<Vec<_>>>()?;
            classes.sort_unstable();
            classes.dedup();
            if classes.is_empty() {
                return Err(Error::InvalidConsentBound(
                    "a reservoir task-class filter must name at least one class; \
                     `None` is how a caller asks for every class",
                ));
            }
            Ok(classes)
        })
        .transpose()?;
    Ok(ReservoirScope {
        task_classes,
        since: scope.since,
    })
}

/// The index row: the tags, without the texts.
///
/// The pair bodies are NOT copied here. They already live in the artifact row,
/// and a second copy would be a second truth that drifts — the index answers
/// "which artifacts are candidates and how are they tagged", and the texts are
/// read from the one place that owns them.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCandidate {
    v: u8,
    task_class: Option<String>,
    skill: Option<String>,
    model_id: Option<String>,
}

fn encode_candidate(pair: &TrainingPair) -> Result<Vec<u8>> {
    encode_row(
        &StoredCandidate {
            v: ROW_VERSION,
            task_class: pair.task_class.clone(),
            skill: pair.skill.map(|id| id.to_hex()),
            model_id: pair.model_id.clone(),
        },
        CANDIDATE_ROW_LABEL,
    )
}

fn candidate_key(artifact: EntityId) -> Vec<u8> {
    meta_key(CANDIDATE_KEY_PREFIX, artifact.as_bytes())
}

fn export_receipt_key(id: EntityId) -> Vec<u8> {
    meta_key(EXPORT_RECEIPT_KEY_PREFIX, id.as_bytes())
}

fn export_receipt_key_id(key: &[u8]) -> Result<EntityId> {
    let tail = key
        .get(EXPORT_RECEIPT_KEY_PREFIX.len()..)
        .and_then(|tail| <[u8; ENTITY_ID_LEN]>::try_from(tail).ok())
        .ok_or(Error::CorruptedIndex(EXPORT_RECEIPT_ROW_LABEL))?;
    EntityId::from_bytes(tail).map_err(|_| Error::CorruptedIndex(EXPORT_RECEIPT_ROW_LABEL))
}

fn meta_key(prefix: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + tail.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(tail);
    key
}

/// Rows serialize through the house canonical-JSON door, so a row's bytes are a
/// function of its values rather than of map iteration order.
fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    crate::llm::canonical_json_bytes(row).map_err(|_| Error::CorruptedIndex(label))
}

fn decode_export(raw: &[u8]) -> Result<StoredExport> {
    let row: StoredExport =
        serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex(EXPORT_RECEIPT_ROW_LABEL))?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(EXPORT_RECEIPT_ROW_LABEL));
    }
    Ok(row)
}

#[cfg(test)]
mod tests;
