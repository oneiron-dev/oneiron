//! ARTL-4 (OF-368 D5/D6/D7): retained-output settle + receipts.
//!
//! An ARTL-3 [`EditProposal`] is a **retained output**: the edited bytes and
//! the edit-manifest exist, but nothing touches the artifact until the proposal
//! is *settled*. Settlement is **consume-once** (D5): exactly one of
//!
//! * **settle-select** — the proposal's bytes become a new blob-artifact
//!   version (provenance [`BlobVersionProvenance::AgentRun`](crate::blob_artifact::BlobVersionProvenance::AgentRun)), the manifest's
//!   anchor effects are replayed onto the artifact's annotation threads, and a
//!   select receipt lands; or
//! * **settle-discard** — the proposal is dropped and a discard receipt records
//!   the proposal ref
//!
//! consumes a proposal. A second settle of *any* kind on the same proposal is a
//! typed refusal ([`Error::EditProposalAlreadySettled`]). Until settled, a
//! proposal is invisible to the version chain — the retained bytes are never a
//! version, never read back.
//!
//! # Consume-once ledger
//!
//! Each proposal is keyed by `(artifact, proposal_ref)` where `proposal_ref` is
//! the agent run ref that produced it. A [`SettlementRecord`] in `vault_meta`
//! is the ledger: a select or discard writes exactly one, and every settle
//! guards on its presence — an early read (which stops a sequential second
//! settle before any side effect) plus a final check-and-insert (the atomic
//! commit point, which stops a racing second settle). Because the version
//! append dedupes identical bytes and the re-anchor sweep is idempotent, a
//! crash-retry of a select converges rather than duplicating work.
//!
//! # Re-anchor on select (D2/D5)
//!
//! Select appends the new version, then replays the manifest's anchor effects
//! ([`EditManifest::anchor_effects`]) onto the threads anchored at the prior
//! head. The manifest's [`AnchorEffect`](crate::edit_roundtrip::AnchorEffect)s
//! lower to ARTL-2 [`ReanchorOp`]s through
//! `From<&AnchorEffect>` (the reconciliation the ARTL-2 module doc calls for),
//! and [`Vault::reanchor_annotation_threads`] does the work: a thread on a
//! moved cell advances to the new version with a remapped locator; a thread on
//! a destroyed range drifts and stays pinned to its origin version.
//!
//! # Receipts (D6/D7)
//!
//! Both paths land an OF-367 receipt ([`ReceiptKind::ArtifactSettle`]) projected
//! from the settlement record — a floor receipt, persisted through its own
//! substrate. A select receipt resolves `artifact@version` plus the anchor set
//! that moved (the tappable door, [`Vault::settle_receipt_door`], opens the lens
//! at those anchors); a discard receipt records the proposal ref and reason.
//! When the settle rode an assigning brief, the receipt's `job_ref` joins that
//! brief's project view (B2 RS4).
//!
//! # Standing-grant seam (D6)
//!
//! D6 lets a standing "agent may edit this workbook" grant authorize a settle
//! without a per-op consent prompt, modeled as a **brief×verb-class bundle
//! grant**. The brief×verb-class *scope* vocabulary already exists as
//! [`StandingOutboundGrantScope::BriefVerbClass`](crate::outbound_grant::StandingOutboundGrantScope),
//! but its only carrier is the outbound-*send* grant family, whose capability is
//! sends-to-counterparties, not artifact writes — honoring one for a settle
//! would conflate two capabilities. Per the ARTL-4 rule "do not invent a new
//! grant family", [`Vault::settle_standing_grant_authorizes`] is a clearly
//! marked seam: it returns "no standing settle authority" (so [`SettleConsent::StandingGrant`]
//! fails closed) until a dedicated settle/edit verb-class bundle-grant
//! capability lands, at which point it plugs in behind that one function using
//! the same [`SETTLE_VERB_CLASS`] scope shape. The owner-driven select/discard
//! ([`SettleConsent::OwnerConsent`]) is the fully implemented P1 path.

use std::collections::BTreeMap;
use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::anchored_annotation::{
    Locator, ReanchorOp, ReanchorSummary, decode_locator, encode_locator,
};
use crate::blob_artifact::{BLOB_ARTIFACT_CONTENT_HASH_LEN, BlobArtifactVersion};
use crate::edit_roundtrip::{EditManifest, EditProposal, OfficeFormat};
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptRecord};
use crate::types::{ENTITY_ID_LEN, EntityId, TimeRange, WriteActor};

/// Current settlement-record body schema version.
pub const SETTLEMENT_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for a [`SettlementRecord`] body.
pub const SETTLEMENT_RECORD_KEYS: [&str; 12] = [
    "schema_version",
    "proposal_ref",
    "outcome",
    "settled_at",
    "actor_ref",
    "brief_ref",
    "version",
    "content_hash",
    "manifest_ref",
    "manifest_ops",
    "anchors",
    "reason",
];

/// Pinned on-disk MessagePack key set for one [`SettledAnchor`] entry.
pub const SETTLED_ANCHOR_KEYS: [&str; 3] = ["thread_id", "locator", "drifted"];

/// Verb class a settle bundle-grant carries under the D6 brief×verb-class scope.
///
/// A settle-specific verb class keeps a future settle grant disjoint from
/// outbound-send grants (which carry `send`), so a send authorization can never
/// stand in for an artifact-write settle. See the module-level standing-grant
/// seam note.
pub const SETTLE_VERB_CLASS: &str = "artifact.settle";

const KEY_SCHEMA_VERSION: &str = SETTLEMENT_RECORD_KEYS[0];
const KEY_PROPOSAL_REF: &str = SETTLEMENT_RECORD_KEYS[1];
const KEY_OUTCOME: &str = SETTLEMENT_RECORD_KEYS[2];
const KEY_SETTLED_AT: &str = SETTLEMENT_RECORD_KEYS[3];
const KEY_ACTOR_REF: &str = SETTLEMENT_RECORD_KEYS[4];
const KEY_BRIEF_REF: &str = SETTLEMENT_RECORD_KEYS[5];
const KEY_VERSION: &str = SETTLEMENT_RECORD_KEYS[6];
const KEY_CONTENT_HASH: &str = SETTLEMENT_RECORD_KEYS[7];
const KEY_MANIFEST_REF: &str = SETTLEMENT_RECORD_KEYS[8];
const KEY_MANIFEST_OPS: &str = SETTLEMENT_RECORD_KEYS[9];
const KEY_ANCHORS: &str = SETTLEMENT_RECORD_KEYS[10];
const KEY_REASON: &str = SETTLEMENT_RECORD_KEYS[11];

const KEY_ANCHOR_THREAD_ID: &str = SETTLED_ANCHOR_KEYS[0];
const KEY_ANCHOR_LOCATOR: &str = SETTLED_ANCHOR_KEYS[1];
const KEY_ANCHOR_DRIFTED: &str = SETTLED_ANCHOR_KEYS[2];

const BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX: &[u8] = b"blob_artifact:settlement:v1:";

const OUTCOME_SELECTED: &str = "selected";
const OUTCOME_DISCARDED: &str = "discarded";

// Receipt field keys.
const FIELD_ARTIFACT_REF: &str = "artifact_ref";
const FIELD_PROPOSAL_REF: &str = "proposal_ref";
const FIELD_RUN_REF: &str = "run_ref";
const FIELD_BRIEF_REF: &str = "brief_ref";
const FIELD_VERSION: &str = "version";
const FIELD_CONTENT_HASH: &str = "content_hash";
const FIELD_MANIFEST_REF: &str = "manifest_ref";
const FIELD_MANIFEST_OPS: &str = "manifest_ops";
const FIELD_ANCHOR_MOVES: &str = "anchor_moves";
const FIELD_ANCHOR_DRIFTS: &str = "anchor_drifts";
const FIELD_REASON: &str = "reason";

// ---------------------------------------------------------------------------
// Consent / authorization
// ---------------------------------------------------------------------------

/// How a settle is authorized (OF-368 D6).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SettleConsent {
    /// The owner is settling the retained output directly (viewer select or
    /// discard). The owner action IS the consent — the fully implemented P1
    /// path. `brief_ref` optionally names the assigning brief so the settle
    /// receipt joins that brief's project view.
    OwnerConsent { brief_ref: Option<String> },
    /// Rely on a standing brief×verb-class bundle grant to settle without a
    /// per-op consent prompt (the D6 escalation). `brief_ref` names the brief
    /// the grant must cover. SEAM — see [`Vault::settle_standing_grant_authorizes`].
    StandingGrant { brief_ref: String },
}

impl SettleConsent {
    /// The assigning brief this settle rides, if any — recorded on the receipt.
    #[must_use]
    pub fn brief_ref(&self) -> Option<&str> {
        match self {
            Self::OwnerConsent { brief_ref } => brief_ref.as_deref(),
            Self::StandingGrant { brief_ref } => Some(brief_ref),
        }
    }
}

// ---------------------------------------------------------------------------
// Settlement record (the consume-once ledger + receipt substrate)
// ---------------------------------------------------------------------------

/// Which way a proposal was consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleOutcomeKind {
    /// The proposal became a new blob-artifact version.
    Selected,
    /// The proposal was dropped.
    Discarded,
}

impl SettleOutcomeKind {
    /// The pinned on-disk / receipt outcome string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Selected => OUTCOME_SELECTED,
            Self::Discarded => OUTCOME_DISCARDED,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            OUTCOME_SELECTED => Some(Self::Selected),
            OUTCOME_DISCARDED => Some(Self::Discarded),
            _ => None,
        }
    }
}

/// One anchor the select re-anchor sweep moved, captured at settle time
/// (record-not-replay): a remapped anchor carries its new locator on the new
/// version; a drifted anchor carries the origin locator it stayed pinned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledAnchor {
    /// The annotation thread whose anchor moved.
    pub thread_id: EntityId,
    /// The locator the anchor resolved to after the settle.
    pub locator: Locator,
    /// Whether the anchor drifted (its region was destroyed) rather than remapped.
    pub drifted: bool,
}

/// The durable consume-once ledger entry for one settled proposal, and the
/// substrate the settle receipt projects from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SettlementRecord {
    /// The agent run ref that produced the proposal — the consume-once key.
    pub proposal_ref: String,
    /// Whether the proposal was selected or discarded.
    pub outcome: SettleOutcomeKind,
    /// Settle time (engine clock).
    pub settled_at: u64,
    /// The settling actor's entity ref (hex), for the receipt.
    pub actor_ref: Option<String>,
    /// The assigning brief this settle rode, if any.
    pub brief_ref: Option<String>,
    /// The committed version (select only).
    pub version: Option<u64>,
    /// The committed version's content hash (select only).
    pub content_hash: Option<[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN]>,
    /// Content hash of the edit-manifest bytes (select only) — the D6 manifest
    /// summary handle.
    pub manifest_ref: Option<[u8; 32]>,
    /// Number of ops in the manifest (0 for a discard).
    pub manifest_ops: u64,
    /// The anchor set that moved on select (empty for a discard).
    pub anchors: Vec<SettledAnchor>,
    /// Why the proposal was discarded (discard only).
    pub reason: Option<String>,
}

/// The tappable-door resolution of a select receipt: the committed
/// `artifact@version` plus the anchor set that moved (OF-368 D6).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SettleReceiptDoor {
    /// The artifact the select committed to.
    pub artifact_id: EntityId,
    /// The version the proposal became.
    pub version: u64,
    /// The anchors the re-anchor sweep moved.
    pub anchors: Vec<SettledAnchor>,
}

/// The result of a settle-select: the committed version, the re-anchor sweep
/// summary, and the select receipt.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SettleSelectOutcome {
    /// The version the proposal became.
    pub version: BlobArtifactVersion,
    /// The threads that remapped or drifted.
    pub reanchor: ReanchorSummary,
    /// The select receipt (OF-367 family).
    pub receipt: ReceiptRecord,
}

/// The result of a settle-discard: the discard receipt.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SettleDiscardOutcome {
    /// The discard receipt (OF-367 family).
    pub receipt: ReceiptRecord,
}

// ---------------------------------------------------------------------------
// Vault surface
// ---------------------------------------------------------------------------

impl Vault {
    /// Settle-selects a retained [`EditProposal`]: appends its bytes as a new
    /// blob-artifact version (provenance [`BlobVersionProvenance::AgentRun`]),
    /// replays the manifest's anchor effects onto the artifact's threads, and
    /// records the select in the consume-once ledger with a receipt.
    ///
    /// Consume-once: a proposal already settled (select or discard) is refused
    /// with [`Error::EditProposalAlreadySettled`] before any side effect.
    ///
    /// [`BlobVersionProvenance::AgentRun`]: crate::blob_artifact::BlobVersionProvenance::AgentRun
    pub fn settle_select_edit_proposal(
        &self,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        consent: &SettleConsent,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SettleSelectOutcome> {
        let proposal_ref = proposal.run_ref.as_str();
        self.ensure_selectable(proposal)?;
        // Early consume-once guard: a sequential second settle is refused before
        // any version is appended.
        if let Some(existing) = self.blob_artifact_settlement(artifact_id, proposal_ref)? {
            return Err(already_settled(&existing));
        }
        self.authorize_settle(consent)?;

        let base = self
            .blob_artifact_head(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let version = self.append_blob_artifact_version(
            artifact_id,
            &proposal.new_bytes,
            &proposal.agent_run_provenance(),
            actor,
            occurred,
            learned_at,
        )?;

        // Replay the manifest's anchor effects onto threads anchored at the
        // prior head. A dedupe no-op append (identical bytes) advances no
        // version, so there is nothing to re-anchor.
        let reanchor = if version.version > base.version {
            let ops: Vec<ReanchorOp> = proposal
                .manifest
                .anchor_effects()
                .iter()
                .map(ReanchorOp::from)
                .collect();
            self.reanchor_annotation_threads(
                artifact_id,
                base.version,
                version.version,
                &ops,
                actor,
                occurred,
                learned_at,
            )?
        } else {
            ReanchorSummary::default()
        };

        let record = SettlementRecord {
            proposal_ref: proposal_ref.to_owned(),
            outcome: SettleOutcomeKind::Selected,
            settled_at: learned_at,
            actor_ref: Some(actor.entity_ref().to_hex()),
            brief_ref: consent.brief_ref().map(str::to_owned),
            version: Some(version.version),
            content_hash: Some(version.content_hash),
            manifest_ref: Some(manifest_ref(&proposal.manifest)?),
            manifest_ops: u64::try_from(proposal.manifest.ops.len()).unwrap_or(u64::MAX),
            anchors: settled_anchors_from_summary(&reanchor),
            reason: None,
        };
        self.commit_settlement_record(artifact_id, &record)?;
        let receipt = settlement_receipt_record(*artifact_id, &record);
        Ok(SettleSelectOutcome {
            version,
            reanchor,
            receipt,
        })
    }

    /// Settle-discards a retained [`EditProposal`]: drops it and records the
    /// discard (with `reason`) in the consume-once ledger with a receipt.
    /// Nothing is appended to the version chain and no anchor moves.
    ///
    /// Consume-once: a proposal already settled is refused with
    /// [`Error::EditProposalAlreadySettled`].
    pub fn settle_discard_edit_proposal(
        &self,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        consent: &SettleConsent,
        actor: WriteActor,
        reason: &str,
        learned_at: u64,
    ) -> Result<SettleDiscardOutcome> {
        let proposal_ref = proposal.run_ref.as_str();
        if proposal_ref.trim().is_empty() {
            return Err(Error::EditRoundtripFailed(
                "proposal run_ref must be non-empty",
            ));
        }
        if let Some(existing) = self.blob_artifact_settlement(artifact_id, proposal_ref)? {
            return Err(already_settled(&existing));
        }
        self.authorize_settle(consent)?;

        let reason = reason.trim();
        let record = SettlementRecord {
            proposal_ref: proposal_ref.to_owned(),
            outcome: SettleOutcomeKind::Discarded,
            settled_at: learned_at,
            actor_ref: Some(actor.entity_ref().to_hex()),
            brief_ref: consent.brief_ref().map(str::to_owned),
            version: None,
            content_hash: None,
            manifest_ref: None,
            manifest_ops: 0,
            anchors: Vec::new(),
            reason: (!reason.is_empty()).then(|| reason.to_owned()),
        };
        self.commit_settlement_record(artifact_id, &record)?;
        let receipt = settlement_receipt_record(*artifact_id, &record);
        Ok(SettleDiscardOutcome { receipt })
    }

    /// Reads the consume-once ledger entry for `(artifact, proposal_ref)`, or
    /// `None` if the proposal has not been settled.
    pub fn blob_artifact_settlement(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<SettlementRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let key = settlement_key(artifact_id, proposal_ref);
        let Some(raw) = self.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_settlement_record(raw).map(Some)
    }

    /// Lists settlement ledger entries across all artifacts (oldest key order),
    /// paired with the artifact each belongs to. Bounded by `limit`.
    pub fn blob_artifact_settlements(
        &self,
        limit: usize,
    ) -> Result<Vec<(EntityId, SettlementRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX)?
        {
            if out.len() >= limit {
                break;
            }
            let (key, raw) = entry?;
            let artifact_id = settlement_key_artifact_id(key)?;
            let record = decode_settlement_record(raw)?;
            out.push((artifact_id, record));
        }
        Ok(out)
    }

    /// Resolves the tappable door of a *select* settle: the committed
    /// `artifact@version` plus the anchor set that moved. Returns `None` when
    /// the proposal was not settled or was discarded (a discard has no
    /// artifact@version to open).
    pub fn settle_receipt_door(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<SettleReceiptDoor>> {
        let Some(record) = self.blob_artifact_settlement(artifact_id, proposal_ref)? else {
            return Ok(None);
        };
        let (Some(version), SettleOutcomeKind::Selected) = (record.version, record.outcome) else {
            return Ok(None);
        };
        Ok(Some(SettleReceiptDoor {
            artifact_id: *artifact_id,
            version,
            anchors: record.anchors,
        }))
    }

    /// Seam (OF-368 D6): whether a standing brief×verb-class bundle grant
    /// authorizes a settle on `brief_ref` without a per-op consent prompt.
    ///
    /// The brief×verb-class scope vocabulary exists today only inside the
    /// outbound-*send* grant family, whose capability is not artifact writes,
    /// so — per "do not invent a new grant family" — this seam does not reuse
    /// it and returns `false` (no standing settle authority). A dedicated
    /// settle/edit verb-class ([`SETTLE_VERB_CLASS`]) bundle-grant capability
    /// plugs in here when it lands. See the module-level seam note.
    pub fn settle_standing_grant_authorizes(&self, brief_ref: &str) -> Result<bool> {
        let _ = brief_ref;
        Ok(false)
    }

    fn authorize_settle(&self, consent: &SettleConsent) -> Result<()> {
        match consent {
            SettleConsent::OwnerConsent { .. } => Ok(()),
            SettleConsent::StandingGrant { brief_ref } => {
                if self.settle_standing_grant_authorizes(brief_ref)? {
                    Ok(())
                } else {
                    Err(Error::SettleNotAuthorized(
                        "no standing brief×verb-class settle grant covers this brief",
                    ))
                }
            }
        }
    }

    /// Atomic consume-once commit: inserts the settlement record only if the
    /// proposal is still unsettled, else refuses. This is the authoritative
    /// guard a racing second settle fails against.
    fn commit_settlement_record(
        &self,
        artifact_id: &EntityId,
        record: &SettlementRecord,
    ) -> Result<()> {
        let key = settlement_key(artifact_id, &record.proposal_ref);
        let encoded = encode_settlement_record(record)?;
        self.with_write_txn(|wtxn| {
            if let Some(raw) = self.store.vault_meta.get(wtxn, &key)? {
                let existing = decode_settlement_record(raw)?;
                return Err(already_settled(&existing));
            }
            self.store.vault_meta.put(wtxn, &key, &encoded)?;
            Ok(())
        })
    }

    fn ensure_selectable(&self, proposal: &EditProposal) -> Result<()> {
        if proposal.run_ref.trim().is_empty() {
            return Err(Error::EditRoundtripFailed(
                "proposal run_ref must be non-empty",
            ));
        }
        // An EditProposal only exists on a passed corruption gate, but a select
        // commits its bytes into the version chain — re-check fail-closed.
        if !proposal.validation.ok {
            return Err(Error::EditRoundtripFailed(
                "proposal failed the corruption gate; a rejected output is never settleable",
            ));
        }
        if proposal.new_bytes.is_empty() {
            return Err(Error::EditRoundtripFailed(
                "proposal has no bytes to settle",
            ));
        }
        // The op vocabulary and re-anchor replay are spreadsheet-specific, the
        // same gate ARTL-3 applies.
        if !matches!(proposal.format, OfficeFormat::Xlsx) {
            return Err(Error::InvalidEditManifest(
                "settle supports only xlsx proposals; docx and pptx are not yet supported",
            ));
        }
        Ok(())
    }
}

/// Builds settle receipts across the settlement ledger for the OF-367 family
/// query. Filtering is the caller's (`receipt.rs`) job.
pub(crate) fn settle_receipts(vault: &Vault, limit: usize) -> Result<Vec<ReceiptRecord>> {
    Ok(vault
        .blob_artifact_settlements(limit)?
        .into_iter()
        .map(|(artifact_id, record)| settlement_receipt_record(artifact_id, &record))
        .collect())
}

// ---------------------------------------------------------------------------
// Receipt projection
// ---------------------------------------------------------------------------

fn settlement_receipt_record(artifact_id: EntityId, record: &SettlementRecord) -> ReceiptRecord {
    let artifact_hex = artifact_id.to_hex();
    let mut fields = BTreeMap::new();
    fields.insert(FIELD_ARTIFACT_REF.to_owned(), artifact_hex.clone());
    fields.insert(FIELD_PROPOSAL_REF.to_owned(), record.proposal_ref.clone());
    // Surface the proposal ref as run_ref too, so the settle joins run-rooted
    // receipt projections like any other agent-run effect.
    fields.insert(FIELD_RUN_REF.to_owned(), record.proposal_ref.clone());
    if let Some(brief_ref) = record.brief_ref.as_ref() {
        fields.insert(FIELD_BRIEF_REF.to_owned(), brief_ref.clone());
    }

    let trigger_ref = match record.outcome {
        SettleOutcomeKind::Selected => {
            let version = record.version.unwrap_or(0);
            fields.insert(FIELD_VERSION.to_owned(), version.to_string());
            if let Some(content_hash) = record.content_hash.as_ref() {
                fields.insert(
                    FIELD_CONTENT_HASH.to_owned(),
                    crate::receipt::hex_lower(content_hash),
                );
            }
            if let Some(manifest_ref) = record.manifest_ref.as_ref() {
                fields.insert(
                    FIELD_MANIFEST_REF.to_owned(),
                    crate::receipt::hex_lower(manifest_ref),
                );
            }
            fields.insert(
                FIELD_MANIFEST_OPS.to_owned(),
                record.manifest_ops.to_string(),
            );
            let drifts = record.anchors.iter().filter(|a| a.drifted).count();
            let moves = record.anchors.len() - drifts;
            fields.insert(FIELD_ANCHOR_MOVES.to_owned(), moves.to_string());
            fields.insert(FIELD_ANCHOR_DRIFTS.to_owned(), drifts.to_string());
            // The door opens the lens at artifact@version.
            format!("artifact:{artifact_hex}@{version}")
        }
        SettleOutcomeKind::Discarded => {
            if let Some(reason) = record.reason.as_ref() {
                fields.insert(FIELD_REASON.to_owned(), reason.clone());
            }
            format!("proposal:{}", record.proposal_ref)
        }
    };

    ReceiptRecord {
        receipt_id: format!("artifact_settle:{artifact_hex}:{}", record.proposal_ref),
        receipt_kind: ReceiptKind::ArtifactSettle,
        occurred_at: record.settled_at,
        actor: record.actor_ref.clone(),
        on_behalf_of: None,
        outcome: record.outcome.as_str().to_owned(),
        // Join the assigning brief's project view (B2 RS4), like other
        // brief-rooted receipts.
        job_ref: record.brief_ref.clone(),
        trigger_ref: Some(trigger_ref),
        policy_trace: Vec::new(),
        fields,
    }
}

fn settled_anchors_from_summary(summary: &ReanchorSummary) -> Vec<SettledAnchor> {
    let mut anchors = Vec::with_capacity(summary.remapped.len() + summary.drifted.len());
    for thread in &summary.remapped {
        anchors.push(SettledAnchor {
            thread_id: thread.thread_id,
            locator: thread.anchor.locator.clone(),
            drifted: false,
        });
    }
    for thread in &summary.drifted {
        anchors.push(SettledAnchor {
            thread_id: thread.thread_id,
            locator: thread.anchor.locator.clone(),
            drifted: true,
        });
    }
    anchors
}

fn manifest_ref(manifest: &EditManifest) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&manifest.to_msgpack()?).as_bytes())
}

fn already_settled(existing: &SettlementRecord) -> Error {
    Error::EditProposalAlreadySettled {
        outcome: existing.outcome.as_str(),
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

fn settlement_key(artifact_id: &EntityId, proposal_ref: &str) -> Vec<u8> {
    let proposal_hash = blake3::hash(proposal_ref.as_bytes());
    let mut key = Vec::with_capacity(
        BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX.len() + ENTITY_ID_LEN + proposal_hash.as_bytes().len(),
    );
    key.extend_from_slice(BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX);
    key.extend_from_slice(artifact_id.as_bytes());
    key.extend_from_slice(proposal_hash.as_bytes());
    key
}

fn settlement_key_artifact_id(key: &[u8]) -> Result<EntityId> {
    let start = BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX.len();
    let end = start + ENTITY_ID_LEN;
    if key.len() != end + 32 || !key.starts_with(BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX) {
        return Err(Error::CorruptedIndex("blob artifact settlement key"));
    }
    let raw: [u8; ENTITY_ID_LEN] = key[start..end]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("blob artifact settlement key"))?;
    EntityId::from_bytes(raw).map_err(|_| Error::CorruptedIndex("blob artifact settlement key"))
}

// ---------------------------------------------------------------------------
// Codec (pinned-key MessagePack)
// ---------------------------------------------------------------------------

fn encode_settlement_record(record: &SettlementRecord) -> Result<Vec<u8>> {
    let anchors: Vec<Value> = record.anchors.iter().map(encode_settled_anchor).collect();
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SETTLEMENT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PROPOSAL_REF),
            Value::from(record.proposal_ref.as_str()),
        ),
        (
            Value::from(KEY_OUTCOME),
            Value::from(record.outcome.as_str()),
        ),
        (Value::from(KEY_SETTLED_AT), Value::from(record.settled_at)),
        (
            Value::from(KEY_ACTOR_REF),
            option_str_value(record.actor_ref.as_deref()),
        ),
        (
            Value::from(KEY_BRIEF_REF),
            option_str_value(record.brief_ref.as_deref()),
        ),
        (
            Value::from(KEY_VERSION),
            record.version.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_CONTENT_HASH),
            record
                .content_hash
                .map_or(Value::Nil, |hash| Value::Binary(hash.to_vec())),
        ),
        (
            Value::from(KEY_MANIFEST_REF),
            record
                .manifest_ref
                .map_or(Value::Nil, |hash| Value::Binary(hash.to_vec())),
        ),
        (
            Value::from(KEY_MANIFEST_OPS),
            Value::from(record.manifest_ops),
        ),
        (Value::from(KEY_ANCHORS), Value::Array(anchors)),
        (
            Value::from(KEY_REASON),
            option_str_value(record.reason.as_deref()),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("settlement record MessagePack encode failed"))?;
    Ok(out)
}

fn encode_settled_anchor(anchor: &SettledAnchor) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_ANCHOR_THREAD_ID),
            Value::Binary(anchor.thread_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_ANCHOR_LOCATOR),
            encode_locator(&anchor.locator),
        ),
        (Value::from(KEY_ANCHOR_DRIFTED), Value::from(anchor.drifted)),
    ])
}

fn decode_settlement_record(bytes: &[u8]) -> Result<SettlementRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| corrupt())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(corrupt());
    }
    let Value::Map(entries) = value else {
        return Err(corrupt());
    };
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64)
        != Some(SETTLEMENT_SCHEMA_VERSION)
    {
        return Err(corrupt());
    }
    let outcome =
        SettleOutcomeKind::parse(field_str(&entries, KEY_OUTCOME)?).ok_or_else(corrupt)?;
    let anchors = decode_anchors(field(&entries, KEY_ANCHORS).ok_or_else(corrupt)?)?;
    Ok(SettlementRecord {
        proposal_ref: field_str(&entries, KEY_PROPOSAL_REF)?.to_owned(),
        outcome,
        settled_at: field_u64(&entries, KEY_SETTLED_AT)?,
        actor_ref: field_opt_str(&entries, KEY_ACTOR_REF)?,
        brief_ref: field_opt_str(&entries, KEY_BRIEF_REF)?,
        version: field_opt_u64(&entries, KEY_VERSION)?,
        content_hash: field_opt_hash(&entries, KEY_CONTENT_HASH)?,
        manifest_ref: field_opt_hash(&entries, KEY_MANIFEST_REF)?,
        manifest_ops: field_u64(&entries, KEY_MANIFEST_OPS)?,
        anchors,
        reason: field_opt_str(&entries, KEY_REASON)?,
    })
}

fn decode_anchors(value: &Value) -> Result<Vec<SettledAnchor>> {
    let Value::Array(items) = value else {
        return Err(corrupt());
    };
    items.iter().map(decode_settled_anchor).collect()
}

fn decode_settled_anchor(value: &Value) -> Result<SettledAnchor> {
    let Value::Map(entries) = value else {
        return Err(corrupt());
    };
    let thread_id = field_entity(entries, KEY_ANCHOR_THREAD_ID)?;
    let locator = decode_locator(field(entries, KEY_ANCHOR_LOCATOR).ok_or_else(corrupt)?)?;
    let drifted = field(entries, KEY_ANCHOR_DRIFTED)
        .and_then(Value::as_bool)
        .ok_or_else(corrupt)?;
    Ok(SettledAnchor {
        thread_id,
        locator,
        drifted,
    })
}

fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn field_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    field(entries, key)
        .and_then(Value::as_str)
        .ok_or_else(corrupt)
}

fn field_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    field(entries, key)
        .and_then(Value::as_u64)
        .ok_or_else(corrupt)
}

fn field_opt_str(entries: &[(Value, Value)], key: &str) -> Result<Option<String>> {
    match field(entries, key) {
        None => Err(corrupt()),
        Some(Value::Nil) => Ok(None),
        Some(value) => Ok(Some(value.as_str().ok_or_else(corrupt)?.to_owned())),
    }
}

fn field_opt_u64(entries: &[(Value, Value)], key: &str) -> Result<Option<u64>> {
    match field(entries, key) {
        None => Err(corrupt()),
        Some(Value::Nil) => Ok(None),
        Some(value) => Ok(Some(value.as_u64().ok_or_else(corrupt)?)),
    }
}

fn field_opt_hash(entries: &[(Value, Value)], key: &str) -> Result<Option<[u8; 32]>> {
    match field(entries, key) {
        None => Err(corrupt()),
        Some(Value::Nil) => Ok(None),
        Some(Value::Binary(bytes)) => Ok(Some(bytes.as_slice().try_into().map_err(|_| corrupt())?)),
        Some(_) => Err(corrupt()),
    }
}

fn field_entity(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    let Some(Value::Binary(bytes)) = field(entries, key) else {
        return Err(corrupt());
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().map_err(|_| corrupt())?;
    EntityId::from_bytes(raw).map_err(|_| corrupt())
}

fn option_str_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

fn corrupt() -> Error {
    Error::CorruptedIndex("blob artifact settlement record")
}

#[cfg(test)]
mod tests;
