use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SKILL_CONTENT_ANCHOR;
use crate::skill::SkillContentHash;
use crate::temporal::TimeRange;

use super::package::HubPackage;
use super::support::{MAX_HUB_TEXT_BYTES, map_text, map_value, validate_text};

/// Claim predicate for scanner receipts attached to a canonical content hash.
pub const PREDICATE_SKILL_SCAN_VERDICT: &str = "skill.scan_verdict";

/// Domain separator for the deterministic content-anchor entity-id
/// derivation (ONE-1741). Bumping this string re-keys every anchor, so it is
/// pinned like a wire constant.
const SKILL_CONTENT_ANCHOR_ID_DOMAIN: &[u8] = b"oneiron:skill-scan-content-anchor:v1";

/// How far a scanner's clock may run ahead of this node's ingest clock before
/// its declared `scannedAt` is treated as skew and clamped (ONE-1892).
///
/// Without the clamp, one receipt stamped a century out would pin the active
/// slot for its `(content_hash, provider)` key against every later legitimate
/// scan — newest-wins turned into a denial-of-update primitive. Five minutes is
/// generous for ordinary clock drift and useless as a pin.
const SCAN_TIMESTAMP_FUTURE_SKEW_SECS: u64 = 300;

/// Independent scanner verdict axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanVerdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
}

impl ScanVerdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::Unknown => "unknown",
        }
    }
}

/// Scanner-reported risk level.
///
/// Ordered least-to-most severe, and the derived `Ord` IS that severity order:
/// the activation dial (`skill_scan`) compares stored risks against a threshold
/// with `>=`, so the variant sequence here is a wire-facing decision, not a
/// cosmetic one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScanRiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl ScanRiskLevel {
    /// The pinned on-disk string for this level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// Scanner coverage completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCompleteness {
    Partial,
    Complete,
}

impl ScanCompleteness {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Partial => "partial",
            Self::Complete => "complete",
        }
    }
}

/// Governance axis stored separately from scanner signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillGovernance {
    Recommended,
    Discouraged,
    Prohibited,
}

impl SkillGovernance {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Recommended => "recommended",
            Self::Discouraged => "discouraged",
            Self::Prohibited => "prohibited",
        }
    }
}

/// One provider receipt attached to a canonical content hash and scan time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillScanReceipt {
    pub provider: String,
    pub scanned_at: u64,
    pub verdict: ScanVerdict,
    pub risk_level: ScanRiskLevel,
    pub completeness: ScanCompleteness,
    pub governance: SkillGovernance,
}

impl SkillScanReceipt {
    /// Constructs a scanner receipt with an orthogonal governance value.
    pub fn new(
        provider: impl Into<String>,
        scanned_at: u64,
        verdict: ScanVerdict,
        risk_level: ScanRiskLevel,
        completeness: ScanCompleteness,
        governance: SkillGovernance,
    ) -> Result<Self> {
        let receipt = Self {
            provider: provider.into(),
            scanned_at,
            verdict,
            risk_level,
            completeness,
            governance,
        };
        validate_text(
            &receipt.provider,
            MAX_HUB_TEXT_BYTES,
            "scan provider must be non-empty",
        )?;
        Ok(receipt)
    }
}

impl Vault {
    /// Ingests a scanner receipt, superseding every prior active row for the
    /// same content-global `(content_hash, provider)` without gating admission.
    pub fn ingest_skill_scan_verdict(
        &self,
        entity: &EntityId,
        content_hash: SkillContentHash,
        receipt: &SkillScanReceipt,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        validate_skill_scan_receipt(receipt)?;
        let mut wtxn = self.store.env.write_txn()?;
        let claim_id = self.ingest_skill_scan_verdict_in_txn(
            &mut wtxn,
            entity,
            content_hash,
            receipt,
            occurred,
            learned_at,
        )?;
        wtxn.commit()?;
        Ok(claim_id)
    }

    fn ingest_skill_scan_verdict_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        content_hash: SkillContentHash,
        receipt: &SkillScanReceipt,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let skill = self.read_skill_record_in_txn(&*wtxn, entity)?;
        if skill.content_hash != Some(content_hash) {
            return Err(Error::InvalidSkillBody(
                "scan receipt content hash does not match the skill",
            ));
        }
        let hash_hex = content_hash.to_hex();
        // ONE-1741: verdicts hang off the deterministic content anchor, not the
        // submitting holder, so ensure it exists before the reserved put (the
        // claim door requires the subject entity) and dedup against the single
        // anchor rather than looping over every current holder.
        let anchor = self.ensure_skill_content_anchor_in_txn(wtxn, content_hash, learned_at)?;
        let scanned_at = clamp_scan_timestamp(receipt.scanned_at, learned_at);
        let mut prior_rows = Vec::new();
        for (id, body, occurred_start) in
            self.active_claims_for_predicate_in_txn(&*wtxn, &anchor, PREDICATE_SKILL_SCAN_VERDICT)?
        {
            if map_text(&body.value, "contentHash") == Some(hash_hex.as_str())
                && map_text(&body.value, "provider") == Some(receipt.provider.as_str())
            {
                prior_rows.push((id, occurred_start, scan_verdict_row_scanned_at(&body)?));
            }
        }

        let claim_id = EntityId::now();
        let mut value = vec![
            (Value::from("contentHash"), Value::from(hash_hex)),
            (
                Value::from("provider"),
                Value::from(receipt.provider.as_str()),
            ),
            (Value::from("scannedAt"), Value::from(scanned_at)),
            (
                Value::from("verdict"),
                Value::from(receipt.verdict.as_str()),
            ),
            (
                Value::from("riskLevel"),
                Value::from(receipt.risk_level.as_str()),
            ),
            (
                Value::from("completeness"),
                Value::from(receipt.completeness.as_str()),
            ),
            (
                Value::from("governance"),
                Value::from(receipt.governance.as_str()),
            ),
        ];
        if scanned_at != receipt.scanned_at {
            // The clamp is RECEIPTED, not silent: the row reports the time the
            // comparison used plus what the provider actually declared, so a
            // skewed scanner is diagnosable from the ledger alone.
            value.push((
                Value::from("scannedAtDeclared"),
                Value::from(receipt.scanned_at),
            ));
        }
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_SCAN_VERDICT,
            ClaimSubject::Entity(anchor),
            Value::Map(value),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        self.put_reserved_claim_in_txn(wtxn, &claim_id, &body, occurred, learned_at)?;

        // F5 newest-wins (ONE-1892): the ACTIVE verdict for a
        // `(content_hash, provider)` key is the one with the latest SCAN time,
        // not the one ingested last. A late-arriving older scan is real
        // evidence and is kept — it lands as a row and is closed under the
        // newer one in the same transaction, so it stays auditable without ever
        // holding the active slot. Ties go to the later call: two scans of the
        // same bytes at the same second are the same finding, and the fresher
        // ingest is the one whose provenance the caller just asserted.
        let newest_prior = prior_rows
            .iter()
            .max_by_key(|(_, _, prior_scanned_at)| *prior_scanned_at)
            .copied();
        if let Some((newest_id, newest_start, newest_scanned_at)) = newest_prior
            && scanned_at < newest_scanned_at
        {
            let superseded_at = learned_at.max(occurred.start).max(newest_start);
            self.supersede_reserved_claim_in_txn(wtxn, &newest_id, &claim_id, superseded_at)?;
            return Ok(claim_id);
        }
        for (prior_id, prior_start, _) in prior_rows {
            let superseded_at = learned_at.max(prior_start);
            self.supersede_reserved_claim_in_txn(wtxn, &claim_id, &prior_id, superseded_at)?;
        }
        Ok(claim_id)
    }

    /// Runs the engine's own static scan over an incoming package and ingests
    /// its receipt (ONE-1892) — the production PRODUCER behind
    /// [`Vault::ingest_skill_scan_verdict`].
    ///
    /// Idempotent on the CONTENT, not on the caller: the static pass is a pure
    /// function of the package bytes, so bytes that already carry an active
    /// receipt from this provider are left alone. Re-running would mint a row
    /// identical but for its timestamp and supersede the row it duplicates —
    /// churn with no new evidence in it. That also means a second hub alias
    /// over known bytes adds no verdict, while bytes first seen through a
    /// non-hub birth path get scanned the moment they arrive at this door.
    pub(crate) fn scan_and_ingest_on_import_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        content_hash: SkillContentHash,
        package: &HubPackage,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let already_scanned = self
            .skill_scan_verdicts_for_content_hash_in_txn(&*wtxn, content_hash)?
            .iter()
            .any(|body| {
                map_text(&body.value, "provider")
                    == Some(crate::skill_scan::SCAN_PROVIDER_STATIC_V1)
            });
        if already_scanned {
            return Ok(());
        }
        let receipt = crate::skill_scan::run_static_skill_scan(package, learned_at)?;
        self.ingest_skill_scan_verdict_in_txn(
            wtxn,
            entity,
            content_hash,
            &receipt,
            occurred,
            learned_at,
        )?;
        Ok(())
    }

    /// Ingests independent provider receipts as content-keyed audit signals.
    pub fn ingest_skill_audit_verdicts(
        &self,
        entity: &EntityId,
        content_hash: SkillContentHash,
        receipts: &[SkillScanReceipt],
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<usize> {
        // Validate the full caller-owned array before opening the transaction,
        // so a malformed middle receipt cannot follow any staged write.
        for receipt in receipts {
            validate_skill_scan_receipt(receipt)?;
        }

        let mut wtxn = self.store.env.write_txn()?;
        for receipt in receipts {
            self.ingest_skill_scan_verdict_in_txn(
                &mut wtxn,
                entity,
                content_hash,
                receipt,
                occurred,
                learned_at,
            )?;
        }
        wtxn.commit()?;
        Ok(receipts.len())
    }

    /// Reads active scanner receipts for canonical bytes off the deterministic
    /// content anchor. The anchor is derived from the content hash and never
    /// departs, so discovery is independent of which SKILL holders currently
    /// carry the bytes (ONE-1741).
    pub fn skill_scan_verdicts_for_content_hash(
        &self,
        content_hash: SkillContentHash,
    ) -> Result<Vec<ClaimBody>> {
        let rtxn = self.store.env.read_txn()?;
        self.skill_scan_verdicts_for_content_hash_in_txn(&rtxn, content_hash)
    }

    /// [`Vault::skill_scan_verdicts_for_content_hash`] inside the caller's
    /// transaction — the activation consult reads from inside the write
    /// transaction that performs the activation, so no verdict can land in
    /// between the consult and the write it governs.
    pub(crate) fn skill_scan_verdicts_for_content_hash_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_hash: SkillContentHash,
    ) -> Result<Vec<ClaimBody>> {
        skill_scan_verdicts_for_content_hash_in_store(&self.store, rtxn, content_hash)
    }

    /// Ensures the deterministic content-anchor entity for `content_hash`
    /// exists, minting it via the engine-authored maintenance door on first
    /// use, and returns its id. Verdict claims are subjected to this anchor, so
    /// it must exist before the reserved put runs (the claim door requires the
    /// subject entity). The anchor body carries the 32-byte content hash so the
    /// record is self-describing.
    ///
    /// An entity already sitting at the derived id must BE an anchor (ONE-1892).
    /// The pre-existence check is what makes the mint idempotent, so without a
    /// type assert any entity that landed on the derived id first would be
    /// silently adopted as the subject of every verdict for those bytes — a
    /// squat the verdict reader could never see. The id is a domain-separated
    /// digest, so this is a corruption guard, not a policy gate; it fails
    /// closed and writes nothing.
    fn ensure_skill_content_anchor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        content_hash: SkillContentHash,
        learned_at: u64,
    ) -> Result<EntityId> {
        let anchor = skill_content_anchor_entity_id(content_hash)?;
        if let Some(raw) = self.store.entities.get(&*wtxn, anchor.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_SKILL_CONTENT_ANCHOR {
                return Err(Error::SkillContentAnchorTypeMismatch {
                    existing: header.entity_type,
                });
            }
            return Ok(anchor);
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: anchor,
                entity_type: ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data: content_hash.as_bytes().to_vec(),
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(anchor)
    }
}

/// Derives the deterministic CONTENT-ANCHOR `EntityId` for `content_hash`
/// (ONE-1741): `id16 = first16(SHA-256(domain ‖ content_hash))`. Two nodes
/// ingesting the same bytes MUST converge on the same anchor, so this is a
/// pure function of the content hash — never `EntityId::now()`. On the
/// astronomically rare chance the first 16 digest bytes hit a reserved-id
/// sentinel (`is_reserved_entity_id_bytes`: all-`0x00` / all-`0xFF` /
/// `[type, 0xFF×15]`), the input is perturbed with a rising counter and
/// re-hashed until the derivation lands on a valid id. The base case (counter
/// 0) appends nothing, so the common path is exactly the domain-separated
/// digest; the terminal `Err` is unreachable and kept only for exhaustiveness.
pub(crate) fn skill_content_anchor_entity_id(content_hash: SkillContentHash) -> Result<EntityId> {
    for perturbation in 0..=u32::MAX {
        let mut hasher = Sha256::new();
        hasher.update(SKILL_CONTENT_ANCHOR_ID_DOMAIN);
        hasher.update(content_hash.as_bytes());
        if perturbation > 0 {
            hasher.update(perturbation.to_be_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "content anchor id derivation exhausted every perturbation",
    ))
}

/// Clamps a provider-declared scan time to this node's ingest clock when it
/// runs further ahead than [`SCAN_TIMESTAMP_FUTURE_SKEW_SECS`].
fn clamp_scan_timestamp(scanned_at: u64, learned_at: u64) -> u64 {
    if scanned_at > learned_at.saturating_add(SCAN_TIMESTAMP_FUTURE_SKEW_SECS) {
        learned_at
    } else {
        scanned_at
    }
}

/// The (already clamped) scan time a stored verdict row reports.
///
/// A row missing the field is corruption rather than an implicit zero: the
/// ingest door writes it on every path, and reading damage as "oldest possible"
/// would let a corrupt row lose the newest-wins comparison silently.
fn scan_verdict_row_scanned_at(body: &ClaimBody) -> Result<u64> {
    map_value(&body.value, "scannedAt")
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex("skill scan verdict scannedAt"))
}

/// The risk level a stored verdict row reports.
///
/// Same fail-closed reading as [`scan_verdict_row_scanned_at`]: a damaged row
/// must not read as harmless to the activation dial.
pub(crate) fn scan_verdict_row_risk(body: &ClaimBody) -> Result<ScanRiskLevel> {
    map_text(&body.value, "riskLevel")
        .and_then(ScanRiskLevel::parse)
        .ok_or(Error::CorruptedIndex("skill scan verdict riskLevel"))
}

/// Active scanner receipts for canonical bytes, read off the deterministic
/// content anchor with only the storage handle in hand.
///
/// The one implementation behind
/// [`Vault::skill_scan_verdicts_for_content_hash_in_txn`]. It takes `&Store`
/// rather than `&Vault` because the activation consult's real chokepoint is
/// the batch entity-materialization arm, which never holds a `Vault` — and a
/// gate that reads different rows depending on which door called it is not a
/// gate. Walks the anchor's inbound `claim_of` edges directly, the same rows
/// `Vault::claims_for_subject_in_txn` resolves: a peer that is missing, not a
/// CLAIM, or of another predicate is skipped, exactly as the edge-peer filter
/// skips it.
pub(crate) fn skill_scan_verdicts_for_content_hash_in_store(
    store: &crate::store::Store,
    rtxn: &heed::RoTxn<'_>,
    content_hash: SkillContentHash,
) -> Result<Vec<ClaimBody>> {
    let hash_hex = content_hash.to_hex();
    let anchor = skill_content_anchor_entity_id(content_hash)?;
    let prefix = crate::vault::edge_kind_prefix(&anchor, crate::edge::EdgeKind::ClaimOf);
    let mut rows = Vec::new();
    for (scanned, entry) in store.edges_in.prefix_iter(rtxn, &prefix)?.enumerate() {
        if scanned >= crate::vault::MAX_EDGE_QUERY_RESULTS {
            return Err(Error::IndexOverflow("skill scan verdicts for content hash"));
        }
        let (key, value) = entry?;
        let claim_id = crate::vault::parse_edge_record(&key, &value)?.target;
        let Some(raw) = store.entities.get(rtxn, claim_id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        // Defense in depth: every row on this anchor is for `content_hash`
        // by construction, but the exact-hash filter keeps discovery precise
        // even against a truncation collision on the derived anchor id.
        if body.predicate == PREDICATE_SKILL_SCAN_VERDICT
            && body.lifecycle == ClaimLifecycleStatus::Active
            && map_text(&body.value, "contentHash") == Some(hash_hex.as_str())
        {
            rows.push(body);
        }
    }
    Ok(rows)
}

fn validate_skill_scan_receipt(receipt: &SkillScanReceipt) -> Result<()> {
    validate_text(
        &receipt.provider,
        MAX_HUB_TEXT_BYTES,
        "scan provider must be non-empty",
    )
}
