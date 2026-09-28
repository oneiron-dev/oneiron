//! On-demand docs NER: only a named trigger crosses the thin-star boundary.
use super::{DocsDerivationEnvelope, DocsSegment, docs_semantic_segments};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimApprovalStatus;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::side_table::{self, HexId, LegacyJson, Raw, SideTable};
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_DEEP_CLAIMS: usize = 256;

// These keys retain the existing lower-case hex spelling and JSON value encoding.
const DEEP_CEILINGS: SideTable<HexId, DeepCeiling, LegacyJson> =
    SideTable::new(&side_table::INGEST_DOCS_DEEP_CEILING);
const DEEP_RECEIPTS: SideTable<HexId, DocsDeepReceipt, LegacyJson> =
    SideTable::new(&side_table::INGEST_DOCS_DEEP_RECEIPT);
const DOCS_EXTRACTIONS: SideTable<String, EntityId, Raw> =
    SideTable::new(&side_table::INGEST_DOCS_EXTRACTION);

/// A source-grounded entity/fact proposed by the host's NER implementation.
/// The quote must occur verbatim in the source segment, never in a model-only summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocsDeepClaim {
    pub predicate: String,
    pub value: Value,
    pub quote: String,
}

/// Optional NER port. No implementation is installed by default.
pub trait DocsDeepExtractor {
    fn binding(&self) -> &str;
    fn extract(&self, segment: &DocsSegment) -> Result<Vec<DocsDeepClaim>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocsDeepTrigger {
    OnRead,
    Explicit,
    Dreamer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsDeepReceipt {
    pub derivation: DocsDerivationEnvelope,
    pub trigger: DocsDeepTrigger,
    pub claim_refs: Vec<String>,
}

pub(super) struct DeepApproval<'a> {
    pub(super) owner: EntityId,
    pub(super) digest: &'a str,
    pub(super) project_id: EntityId,
}

struct PreparedDeepClaim {
    id: EntityId,
    chunk: EntityId,
    segment_hash: String,
    source_record_id: String,
    predicate: String,
    value: Value,
}

#[derive(Serialize, Deserialize)]
struct DeepCeiling {
    source_hash: String,
    allowed: bool,
    owner: String,
    approval_digest: String,
    project_id: EntityId,
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
fn transport_normalized_text(text: &str) -> String {
    text.strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n")
}

pub(super) fn source_hash(text: &str) -> String {
    blake3::hash(transport_normalized_text(text).as_bytes())
        .to_hex()
        .to_string()
}

fn imported_docs_source_body(body: &[u8], kind: u8) -> Option<Value> {
    let mut value: Value = rmp_serde::from_slice(body).ok()?;
    let fields = value.as_object_mut()?;
    if fields.get("source")?.as_str()? != "imported" {
        return None;
    }
    let text = transport_normalized_text(fields.get("text")?.as_str()?);
    fields.insert("text".into(), Value::String(text));
    if kind == ENTITY_TYPE_ASSET {
        // NER reads the page text, not the renderer path or registry metadata.
        fields.remove("path");
        fields.remove("registry");
    } else if kind == crate::registry::ENTITY_TYPE_ASSET_TEXT {
        // A newly inserted heading renumbers an unchanged chunk, but its
        // text and asset provenance still name the same source content.
        // Summaries rewritten under the stable chunk id must stay live.
        fields.remove("section");
    }
    Some(value)
}

/// Classifies a changed imported docs source at the shared put door.
/// The caller invalidates dependents after releasing the old-row read borrow,
/// in the same writer transaction; transport-only changes are not new sources.
pub(crate) fn docs_source_put_changes(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    previous: &[u8],
    next: &[u8],
) -> Result<bool> {
    if !matches!(
        kind,
        ENTITY_TYPE_ASSET | crate::registry::ENTITY_TYPE_ASSET_TEXT
    ) {
        return Ok(false);
    }
    let Some(previous) = imported_docs_source_body(previous, kind) else {
        return Ok(false);
    };
    if kind == ENTITY_TYPE_ASSET && !DEEP_RECEIPTS.contains(store, txn, &HexId(*id))? {
        // The docs importer retracted its prior claims and removed their
        // receipt before staging a changed approved source revision.
        return Ok(false);
    }
    Ok(Some(previous) != imported_docs_source_body(next, kind))
}

/// Only the shared batch entity-put door calls this, before it stages a new
/// body. Classify under a read borrow, release that borrow, then invalidate
/// dependents in the same transaction as the replacement.
pub(crate) fn invalidate_docs_source_before_put(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    next: &[u8],
) -> Result<()> {
    if !matches!(
        kind,
        ENTITY_TYPE_ASSET | crate::registry::ENTITY_TYPE_ASSET_TEXT
    ) {
        return Ok(());
    }
    let changed = {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, &*txn, id)? else {
            return Ok(());
        };
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::CorruptedIndex("docs source header"));
        }
        let previous = &raw[ENTITY_METADATA_HEADER_LEN..];
        previous != next && docs_source_put_changes(store, txn, id, kind, previous, next)?
    };
    if changed {
        crate::ports::invalidate_source_in_txn(store, txn, id)?;
    }
    Ok(())
}

/// The import's approved revision is the only source that can enable deep work.
/// Replacing a page closes its old derived claims in the SAME import transaction.
pub(super) fn set_deep_ceiling(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    asset: EntityId,
    text: &str,
    allowed: bool,
    approval: DeepApproval<'_>,
    now: u64,
) -> Result<()> {
    let old: Option<DeepCeiling> = DEEP_CEILINGS
        .get_bytes(&vault.store, txn, &HexId(asset))?
        .map(|raw| serde_json::from_slice(&raw).map_err(|_| invalid("corrupt docs deep ceiling")))
        .transpose()?;
    let hash = source_hash(text);
    if old.as_ref().is_some_and(|old| {
        old.source_hash != hash
            || old.project_id != approval.project_id
            || (old.allowed && !allowed)
    }) && let Some(raw) = DEEP_RECEIPTS.get_bytes(&vault.store, txn, &HexId(asset))?
    {
        let previous: DocsDeepReceipt =
            serde_json::from_slice(&raw).map_err(|_| invalid("corrupt docs deep receipt"))?;
        for reference in previous.claim_refs {
            let id = EntityId::from_hex(&reference)?;
            if vault
                .get_claim_in_txn(txn, &id)?
                .is_some_and(|body| body.lifecycle == crate::claim::ClaimLifecycleStatus::Active)
            {
                vault.retract_claim_in_txn(txn, &id, now)?;
            }
        }
        DEEP_RECEIPTS.delete(&vault.store, txn, &HexId(asset))?;
    }
    DEEP_CEILINGS.put(
        &vault.store,
        txn,
        &HexId(asset),
        &DeepCeiling {
            source_hash: hash,
            allowed,
            owner: approval.owner.to_hex(),
            approval_digest: approval.digest.to_owned(),
            project_id: approval.project_id,
        },
    )?;
    Ok(())
}

impl Vault {
    /// Extract imported, proposed claims from one approved docs asset.
    /// This is the explicit and lazy-Dreamer entry point; the scoped read
    /// sibling is the on-read entry point. Neither runs during import/search.
    pub fn deep_ingest_docs_asset(
        &self,
        owner: &AuthenticatedOwner,
        asset: EntityId,
        trigger: DocsDeepTrigger,
        extractor: &dyn DocsDeepExtractor,
        now: u64,
    ) -> Result<DocsDeepReceipt> {
        if trigger == DocsDeepTrigger::OnRead {
            return Err(invalid("on-read deep ingest requires a scoped reader"));
        }
        self.deep_ingest_docs_asset_checked(owner, asset, trigger, extractor, now, None)
    }

    /// Internal read-triggered door binds the observed source revision and
    /// the acting reader to both the model-input and writer snapshots.
    pub(crate) fn deep_ingest_docs_asset_checked(
        &self,
        owner: &AuthenticatedOwner,
        asset: EntityId,
        trigger: DocsDeepTrigger,
        extractor: &dyn DocsDeepExtractor,
        now: u64,
        read: Option<(&crate::claim::ScopedRead<'_>, &str)>,
    ) -> Result<DocsDeepReceipt> {
        if extractor.binding().trim().is_empty() {
            return Err(invalid("docs deep extractor needs a binding"));
        }
        let (text, corpus, page, hash, approval_digest, project_id) = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
            if let Some((reader, _)) = read
                && !reader.is_entity_readable_in(&txn, &asset)?
            {
                return Err(invalid("docs source no longer readable by scoped actor"));
            }
            let (text, corpus, page, hash, approval_digest, project_id) =
                self.deep_source_in(&txn, asset, owner.actor())?;
            if read.is_some_and(|(_, expected)| expected != hash) {
                return Err(invalid("docs source changed since authorized expansion"));
            }
            if let Some(receipt) = self.deep_receipt_in(&txn, asset)?
                && receipt.derivation.source_hash == hash
                && receipt.derivation.producer == extractor.binding()
            {
                self.require_live_deep_receipt(&txn, &receipt)?;
                return Ok(receipt);
            }
            (text, corpus, page, hash, approval_digest, project_id)
        };
        // Model work never holds the LMDB writer slot. Every quote is checked
        // against the corresponding unmodified source unit before admission.
        let mut prepared = Vec::new();
        for segment in docs_semantic_segments(&text) {
            for claim in extractor.extract(&segment)? {
                if claim.quote.trim().is_empty() || !segment.text.contains(&claim.quote) {
                    return Err(invalid("docs deep claim lacks a source quote"));
                }
                if claim.predicate == crate::claim::KEY_VALUE_PREDICATE {
                    return Err(invalid("keyed claim requires its owned write door"));
                }
                if prepared.len() == MAX_DEEP_CLAIMS {
                    return Err(invalid("docs deep claim ceiling exceeded"));
                }
                prepared.push((
                    segment.block.clone(),
                    segment.text.clone(),
                    source_hash(&segment.text),
                    claim,
                ));
            }
        }
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        if let Some((reader, _)) = read
            && !reader.is_entity_readable_in(&txn, &asset)?
        {
            return Err(invalid("docs source no longer readable by scoped actor"));
        }
        let (
            _,
            current_corpus,
            current_page,
            current_hash,
            current_approval_digest,
            current_project,
        ) = self.deep_source_in(&txn, asset, owner.actor())?;
        if (
            current_corpus.as_str(),
            current_page.as_str(),
            current_hash.as_str(),
        ) != (corpus.as_str(), page.as_str(), hash.as_str())
            || current_approval_digest != approval_digest
            || current_project != project_id
        {
            return Err(invalid("docs source changed during deep ingest; retry"));
        }
        if let Some(previous) = self.deep_receipt_in(&txn, asset)? {
            if previous.derivation.source_hash == hash
                && previous.derivation.producer == extractor.binding()
            {
                self.require_live_deep_receipt(&txn, &previous)?;
                return Ok(previous);
            }
            for reference in &previous.claim_refs {
                let id = EntityId::from_hex(reference)?;
                if self.get_claim_in_txn(&txn, &id)?.is_some_and(|body| {
                    body.lifecycle == crate::claim::ClaimLifecycleStatus::Active
                }) {
                    self.retract_claim_in_txn(&mut txn, &id, now)?;
                }
            }
        }
        let mut receipt = DocsDeepReceipt {
            derivation: DocsDerivationEnvelope {
                source_ref: asset.to_hex(),
                source_hash: hash.clone(),
                producer: extractor.binding().to_owned(),
                source: "imported".into(),
                derived_kind: "ner_claims".into(),
            },
            trigger,
            claim_refs: Vec::new(),
        };
        let actor = WriteActor::new(owner.actor(), EdgeActorClass::Human);
        let mut claims = Vec::new();
        for (block, segment_text, segment_hash, claim) in prepared {
            let chunk = self.deep_chunk_in(&txn, asset, &corpus, &page, &block, &segment_text)?;
            claims.push(PreparedDeepClaim {
                id: EntityId::now(),
                chunk,
                segment_hash,
                source_record_id: format!(
                    "{}:{hash}:{}:{}",
                    chunk.to_hex(),
                    extractor.binding(),
                    source_hash(&claim.quote)
                ),
                predicate: claim.predicate,
                value: claim.value,
            });
        }
        // Follow the import-batch Gate door: Proposed preflight, then the
        // approved transition under the stored, source-revision-bound bulk act.
        // Pending rows are transient in this writer txn and never reach a tray.
        for approval in [ClaimApprovalStatus::Proposed, ClaimApprovalStatus::Approved] {
            let mut builder = self.batch_in();
            for claim in &claims {
                let admission = super::ImportedEvidenceAdmission::proposed(
                    super::DOCS_EXPORT_SOURCE_ID,
                    claim.id,
                    super::ImportedEvidenceEntityResolution::subject(asset),
                    actor,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
                .with_approval(approval);
                let (candidate, envelope) = super::admission::imported_candidate(
                    &claim.predicate,
                    super::admission::json_to_msgpack_value(&claim.value),
                    &claim.source_record_id,
                    &admission,
                )?;
                let v = rmpv::Value::from;
                let rmpv::Value::Map(mut evidence) = super::admission::imported_evidence_value(
                    super::DOCS_EXPORT_SOURCE_ID,
                    &claim.source_record_id,
                ) else {
                    unreachable!("imported evidence is a map")
                };
                evidence.push((
                    v("derivation"),
                    rmpv::Value::Map(vec![
                        (v("source_ref"), rmpv::Value::from(claim.chunk.to_hex())),
                        (v("source_hash"), v(claim.segment_hash.as_str())),
                        (v("producer"), v(extractor.binding())),
                        (v("source"), v("imported")),
                        (v("derived_kind"), v("ner_claim")),
                        (v("approval_digest"), v(approval_digest.as_str())),
                    ]),
                ));
                builder = builder.claim_candidate(
                    &claim.id,
                    candidate
                        .with_scope(rmpv::Value::Map(vec![(
                            v("scopeProjectId"),
                            rmpv::Value::Binary(project_id.as_bytes().to_vec()),
                        )]))
                        .with_evidence(rmpv::Value::Map(evidence)),
                    &envelope,
                    admission.occurred,
                    admission.learned_at,
                );
            }
            builder.apply(&mut txn)?;
        }
        for claim in &claims {
            crate::ports::record_derived_edge_in_txn(
                &self.store,
                &mut txn,
                &claim.id,
                &claim.chunk,
            )?;
            // The dependency index is one hop, not recursive. Bind the root
            // asset too, so deleting it invalidates the derived claim directly.
            crate::ports::record_derived_edge_in_txn(&self.store, &mut txn, &claim.id, &asset)?;
            self.store
                .delete_pending_gate_consent_in_txn(&mut txn, &claim.id)?;
            receipt.claim_refs.push(claim.id.to_hex());
        }
        DEEP_RECEIPTS.put(&self.store, &mut txn, &HexId(asset), &receipt)?;
        txn.commit()?;
        Ok(receipt)
    }

    fn deep_chunk_in(
        &self,
        txn: &heed::RoTxn<'_>,
        asset: EntityId,
        corpus: &str,
        page: &str,
        block: &str,
        text: &str,
    ) -> Result<EntityId> {
        let extraction = super::docs_extraction_id(corpus, page, &format!("chunk:{block}"));
        let raw_id = DOCS_EXTRACTIONS
            .get_bytes(&self.store, txn, &extraction)?
            .ok_or_else(|| invalid("docs deep source chunk missing"))?;
        let id = EntityId::from_bytes(
            raw_id
                .as_slice()
                .try_into()
                .map_err(|_| invalid("corrupt docs deep chunk reference"))?,
        )?;
        let visibility =
            crate::ports::TombstoneStoreRead::port_deletion_state(&self.store, txn, &id)?;
        if visibility.deleted || visibility.stale {
            return Err(invalid("docs deep source chunk invalidated"));
        }
        let raw = self
            .get_raw_in(txn, &id)?
            .ok_or_else(|| invalid("docs deep source chunk deleted"))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("docs deep chunk header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_ASSET_TEXT {
            return Err(invalid("docs deep source chunk has wrong kind"));
        }
        let body: Value = rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| invalid("docs deep source chunk body invalid"))?;
        if body.get("text").and_then(Value::as_str) != Some(text)
            || body.get("source").and_then(Value::as_str) != Some("imported")
            || body.get("asset_ref").and_then(Value::as_str) != Some(asset.to_hex().as_str())
        {
            return Err(invalid("docs deep source chunk changed"));
        }
        Ok(id)
    }

    fn require_live_deep_receipt(
        &self,
        txn: &heed::RoTxn<'_>,
        receipt: &DocsDeepReceipt,
    ) -> Result<()> {
        for reference in &receipt.claim_refs {
            let id = EntityId::from_hex(reference)?;
            if crate::ports::stale_in_txn(&self.store, txn, &id)?
                || !self.get_claim_in_txn(txn, &id)?.is_some_and(|body| {
                    body.lifecycle == crate::claim::ClaimLifecycleStatus::Active
                })
            {
                return Err(invalid("docs deep receipt has invalidated claims"));
            }
        }
        Ok(())
    }

    fn deep_receipt_in(
        &self,
        txn: &heed::RoTxn<'_>,
        asset: EntityId,
    ) -> Result<Option<DocsDeepReceipt>> {
        DEEP_RECEIPTS
            .get_bytes(&self.store, txn, &HexId(asset))?
            .map(|raw| {
                serde_json::from_slice(&raw).map_err(|_| invalid("corrupt docs deep receipt"))
            })
            .transpose()
    }

    fn deep_source_in(
        &self,
        txn: &heed::RoTxn<'_>,
        asset: EntityId,
        owner: EntityId,
    ) -> Result<(String, String, String, String, String, EntityId)> {
        let raw = self.get_raw_in(txn, &asset)?.ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("docs asset header"))?;
        if header.entity_type != ENTITY_TYPE_ASSET {
            return Err(invalid("docs deep source must be an asset"));
        }
        let body: Value = rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| invalid("docs deep source body invalid"))?;
        let get = |field: &str| -> Result<String> {
            body.get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| invalid("docs deep source field missing"))
        };
        let text = get("text")?;
        let corpus = get("corpus")?;
        let project_id = EntityId::from_hex(&get("project_id")?)
            .map_err(|_| invalid("docs corpus PROJECT id invalid"))?;
        super::docs_import::require_docs_corpus_project(self, txn, project_id)?;
        let page = get("page_id")?;
        if get("source")? != "imported" {
            return Err(invalid("docs deep source is not imported"));
        }
        let hash = source_hash(&text);
        let ceiling: DeepCeiling = DEEP_CEILINGS
            .get_bytes(&self.store, txn, &HexId(asset))?
            .map(|raw| {
                serde_json::from_slice(&raw).map_err(|_| invalid("corrupt docs deep ceiling"))
            })
            .transpose()?
            .ok_or_else(|| invalid("docs deep import consent missing"))?;
        if !ceiling.allowed
            || ceiling.source_hash != hash
            || ceiling.owner != owner.to_hex()
            || ceiling.approval_digest.is_empty()
            || ceiling.project_id != project_id
        {
            return Err(invalid(
                "docs deep import ceiling or source revision refused",
            ));
        }
        let extraction = super::docs_extraction_id(&corpus, &page, "asset");
        if DOCS_EXTRACTIONS
            .get_bytes(&self.store, txn, &extraction)?
            .as_deref()
            != Some(asset.as_bytes().as_slice())
        {
            return Err(invalid("docs deep asset lacks imported identity"));
        }
        for segment in docs_semantic_segments(&text) {
            self.deep_chunk_in(txn, asset, &corpus, &page, &segment.block, &segment.text)?;
        }
        Ok((
            text,
            corpus,
            page,
            hash,
            ceiling.approval_digest,
            project_id,
        ))
    }
}
