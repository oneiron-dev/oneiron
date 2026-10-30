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
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};

mod review;
pub use review::{DocsDeepReview, DocsDeepReviewClaim};

/// The source segments one batch extracts before its claims are written in a
/// writer transaction of their own; other writers take turns between batches.
const DEEP_BATCH_SEGMENTS: usize = 32;

/// How long one deep-ingest call keeps starting batches. Past it the call
/// returns its receipt with the segment the next call resumes from.
const DEEP_INGEST_DEADLINE: Duration = Duration::from_secs(60);

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
    /// The first source segment no batch has extracted yet when the call's
    /// deadline passed; `None` once every segment has been. The next call
    /// for this revision and extractor resumes there.
    pub resume_segment: Option<usize>,
    /// The derived claims as the owner reviews them: one exact batch.
    pub review: DocsDeepReview,
}

pub(super) struct DeepApproval<'a> {
    pub(super) owner: EntityId,
    pub(super) digest: &'a str,
    pub(super) project_id: EntityId,
}

/// One extracted claim beside its segment's block, text and source hash.
type SegmentClaim = (String, String, String, DocsDeepClaim);

/// The source revision a deep ingest read, and one batch's segment span.
struct DeepBatch<'a> {
    corpus: &'a str,
    page: &'a str,
    hash: &'a str,
    approval_digest: &'a str,
    project_id: EntityId,
    start: usize,
    end: usize,
    segments: usize,
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

/// The whole ASSET body `facts` names, read from its file and checked: the
/// store-only half of the materializing row read, for a door with only
/// `&Store`. The put's own write transaction replaces the row, so no release
/// can run while it reads (FIX 5391).
fn asset_file_body_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    facts: &crate::store::AssetBodyFacts,
) -> Result<Vec<u8>> {
    let key = crate::store::body_key_row_in_txn(store, txn, &facts.blake3)?;
    crate::store::CheckedAssetBody::read_all(&store.body_dir()?, facts, key.as_ref())
}

/// Only the shared batch entity-put door calls this, before it stages a new
/// body. Classify under a read borrow, release that borrow, then invalidate
/// dependents in the same transaction as the replacement. `asset_file` is the
/// put's filed body, when `next` is its manifest rather than its bytes.
pub(crate) fn invalidate_docs_source_before_put(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    next: &[u8],
    asset_file: Option<crate::store::AssetBodyFacts>,
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
        // A file-plane ASSET's row holds its manifest, not its body: the
        // compare below reads the body's bytes (FIX 5391).
        let file_previous = match crate::store::asset_file_of_raw_in_txn(store, &*txn, id, &raw)? {
            Some(manifest) => Some(asset_file_body_in_txn(store, &*txn, &manifest.facts)?),
            None => None,
        };
        let previous = file_previous
            .as_deref()
            .unwrap_or(&raw[ENTITY_METADATA_HEADER_LEN..]);
        // A put that filed its body passes its manifest as `next`: the same
        // read. Only an ASSET files its body; any other kind holds its bytes.
        let file_next = match asset_file {
            Some(facts) if kind == ENTITY_TYPE_ASSET => {
                Some(asset_file_body_in_txn(store, &*txn, &facts)?)
            }
            _ => None,
        };
        let next = file_next.as_deref().unwrap_or(next);
        previous != next && docs_source_put_changes(store, txn, id, kind, previous, next)?
    };
    if changed {
        crate::ports::invalidate_source_in_txn(
            store,
            txn,
            id,
            crate::ports::DependentWalkDoor::ChangedDocsSource,
        )?;
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

/// Whether the import approved as `digest` wrote this revision of `asset`:
/// its ceiling row names that approval and the revision's source hash.
pub(super) fn deep_ceiling_names(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    asset: EntityId,
    digest: &str,
    text: &str,
) -> Result<bool> {
    let ceiling: Option<DeepCeiling> = DEEP_CEILINGS
        .get_bytes(&vault.store, txn, &HexId(asset))?
        .map(|raw| serde_json::from_slice(&raw).map_err(|_| invalid("corrupt docs deep ceiling")))
        .transpose()?;
    Ok(ceiling.is_some_and(|ceiling| {
        ceiling.approval_digest == digest && ceiling.source_hash == source_hash(text)
    }))
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
    ///
    /// Every valid claim the extractor finds is kept. Segments are extracted
    /// in batches of [`DEEP_BATCH_SEGMENTS`], each written in its own writer
    /// transaction with the receipt naming the next segment; once
    /// [`DEEP_INGEST_DEADLINE`] has passed no further batch starts, and a
    /// later call for the same revision and extractor resumes there.
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
        let started = Instant::now();
        let (text, corpus, page, hash, approval_digest, project_id, mut next) = {
            let txn = self.store.env.read_txn()?;
            let owner_actor = owner.revalidate_in_txn(self, &txn)?;
            if let Some((reader, _)) = read
                && !reader.is_entity_readable_in(&txn, &asset)?
            {
                return Err(invalid("docs source no longer readable by scoped actor"));
            }
            let (text, corpus, page, hash, approval_digest, project_id) =
                self.deep_source_in(&txn, asset, owner_actor)?;
            if read.is_some_and(|(_, expected)| expected != hash) {
                return Err(invalid("docs source changed since authorized expansion"));
            }
            let mut next = 0;
            if let Some(receipt) = self.deep_receipt_in(&txn, asset)?
                && receipt.derivation.source_hash == hash
                && receipt.derivation.producer == extractor.binding()
            {
                self.require_live_deep_receipt(&txn, &receipt)?;
                match receipt.resume_segment {
                    None => return Ok(receipt),
                    Some(resume) => next = resume,
                }
            }
            (text, corpus, page, hash, approval_digest, project_id, next)
        };
        let segments = docs_semantic_segments(&text);
        loop {
            let end = next.saturating_add(DEEP_BATCH_SEGMENTS).min(segments.len());
            // Model work never holds the LMDB writer slot. Every quote is
            // checked against the corresponding unmodified source unit first.
            let prepared =
                prepare_deep_claims(segments.get(next..end).unwrap_or_default(), extractor)?;
            let batch = DeepBatch {
                corpus: &corpus,
                page: &page,
                hash: &hash,
                approval_digest: &approval_digest,
                project_id,
                start: next,
                end,
                segments: segments.len(),
            };
            let receipt = self.write_deep_batch(
                owner,
                asset,
                trigger,
                extractor.binding(),
                now,
                read,
                &batch,
                prepared,
            )?;
            match receipt.resume_segment {
                Some(resume) if started.elapsed() < DEEP_INGEST_DEADLINE => next = resume,
                _ => return Ok(receipt),
            }
        }
    }

    /// Writes one batch's claims in a writer transaction of its own, after
    /// checking the source revision is still the one extracted, and stores
    /// the receipt with the segment the next batch starts at.
    #[expect(
        clippy::too_many_arguments,
        reason = "owner proof, asset, trigger, producer, write time, scoped reader, batch span and its extracted claims are distinct inputs"
    )]
    fn write_deep_batch(
        &self,
        owner: &AuthenticatedOwner,
        asset: EntityId,
        trigger: DocsDeepTrigger,
        producer: &str,
        now: u64,
        read: Option<(&crate::claim::ScopedRead<'_>, &str)>,
        batch: &DeepBatch<'_>,
        prepared: Vec<SegmentClaim>,
    ) -> Result<DocsDeepReceipt> {
        let mut txn = self.store.env.write_txn()?;
        let owner_actor = owner.revalidate_in_txn(self, &txn)?;
        if let Some((reader, _)) = read
            && !reader.is_entity_readable_in(&txn, &asset)?
        {
            return Err(invalid("docs source no longer readable by scoped actor"));
        }
        let (_, corpus, page, hash, approval_digest, project_id) =
            self.deep_source_in(&txn, asset, owner_actor)?;
        if (
            corpus.as_str(),
            page.as_str(),
            hash.as_str(),
            approval_digest.as_str(),
        ) != (batch.corpus, batch.page, batch.hash, batch.approval_digest)
            || project_id != batch.project_id
        {
            return Err(invalid("docs source changed during deep ingest; retry"));
        }
        let mut receipt = match self.deep_receipt_in(&txn, asset)? {
            Some(previous)
                if previous.derivation.source_hash == batch.hash
                    && previous.derivation.producer == producer =>
            {
                match previous.resume_segment {
                    // Another call finished this revision meanwhile.
                    None => {
                        self.require_live_deep_receipt(&txn, &previous)?;
                        return Ok(previous);
                    }
                    Some(resume) if resume == batch.start => previous,
                    Some(_) => return Err(invalid("docs deep ingest moved meanwhile; retry")),
                }
            }
            previous => {
                if batch.start != 0 {
                    return Err(invalid("docs deep receipt replaced meanwhile; retry"));
                }
                if let Some(previous) = previous {
                    for reference in &previous.claim_refs {
                        let id = EntityId::from_hex(reference)?;
                        if self.get_claim_in_txn(&txn, &id)?.is_some_and(|body| {
                            body.lifecycle == crate::claim::ClaimLifecycleStatus::Active
                        }) {
                            self.retract_claim_in_txn(&mut txn, &id, now)?;
                        }
                    }
                }
                DocsDeepReceipt {
                    derivation: DocsDerivationEnvelope {
                        source_ref: asset.to_hex(),
                        source_hash: batch.hash.to_owned(),
                        producer: producer.to_owned(),
                        source: "imported".into(),
                        derived_kind: "ner_claims".into(),
                    },
                    trigger,
                    claim_refs: Vec::new(),
                    resume_segment: Some(0),
                    review: DocsDeepReview::proposed(),
                }
            }
        };
        let mut claims = Vec::with_capacity(prepared.len());
        let mut edges = Vec::with_capacity(prepared.len());
        for (block, segment_text, segment_hash, claim) in prepared {
            let chunk =
                self.deep_chunk_in(&txn, asset, batch.corpus, batch.page, &block, &segment_text)?;
            let id = EntityId::now();
            edges.push((id, chunk));
            claims.push(DocsDeepReviewClaim {
                claim_ref: id.to_hex(),
                chunk_ref: chunk.to_hex(),
                segment_hash,
                source_record_id: format!(
                    "{}:{}:{producer}:{}",
                    chunk.to_hex(),
                    batch.hash,
                    source_hash(&claim.quote)
                ),
                predicate: claim.predicate,
                value: claim.value,
                learned_at: now,
            });
        }
        let write = review::DeepWrite {
            asset,
            project_id,
            approval_digest: batch.approval_digest,
            producer,
            actor: WriteActor::new(owner_actor, EdgeActorClass::Human),
        };
        self.admit_deep_claims_in_txn(&mut txn, owner_actor, &write, &mut receipt.review, &claims)?;
        self.persist_deep_claim_dependencies(&mut txn, &edges, asset, &mut receipt)?;
        receipt.resume_segment = (batch.end < batch.segments).then_some(batch.end);
        DEEP_RECEIPTS.put(&self.store, &mut txn, &HexId(asset), &receipt)?;
        txn.commit()?;
        Ok(receipt)
    }

    /// Binds each admitted claim to its chunk and its root asset in the
    /// dependency index and names it on the receipt.
    fn persist_deep_claim_dependencies(
        &self,
        txn: &mut heed::RwTxn<'_>,
        claims: &[(EntityId, EntityId)],
        asset: EntityId,
        receipt: &mut DocsDeepReceipt,
    ) -> Result<()> {
        for (claim, chunk) in claims {
            crate::ports::record_derived_edge_in_txn(&self.store, txn, claim, chunk)?;
            // The dependency index is one hop, not recursive. Bind the root
            // asset too, so deleting it invalidates the derived claim directly.
            crate::ports::record_derived_edge_in_txn(&self.store, txn, claim, &asset)?;
            receipt.claim_refs.push(claim.to_hex());
        }
        Ok(())
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
        // The owner's decline retracted a declined batch's claims; it stands.
        if receipt.review.decision == ClaimApprovalStatus::Rejected {
            return Ok(());
        }
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

/// Every claim the extractor finds in `segments`, each checked against its
/// unmodified source unit, with its block, source text and source hash.
fn prepare_deep_claims(
    segments: &[DocsSegment],
    extractor: &dyn DocsDeepExtractor,
) -> Result<Vec<SegmentClaim>> {
    let mut prepared = Vec::new();
    for segment in segments {
        for claim in extractor.extract(segment)? {
            if claim.quote.trim().is_empty() || !segment.text.contains(&claim.quote) {
                return Err(invalid("docs deep claim lacks a source quote"));
            }
            if claim.predicate == crate::claim::KEY_VALUE_PREDICATE {
                return Err(invalid("keyed claim requires its owned write door"));
            }
            prepared.push((
                segment.block.clone(),
                segment.text.clone(),
                source_hash(&segment.text),
                claim,
            ));
        }
    }
    Ok(prepared)
}
