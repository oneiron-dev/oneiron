//! Atomic bulk consent and thin-star docs membership. Derivations never rewrite source evidence.
use super::{DocsExport, DocsSegment, docs_extraction_id, docs_semantic_segments};
use crate::batch::{BatchOp, apply_ops};
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ComposedEffect, EffectFacts,
    GrantBound,
};
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DocsImportCeiling {
    pub max_pages: usize,
    pub max_bytes: usize,
    pub allow_derivations: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsDerivationEnvelope {
    pub source_ref: String,
    pub source_hash: String,
    pub producer: String,
    pub source: String,
    pub derived_kind: String,
}
pub trait DocsInjectionClassifier {
    fn binding(&self) -> &str;
    fn classify(&self, source: &str) -> Result<Value>;
}
pub trait DocsSummaryModel {
    fn binding(&self) -> &str;
    fn summarize(&self, segment: &DocsSegment) -> Result<String>;
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsImportReceipt {
    pub approval_digest: String,
    pub asset_refs: Vec<String>,
    pub chunk_refs: Vec<String>,
    pub summary_refs: Vec<String>,
    pub annotation_refs: Vec<String>,
    pub fingerprints: Vec<(String, super::BlobBirthDecision)>,
}
fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
fn encoded(value: &Value) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid("docs encoding failed"))
}
fn put(id: EntityId, kind: u8, body: Value, now: u64) -> Result<BatchOp> {
    Ok(BatchOp::Put {
        id,
        entity_type: kind,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        data: encoded(&body)?,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    })
}
fn edge(src: EntityId, tgt: EntityId) -> BatchOp {
    BatchOp::Edge {
        src,
        kind: crate::EdgeKind::DerivedFrom,
        tgt,
        weight: 1.0,
        vad: crate::Vad::NEUTRAL,
    }
}
fn existing_ref(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    extraction: &str,
) -> Result<Option<EntityId>> {
    let key = format!("docs-extraction:v1:{extraction}");
    vault
        .store
        .vault_meta
        .get(txn, key.as_bytes())?
        .map(|raw| {
            EntityId::from_bytes(
                raw.as_ref()
                    .try_into()
                    .map_err(|_| invalid("corrupt docs extraction reference"))?,
            )
        })
        .transpose()
}
fn stable_ref(vault: &Vault, txn: &mut heed::RwTxn<'_>, extraction: &str) -> Result<EntityId> {
    let key = format!("docs-extraction:v1:{extraction}");
    if let Some(raw) = vault.store.vault_meta.get(txn, key.as_bytes())? {
        let bytes = raw
            .as_ref()
            .try_into()
            .map_err(|_| invalid("corrupt docs extraction reference"))?;
        return EntityId::from_bytes(bytes);
    }
    let id = EntityId::now();
    vault
        .store
        .vault_meta
        .put(txn, key.as_bytes(), id.as_bytes())?;
    Ok(id)
}
impl Vault {
    /// Build the exact consent-once request before any source or model output is stored.
    pub fn docs_import_effect(
        &self,
        owner: &AuthenticatedOwner,
        request_id: EntityId,
        docs: &DocsExport,
        ceiling: DocsImportCeiling,
    ) -> Result<ComposedEffect> {
        docs.validate()
            .map_err(|_| invalid("invalid docs export"))?;
        let bytes = serde_json::to_vec(docs).map_err(|_| invalid("docs export encoding"))?;
        if docs.pages.len() > ceiling.max_pages || bytes.len() > ceiling.max_bytes {
            return Err(invalid("docs import exceeds consent ceiling"));
        }
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let bound = GrantBound::action(
            ActorBound::new(owner.actor().to_hex())?,
            ActionClass::new("docs.import")?,
            ActionEnvelope::new([
                format!("corpus:{}", docs.corpus_id),
                format!("request:{}", request_id.to_hex()),
                format!("content:{hash}"),
                format!(
                    "ceiling:{}:{}:{}",
                    ceiling.max_pages, ceiling.max_bytes, ceiling.allow_derivations
                ),
            ])?,
        )?;
        ComposedEffect::new(EffectFacts::new("docs.import")?).with_action_requirement(bound)
    }

    /// One exact approve-once covers the entire batch and its explicit derivation ceiling.
    /// Classifier is off by default (`None`); it produces an annotation, never a wall or edit.
    pub fn ingest_docs_export(
        &self,
        owner: &AuthenticatedOwner,
        request_id: EntityId,
        docs: &DocsExport,
        ceiling: DocsImportCeiling,
        summary: Option<&dyn DocsSummaryModel>,
        classifier: Option<&dyn DocsInjectionClassifier>,
        now: u64,
    ) -> Result<DocsImportReceipt> {
        if !ceiling.allow_derivations && (summary.is_some() || classifier.is_some()) {
            return Err(invalid("derived docs output exceeds consent ceiling"));
        }
        let digest = self
            .docs_import_effect(owner, request_id, docs, ceiling)?
            .digest();
        {
            let txn = self.store.env.read_txn()?;
            if crate::consent::approve_once_authorization_in_txn(&self.store, &txn, &digest)?
                .is_none()
            {
                return Err(invalid("docs import requires bulk consent"));
            }
        }
        // Optional model calls never hold the LMDB writer slot. Consent is rechecked at commit.
        let mut prepared = Vec::new();
        for page in &docs.pages {
            let predicted = {
                let read = self.store.env.read_txn()?;
                let key = format!(
                    "docs-extraction:v1:{}",
                    docs_extraction_id(&docs.corpus_id, &page.page_id, "asset")
                );
                match self.store.vault_meta.get(&read, key.as_bytes())? {
                    Some(bytes) => {
                        let id = EntityId::from_bytes(
                            bytes
                                .as_ref()
                                .try_into()
                                .map_err(|_| invalid("corrupt docs asset mapping"))?,
                        )?;
                        super::fingerprint::prepare_blob_birth(
                            &self.store,
                            &read,
                            &id,
                            page.text.as_bytes(),
                            &page.text,
                        )?
                        .decision
                    }
                    None => {
                        super::fingerprint::prepare_new_blob_birth(page.text.as_bytes(), &page.text)
                            .decision
                    }
                }
            };
            let changed = match &predicted {
                super::BlobBirthDecision::Unchanged(_) => Vec::new(),
                super::BlobBirthDecision::Changed { blocks, .. } => blocks.clone(),
            };
            let segments = docs_semantic_segments(&page.text);
            let summaries = segments
                .iter()
                .map(|segment| {
                    if changed.contains(&segment.block) {
                        summary.map(|model| model.summarize(segment)).transpose()
                    } else {
                        Ok(None)
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            let annotation = if matches!(predicted, super::BlobBirthDecision::Unchanged(_)) {
                None
            } else {
                classifier
                    .map(|model| model.classify(&page.text))
                    .transpose()?
            };
            prepared.push((page, segments, summaries, annotation, predicted));
        }
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let authorization =
            crate::consent::approve_once_authorization_in_txn(&self.store, &txn, &digest)?
                .ok_or_else(|| invalid("docs consent already consumed"))?;
        let mut receipt = DocsImportReceipt {
            approval_digest: digest.to_hex(),
            asset_refs: Vec::new(),
            chunk_refs: Vec::new(),
            summary_refs: Vec::new(),
            annotation_refs: Vec::new(),
            fingerprints: Vec::new(),
        };
        let mut ops = Vec::new();
        let mut fingerprint_updates = Vec::new();
        let mut membership_updates = Vec::new();
        for (page, segments, summaries, annotation, predicted) in prepared {
            let asset = stable_ref(
                self,
                &mut txn,
                &docs_extraction_id(&docs.corpus_id, &page.page_id, "asset"),
            )?;
            receipt.asset_refs.push(asset.to_hex());
            let fingerprint = super::fingerprint::prepare_blob_birth(
                &self.store,
                &txn,
                &asset,
                page.text.as_bytes(),
                &page.text,
            )?;
            if fingerprint.decision != predicted {
                return Err(invalid("docs fingerprint moved during derivation; retry"));
            }
            let changed_blocks = match &fingerprint.decision {
                super::BlobBirthDecision::Changed { blocks, .. } => blocks.clone(),
                _ => Vec::new(),
            };
            receipt
                .fingerprints
                .push((asset.to_hex(), fingerprint.decision.clone()));
            let unchanged = matches!(fingerprint.decision, super::BlobBirthDecision::Unchanged(_));
            fingerprint_updates.push((asset, fingerprint));
            ops.push(put(asset,crate::registry::ENTITY_TYPE_ASSET,json!({"corpus":docs.corpus_id,"page_id":page.page_id,"path":page.path,"text":page.text,"registry":docs.registry,"source":"imported"}),now)?);
            if unchanged {
                continue;
            }
            let membership_key = format!("docs-membership:v1:{}", asset.to_hex());
            let previous_members: Vec<String> = self
                .store
                .vault_meta
                .get(&txn, membership_key.as_bytes())?
                .map(|raw| {
                    serde_json::from_slice(&raw).map_err(|_| invalid("corrupt docs membership"))
                })
                .transpose()?
                .unwrap_or_default();
            let mut members = std::collections::BTreeSet::new();
            for (segment, summary_text) in segments.iter().zip(summaries) {
                let chunk = stable_ref(
                    self,
                    &mut txn,
                    &docs_extraction_id(
                        &docs.corpus_id,
                        &page.page_id,
                        &format!("chunk:{}", segment.block),
                    ),
                )?;
                members.insert(chunk.to_hex());
                if !changed_blocks.contains(&segment.block) {
                    if let Some(id) = existing_ref(
                        self,
                        &txn,
                        &docs_extraction_id(
                            &docs.corpus_id,
                            &page.page_id,
                            &format!("summary:{}", segment.block),
                        ),
                    )? {
                        members.insert(id.to_hex());
                    }
                    continue;
                }
                receipt.chunk_refs.push(chunk.to_hex());
                ops.push(put(chunk,crate::registry::ENTITY_TYPE_ASSET_TEXT,json!({"text":segment.text,"source":"imported","asset_ref":asset.to_hex(),"section":segment.section}),now)?);
                ops.push(BatchOp::Text {
                    id: chunk,
                    fields: vec![("text".into(), segment.text.clone())],
                });
                ops.push(edge(chunk, asset));
                if let Some(text) = summary_text {
                    let model = summary.expect("summary output requires model");
                    let id = stable_ref(
                        self,
                        &mut txn,
                        &docs_extraction_id(
                            &docs.corpus_id,
                            &page.page_id,
                            &format!("summary:{}", segment.block),
                        ),
                    )?;
                    let envelope = DocsDerivationEnvelope {
                        source_ref: chunk.to_hex(),
                        source_hash: blake3::hash(segment.text.as_bytes()).to_hex().to_string(),
                        producer: model.binding().to_owned(),
                        source: "imported".into(),
                        derived_kind: "summary".into(),
                    };
                    ops.push(put(
                        id,
                        crate::registry::ENTITY_TYPE_SUMMARY,
                        json!({"text":text,"derivation":envelope}),
                        now,
                    )?);
                    ops.push(BatchOp::Text {
                        id,
                        fields: vec![("text".into(), text)],
                    });
                    ops.push(edge(id, chunk));
                    members.insert(id.to_hex());
                    receipt.summary_refs.push(id.to_hex());
                }
            }
            for prior in previous_members {
                if !members.contains(&prior) {
                    ops.push(BatchOp::Delete {
                        id: EntityId::from_hex(&prior)?,
                    });
                }
            }
            membership_updates.push((membership_key, members));
            if let Some(annotation) = annotation {
                let model = classifier.expect("annotation requires classifier");
                let envelope = DocsDerivationEnvelope {
                    source_ref: asset.to_hex(),
                    source_hash: blake3::hash(page.text.as_bytes()).to_hex().to_string(),
                    producer: model.binding().to_owned(),
                    source: "imported".into(),
                    derived_kind: "injection_classification".into(),
                };
                let mut data = json!({"derivation":envelope,"annotation":annotation});
                if crate::batch::export::redact_credentials(&mut data) {
                    return Err(invalid("credential-shaped classifier annotation"));
                }
                let key = format!(
                    "docs-annotation:v1:{}:{}",
                    asset.to_hex(),
                    request_id.to_hex()
                );
                self.store.vault_meta.put(
                    &mut txn,
                    key.as_bytes(),
                    &serde_json::to_vec(&data).map_err(|_| invalid("docs annotation encode"))?,
                )?;
                receipt.annotation_refs.push(key);
            }
        }
        for op in &ops {
            if let BatchOp::Put {
                id, entity_type, ..
            } = op
            {
                if self
                    .store
                    .entities
                    .get(&txn, id.as_bytes())?
                    .is_some_and(|raw| {
                        crate::batch::EntityMetadataHeader::parse(&raw)
                            .is_none_or(|header| header.entity_type != *entity_type)
                    })
                {
                    return Err(invalid("docs extraction id occupied by another kind"));
                }
            }
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut txn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        for (asset, fingerprint) in fingerprint_updates {
            fingerprint.persist(&self.store, &mut txn, &asset)?;
        }
        for (key, members) in membership_updates {
            self.store.vault_meta.put(
                &mut txn,
                key.as_bytes(),
                &serde_json::to_vec(&members).map_err(|_| invalid("docs membership encode"))?,
            )?;
        }
        crate::consent::spend_approve_once_in_txn(&self.store, &mut txn, &authorization)?;
        txn.commit()?;
        Ok(receipt)
    }
    pub fn docs_annotation(&self, reference: &str) -> Result<Option<Value>> {
        if !reference.starts_with("docs-annotation:v1:") {
            return Err(invalid("not a docs annotation reference"));
        }
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, reference.as_bytes())?
            .map(|raw| serde_json::from_slice(&raw).map_err(|_| invalid("corrupt docs annotation")))
            .transpose()
    }
}
