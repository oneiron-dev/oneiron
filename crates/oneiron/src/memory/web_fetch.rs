//! Actor-bound web acquisition and import. Network work never holds a writer.
use crate::ingest::{
    ImportedEvidenceAdmission, ImportedEvidenceEntityResolution,
    admit_imported_evidence_in_content, docs_semantic_segments,
};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM};
use crate::web_fetch::{
    CrawlResult, FetchResult, WebCrawlRequest, WebFetchError, WebFetchRequest, WebFetcher,
};
use crate::{EntityId, TimeRange, WriteActor};

impl Memory<'_> {
    /// Fetches one page through the host's ladder, then imports the witnessed
    /// bytes through the same actor-bound candidate door as other imports.
    pub fn fetch_web_through(
        &self,
        fetcher: &WebFetcher,
        input: WebFetchRequest,
    ) -> MemoryResult<FetchResult> {
        let page = fetcher
            .fetch(&input.url, self.vault.now_recorded_at())
            .map_err(fetch_error)?;
        self.import_web_pages(std::slice::from_ref(&page))?;
        Ok(page)
    }

    /// Acquires first, then atomically imports every successful page. Failed
    /// crawl pages remain the crawler's own typed failures and completion.
    pub fn crawl_web_through(
        &self,
        fetcher: &WebFetcher,
        input: WebCrawlRequest,
    ) -> MemoryResult<CrawlResult> {
        let request = input
            .into_request(self.vault.now_recorded_at())
            .map_err(fetch_error)?;
        let crawl = fetcher.crawl(request).map_err(fetch_error)?;
        self.import_web_pages(&crawl.pages)?;
        Ok(crawl)
    }

    fn import_web_pages(&self, pages: &[FetchResult]) -> MemoryResult<()> {
        self.vault.ensure_text_index_trusted()?;
        let writer = WriteActor::new(self.actor, self.actor_class);
        let mut sources = Vec::new();
        self.with_actor_content_write_txn(|content| {
            for page in pages {
                // The caller's own immutable source revision: a retry reuses
                // the same source, chunks and claim without reproposing review.
                let asset = web_id(writer, page, "asset")?;
                let claim = web_id(writer, page, "claim")?;
                let occurred = TimeRange {
                    start: page.fetched_at(),
                    end: page.fetched_at(),
                };
                for id in [asset, claim] {
                    if self
                        .vault
                        .local_hard_delete_marker_exists_in_txn(content.read(), &id)?
                    {
                        return Err(MemoryError::new(
                            crate::memory::MEMORY_CODE_FORBIDDEN,
                            "an erased web source revision cannot be recreated",
                            &[],
                        ));
                    }
                }
                let source = serde_json::json!({
                    "source": "imported",
                    "source_id": "web-fetch",
                    "page": page,
                });
                let data = rmp_serde::to_vec_named(&source)
                    .map_err(|_| MemoryError::bad_request("web source encoding"))?;
                match self.vault.get_entity_type_in_txn(content.read(), &asset)? {
                    None => content.apply_batch(
                        self.vault
                            .batch_in()
                            .put(
                                &asset,
                                ENTITY_TYPE_ASSET,
                                occurred,
                                page.fetched_at(),
                                &data,
                            )
                            .made_by(
                                &asset,
                                RowBirth::written(
                                    writer,
                                    MadeByClass::of_writer(self.actor_class),
                                    "web-fetch",
                                    &[],
                                    &[page.markdown().as_bytes()],
                                    page.fetched_at(),
                                ),
                            ),
                    )?,
                    Some(ENTITY_TYPE_ASSET) => {
                        let raw = self
                            .vault
                            .get_raw_in(content.read(), &asset)?
                            .ok_or_else(|| MemoryError::not_found("web source missing"))?;
                        let stored: serde_json::Value =
                            rmp_serde::from_slice(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                                .map_err(|_| {
                                    MemoryError::bad_request("invalid stored web source")
                                })?;
                        if stored["source"] != source["source"]
                            || stored["source_id"] != source["source_id"]
                            || stored["page"]["canonical_url"] != page.canonical_url()
                            || stored["page"]["content_hash"] != page.content_hash()
                            || stored["page"]["markdown"] != page.markdown()
                        {
                            return Err(MemoryError::bad_request(
                                "web source revision does not match",
                            ));
                        }
                    }
                    Some(_) => {
                        return Err(MemoryError::bad_request("web source id has another kind"));
                    }
                }
                for segment in docs_semantic_segments(page.markdown()) {
                    let chunk = web_id(writer, page, &format!("chunk:{}", segment.block))?;
                    if self
                        .vault
                        .local_hard_delete_marker_exists_in_txn(content.read(), &chunk)?
                    {
                        return Err(MemoryError::new(
                            crate::memory::MEMORY_CODE_FORBIDDEN,
                            "an erased web text revision cannot be recreated",
                            &[],
                        ));
                    }
                    let data = rmp_serde::to_vec_named(&serde_json::json!({
                        "text": segment.text,
                        "source": "imported",
                        "asset_ref": asset.to_hex(),
                        "content_hash": page.content_hash(),
                        "section": segment.section,
                    }))
                    .map_err(|_| MemoryError::bad_request("web text encoding"))?;
                    match self.vault.get_entity_type_in_txn(content.read(), &chunk)? {
                        Some(ENTITY_TYPE_ASSET_TEXT) => {
                            let raw = self
                                .vault
                                .get_raw_in(content.read(), &chunk)?
                                .ok_or_else(|| MemoryError::not_found("web text missing"))?;
                            if raw[crate::batch::ENTITY_METADATA_HEADER_LEN..] != data {
                                return Err(MemoryError::bad_request(
                                    "web text revision does not match",
                                ));
                            }
                            continue;
                        }
                        Some(_) => {
                            return Err(MemoryError::bad_request("web chunk id has another kind"));
                        }
                        None => {}
                    }
                    content.apply_batch(
                        self.vault
                            .batch_in()
                            .asset_text_birth(
                                &chunk,
                                occurred,
                                page.fetched_at(),
                                &data,
                                &[(asset, 1.0)],
                            )
                            .text(&chunk, &[("text", segment.text.as_str())])
                            .made_by(
                                &chunk,
                                RowBirth::written(
                                    writer,
                                    MadeByClass::of_writer(self.actor_class),
                                    "web-fetch.chunk",
                                    &[asset],
                                    &[segment.text.as_bytes()],
                                    page.fetched_at(),
                                ),
                            ),
                    )?;
                }
                let value = rmpv::Value::Map(vec![
                    ("canonical_url".into(), page.canonical_url().into()),
                    ("content_hash".into(), page.content_hash().into()),
                    ("source_ref".into(), asset.to_hex().into()),
                ]);
                match self.vault.get_entity_type_in_txn(content.read(), &claim)? {
                    Some(ENTITY_TYPE_CLAIM) => {
                        // A prior approval or decline is not reset by a refetch.
                        let body = self
                            .vault
                            .get_claim_in_txn(content.read(), &claim)?
                            .ok_or_else(|| MemoryError::not_found("web claim missing"))?;
                        if body.predicate != "web.page"
                            || body.subject != crate::claim::ClaimSubject::Entity(asset)
                            || body.source != Some(crate::claim::ClaimSource::Imported)
                            || body.value != value
                        {
                            return Err(MemoryError::bad_request(
                                "web claim revision does not match",
                            ));
                        }
                        crate::memory::guard_existing_claim_in_txn(
                            self.vault,
                            content.read(),
                            writer,
                            claim,
                        )?;
                    }
                    Some(_) => {
                        return Err(MemoryError::bad_request("web claim id has another kind"));
                    }
                    None => {
                        let admission = ImportedEvidenceAdmission::proposed(
                            "web-fetch",
                            claim,
                            ImportedEvidenceEntityResolution::subject(asset),
                            writer,
                            occurred,
                            page.fetched_at(),
                        );
                        admit_imported_evidence_in_content(
                            self.vault,
                            content,
                            "web.page",
                            value,
                            &format!("{}@{}", page.canonical_url(), page.content_hash()),
                            &admission,
                        )?;
                    }
                }
                sources.push(asset);
            }
            Ok(())
        })?;
        self.produced_from(sources);
        Ok(())
    }
}

/// Separate ids per writer, canonical URL and content revision. No source can
/// overwrite another writer's acquisition or borrow their review decision.
fn web_id(writer: WriteActor, page: &FetchResult, slot: &str) -> MemoryResult<EntityId> {
    let mut hash = blake3::Hasher::new_derive_key("oneiron web import revision v1");
    for part in [
        writer.entity_ref().to_hex(),
        writer.actor_class().gate_actor_class().to_owned(),
        page.canonical_url().to_owned(),
        page.content_hash().to_owned(),
        slot.to_owned(),
    ] {
        hash.update(&(part.len() as u64).to_le_bytes());
        hash.update(part.as_bytes());
    }
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    EntityId::from_bytes(id).map_err(MemoryError::from)
}

fn fetch_error(error: WebFetchError) -> MemoryError {
    match error {
        error @ (WebFetchError::InvalidUrl { .. }
        | WebFetchError::UnsupportedScheme { .. }
        | WebFetchError::CredentialsInUrl { .. }
        | WebFetchError::InvalidPageBudget) => MemoryError::bad_request(error.to_string()),
        // A managed node's typed refusal (SCAN C447): its message names
        // `hosted_infrastructure`.
        error @ WebFetchError::HostedInfrastructure { .. } => MemoryError::new(
            crate::memory::MEMORY_CODE_FORBIDDEN,
            error.to_string(),
            &[
                "A hosted node never fetches the infrastructure it runs on; a self-hosted node fetches this address.",
            ],
        ),
        other => MemoryError::new("WEB_FETCH_FAILED", other.to_string(), &[]),
    }
}
