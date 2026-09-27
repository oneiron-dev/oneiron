use super::*;
use crate::error::Result;
use crate::ports::DependencyIndex;
use crate::{EntityId, TimeRange};
use serde_json::json;
struct Summary;
impl DocsSummaryModel for Summary {
    fn binding(&self) -> &str {
        "fixture.summary.v1"
    }
    fn summarize(&self, segment: &DocsSegment) -> Result<String> {
        Ok(segment
            .text
            .lines()
            .next()
            .unwrap_or_default()
            .split(" describes")
            .next()
            .unwrap_or_default()
            .to_owned())
    }
}
struct Classifier;
impl DocsInjectionClassifier for Classifier {
    fn binding(&self) -> &str {
        "fixture.injection.v1"
    }
    fn classify(&self, _: &str) -> Result<serde_json::Value> {
        Ok(json!({"label":"suspected_injection"}))
    }
}
fn field<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    match value {
        rmpv::Value::Map(entries) => entries
            .iter()
            .find_map(|(name, value)| (name.as_str() == Some(key)).then_some(value)),
        _ => None,
    }
}

struct FalseQuote;
impl DocsDeepExtractor for FalseQuote {
    fn binding(&self) -> &str {
        "fixture.false-quote"
    }
    fn extract(&self, _: &DocsSegment) -> Result<Vec<DocsDeepClaim>> {
        Ok(vec![DocsDeepClaim {
            predicate: "docs.topic".into(),
            value: json!("bad"),
            quote: "not in source".into(),
        }])
    }
}

fn document() -> DocsExport {
    DocsExport {
        corpus_id: "manual".into(),
        registry: json!({"rows":[]}),
        pages: vec![DocsPage {
            page_id: "stable-page".into(),
            path: "old/path.md".into(),
            text: "# Gravity\n\nGravity describes attraction.".into(),
        }],
    }
}
fn deep_fixture() -> Result<(
    tempfile::TempDir,
    crate::Vault,
    crate::consent::AuthenticatedOwner,
    DocsExport,
    DocsImportCeiling,
    DocsImportReceipt,
)> {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner =
        vault.authenticate_owner(person, "owner", true, crate::store::GateDecisionId::now())?;
    let doc = document();
    let ceiling = DocsImportCeiling {
        max_pages: 2,
        max_bytes: 10_000,
        allow_derivations: true,
    };
    let receipt = approved_docs_import(&vault, &owner, &doc, ceiling, 2)?;
    Ok((dir, vault, owner, doc, ceiling, receipt))
}

fn approved_docs_import(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    doc: &DocsExport,
    ceiling: DocsImportCeiling,
    now: u64,
) -> Result<DocsImportReceipt> {
    let request = EntityId::now();
    vault.approve_once(
        owner,
        vault
            .docs_import_effect(owner, request, doc, ceiling)?
            .digest(),
    )?;
    vault.ingest_docs_export(owner, request, doc, ceiling, None, None, now)
}

struct MultiNer;
impl DocsDeepExtractor for MultiNer {
    fn binding(&self) -> &str {
        "fixture.multi.ner"
    }
    fn extract(&self, segment: &DocsSegment) -> Result<Vec<DocsDeepClaim>> {
        Ok(vec![DocsDeepClaim {
            predicate: "docs.topic".into(),
            value: json!(segment.section),
            quote: segment.text.clone(),
        }])
    }
}

struct CallbackNer<F>(F);
impl<F: Fn(&DocsSegment) -> Result<()>> DocsDeepExtractor for CallbackNer<F> {
    fn binding(&self) -> &str {
        "fixture.callback.ner"
    }
    fn extract(&self, segment: &DocsSegment) -> Result<Vec<DocsDeepClaim>> {
        (self.0)(segment)?;
        Ok(vec![DocsDeepClaim {
            predicate: "docs.topic".into(),
            value: json!("gravity"),
            quote: segment.text.clone(),
        }])
    }
}

fn grant_core_read(vault: &crate::Vault, actor_ref: &str) -> Result<()> {
    use rmpv::Value;
    let default = crate::gate::default_policy_manifest();
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut default.as_slice()).unwrap() else {
        panic!("default policy manifest is a map");
    };
    entries.push((
        Value::from("scoped_grants"),
        Value::Array(vec![Value::Map(vec![
            (Value::from("actor_ref"), Value::from(actor_ref)),
            (Value::from("effector"), Value::from("core:read")),
            (
                Value::from("scope"),
                crate::federation::scope_codec::encode_scope_value(
                    &crate::federation::scope_codec::read_preset(),
                )?,
            ),
            (Value::from("receipt_required"), Value::Boolean(false)),
        ])]),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}
#[test]
fn docs_registry_thin_star_ids_do_not_depend_on_export_path() {
    let mut doc = document();
    let before = INGEST_SOURCE_REGISTRY
        .normalize(DOCS_EXPORT_SOURCE_ID, &serde_json::to_string(&doc).unwrap())
        .unwrap();
    doc.pages[0].path = "new/path.md".into();
    let after = INGEST_SOURCE_REGISTRY
        .normalize(DOCS_EXPORT_SOURCE_ID, &serde_json::to_string(&doc).unwrap())
        .unwrap();
    assert_eq!(before.records, after.records);
    assert!(before.claims.is_empty());
    assert!(
        before
            .entities
            .iter()
            .any(|e| e.entity_type == crate::registry::ENTITY_TYPE_ASSET)
    );
    assert!(
        before
            .entities
            .iter()
            .any(|e| e.entity_type == crate::registry::ENTITY_TYPE_ASSET_TEXT)
    );
}
#[test]
fn one_bulk_consent_lands_refs_derived_labels_and_summary_first_expansion() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let document = document();
    let request = EntityId::now();
    let ceiling = DocsImportCeiling {
        max_pages: 2,
        max_bytes: 10_000,
        allow_derivations: true,
    };
    assert!(
        vault
            .ingest_docs_export(&owner, request, &document, ceiling, Some(&Summary), None, 2)
            .is_err()
    );
    let effect = vault.docs_import_effect(&owner, request, &document, ceiling)?;
    vault.approve_once(&owner, effect.digest())?;
    let receipt = vault.ingest_docs_export(
        &owner,
        request,
        &document,
        ceiling,
        Some(&Summary),
        Some(&Classifier),
        2,
    )?;
    assert_eq!(receipt.asset_refs.len(), 1);
    assert_eq!(receipt.summary_refs.len(), 2);
    assert_eq!(receipt.annotation_refs.len(), 1);
    assert!(
        vault
            .ingest_docs_export(&owner, request, &document, ceiling, None, None, 3)
            .is_err()
    );
    let annotation = vault.docs_annotation(&receipt.annotation_refs[0])?.unwrap();
    assert_eq!(annotation["derivation"]["source"], "imported");
    assert_eq!(annotation["annotation"]["label"], "suspected_injection");
    let summary_id = EntityId::from_hex(&receipt.summary_refs[0])?;
    let chunk_id = EntityId::from_hex(&receipt.chunk_refs[0])?;
    vault.put_vector(&summary_id, &[1.0, 0.0, 0.0, 0.0])?;
    vault.put_vector(&chunk_id, &[1.0, 0.0, 0.0, 0.0])?;
    grant_core_read(&vault, "owner")?;
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    let source = reader
        .expand_doc_ref(&receipt.asset_refs[0])?
        .value
        .unwrap();
    assert_eq!(source["text"], document.pages[0].text);
    let exact_hits = reader.search_docs_summaries("attraction", 4)?;
    assert_eq!(
        exact_hits.value[0].entity_type,
        crate::registry::ENTITY_TYPE_ASSET_TEXT
    );
    assert!(exact_hits.value[0].summary.is_none());
    let hits = reader.search_docs_summaries("Gravity", 4)?;
    assert_eq!(
        hits.value[0].entity_type,
        crate::registry::ENTITY_TYPE_SUMMARY
    );
    let conceptual =
        reader.search_docs_summaries_with_vector("Gravity", Some(&[1.0, 0.0, 0.0, 0.0]), 4)?;
    assert_eq!(
        conceptual.value[0].entity_type,
        crate::registry::ENTITY_TYPE_SUMMARY
    );
    assert!(conceptual.value[0].summary.is_some());
    assert!(
        hits.value
            .iter()
            .any(|hit| hit.entity_type == crate::registry::ENTITY_TYPE_SUMMARY)
    );
    assert!(
        hits.receipt
            .applied
            .entity_types
            .as_ref()
            .unwrap()
            .contains(&crate::registry::ENTITY_TYPE_ASSET_TEXT)
    );
    let wire = serde_json::to_value(&hits.value).unwrap();
    assert!(wire[0].get("text").is_none());
    assert!(
        hits.value
            .iter()
            .any(|hit| hit.summary.as_deref() == Some("# Gravity"))
    );
    assert!(hits.value.iter().any(|hit| hit.entity_type
        == crate::registry::ENTITY_TYPE_ASSET_TEXT
        && hit.summary.is_none()));
    assert!(
        reader
            .expand_doc_ref(&hits.value[0].reference)?
            .value
            .unwrap()["text"]
            .is_string()
    );
    let summary_ref = &hits
        .value
        .iter()
        .find(|hit| hit.summary.as_deref() == Some("# Gravity"))
        .unwrap()
        .reference;
    let mut next = summary_ref.clone();
    for (level, expected) in [
        (DocsExpansionLevel::Summary, "# Gravity"),
        (DocsExpansionLevel::Span, "# Gravity"),
        (
            DocsExpansionLevel::Section,
            "# Gravity\n\nGravity describes attraction.",
        ),
        (
            DocsExpansionLevel::FullText,
            document.pages[0].text.as_str(),
        ),
        (
            DocsExpansionLevel::RawAsset,
            document.pages[0].text.as_str(),
        ),
    ] {
        let step = reader.expand_doc_ladder_ref(&next)?.value.unwrap();
        assert_eq!(step.level, level);
        assert_eq!(step.text, expected);
        assert_eq!(step.asset.is_some(), level == DocsExpansionLevel::RawAsset);
        next = step.next_ref.unwrap_or_default();
    }
    assert!(reader.expand_doc_ladder_ref(&person.to_hex()).is_err());
    let previous: Vec<_> = receipt
        .summary_refs
        .iter()
        .map(|reference| reader.expand_doc_ref(reference).map(|r| r.value))
        .collect::<Result<_>>()?;
    let mut edited = document;
    edited.pages[0].text.insert_str(0, "Inserted preface.\n\n");
    let next_request = EntityId::now();
    vault.approve_once(
        &owner,
        vault
            .docs_import_effect(&owner, next_request, &edited, ceiling)?
            .digest(),
    )?;
    vault.ingest_docs_export(
        &owner,
        next_request,
        &edited,
        ceiling,
        Some(&Summary),
        Some(&Classifier),
        4,
    )?;
    for (reference, expected) in receipt.summary_refs.iter().zip(previous) {
        assert_eq!(reader.expand_doc_ref(reference)?.value, expected);
    }
    Ok(())
}

fn searchable_docs(
    docs: &DocsExport,
) -> Result<(tempfile::TempDir, crate::Vault, DocsImportReceipt, EntityId)> {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let request = EntityId::now();
    let ceiling = DocsImportCeiling {
        max_pages: 8,
        max_bytes: 10_000,
        allow_derivations: true,
    };
    vault.approve_once(
        &owner,
        vault
            .docs_import_effect(&owner, request, docs, ceiling)?
            .digest(),
    )?;
    let receipt =
        vault.ingest_docs_export(&owner, request, docs, ceiling, Some(&Summary), None, 2)?;
    grant_core_read(&vault, "owner")?;
    Ok((dir, vault, receipt, person))
}

#[test]
fn mixed_summary_producers_do_not_abort_or_starve_document_hits() -> Result<()> {
    let (_dir, vault, docs, actor_id) = searchable_docs(&document())?;
    let actor = crate::WriteActor::new(actor_id, crate::EdgeActorClass::Human);
    let conv = EntityId::now();
    vault.put_entity(
        &conv,
        crate::registry::ENTITY_TYPE_CONVERSATION,
        TimeRange { start: 1, end: 1 },
        1,
        &crate::conversation_dag::fixtures::body("conversation"),
    )?;
    crate::conversation_dag::test_support::put_dag_test_policy(&vault, actor, true)?;
    let turn = vault
        .append_dag_record(&crate::conversation_dag::fixtures::input(
            conv, None, true, actor,
        ))?
        .id;
    let dag = vault.mint_dag_scope_summary(
        &crate::conversation_dag::fixtures::scope(
            conv,
            crate::conversation_dag::ScopePath::Canonical,
            false,
        ),
        "Gravity in the DAG",
        actor,
    )?;
    // Promotion keeps the witness's MessagePack `content` body and matching
    // text index entry; neither belongs to the document-summary schema.
    let session = EntityId::now();
    vault
        .batch()
        .put(
            &session,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({"content": "Gravity in the session"})).unwrap(),
        )
        .text(&session, &[("content", "Gravity in the session")])
        .commit()?;
    assert!(vault.get(&turn)?.is_some());
    assert!(vault.get(&dag)?.is_some());
    assert!(vault.get(&session)?.is_some());
    vault.put_vector(&session, &[1.0, 0.0, 0.0, 0.0])?;
    vault.put_vector(&dag, &[1.0, 0.0, 0.0, 0.0])?;
    grant_core_read(&vault, "owner")?;
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    // Both alien summaries outrank a lexical-only doc hit with this vector.
    // Filtering after `limit` would leave no document result.
    let hits =
        reader.search_docs_summaries_with_vector("Gravity", Some(&[1.0, 0.0, 0.0, 0.0]), 1)?;
    assert_eq!(hits.value.len(), 1);
    assert!(docs.summary_refs.contains(&hits.value[0].reference));
    for hit in reader.search_docs_summaries("Gravity", 16)?.value {
        if hit.entity_type == crate::registry::ENTITY_TYPE_SUMMARY {
            assert!(docs.summary_refs.contains(&hit.reference));
            assert_eq!(
                reader
                    .expand_doc_ladder_ref(&hit.reference)?
                    .value
                    .unwrap()
                    .level,
                DocsExpansionLevel::Summary
            );
        }
    }
    Ok(())
}

#[test]
fn ocr_asset_text_cannot_fill_document_result_or_offer_an_unopenable_ref() -> Result<()> {
    let (_dir, vault, docs, _) = searchable_docs(&document())?;
    let ocr = EntityId::now();
    let raw = NormalizedIngestEntity {
        entity_type: crate::registry::ENTITY_TYPE_ASSET_TEXT,
        body: "[PROVENANCE recognizer_locality=1]\n[OCR]\nGravity attraction\n".into(),
        recognizer_locality: Some(LocalityRung::HostLocal),
    };
    admit_imported_entity(&vault, &ocr, &raw, TimeRange { start: 3, end: 3 }, 3)?;
    vault
        .batch()
        .text(&ocr, &[("text", raw.body.as_str())])
        .commit()?;
    vault.put_vector(&ocr, &[1.0, 0.0, 0.0, 0.0])?;
    assert_eq!(vault.get(&ocr)?, Some(raw.body.into_bytes()));
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    for (query, expected_kind) in [
        ("Gravity", crate::registry::ENTITY_TYPE_SUMMARY),
        ("attraction", crate::registry::ENTITY_TYPE_ASSET_TEXT),
    ] {
        let hits =
            reader.search_docs_summaries_with_vector(query, Some(&[1.0, 0.0, 0.0, 0.0]), 1)?;
        assert_eq!(hits.value.len(), 1, "OCR must not starve {query}");
        let hit = &hits.value[0];
        assert_ne!(hit.reference, ocr.to_hex());
        assert_eq!(hit.entity_type, expected_kind);
        let expanded = reader.expand_doc_ladder_ref(&hit.reference)?.value.unwrap();
        assert_eq!(
            expanded.level,
            if expected_kind == crate::registry::ENTITY_TYPE_SUMMARY {
                DocsExpansionLevel::Summary
            } else {
                DocsExpansionLevel::Span
            }
        );
        assert!(expanded.next_ref.is_some());
        if expected_kind == crate::registry::ENTITY_TYPE_ASSET_TEXT {
            assert!(docs.chunk_refs.contains(&hit.reference));
            assert!(hit.summary.is_none());
        }
    }
    assert!(
        reader
            .search_docs_summaries_with_vector(
                "unmatched_query_xyz",
                Some(&[1.0, 0.0, 0.0, 0.0]),
                1,
            )?
            .value
            .is_empty()
    );
    Ok(())
}

#[test]
fn fused_receipt_adds_disjoint_lexical_and_vector_exclusions() -> Result<()> {
    let mut pages = document();
    pages.pages.push(DocsPage {
        page_id: "other-page".into(),
        path: "other.md".into(),
        text: "# Orbit\n\nOrbit describes motion.".into(),
    });
    let (_dir, vault, docs, _) = searchable_docs(&pages)?;
    let orbit = EntityId::from_hex(&docs.summary_refs[2])?;
    vault.put_vector(&orbit, &[1.0, 0.0, 0.0, 0.0])?;
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    let only = |kind| crate::gate::RetrievalFilter {
        entity_types: Some(std::collections::BTreeSet::from([kind])),
        ..Default::default()
    };
    let summary = only(crate::registry::ENTITY_TYPE_SUMMARY);
    let chunk = only(crate::registry::ENTITY_TYPE_ASSET_TEXT);
    let lexical_summary = reader
        .search_text("Gravity", 16, Some(&summary))?
        .receipt
        .suppressed_count;
    let lexical_chunk = reader
        .search_text("Gravity", 16, Some(&chunk))?
        .receipt
        .suppressed_count;
    let vector_summary = reader
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 16, Some(&summary))?
        .receipt
        .suppressed_count;
    let vector_chunk = reader
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 16, Some(&chunk))?
        .receipt
        .suppressed_count;
    assert!(lexical_chunk > 0 && vector_chunk > 0);
    assert!(lexical_chunk + vector_chunk > lexical_chunk.max(vector_chunk));
    let fused =
        reader.search_docs_summaries_with_vector("Gravity", Some(&[1.0, 0.0, 0.0, 0.0]), 16)?;
    assert_eq!(
        fused.receipt.suppressed_count,
        lexical_summary + lexical_chunk + vector_summary + vector_chunk
    );
    Ok(())
}

#[test]
fn blob_birth_tree_reuses_unchanged_blocks_but_never_hides_case_edits() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let ceiling = DocsImportCeiling {
        max_pages: 2,
        max_bytes: 100_000,
        allow_derivations: false,
    };
    let ingest = |docs: &DocsExport| -> Result<DocsImportReceipt> {
        let request = EntityId::now();
        vault.approve_once(
            &owner,
            vault
                .docs_import_effect(&owner, request, docs, ceiling)?
                .digest(),
        )?;
        vault.ingest_docs_export(&owner, request, docs, ceiling, None, None, 2)
    };
    let mut doc = document();
    let first = ingest(&doc)?;
    let asset = EntityId::from_hex(&first.asset_refs[0])?;
    let before = vault.blob_fingerprint(&asset)?.unwrap();
    assert_eq!(
        ingest(&doc)?.fingerprints[0].1,
        BlobBirthDecision::Unchanged(FingerprintRung::Asset)
    );
    doc.pages[0]
        .text
        .push_str("\n\n# Orbit\n\nOrbit is another section.");
    let changed = ingest(&doc)?;
    let added_blocks: Vec<_> = docs_semantic_segments(&doc.pages[0].text)
        .into_iter()
        .skip(2)
        .map(|s| s.block)
        .collect();
    assert_eq!(
        changed.fingerprints[0].1,
        BlobBirthDecision::Changed {
            sections: vec!["2".into()],
            blocks: added_blocks
        }
    );
    let after = vault.blob_fingerprint(&asset)?.unwrap();
    for (key, value) in &before.blocks {
        assert_eq!(Some(value), after.blocks.get(key));
    }
    doc.pages[0].text = doc.pages[0].text.replace("\n", "\r\n");
    assert_eq!(
        ingest(&doc)?.fingerprints[0].1,
        BlobBirthDecision::Unchanged(FingerprintRung::TextRoot)
    );
    doc.pages[0].text = doc.pages[0].text.replace("Gravity", "GRAVITY");
    assert!(matches!(
        ingest(&doc)?.fingerprints[0].1,
        BlobBirthDecision::Changed { .. }
    ));
    // Direct text editing never enters the birth deduplicator and invalidates its cache.
    vault.put_entity(
        &asset,
        crate::registry::ENTITY_TYPE_ASSET,
        TimeRange { start: 3, end: 3 },
        3,
        b"Edited bytes",
    )?;
    assert!(vault.blob_fingerprint(&asset)?.is_none());
    ingest(&doc)?;
    assert!(vault.blob_fingerprint(&asset)?.is_some());
    vault.delete_entity(&asset)?;
    assert!(vault.blob_fingerprint(&asset)?.is_none());
    Ok(())
}

struct Ner(std::sync::atomic::AtomicUsize);
impl DocsDeepExtractor for Ner {
    fn binding(&self) -> &str {
        "fixture.ner.v1"
    }
    fn extract(&self, segment: &DocsSegment) -> Result<Vec<DocsDeepClaim>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if segment.text.contains("Gravity describes attraction") {
            Ok(vec![DocsDeepClaim {
                predicate: "docs.topic".into(),
                value: json!("gravity"),
                quote: "Gravity describes attraction".into(),
            }])
        } else {
            Ok(Vec::new())
        }
    }
}

#[test]
fn thin_docs_wait_for_authorized_read_or_explicit_deep_trigger() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner =
        vault.authenticate_owner(person, "owner", true, crate::store::GateDecisionId::now())?;
    let document = document();
    let ceiling = DocsImportCeiling {
        max_pages: 2,
        max_bytes: 10_000,
        allow_derivations: true,
    };
    let request = EntityId::now();
    vault.approve_once(
        &owner,
        vault
            .docs_import_effect(&owner, request, &document, ceiling)?
            .digest(),
    )?;
    let receipt = vault.ingest_docs_export(&owner, request, &document, ceiling, None, None, 2)?;
    let asset = EntityId::from_hex(&receipt.asset_refs[0])?;
    let ner = Ner(AtomicUsize::new(0));
    assert!(receipt.summary_refs.is_empty());
    assert!(vault.claims_for_subject(&asset)?.is_empty());
    assert_eq!(ner.0.load(Ordering::Relaxed), 0);
    grant_core_read(&vault, "owner")?;
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    let hits = reader.search_docs_summaries("Gravity", 4)?;
    assert!(!hits.value.is_empty());
    let other = vault.scoped_read(crate::claim::ScopedReadActorKey::new("other").unwrap());
    assert!(
        other
            .expand_doc_ref_deep(&receipt.asset_refs[0], &owner, &ner, 3)
            .is_err()
    );
    assert_eq!(ner.0.load(Ordering::Relaxed), 0);
    assert!(
        vault
            .deep_ingest_docs_asset(&owner, person, DocsDeepTrigger::Explicit, &ner, 3)
            .is_err()
    );
    assert_eq!(ner.0.load(Ordering::Relaxed), 0);
    assert!(
        reader
            .expand_doc_ref(&receipt.asset_refs[0])?
            .value
            .is_some()
    );
    assert_eq!(ner.0.load(Ordering::Relaxed), 0);
    assert!(vault.claims_for_subject(&asset)?.is_empty());
    let (_, deep) = reader.expand_doc_ref_deep(&receipt.asset_refs[0], &owner, &ner, 3)?;
    let deep = deep.unwrap();
    assert_eq!(deep.trigger, DocsDeepTrigger::OnRead);
    assert_eq!(deep.claim_refs.len(), 1);
    assert_eq!(deep.derivation.source, "imported");
    let claim_id = EntityId::from_hex(&deep.claim_refs[0])?;
    let claim = vault.get_claim(&claim_id)?.unwrap();
    assert_eq!(claim.source, Some(crate::claim::ClaimSource::Imported));
    assert_eq!(claim.approval, crate::claim::ClaimApprovalStatus::Approved);
    assert_eq!(claim.subject, crate::claim::ClaimSubject::Entity(asset));
    let evidence = claim.evidence.as_ref().unwrap();
    let candidate = field(
        evidence,
        crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    )
    .unwrap();
    let derivation = field(candidate, "derivation").unwrap();
    assert_eq!(
        field(derivation, "source").and_then(rmpv::Value::as_str),
        Some("imported")
    );
    assert_eq!(
        field(derivation, "source_ref").and_then(rmpv::Value::as_str),
        Some(receipt.chunk_refs[1].as_str())
    );
    let calls = ner.0.load(Ordering::Relaxed);
    let again = vault.deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Explicit, &ner, 4)?;
    assert_eq!(again.claim_refs, deep.claim_refs);
    assert_eq!(ner.0.load(Ordering::Relaxed), calls);
    Ok(())
}

#[test]
fn deep_docs_respect_revision_ceiling_and_quote_validation() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner =
        vault.authenticate_owner(person, "owner", true, crate::store::GateDecisionId::now())?;
    let ceiling = DocsImportCeiling {
        max_pages: 2,
        max_bytes: 10_000,
        allow_derivations: true,
    };
    let import = |doc: &DocsExport, ceiling, now| -> Result<EntityId> {
        let request = EntityId::now();
        vault.approve_once(
            &owner,
            vault
                .docs_import_effect(&owner, request, doc, ceiling)?
                .digest(),
        )?;
        let receipt = vault.ingest_docs_export(&owner, request, doc, ceiling, None, None, now)?;
        EntityId::from_hex(&receipt.asset_refs[0])
    };
    let mut doc = document();
    let asset = import(&doc, ceiling, 2)?;
    assert!(
        vault
            .deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Explicit, &FalseQuote, 3)
            .is_err()
    );
    assert!(vault.claims_for_subject(&asset)?.is_empty());
    let ner = Ner(std::sync::atomic::AtomicUsize::new(0));
    let deep = vault.deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Dreamer, &ner, 3)?;
    assert_eq!(deep.trigger, DocsDeepTrigger::Dreamer);
    doc.pages[0].text = "# A new page\n\nNew facts.".into();
    assert_eq!(asset, import(&doc, ceiling, 4)?);
    assert_eq!(
        vault
            .get_claim(&EntityId::from_hex(&deep.claim_refs[0])?)?
            .unwrap()
            .lifecycle,
        crate::claim::ClaimLifecycleStatus::Retracted
    );
    assert!(
        vault
            .deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Explicit, &ner, 4)?
            .claim_refs
            .is_empty()
    );
    let denied = DocsImportCeiling {
        allow_derivations: false,
        ..ceiling
    };
    import(&doc, denied, 5)?;
    let calls = ner.0.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        vault
            .deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Explicit, &ner, 5)
            .is_err()
    );
    assert_eq!(ner.0.load(std::sync::atomic::Ordering::Relaxed), calls);
    Ok(())
}

#[test]
fn docs_deep_on_read_rechecks_reader_and_observed_source_after_model_work() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_dir, vault, owner, doc, ceiling, receipt) = deep_fixture()?;
    let asset = EntityId::from_hex(&receipt.asset_refs[0])?;
    grant_core_read(&vault, "owner")?;
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    let calls = AtomicUsize::new(0);
    let revoke = CallbackNer(|_: &DocsSegment| {
        if calls.fetch_add(1, Ordering::Relaxed) == 0 {
            crate::test_util::put_policy_manifest_bytes(
                &vault,
                crate::gate::default_policy_manifest_id()?,
                &crate::gate::default_policy_manifest(),
            )?;
        }
        Ok(())
    });
    assert!(
        reader
            .expand_doc_ref_deep(&asset.to_hex(), &owner, &revoke, 3)
            .is_err()
    );
    assert!(calls.load(Ordering::Relaxed) > 0);
    assert!(vault.claims_for_subject(&asset)?.is_empty());

    grant_core_read(&vault, "owner")?;
    let calls = AtomicUsize::new(0);
    let mut replacement = doc;
    replacement.pages[0].text = "# Different\n\nReplacement content.".into();
    let replace = CallbackNer(|_: &DocsSegment| {
        if calls.fetch_add(1, Ordering::Relaxed) == 0 {
            approved_docs_import(&vault, &owner, &replacement, ceiling, 4)?;
        }
        Ok(())
    });
    assert!(
        reader
            .expand_doc_ref_deep(&asset.to_hex(), &owner, &replace, 5)
            .is_err()
    );
    assert!(calls.load(Ordering::Relaxed) > 0);
    assert!(vault.claims_for_subject(&asset)?.is_empty());
    Ok(())
}

#[test]
fn docs_deep_claims_register_source_dependencies_and_refuse_dangling_chunks() -> Result<()> {
    let (_dir, vault, owner, mut doc, ceiling, receipt) = deep_fixture()?;
    let asset = EntityId::from_hex(&receipt.asset_refs[0])?;
    let chunk = EntityId::from_hex(&receipt.chunk_refs[1])?;
    let deep = vault.deep_ingest_docs_asset(
        &owner,
        asset,
        DocsDeepTrigger::Explicit,
        &Ner(std::sync::atomic::AtomicUsize::new(0)),
        3,
    )?;
    let claim = EntityId::from_hex(&deep.claim_refs[0])?;
    let txn = vault.store.env.read_txn()?;
    let raw = vault.get_raw_in(&txn, &chunk)?.unwrap();
    let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
    let source = crate::ports::SourceSpan {
        document: chunk,
        frontier: header.learned_at,
    };
    assert!(
        vault
            .store
            .port_dependency_list_by_source(&txn, source)?
            .contains(&claim)
    );
    drop(txn);
    vault.delete_entity(&chunk)?;
    let txn = vault.store.env.read_txn()?;
    assert!(crate::ports::stale_in_txn(&vault.store, &txn, &claim)?);
    drop(txn);
    assert!(
        vault
            .deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Explicit, &MultiNer, 4)
            .is_err()
    );
    assert!(
        vault
            .deep_ingest_docs_asset(
                &owner,
                asset,
                DocsDeepTrigger::Dreamer,
                &Ner(std::sync::atomic::AtomicUsize::new(0)),
                4
            )
            .is_err()
    );
    doc.pages[0].page_id = "another-page".into();
    let other = approved_docs_import(&vault, &owner, &doc, ceiling, 5)?;
    let second_asset = EntityId::from_hex(&other.asset_refs[0])?;
    vault.delete_entity(&EntityId::from_hex(&other.chunk_refs[1])?)?;
    assert!(
        vault
            .deep_ingest_docs_asset(
                &owner,
                second_asset,
                DocsDeepTrigger::Explicit,
                &MultiNer,
                6
            )
            .is_err()
    );
    assert!(vault.claims_for_subject(&second_asset)?.is_empty());
    Ok(())
}

#[test]
fn docs_deep_bulk_import_consent_yields_approved_claims_without_individual_tray_rows() -> Result<()>
{
    let (_dir, vault, owner, _doc, _ceiling, receipt) = deep_fixture()?;
    let asset = EntityId::from_hex(&receipt.asset_refs[0])?;
    assert!(vault.pending_gate_consents(20)?.is_empty());
    let deep =
        vault.deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Dreamer, &MultiNer, 3)?;
    assert_eq!(deep.claim_refs.len(), 2);
    assert!(vault.pending_gate_consents(20)?.is_empty());
    for reference in deep.claim_refs {
        let claim = vault.get_claim(&EntityId::from_hex(&reference)?)?.unwrap();
        assert_eq!(claim.source, Some(crate::claim::ClaimSource::Imported));
        assert_eq!(claim.approval, crate::claim::ClaimApprovalStatus::Approved);
        let derivation = field(
            field(
                claim.evidence.as_ref().unwrap(),
                crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
            )
            .unwrap(),
            "derivation",
        )
        .unwrap();
        assert!(
            field(derivation, "approval_digest")
                .and_then(rmpv::Value::as_str)
                .is_some()
        );
    }
    Ok(())
}

#[test]
fn docs_deep_transport_reimport_preserves_claims_and_receipt() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_dir, vault, owner, mut doc, ceiling, receipt) = deep_fixture()?;
    let asset = EntityId::from_hex(&receipt.asset_refs[0])?;
    let ner = Ner(AtomicUsize::new(0));
    let original =
        vault.deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Explicit, &ner, 3)?;
    let calls = ner.0.load(Ordering::Relaxed);
    doc.pages[0].text = format!("\u{feff}{}", doc.pages[0].text);
    assert_eq!(
        approved_docs_import(&vault, &owner, &doc, ceiling, 4)?.fingerprints[0].1,
        BlobBirthDecision::Unchanged(FingerprintRung::TextRoot)
    );
    let bom = vault.deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Explicit, &ner, 5)?;
    assert_eq!(bom.claim_refs, original.claim_refs);
    doc.pages[0].text = doc.pages[0].text.replace("\n", "\r\n");
    assert_eq!(
        approved_docs_import(&vault, &owner, &doc, ceiling, 6)?.fingerprints[0].1,
        BlobBirthDecision::Unchanged(FingerprintRung::TextRoot)
    );
    let crlf = vault.deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Explicit, &ner, 7)?;
    assert_eq!(crlf.claim_refs, original.claim_refs);
    assert_eq!(ner.0.load(Ordering::Relaxed), calls);
    grant_core_read(&vault, "owner")?;
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    assert!(reader.is_entity_readable(&EntityId::from_hex(&original.claim_refs[0])?)?);
    assert_eq!(
        vault
            .get_claim(&EntityId::from_hex(&original.claim_refs[0])?)?
            .unwrap()
            .lifecycle,
        crate::claim::ClaimLifecycleStatus::Active
    );
    Ok(())
}

#[test]
fn deleting_docs_asset_invalidates_its_deep_claim_at_normal_read() -> Result<()> {
    let (_dir, vault, owner, _doc, _ceiling, receipt) = deep_fixture()?;
    let asset = EntityId::from_hex(&receipt.asset_refs[0])?;
    let deep =
        vault.deep_ingest_docs_asset(&owner, asset, DocsDeepTrigger::Explicit, &MultiNer, 3)?;
    let claim = EntityId::from_hex(&deep.claim_refs[0])?;
    grant_core_read(&vault, "owner")?;
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    assert!(reader.is_entity_readable(&claim)?);
    vault.delete_entity(&asset)?;
    let txn = vault.store.env.read_txn()?;
    assert!(crate::ports::stale_in_txn(&vault.store, &txn, &claim)?);
    drop(txn);
    assert!(!reader.is_entity_readable(&claim)?);
    Ok(())
}

#[test]
fn ordinary_docs_source_put_invalidates_live_deep_claims() -> Result<()> {
    for change_asset in [false, true] {
        let (_dir, vault, owner, _doc, _ceiling, receipt) = deep_fixture()?;
        let asset = EntityId::from_hex(&receipt.asset_refs[0])?;
        let chunk = EntityId::from_hex(&receipt.chunk_refs[1])?;
        let deep = vault.deep_ingest_docs_asset(
            &owner,
            asset,
            DocsDeepTrigger::Explicit,
            &Ner(std::sync::atomic::AtomicUsize::new(0)),
            3,
        )?;
        let claim = EntityId::from_hex(&deep.claim_refs[0])?;
        grant_core_read(&vault, "owner")?;
        let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
        assert!(reader.is_entity_readable(&claim)?);
        let source = if change_asset { asset } else { chunk };
        let kind = if change_asset {
            crate::registry::ENTITY_TYPE_ASSET
        } else {
            crate::registry::ENTITY_TYPE_ASSET_TEXT
        };
        let txn = vault.store.env.read_txn()?;
        let raw = vault.get_raw_in(&txn, &source)?.unwrap();
        let mut body: serde_json::Value =
            rmp_serde::from_slice(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]).unwrap();
        drop(txn);
        body["text"] = json!("# Gravity\n\nA different source fact.");
        vault.put_entity(
            &source,
            kind,
            TimeRange { start: 4, end: 4 },
            4,
            &rmp_serde::to_vec_named(&body).unwrap(),
        )?;
        let txn = vault.store.env.read_txn()?;
        assert!(crate::ports::stale_in_txn(&vault.store, &txn, &claim)?);
        drop(txn);
        assert!(!reader.is_entity_readable(&claim)?);
    }
    Ok(())
}

#[test]
fn heading_reimport_keeps_rewritten_summaries_readable() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner =
        vault.authenticate_owner(person, "owner", true, crate::store::GateDecisionId::now())?;
    let ceiling = DocsImportCeiling {
        max_pages: 2,
        max_bytes: 10_000,
        allow_derivations: true,
    };
    let mut docs = document();
    let request = EntityId::now();
    vault.approve_once(
        &owner,
        vault
            .docs_import_effect(&owner, request, &docs, ceiling)?
            .digest(),
    )?;
    let first =
        vault.ingest_docs_export(&owner, request, &docs, ceiling, Some(&Summary), None, 2)?;
    assert_eq!(first.summary_refs.len(), 2);
    grant_core_read(&vault, "owner")?;
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    let before: Vec<_> = first
        .summary_refs
        .iter()
        .map(|reference| reader.expand_doc_ref(reference).map(|row| row.value))
        .collect::<Result<_>>()?;
    assert!(before.iter().all(Option::is_some));

    docs.pages[0].text.insert_str(0, "# Preface\n\n");
    let request = EntityId::now();
    vault.approve_once(
        &owner,
        vault
            .docs_import_effect(&owner, request, &docs, ceiling)?
            .digest(),
    )?;
    let second =
        vault.ingest_docs_export(&owner, request, &docs, ceiling, Some(&Summary), None, 3)?;
    for (reference, expected) in first.summary_refs.iter().zip(before) {
        assert!(second.summary_refs.contains(reference));
        assert_eq!(reader.expand_doc_ref(reference)?.value, expected);
    }
    let hits = reader.search_docs_summaries("Gravity", 4)?;
    assert!(hits.value.iter().any(|hit| {
        hit.entity_type == crate::registry::ENTITY_TYPE_SUMMARY
            && first.summary_refs.contains(&hit.reference)
    }));
    Ok(())
}
