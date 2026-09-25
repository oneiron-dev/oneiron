use super::*;
use crate::error::Result;
use crate::{EntityId, TimeRange};
use serde_json::json;
struct Summary;
impl DocsSummaryModel for Summary {
    fn binding(&self) -> &str {
        "fixture.summary.v1"
    }
    fn summarize(&self, segment: &DocsSegment) -> Result<String> {
        Ok(segment.text.lines().next().unwrap_or_default().to_owned())
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
    grant_core_read(&vault, "owner")?;
    let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("owner").unwrap());
    let source = reader
        .expand_doc_ref(&receipt.asset_refs[0])?
        .value
        .unwrap();
    assert_eq!(source["text"], document.pages[0].text);
    let hits = reader.search_docs_summaries("Gravity", 4)?;
    assert_eq!(
        hits.value[0].entity_type,
        crate::registry::ENTITY_TYPE_SUMMARY
    );
    let wire = serde_json::to_value(&hits.value).unwrap();
    assert!(wire[0].get("text").is_none());
    assert!(
        reader
            .expand_doc_ref(&hits.value[0].reference)?
            .value
            .unwrap()["text"]
            .is_string()
    );
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
