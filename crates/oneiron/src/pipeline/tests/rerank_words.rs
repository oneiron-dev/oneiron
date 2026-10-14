//! A reranker that binds words scores the words a row's pin holds, and the
//! run serves those words (Sol R31 F1 and F4 on #1419's code, Astra F2 on
//! #1426). A row whose
//! index publication waits holds two bodies: the one its pin and postings
//! name, and a newer live one.

use super::*;
use crate::registry::ENTITY_TYPE_ASSET_TEXT;
use crate::vault::ReadMode;

/// A binding reranker that keeps each claim it is handed and leaves the
/// order as it is.
#[derive(Default)]
struct ClaimKeepingReranker {
    claims: std::sync::Mutex<Vec<rmpv::Value>>,
}

impl Reranker for ClaimKeepingReranker {
    fn id(&self) -> &str {
        "test/reranker-claim-keeping@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        self.claims.lock().unwrap().extend(
            candidates
                .iter()
                .filter_map(|candidate| candidate.claim.map(|claim| claim.value.clone())),
        );
        Ok(vec![0.0; candidates.len()])
    }

    fn binds_words(&self) -> bool {
        true
    }
}

/// A row whose index publication waits: born with `old`, then put again
/// with `new`, which stays live until the index publishes it.
fn put_twice(vault: &Vault, id: EntityId, entity_type: u8, old: &[u8], new: &[u8]) -> Result<()> {
    crate::test_util::publish_seeded_revisions(vault);
    for body in [old, new] {
        vault
            .batch()
            .put(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, body)
            .text(&id, &[("body", "the brass lantern")])
            .commit()?;
    }
    Ok(())
}

fn claim_body(value: &str) -> Vec<u8> {
    let body = ClaimBody::new(
        "test.rerank_words",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

/// Sol R31 F1: a binding reranker was handed a claim's live body while its
/// pin, and the bytes the write door judged, were its indexed revision; the
/// run then served that revision under the score for other words. It is
/// handed the body its pin holds.
#[test]
fn a_binding_reranker_is_handed_the_claim_its_pin_holds() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x6A);
    put_twice(
        &vault,
        id,
        ENTITY_TYPE_CLAIM,
        &claim_body("old-words"),
        &claim_body("new-words"),
    )?;
    let reranker = ClaimKeepingReranker::default();

    let results = vault
        .query()
        .search_text("lantern", 10)
        .rerank(&reranker, RerankOptions::default())
        .run()?;

    assert_eq!(results.first().map(|row| row.id), Some(id));
    assert_eq!(
        *reranker.claims.lock().unwrap(),
        [rmpv::Value::from("old-words")]
    );
    Ok(())
}

/// Sol R31 F4: a context pack read live hydrated a row a binding reranker
/// scored at its pin from the live body, serving other words than were
/// scored. A scored row is served at its pin whatever mode the pack reads.
#[test]
fn a_live_pack_serves_a_scored_row_at_the_words_scored() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x6B);
    let body = |content: &str| {
        rmp_serde::to_vec_named(&serde_json::json!({"content": content})).expect("body")
    };
    put_twice(
        &vault,
        id,
        ENTITY_TYPE_ASSET_TEXT,
        &body("old-words"),
        &body("new-words"),
    )?;
    let reranker = ClaimKeepingReranker::default();

    let pack = vault
        .context_pack()
        .read_mode(ReadMode::Live)
        .search_text("lantern", 10)
        .rerank(&reranker, RerankOptions::default())
        .run()?;

    let served = pack.results.first().expect("the row");
    assert_eq!(served.id, id);
    assert_eq!(
        served
            .fields
            .as_ref()
            .and_then(|fields| fields.get("content")),
        Some(&serde_json::json!("old-words")),
        "{served:?}"
    );
    Ok(())
}

/// A binding reranker that, while it scores, has another thread put `body`
/// back as `id`'s live row: a write landing after retrieval read the row and
/// before the pack hydrates it.
struct RestoringReranker<'a> {
    vault: &'a Vault,
    id: EntityId,
    body: Vec<u8>,
}

impl Reranker for RestoringReranker<'_> {
    fn id(&self) -> &str {
        "test/reranker-restoring@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    self.vault
                        .batch()
                        .put(
                            &self.id,
                            ENTITY_TYPE_CLAIM,
                            TimeRange { start: 1, end: 1 },
                            1,
                            &self.body,
                        )
                        .commit()
                })
                .join()
                .expect("the writer")
        })?;
        Ok(vec![0.0; candidates.len()])
    }

    fn binds_words(&self) -> bool {
        true
    }
}

/// The context pack a binding reranker scores claim `id` in, born with
/// `old`, put again with newer words whose index publication waits, and put
/// back to `old` while the reranker scores it.
fn restored_pack(vault: &Vault, id: EntityId, old: Vec<u8>) -> Result<crate::ContextPack> {
    // The claim's subject, which the pack's validation reads.
    vault.put_entity(
        &entity_id(0x7C),
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    put_twice(vault, id, ENTITY_TYPE_CLAIM, &old, &claim_body("new-words"))?;
    let reranker = RestoringReranker {
        vault,
        id,
        body: old,
    };
    vault
        .context_pack()
        .read_mode(ReadMode::Live)
        .search_text("lantern", 10)
        .rerank(&reranker, RerankOptions::default())
        .run()
}

/// Astra on #1426 (F2): a claim scored at its pin was hydrated from the body
/// the claim gate cached when retrieval read it live, whenever the live row
/// equalled the pin by the time the pack hydrated. A write restoring the
/// pinned bytes did that, and the pack served the words retrieval read live
/// under the score for the pinned ones. A scored claim takes the cache only
/// when it holds the pinned body.
#[test]
fn a_restored_claim_is_served_at_the_words_scored() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x6C);

    let pack = restored_pack(&vault, id, claim_body("old-words"))?;

    let served = pack.results.first().expect("the claim");
    assert_eq!(served.id, id);
    assert_eq!(
        served.fields.as_ref().and_then(|fields| fields.get("val")),
        Some(&serde_json::json!("old-words")),
        "{served:?}"
    );
    Ok(())
}

/// Sol R9 on this branch: a scored claim the cache could not stand for was
/// held to `claim_surfaceable` alone. Pinned words citing a source that is
/// not live, put back during the rerank stage, were served, though
/// retrieval would now suppress the claim. They are held to its live
/// support too.
#[test]
fn a_restored_claim_with_no_live_support_is_not_served() -> Result<()> {
    use crate::dreamer_consolidation::{
        ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
    };
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x6D);
    let mut unsupported = ClaimBody::new(
        "test.rerank_words",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from("old-words"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    unsupported.evidence = Some(encode_consolidation_evidence(
        &ConsolidationEvidenceEnvelope {
            refs: vec![entity_id(0x7D)],
            chain: Vec::new(),
            source_meet: ClaimSource::UserStated,
        },
    ));
    let old = crate::claim::encode_claim_body(&unsupported).expect("encode claim body");

    let pack = restored_pack(&vault, id, old)?;

    assert!(
        pack.results.iter().all(|row| row.id != id),
        "{:?}",
        pack.results
    );
    Ok(())
}
