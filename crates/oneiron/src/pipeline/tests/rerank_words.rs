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

/// A reranker that, while it scores, has another thread run `write`: a
/// write landing after retrieval read the block and before the pack hydrates
/// it. It binds words unless `unbound`.
struct WritingReranker<'a> {
    write: &'a (dyn Fn() -> Result<()> + Sync),
    unbound: bool,
}

impl Reranker for WritingReranker<'_> {
    fn id(&self) -> &str {
        "test/reranker-writing@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        std::thread::scope(|scope| scope.spawn(self.write).join().expect("the writer"))?;
        Ok(vec![0.0; candidates.len()])
    }

    fn binds_words(&self) -> bool {
        !self.unbound
    }
}

/// The context pack, read live, of a search for lanterns that `reranker`
/// scores.
fn scored_pack<'a>(vault: &'a Vault, reranker: &'a dyn Reranker) -> Result<crate::ContextPack> {
    vault
        .context_pack()
        .read_mode(ReadMode::Live)
        .search_text("lantern", 10)
        .rerank(reranker, RerankOptions::default())
        .run()
}

/// Stores the subject [`claim_body`] names, which a pack's validation reads.
fn put_subject(vault: &Vault) -> Result<()> {
    vault.put_entity(
        &entity_id(0x7C),
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )
}

/// The context pack a binding reranker scores claim `id` in, born with
/// `old`, put again with newer words whose index publication waits, and put
/// back to `old` while the reranker scores it.
fn restored_pack(vault: &Vault, id: EntityId, old: Vec<u8>) -> Result<crate::ContextPack> {
    put_subject(vault)?;
    put_twice(vault, id, ENTITY_TYPE_CLAIM, &old, &claim_body("new-words"))?;
    let restore = || {
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &old,
            )
            .commit()
    };
    let reranker = WritingReranker {
        write: &restore,
        unbound: false,
    };
    scored_pack(vault, &reranker)
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
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x6D);

    let pack = restored_pack(&vault, id, cited_body(entity_id(0x7D), "old-words"))?;

    assert!(
        pack.results.iter().all(|row| row.id != id),
        "{:?}",
        pack.results
    );
    Ok(())
}

/// A claim body of `words` whose consolidation evidence cites `source`
/// alone: it has live support only while `source` is live.
fn cited_body(source: EntityId, words: &str) -> Vec<u8> {
    use crate::dreamer_consolidation::{
        ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
    };
    let mut body = ClaimBody::new(
        "test.rerank_words",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from(words),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.evidence = Some(encode_consolidation_evidence(
        &ConsolidationEvidenceEnvelope {
            refs: vec![source],
            chain: Vec::new(),
            source_meet: ClaimSource::UserStated,
        },
    ));
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

/// Wonder R10 and Sol R11 on this branch: the claim gate judged a claim's
/// live support in retrieval's snapshot, and the pack, hydrated in a later
/// one, served the claim without asking again; validation never asks for a
/// neighbor. The only source the claim cites, deleted while a reranker
/// scored the block, left a claim retrieval would now suppress in the pack:
/// a word-bound hit from the gate's cache, an unbound hit at its indexed pin,
/// and either one again as a neighbor of a row that cites it. Every claim a
/// pack serves is held to its live support where the pack is hydrated.
#[test]
fn a_claim_whose_source_is_deleted_while_it_is_scored_is_not_served() -> Result<()> {
    // A word-bound hit read live from the gate's cache, and an unbound hit
    // read at its indexed pin while newer words wait to be published.
    let mut served = Vec::new();
    for (unbound, read_mode, newer) in [
        (false, ReadMode::Live, None),
        (true, ReadMode::Indexed, Some("new-words")),
    ] {
        let (_dir, vault) = open_test_vault();
        put_subject(&vault)?;
        let source = entity_id(0x7E);
        vault.put_entity(
            &source,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"source",
        )?;
        let id = entity_id(0x6E);
        let old = cited_body(source, "old-words");
        match newer {
            Some(words) => put_twice(
                &vault,
                id,
                ENTITY_TYPE_CLAIM,
                &old,
                &cited_body(source, words),
            )?,
            None => {
                crate::test_util::publish_seeded_revisions(&vault);
                vault
                    .batch()
                    .put(
                        &id,
                        ENTITY_TYPE_CLAIM,
                        TimeRange { start: 1, end: 1 },
                        1,
                        &old,
                    )
                    .text(&id, &[("body", "the brass lantern")])
                    .commit()?;
            }
        }
        // A row the search finds too, which points at the claim.
        let seed = entity_id(0x6F);
        vault
            .batch()
            .put(
                &seed,
                ENTITY_TYPE_ASSET_TEXT,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({"content": "a lantern shelf"}))
                    .expect("body"),
            )
            .text(&seed, &[("body", "the lantern shelf")])
            .commit()?;
        vault.put_edge(&seed, crate::edge::EdgeKind::Supports, &id, 1.0)?;
        let delete = || vault.delete_entity(&source).map(drop);
        let reranker = WritingReranker {
            write: &delete,
            unbound,
        };

        let pack = vault
            .context_pack()
            .read_mode(read_mode)
            .search_text("lantern", 10)
            .edge_hop(1)
            .rerank(&reranker, RerankOptions::default())
            .run()?;

        assert!(
            pack.results.iter().any(|row| row.id == seed),
            "the seed is served: {:?}",
            pack.results
        );
        for (part, rows) in [("results", &pack.results), ("neighbors", &pack.neighbors)] {
            if rows.iter().any(|row| row.id == id) {
                served.push(format!("unbound {unbound}: in {part}"));
            }
        }
    }
    assert!(served.is_empty(), "{served:?}");
    Ok(())
}
