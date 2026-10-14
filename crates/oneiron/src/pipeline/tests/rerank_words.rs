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
    claim_body_at(value, ClaimApprovalStatus::Auto)
}

/// [`claim_body`] under `approval`.
fn claim_body_at(value: &str, approval: ClaimApprovalStatus) -> Vec<u8> {
    let body = ClaimBody::new(
        "test.rerank_words",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from(value),
        0.9,
        approval,
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

/// The context pack, read at `read_mode`, of a search for lanterns that
/// `reranker` scores.
fn scored_pack<'a>(
    vault: &'a Vault,
    reranker: &'a dyn Reranker,
    read_mode: ReadMode,
) -> Result<crate::ContextPack> {
    vault
        .context_pack()
        .read_mode(read_mode)
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

/// The context pack, read at `read_mode`, a reranker (binding unless
/// `unbound`) scores claim `id` in, born with `old`, put again with newer
/// words whose index publication waits, and put back to `old` while the
/// reranker scores it.
fn restored_pack(
    vault: &Vault,
    id: EntityId,
    old: Vec<u8>,
    unbound: bool,
    read_mode: ReadMode,
) -> Result<crate::ContextPack> {
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
        unbound,
    };
    scored_pack(vault, &reranker, read_mode)
}

/// Astra on #1426 (F2): a claim scored at its pin was hydrated from the body
/// the claim gate cached when retrieval read it live, whenever the live row
/// equalled the pin by the time the pack hydrated. A write restoring the
/// pinned bytes did that, and the pack served the words retrieval read live
/// under the score for the pinned ones. A scored claim takes the cache only
/// when it holds the pinned body. Sol R15 on this branch: an indexed hit no
/// reranker binds, restored the same way, was withheld as a row written
/// since the gate read it, though the pack reads it at its pin too.
#[test]
fn a_restored_claim_is_served_at_the_words_scored() -> Result<()> {
    for (unbound, read_mode) in [(false, ReadMode::Live), (true, ReadMode::Indexed)] {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x6C);

        let pack = restored_pack(&vault, id, claim_body("old-words"), unbound, read_mode)?;

        let served = pack.results.first();
        assert_eq!(
            served.map(|row| (
                row.id,
                row.fields.as_ref().and_then(|fields| fields.get("val"))
            )),
            Some((id, Some(&serde_json::json!("old-words")))),
            "unbound {unbound}: {served:?}"
        );
    }
    Ok(())
}

/// Sol R9 on this branch: a scored claim the cache could not stand for was
/// held to `claim_surfaceable` alone. Pinned words citing a source that is
/// not live, put back during the rerank stage, were served, though
/// retrieval would now suppress the claim. They are held to its live
/// support too.
#[test]
fn a_restored_claim_with_no_live_support_is_not_served() -> Result<()> {
    // Bound, the pin; unbound (Sol R13), the live row, which the restore
    // made the pinned bytes again while the gate's cache holds newer words.
    for unbound in [false, true] {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x6D);

        let pack = restored_pack(
            &vault,
            id,
            cited_body(entity_id(0x7D), "old-words"),
            unbound,
            ReadMode::Live,
        )?;

        assert!(
            pack.results.iter().all(|row| row.id != id),
            "unbound {unbound}: {:?}",
            pack.results
        );
    }
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

/// Wonder R10, Sol R11 and Wonder R12 on this branch: the claim gate judged
/// a claim's live support in retrieval's snapshot, and the pack, hydrated in
/// a later one, served the claim without asking again; validation never asks
/// for a neighbor. The only source the claim cites, deleted while a reranker
/// scored the block, left a claim retrieval would now suppress in the pack:
/// a word-bound hit from the gate's cache, an unbound hit at its indexed pin,
/// and either one again as a neighbor of a row that points at it. So did an
/// indexed pin whose own source stays while the live body's is deleted:
/// retrieval judges the live body. Every claim a pack serves is held to its
/// live support where the pack is hydrated, and a pinned one to its live
/// body's too.
#[test]
fn a_claim_whose_source_is_deleted_while_it_is_scored_is_not_served() -> Result<()> {
    // A word-bound hit read live from the gate's cache; an unbound hit read
    // at its indexed pin while newer words wait to be published; and that pin
    // again, its old words citing a source that stays.
    let mut served = Vec::new();
    for (unbound, read_mode, newer, pin_kept) in [
        (false, ReadMode::Live, None, false),
        (true, ReadMode::Indexed, Some("new-words"), false),
        (true, ReadMode::Indexed, Some("new-words"), true),
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
        let kept = entity_id(0x7F);
        vault.put_entity(
            &kept,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"kept source",
        )?;
        let id = entity_id(0x6E);
        let old = cited_body(if pin_kept { kept } else { source }, "old-words");
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
                served.push(format!("unbound {unbound}, pin kept {pin_kept}: in {part}"));
            }
        }
    }
    assert!(served.is_empty(), "{served:?}");
    Ok(())
}

/// Sol and Wonder R13 on this branch: a claim the reranker does not bind,
/// read live, took the gate's cached body whenever the live row equalled the
/// row read, though the gate read an older row. Rewritten while scored to
/// words citing only a source that is gone, it was served on its old words
/// and their source. The gate's verdict stands only for the body it read; a
/// row written since, unpinned, has no verdict in this run and is not
/// served (Sol R14: judging the new body here would serve words that the
/// rest of the pack's assembly never read). Sol and Wonder R16: a body
/// whose value went from a binary to a string of the same bytes, which are
/// not UTF-8, encodes as the old one did, and was served as the gate's.
#[test]
fn a_claim_rewritten_while_it_is_scored_is_not_served_on_its_old_verdict() -> Result<()> {
    let binary = valued_body(
        "test.rerank_words",
        rmpv::Value::Binary(b"lantern\xff".to_vec()),
        false,
    );
    let marker = [&[0xC4_u8, 8][..], &b"lantern\xff"[..]].concat();
    let at = binary
        .windows(marker.len())
        .position(|bytes| bytes == marker.as_slice())
        .expect("the binary value");
    let mut string = binary.clone();
    // str 8 in place of bin 8: the same length, the same bytes.
    string[at] = 0xD9;
    let mut served = Vec::new();
    for (case, old, newer) in [
        (
            "to a gone source",
            cited_body(entity_id(0x7F), "old-words"),
            cited_body(entity_id(0x7D), "new-words"),
        ),
        ("binary to string", binary, string),
    ] {
        let (_dir, vault) = open_test_vault();
        put_subject(&vault)?;
        vault.put_entity(
            &entity_id(0x7F),
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"kept source",
        )?;
        let id = entity_id(0x6B);
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
        let rewrite = || {
            vault
                .batch()
                .put(
                    &id,
                    ENTITY_TYPE_CLAIM,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &newer,
                )
                .commit()
        };
        let reranker = WritingReranker {
            write: &rewrite,
            unbound: true,
        };

        let pack = scored_pack(&vault, &reranker, ReadMode::Live)?;

        if pack.results.iter().any(|row| row.id == id) {
            served.push(format!("{case}: {:?}", pack.results));
        }
    }
    assert!(served.is_empty(), "{served:?}");
    Ok(())
}

/// A claim body of `value` about the subject [`put_subject`] stores.
fn valued_body(predicate: &str, value: rmpv::Value, public: bool) -> Vec<u8> {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(entity_id(0x7C)),
        value,
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    if public {
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from("public"),
        )]));
    }
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

/// Sol and Wonder R15 on this branch: the gate's verdict stood for a claim
/// only when the body hydrated equalled the body the gate read, by a
/// comparison a NaN in an opaque value never passes. A claim holding one,
/// unchanged, was withheld from every pack, as a result and as a neighbor.
#[test]
fn an_unchanged_claim_holding_a_nan_is_served() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_subject(&vault)?;
    let body = valued_body(
        "test.rerank_words",
        rmpv::Value::Array(vec![
            rmpv::Value::from("old-words"),
            rmpv::Value::F64(f64::NAN),
        ]),
        false,
    );
    let (result, neighbor, seed) = (entity_id(0x6A), entity_id(0x69), entity_id(0x6F));
    crate::test_util::publish_seeded_revisions(&vault);
    for (id, text) in [(result, Some("the brass lantern")), (neighbor, None)] {
        let batch = vault.batch().put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        );
        match text {
            Some(text) => batch.text(&id, &[("body", text)]).commit()?,
            None => batch.commit()?,
        }
    }
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
    vault.put_edge(&seed, crate::edge::EdgeKind::Supports, &neighbor, 1.0)?;

    let pack = vault
        .context_pack()
        .read_mode(ReadMode::Live)
        .search_text("lantern", 10)
        .edge_hop(1)
        .run()?;

    assert!(
        pack.results.iter().any(|row| row.id == result)
            && pack.neighbors.iter().any(|row| row.id == neighbor),
        "{pack:?}"
    );
    Ok(())
}

/// Wonder R15 on this branch: a pack read live serves a word-bound claim at
/// its pin, while the disclosure clamp judged the claim on the body the gate
/// read live. Pinned words of a Tier-A predicate, behind a live body a guest
/// may read, reached the guest. The body served is judged. The reranker is
/// still handed those words: they are surfaceable, and the clamp sweeps what
/// the pack serves after ranking, a live row's words too.
#[test]
fn a_clamped_pack_serves_no_tier_a_words_a_pin_holds() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_subject(&vault)?;
    let id = entity_id(0x6C);
    put_twice(
        &vault,
        id,
        ENTITY_TYPE_CLAIM,
        &valued_body("voice_print.label", rmpv::Value::from("old-words"), true),
        &valued_body("test.rerank_words", rmpv::Value::from("new-words"), true),
    )?;
    let contact = entity_id(0xC0);
    vault.create_counterparty_contact(
        &contact,
        &crate::counterparty_contact::CounterpartyContactRecord::user_introduction(
            entity_id(0xA0),
            "guest@example.com",
            10,
        )?,
    )?;
    let guest = crate::disclosure::DisclosureContext::resolve(
        &vault,
        crate::interlocutor::InterlocutorSet::with_session_owner(vec![
            crate::interlocutor::Interlocutor::known_contact(
                contact,
                "guest@example.com",
                crate::counterparty_contact::CounterpartyFirstTouch::UserIntroduction,
            ),
        ]),
    )?;
    let reranker = ClaimKeepingReranker::default();

    let pack = vault
        .context_pack()
        .read_mode(ReadMode::Live)
        .search_text("lantern", 10)
        .rerank(&reranker, RerankOptions::default())
        .disclosure_context(guest)
        .run()?;

    assert_eq!(
        *reranker.claims.lock().unwrap(),
        [rmpv::Value::from("old-words")]
    );
    assert!(
        pack.results
            .iter()
            .chain(&pack.neighbors)
            .all(|row| row.id != id),
        "{pack:?}"
    );
    Ok(())
}

/// CodeRabbit on #1426: a binding reranker was handed a claim's body at its
/// pin whenever it decoded, though the gate judged the live body. Pinned
/// words that are Rejected or Proposed, behind a live body that surfaces,
/// left for the reranker, and hydration withheld the row only after. They
/// leave no more: the row is not reranked, and the pack serves what it
/// serves with no reranker.
#[test]
fn a_binding_reranker_is_handed_no_pinned_claim_the_run_withholds() -> Result<()> {
    for approval in [ClaimApprovalStatus::Rejected, ClaimApprovalStatus::Proposed] {
        for read_mode in [ReadMode::Indexed, ReadMode::Live] {
            let (_dir, vault) = open_test_vault();
            put_subject(&vault)?;
            let id = entity_id(0x6E);
            put_twice(
                &vault,
                id,
                ENTITY_TYPE_CLAIM,
                &claim_body_at("old-words", approval),
                &claim_body("new-words"),
            )?;
            let reranker = ClaimKeepingReranker::default();

            let pack = scored_pack(&vault, &reranker, read_mode)?;
            let unreranked = vault
                .context_pack()
                .read_mode(read_mode)
                .search_text("lantern", 10)
                .run()?;

            let served = |pack: &crate::ContextPack| {
                pack.results
                    .iter()
                    .chain(&pack.neighbors)
                    .map(|row| (row.id, row.fields.clone()))
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                *reranker.claims.lock().unwrap(),
                Vec::<rmpv::Value>::new(),
                "{approval:?} at {read_mode:?}"
            );
            assert_eq!(
                served(&pack),
                served(&unreranked),
                "{approval:?} at {read_mode:?}"
            );
        }
    }
    Ok(())
}

/// Sol and Astra R22 on this branch: the check above took a pinned body
/// equal to the one the gate admitted as served. A stale claim, which a
/// filter that includes stale claims admits to retrieval, has such a body,
/// but no pack serves it: its live row reads as none. Its words were handed
/// to the reranker all the same. They are handed to none now.
#[test]
fn a_stale_claim_the_filter_admits_is_handed_to_no_reranker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_subject(&vault)?;
    let id = entity_id(0x6E);
    let mut body = ClaimBody::new(
        "test.rerank_words",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from("old-words"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.stale = true;
    vault.put_entity(
        &id,
        ENTITY_TYPE_CLAIM,
        TimeRange { start: 1, end: 1 },
        1,
        &crate::claim::encode_claim_body(&body).expect("encode claim body"),
    )?;
    let with_stale = || crate::gate::ResolvedRetrievalFilter {
        entity_types: None,
        max_sensitivity_band: 3,
        include_stale: true,
        min_confidence: 0.0,
        min_salience: 0.0,
        deny_all: false,
        credential: None,
    };
    let reranker = ClaimKeepingReranker::default();

    let found = vault
        .query()
        .authority_filter(with_stale())
        .search_temporal(1, 1, 10)
        .run()?;
    let pack = vault
        .context_pack()
        .read_mode(ReadMode::Live)
        .authority_filter(with_stale())
        .search_temporal(1, 1, 10)
        .rerank(
            &reranker,
            RerankOptions {
                query: Some("lantern".to_owned()),
                ..RerankOptions::default()
            },
        )
        .run()?;

    assert!(
        found.iter().any(|hit| hit.id == id),
        "retrieval admits the claim"
    );
    // The vault's own seeded claims are found at that time too.
    let handed = reranker.claims.lock().unwrap().clone();
    assert!(
        handed
            .iter()
            .all(|value| value.as_str() != Some("old-words")),
        "{handed:?}"
    );
    assert!(
        pack.results
            .iter()
            .chain(&pack.neighbors)
            .all(|row| row.id != id),
        "{pack:?}"
    );
    Ok(())
}
