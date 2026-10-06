//! REPRO (ignored until the engine fix lands): channel relevance never
//! orders the result list.
//!
//! Found by the oneiron-bench Japanese set (2026-10-06). Since commit
//! 35470684e ("retrieval: add linear-log ranking blend") retired RRF,
//! `fusion::retrieval_candidates_from_ranked_lists` keeps only the candidate
//! ids of every channel list and drops their scores, and
//! `fusion::linear_log_blend_scores_with_weights` blends only recency,
//! salience, confidence and gravity. BM25F and vector scores choose the pool
//! but never its order. With those four signals tied (plain turns) every
//! candidate blends to exactly 1.0 and ties fall to id order, so an
//! exact-phrase query does not rank its own turn first. Not CJK-specific:
//! English ties the same way. A candidate fix and the pinned tests it moves
//! are in the bench branch notes (engine-relevance-blend.candidate.patch).
//!
//! Run: cargo test -p oneiron --lib relevance_order -- --ignored

use super::*;

/// Twelve short turns. Only the target holds the whole company name; the
/// distractors share its characters (会社, 青, リン, ク) and so enter the
/// candidate pool through the CJK bigram and unigram postings.
const TURNS: [&str; 12] = [
    "今日は会社の会議が長かったです。",
    "青い傘を買いました。",
    "リンゴを三つ食べた。",
    "私は相沢美咲、株式会社青葉リンクの法人営業をしています。",
    "会社の近くに新しいカフェができた。",
    "週末はクッキーを焼く予定です。",
    "青葉の季節が好きです。",
    "リンクを送ってくれてありがとう。",
    "株価のニュースを見た。",
    "式の準備で忙しい。",
    "社員旅行は来月です。",
    "クラスの友達と話した。",
];
const TARGET: usize = 3;

fn ids_and_vault() -> (tempfile::TempDir, Vault, Vec<EntityId>) {
    let (dir, vault) = open_test_vault();
    // Ids ascend with the turn index, so an id-order tie puts the target
    // fourth, never first by accident.
    let ids: Vec<EntityId> = (0..TURNS.len())
        .map(|index| entity_id(0x50 + index as u8))
        .collect();
    for (id, text) in ids.iter().zip(TURNS) {
        put_text(&vault, *id, text).unwrap();
    }
    (dir, vault, ids)
}

#[test]
#[ignore = "engine issue: channel relevance never reaches the blend (fusion.rs)"]
fn exact_japanese_phrase_ranks_its_own_turn_first() -> Result<()> {
    let (_dir, vault, ids) = ids_and_vault();
    let results = vault.query().search_text("株式会社青葉リンク", 10).run()?;
    assert!(results.len() > 1, "distractors enter the pool");
    assert_eq!(results[0].id, ids[TARGET]);
    assert!(
        results[0].score > results[1].score,
        "relevance separates the target from the pool: {:?}",
        results.iter().map(|row| row.score).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
#[ignore = "engine issue: channel relevance never reaches the blend (fusion.rs)"]
fn exact_japanese_phrase_ranks_first_with_a_temporal_now() -> Result<()> {
    let (_dir, vault, ids) = ids_and_vault();
    let results = vault
        .query()
        .search_text("株式会社青葉リンク", 10)
        .with_temporal_now(1_710_504_000)
        .run()?;
    assert_eq!(results[0].id, ids[TARGET]);
    Ok(())
}

#[test]
#[ignore = "engine issue: channel relevance never reaches the blend (fusion.rs)"]
fn english_relevance_orders_tied_turns_too() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let weak = entity_id(0x61);
    let strong = entity_id(0x62);
    put_text(
        &vault,
        weak,
        "a note about the archive code and nothing else",
    )?;
    put_text(
        &vault,
        strong,
        "the contract launch code is tulip, the contract launch code",
    )?;
    let results = vault
        .query()
        .search_text("contract launch code", 10)
        .run()?;
    assert_eq!(results[0].id, strong, "the lower id does not win a tie");
    assert!(results[0].score > results[1].score);
    Ok(())
}
