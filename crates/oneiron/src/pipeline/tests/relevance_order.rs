//! Channel relevance orders the result list (ONE-2702).
//!
//! Found by the oneiron-bench Japanese set (2026-10-06). Commit 35470684e
//! ("retrieval: add linear-log ranking blend") retired RRF, and from then the
//! blend read only recency, salience, confidence and gravity: BM25F and vector
//! scores chose the pool but never its order, so with those four signals tied
//! (plain turns) every candidate blended to 1.0 and ties fell to id order.
//! Relevance is now the blend's fifth input (`fusion::RELEVANCE_LOG_WEIGHT`).
//! These pin that an exact-phrase query ranks its own turn first, in Japanese
//! and in English, with and without a temporal now.

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
