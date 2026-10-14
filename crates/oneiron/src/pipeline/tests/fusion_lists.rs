//! EMBED-PACK (owner ruling, 2026-10-14): the engine's merge rule stays (each
//! channel's list z-scored on its own, a missed candidate taking the list's
//! lowest z, the z values added), with two fixes and a pinned list length.
//! A phonetic list counts matches, so it is scored over every candidate, and
//! the no-match floors are keyed by embedding space and kind. Design:
//! embedder-config DESIGN §1.5.

use super::*;
use crate::config::VectorEvidenceFloors;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};

const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

/// A unit vector at `cosine` to [`QUERY`].
fn at(cosine: f32) -> [f32; 4] {
    [cosine, (1.0 - cosine * cosine).sqrt(), 0.0, 0.0]
}

fn floors(floor: f32, strong: f32) -> VectorEvidenceFloors {
    VectorEvidenceFloors { floor, strong }
}

/// Bug repro (DESIGN §1.5 item 5): the phonetic list holds only its hits, at
/// 1.0 per matched code, and z over the hits alone gave every one-code hit a
/// z of 0, the same lowest z a candidate it missed takes. A misspelled name
/// that matched one code could never lift its row over a row with no match.
#[test]
fn a_one_code_phonetic_hit_outranks_a_row_with_no_match() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    // Same words, so the text channel ties them; an id-order tie puts the
    // row with no match first.
    let (missed, matched) = (entity_id(0x43), entity_id(0x44));
    for id in [missed, matched] {
        let mut batch = vault
            .batch()
            .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .text(&id, &[("body", "the harbour lantern")]);
        if id == matched {
            batch = batch.phonetic(&id, &["LNTRN"]);
        }
        batch.commit()?;
    }

    let results = vault
        .query()
        .search_text("lantern", 10)
        .search_phonetic(&["LNTRN"])
        .run()?;

    assert_eq!(
        results.iter().map(|row| row.id).collect::<Vec<_>>(),
        [matched, missed]
    );
    assert!(results[0].score > results[1].score, "{results:?}");
    Ok(())
}

/// Done-means (DESIGN §1.5 item 4): fusion scores each list at a fixed
/// length of about 80, separate from the pack limit, and the run records
/// it. A run that asks for 5 rows records 80 in its trace and its replay
/// inputs, and its fork key covers it.
#[test]
fn a_run_records_the_fusion_list_length_whatever_its_limit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for byte in 0x50..0x58 {
        put_text_and_vector(&vault, entity_id(byte), "a brass lantern hook", at(0.9))?;
    }

    let (run_id, trace) = captured_retrieval_run_trace(
        &vault,
        vault
            .query()
            .search_text("lantern", 5)
            .search_vector(&QUERY, 5)
            .limit(5),
    )?;

    assert_eq!(trace.fusion_list_length, 80);
    let config = vault
        .retrieval_run(run_id)?
        .and_then(|run| run.replay_inputs)
        .expect("replay inputs")
        .config;
    assert_eq!(config["fusion"]["list_length"], 80, "{config}");
    assert_eq!(config["fusion"]["sparse"], serde_json::json!(["phonetic"]));
    Ok(())
}

/// Done-means (DESIGN §1.5 item 6): RET-01's no-match floors are keyed by
/// embedding space and kind. Two vaults hold the same table, one row per
/// space; a 0.29 paraphrase is a match in the space whose floor is 0.15 and
/// no match in the one whose floor is 0.35, the opposite of what each
/// vault's own pair says. A space with floors for another kind only judges
/// this kind by the pair.
#[test]
fn a_score_is_judged_by_its_own_space_and_kind() -> Result<()> {
    let (wide, compressed) = ("test/wide@v1", "test/compressed@v1");
    for (space, pair, table, found) in [
        (
            compressed,
            VectorEvidenceFloors::default(),
            [
                (compressed, ENTITY_TYPE_TURN, floors(0.15, 0.25)),
                (wide, ENTITY_TYPE_TURN, floors(0.35, 0.5)),
            ],
            true,
        ),
        (
            wide,
            floors(0.15, 0.25),
            [
                (compressed, ENTITY_TYPE_TURN, floors(0.15, 0.25)),
                (wide, ENTITY_TYPE_TURN, floors(0.35, 0.5)),
            ],
            false,
        ),
        (
            compressed,
            VectorEvidenceFloors::default(),
            [
                (compressed, ENTITY_TYPE_CLAIM, floors(0.15, 0.25)),
                (wide, ENTITY_TYPE_TURN, floors(0.15, 0.25)),
            ],
            false,
        ),
    ] {
        let mut config = embedding_test_config();
        config.embedding_model = Some(space.to_owned());
        config.vector_evidence = pair;
        let (_dir, vault) = crate::test_util::open_test_vault_with(config);
        for (keyed_space, kind, kind_floors) in table {
            vault.set_vector_evidence_for(keyed_space, kind, kind_floors)?;
        }
        let target = entity_id(0x3C);
        put_text_and_vector(
            &vault,
            target,
            "the mechanic says the automobile needs new brakes",
            at(0.29),
        )?;
        put_text_and_vector(
            &vault,
            entity_id(0x3D),
            "renew the passport before october",
            at(0.12),
        )?;

        let pack = vault
            .context_pack()
            .search_text("who fixes my car", 10)
            .search_vector(&QUERY, 10)
            .run()?;

        assert_eq!(
            pack.results.first().map(|entity| entity.id) == Some(target),
            found,
            "{space} {pair:?} {table:?}: {:?}",
            pack.empty
        );
    }
    Ok(())
}

/// The keyed floors decide what a run returns, so they key its replay: a
/// change to the floors of a kind in the run's space changes the fork key,
/// and the replay inputs record them.
#[test]
fn a_kind_floor_in_the_runs_space_keys_the_replay() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_text_and_vector(
        &vault,
        entity_id(0x3E),
        "the mechanic says the automobile needs new brakes",
        at(0.29),
    )?;
    let space = vault.evidence_space().to_owned();

    let mut keys = Vec::new();
    for kind_floors in [floors(0.15, 0.25), floors(0.2, 0.25)] {
        vault.set_vector_evidence_for(&space, ENTITY_TYPE_TURN, kind_floors)?;
        let (run_id, trace) = captured_retrieval_run_trace(
            &vault,
            vault
                .query()
                .search_text("who fixes my car", 10)
                .search_vector(&QUERY, 10)
                .limit(10),
        )?;
        let config = vault
            .retrieval_run(run_id)?
            .and_then(|run| run.replay_inputs)
            .expect("replay inputs")
            .config;
        let recorded = &config["vector_evidence"];
        assert_eq!(recorded["space"], space.as_str(), "{config}");
        assert_eq!(recorded["kinds"][0]["entity_type"], ENTITY_TYPE_TURN);
        assert_eq!(
            recorded["kinds"][0]["floor"].as_f64().map(|v| v as f32),
            Some(kind_floors.floor),
            "{config}"
        );
        keys.push(trace.fork_hash);
    }

    assert_ne!(keys[0], keys[1], "a kind's floor keys the replay");
    Ok(())
}
