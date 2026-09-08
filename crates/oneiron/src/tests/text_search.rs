//! Full-text index maintenance across local/replicated re-put and lifecycle transitions.

use super::*;

/// ONE-1118 AC3 round-trip at the vault level (ARCH-0031 dispatch row
/// "Emoji / unknown → Grapheme per token"): an emoji-only doc is
/// retrievable by an emoji-only query, and a multi-codepoint ZWJ cluster
/// indexes as exactly ONE token — a member-emoji query must not match it.
#[test]
fn emoji_doc_round_trips_through_text_search() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let crab_doc = EntityId::now();
    let family_doc = EntityId::now();
    let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}"; // 👨‍👩‍👧‍👦

    vault
        .batch()
        .put(&crab_doc, 1, test_time_range(1, 1), 1, b"emoji-crab")
        .text(&crab_doc, &[("body", "🦀🔥")])
        .put(&family_doc, 1, test_time_range(2, 2), 2, b"emoji-family")
        .text(&family_doc, &[("body", family)])
        .commit()?;

    // AC3: doc "🦀🔥" retrievable by query "🦀".
    let hits = vault.search_text("🦀", 10)?;
    assert!(
        hits.iter().any(|h| h.id == crab_doc),
        "emoji-only query must retrieve the emoji doc"
    );

    // A member emoji of the ZWJ cluster must NOT match: the cluster is one
    // token. A codepoint-per-token implementation would match here.
    let hits = vault.search_text("\u{1F468}", 10)?;
    assert!(
        !hits.iter().any(|h| h.id == family_doc),
        "ZWJ member emoji must not match the whole-cluster token"
    );

    // The whole-cluster query does match.
    let hits = vault.search_text(family, 10)?;
    assert!(
        hits.iter().any(|h| h.id == family_doc),
        "whole-cluster query must retrieve the ZWJ doc"
    );
    Ok(())
}

/// ONE-1118 AC4: a populated text index stamped by the previous analyzer
/// version must fail closed at `Vault::open` with `IncompatibleAnalyzer` —
/// never silently reopen and score v3 queries against postings written by
/// the emoji-dropping v2 tokenizer. The stored manifest is rewritten to be
/// byte-identical to the current one except `analyzer_version: "v2"`, with
/// a matching (self-consistent) hash, so ONLY the version bump trips the
/// handshake.
#[test]
fn populated_v2_analyzer_manifest_fails_closed_on_open() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path();

    {
        let vault = Vault::open(path, test_config())?;
        let id = EntityId::now();
        vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 1, b"emoji-handshake")
            .text(&id, &[("body", "emoji handshake corpus 🦀")])
            .commit()?;

        let mut wtxn = vault.store.env.write_txn()?;
        let stored = vault
            .store
            .vault_meta
            .get(&wtxn, crate::store::TEXT_ANALYZER_MANIFEST_KEY)?
            .expect("populated vault must have a stored analyzer manifest")
            .to_vec();
        let mut manifest: AnalyzerManifest =
            serde_json::from_slice(&stored).expect("stored manifest must parse");
        assert_eq!(manifest.analyzer_version, ANALYZER_VERSION);
        assert_eq!(manifest.analyzer_version, "v3");
        manifest.analyzer_version = "v2".to_owned();
        let json = manifest.canonical_json().expect("canonical json");
        let hash = manifest.canonical_hash().expect("canonical hash");
        vault.store.vault_meta.put(
            &mut wtxn,
            crate::store::TEXT_ANALYZER_MANIFEST_KEY,
            json.as_bytes(),
        )?;
        vault.store.vault_meta.put(
            &mut wtxn,
            crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY,
            &hash,
        )?;
        wtxn.commit()?;
    }

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("v2-stamped populated index must fail closed on open"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), ErrorKind::IncompatibleAnalyzer);
    Ok(())
}

/// ONE-1168: a local body-changing re-put without a covering `BatchOp::Text`
/// must drop the old full-text projection in the same transaction as the
/// entity overwrite.
#[test]
fn local_overwrite_changed_body_without_text_drops_stale_text_postings_same_txn() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"payload-from-old-local")?;
    vault
        .batch()
        .text(&id, &[("body", "alpha_stale_xyz")])
        .commit()?;
    assert_eq!(
        vault.search_text("alpha_stale_xyz", 10)?.len(),
        1,
        "precondition: the old term must be indexed and searchable"
    );

    vault.put_entity(&id, 1, test_time_range(2, 2), 2, b"payload-from-new-local")?;

    let raw = vault.get_raw(&id)?.expect("entity stored");
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        b"payload-from-new-local"
    );
    assert!(
        vault.search_text("alpha_stale_xyz", 10)?.is_empty(),
        "old body's postings must not match searches after a local overwrite"
    );
    assert_text_rows_deindexed(&vault, &id)?;
    assert_empty_text_corpus_after_deindex(&vault)
}

#[test]
fn retract_claim_lifecycle_reput_drops_stale_text_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let id = put_active_claim(&vault, &subject, "profile.status", "active", 1)?;
    vault
        .batch()
        .text(&id, &[("body", "retract_lifecycle_stale_xyz")])
        .commit()?;
    assert_eq!(
        vault.search_text("retract_lifecycle_stale_xyz", 10)?.len(),
        1,
        "precondition: the active claim's term must be indexed and searchable"
    );

    vault.retract_claim(&id, 2_000)?;

    assert_eq!(
        vault
            .get_claim(&id)?
            .expect("retracted claim must stay readable")
            .lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert!(
        vault
            .search_text("retract_lifecycle_stale_xyz", 10)?
            .is_empty(),
        "Vault::retract_claim must deindex stale postings from its lifecycle re-put"
    );
    assert_text_rows_deindexed(&vault, &id)?;
    assert_empty_text_corpus_after_deindex(&vault)
}

#[test]
fn local_overwrite_same_body_replay_without_text_keeps_text_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"stable-local-payload")?;
    vault
        .batch()
        .text(&id, &[("body", "stable_replay_xyz")])
        .commit()?;
    let forward_before = text_forward_row(&vault, &id)?;

    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"stable-local-payload")?;

    assert_eq!(
        vault.search_text("stable_replay_xyz", 10)?.len(),
        1,
        "same-bytes local replay must leave postings serving"
    );
    assert_eq!(
        text_forward_row(&vault, &id)?,
        forward_before,
        "same-bytes local replay must not rewrite the forward row"
    );
    Ok(())
}

#[test]
fn local_metadata_only_reput_without_text_keeps_text_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"metadata-stable-payload")?;
    vault
        .batch()
        .text(&id, &[("body", "metadata_only_xyz")])
        .commit()?;
    let forward_before = text_forward_row(&vault, &id)?;

    vault.put_entity(&id, 1, test_time_range(5, 7), 9, b"metadata-stable-payload")?;

    assert_eq!(
        vault.search_text("metadata_only_xyz", 10)?.len(),
        1,
        "metadata-only local re-put must leave postings serving"
    );
    assert_eq!(
        text_forward_row(&vault, &id)?,
        forward_before,
        "metadata-only local re-put must not rewrite the forward row"
    );

    let err = vault
        .put_entity(
            &id,
            1,
            test_time_range(9, 8),
            10,
            b"metadata-stable-payload",
        )
        .expect_err("reversed time range must still fail before mutation");
    assert_matches!(err, Error::InvalidTimeRange { start: 9, end: 8 });
    assert_eq!(
        vault.search_text("metadata_only_xyz", 10)?.len(),
        1,
        "failed metadata write must leave postings serving"
    );
    Ok(())
}

#[test]
fn local_changed_body_with_text_op_reindexes_new_terms() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"body-before-text")?;
    vault
        .batch()
        .text(&id, &[("body", "old_term_xyz")])
        .commit()?;

    vault
        .batch()
        .put(&id, 1, test_time_range(2, 2), 2, b"body-after-text")
        .text(&id, &[("body", "new_term_xyz")])
        .commit()?;

    assert!(
        vault.search_text("old_term_xyz", 10)?.is_empty(),
        "Text op self-deindex must remove the old term"
    );
    assert_eq!(
        vault.search_text("new_term_xyz", 10)?.len(),
        1,
        "Text op must leave the new term indexed"
    );
    Ok(())
}

#[test]
fn batch_put_text_put_deindexes_text_from_non_final_body() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let other = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(0, 0), 0, b"payload-body-v0")?;
    vault
        .batch()
        .text(&id, &[("body", "body_v0_unique_xyz")])
        .commit()?;
    vault
        .batch()
        .put(&other, 1, test_time_range(1, 1), 1, b"unrelated-payload")
        .text(&other, &[("body", "unrelated_survives_xyz")])
        .commit()?;

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 1), 1, b"payload-body-v1")
        .text(&id, &[("body", "body_v1_unique_xyz")])
        .put(&id, 1, test_time_range(2, 2), 2, b"payload-body-v2")
        .commit()?;

    let raw = vault.get_raw(&id)?.expect("entity stored");
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], b"payload-body-v2");
    assert!(
        vault
            .search_text("body_v0_unique_xyz", 10)?
            .iter()
            .all(|hit| hit.id != id),
        "Text rows from the pre-existing body must not retrieve the entity"
    );
    assert!(
        vault
            .search_text("body_v1_unique_xyz", 10)?
            .iter()
            .all(|hit| hit.id != id),
        "Text rows for the non-final body must not retrieve the entity"
    );
    assert_eq!(
        vault.search_text("unrelated_survives_xyz", 10)?.len(),
        1,
        "per-entity stale deindex must leave unrelated postings intact"
    );
    assert_text_rows_deindexed(&vault, &id)?;

    vault
        .batch()
        .text(&id, &[("body", "body_v2_unique_xyz")])
        .commit()?;
    assert!(
        vault
            .search_text("body_v2_unique_xyz", 10)?
            .iter()
            .any(|hit| hit.id == id),
        "final-body text remains indexable after the stale projection is removed"
    );
    assert!(
        vault
            .search_text("body_v1_unique_xyz", 10)?
            .iter()
            .all(|hit| hit.id != id),
        "reindexing final-body text must not resurrect non-final terms"
    );
    Ok(())
}

/// ONE-1141 (ARCH-0031 amendment, ratified 2026-06-13): "When an LWW
/// replicated overwrite replaces a document, the loser document's postings
/// must be removed in the same transaction as the overwrite — no replicated
/// overwrite ever leaves loser postings live."
///
/// Directed batch-level unit for the sync replay doors (`put_replicated` →
/// `apply_put`, replicated arm): text-index term A, replicated-overwrite the
/// entity with body B inside ONE write txn, then assert the loser's text
/// rows are gone at the DB level — mirroring exactly what SoftErase's
/// `deindex_text` leaves behind (`text_forward` / `text_meta` /
/// `text_doc_field_lengths` rows deleted under the literal id-bytes key, the
/// posting row dropped with its last duplicate, the per-field stats row
/// deleted at zero, and the TOTAL_DOCS sentinel row decremented back to 0).
#[cfg(feature = "sync")]
#[test]
fn replicated_overwrite_changed_body_drops_loser_text_postings_same_txn() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"payload-from-loser")?;
    vault
        .batch()
        .text(&id, &[("body", "loseronlyterm")])
        .commit()?;
    assert_eq!(
        vault.search_text("loseronlyterm", 10)?.len(),
        1,
        "precondition: the loser term must be indexed and searchable"
    );

    // Replicated overwrite with a CHANGED body through the Observer-B replay
    // door (`TxnBatchBuilder::put_replicated`) — overwrite + deindex must
    // land in the SAME externally-owned wtxn.
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_replicated(&id, 1, test_time_range(2, 2), 2, b"payload-from-winner")
            .apply(wtxn)
    })?;

    // The winner body is stored (header + body layout, body at offset 25)…
    let raw = vault.get_raw(&id)?.expect("entity stored");
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], b"payload-from-winner");
    // …and the loser term no longer serves.
    assert!(
        vault.search_text("loseronlyterm", 10)?.is_empty(),
        "loser postings must not match searches after a replicated overwrite"
    );

    // DB-level: identical end-state to SoftErase's deindex.
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .text_forward
            .get(&rtxn, id.as_bytes())?
            .is_none(),
        "text_forward row (key = literal id bytes) must be deleted"
    );
    assert!(
        vault.store.text_meta.get(&rtxn, id.as_bytes())?.is_none(),
        "text_meta doc row (key = literal id bytes) must be deleted"
    );
    assert!(
        vault
            .store
            .text_doc_field_lengths
            .get(&rtxn, id.as_bytes())?
            .is_none(),
        "text_doc_field_lengths row (key = literal id bytes) must be deleted"
    );
    // This doc was the only indexed document: dropping its last duplicate
    // removes the posting term key entirely, and the zeroed per-field stats
    // row is deleted rather than kept at 0/0.
    assert!(
        vault.store.text_postings.iter(&rtxn)?.next().is_none(),
        "no posting row may survive the loser's deindex"
    );
    assert!(
        vault
            .store
            .text_bm25_field_stats
            .iter(&rtxn)?
            .next()
            .is_none(),
        "the zeroed per-field stats row must be deleted, not kept at 0/0"
    );
    // TOTAL_DOCS sentinel ([0x00; 16] key in text_meta, u32 LE value): the
    // corpus count is decremented back to 0, never left dangling at 1.
    assert_eq!(
        vault.store.text_meta.get(&rtxn, &[0u8; 16])?.as_deref(),
        Some(&0u32.to_le_bytes()[..]),
        "TOTAL_DOCS must be decremented in the same txn as the overwrite"
    );
    Ok(())
}

/// ONE-1141 byte-compare guard + scope pin. Two non-deindexing overwrites:
///
/// * SAME-BYTES replicated overwrite (idempotent re-import / reconnect echo,
///   or the winner node re-receiving its own winning value during a
///   convergence exchange) must NOT touch the text index — postings keep
///   serving and the `text_forward` row stays byte-identical. Metadata-only
///   changes (occurred/learned) are NOT body changes.
/// * ONE-1168 widens stale-posting cleanup to LOCAL body-changing overwrites
///   that have no covering same-batch `BatchOp::Text`; same-bytes replay and
///   metadata-only changes remain guarded by the body byte compare.
#[cfg(feature = "sync")]
#[test]
fn replicated_overwrite_same_body_bytes_keeps_text_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"stable-payload")?;
    vault
        .batch()
        .text(&id, &[("body", "winneronlyterm")])
        .commit()?;

    let forward_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .text_forward
            .get(&rtxn, id.as_bytes())?
            .map(|value| value.to_vec())
            .expect("precondition: forward row exists for the indexed doc")
    };

    // Same body bytes, different temporal metadata, through the
    // forward_rematerialize replay door (`BatchBuilder::put_replicated`).
    vault
        .batch()
        .put_replicated(&id, 1, test_time_range(5, 7), 9, b"stable-payload")
        .commit()?;

    assert_eq!(
        vault.search_text("winneronlyterm", 10)?.len(),
        1,
        "a same-bytes replicated replay must leave postings serving"
    );
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .text_forward
                .get(&rtxn, id.as_bytes())?
                .map(|value| value.to_vec()),
            Some(forward_before),
            "the forward row must be byte-identical after a same-bytes replay"
        );
    }

    // ONE-1168: a LOCAL body-changing overwrite with no Text op now deindexes
    // stale postings while preserving the same-bytes replicated replay guard
    // above.
    vault.put_entity(&id, 1, test_time_range(8, 8), 11, b"locally-edited-payload")?;
    assert!(
        vault.search_text("winneronlyterm", 10)?.is_empty(),
        "local body-changing overwrite without Text must deindex stale postings"
    );
    Ok(())
}
