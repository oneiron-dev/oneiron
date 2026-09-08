//! P5 ONE-1730 promote tests, the P6 ONE-1731 fence-symbol census and the P7 ONE-1732 storage-ABI gate.

use crate::error::Result;

use super::seam;
use super::tests_substrate::{full_db_census, temp_vault};

// ─── P5 · ONE-1730 — promote: typed-journal replay in one txn ────────────

/// §4 master promote: exactly ONE turn's subgraph replays into base;
/// sibling turns stay evaporable.
#[test]
fn promote_replays_exactly_one_turn_subgraph() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-promote").expect("enter session");
    session.bind_actor()?;
    let (turn_a, msg_a, summary_a) = session.witness_turn("promoted turn")?;
    let (turn_b, _msg_b, _summary_b) = session.witness_turn("stays in the room")?;
    let shell_a = session.session_shell_for_turn(&turn_a)?;
    let outcome = session.promote_turn(&turn_a)?;
    // Exact closure IDENTITY (codex F9): the turn, its PartOf MESSAGE, its
    // DerivedFrom SUMMARY, and the fresh conversation shell — these four
    // ids and no others.
    let mut replayed = outcome.replayed;
    replayed.sort_unstable();
    let mut expected_closure = vec![turn_a, msg_a, summary_a, shell_a];
    expected_closure.sort_unstable();
    assert_eq!(
        replayed, expected_closure,
        "promoted closure must be exactly {{turn, message, summary, shell}}"
    );
    // Every promoted entity lands with its journaled KIND.
    assert_eq!(
        vault.get_entity_type(&turn_a)?,
        Some(crate::registry::ENTITY_TYPE_TURN)
    );
    assert_eq!(
        vault.get_entity_type(&msg_a)?,
        Some(crate::registry::ENTITY_TYPE_MESSAGE)
    );
    assert_eq!(
        vault.get_entity_type(&summary_a)?,
        Some(crate::registry::ENTITY_TYPE_SUMMARY)
    );
    assert_eq!(
        vault.get_entity_type(&shell_a)?,
        Some(crate::registry::ENTITY_TYPE_CONVERSATION)
    );
    assert!(!vault.entity_exists(&turn_b)?, "sibling stays in-room");
    session.close()?;
    assert!(
        vault.entity_exists(&turn_a)?,
        "promoted content survives close"
    );
    Ok(())
}

/// §4 exact attribution-edge set: base gains the promoted turn's three
/// ratified attribution edges plus its structural `ChildOf(turn -> shell)` —
/// no extras, none missing.
///
/// The room ALSO journals `AuthoredBy(message -> actor)` for a non-`System`
/// author, and that edge is deliberately NOT promoted: its target is a base
/// identity the closure does not own, so it points out of the subgraph the
/// user consented to publish. It stays in the overlay and evaporates at close.
#[test]
fn promote_attribution_edge_set_is_exact() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-edges").expect("enter session");
    // The witness door writes ONE base actor row, so bind BEFORE the census:
    // the delta below must charge the room for its own rows only.
    let actor = session.bind_actor()?;
    let edges_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.edges_out.len(&rtxn)?
    };
    let entities_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.entities.len(&rtxn)?
    };
    let (turn, msg, summary) = session.witness_turn("edge closure")?;
    let shell = session.session_shell_for_turn(&turn)?;
    session.promote_turn(&turn)?;
    let rtxn = vault.store.env.read_txn()?;
    // The FULL promoted edge set, every edge with exact endpoints
    // (codex F9): PartOf(msg -> turn), DerivedFrom(summary -> turn),
    // BelongsTo(msg -> shell), and ChildOf(turn -> shell) — and nothing else.
    assert_eq!(
        vault.store.edges_out.len(&rtxn)? - edges_before,
        4,
        "three attribution edges plus the structural ChildOf replay — no extras"
    );
    // Base census delta == exactly the promoted subgraph: 4 entities in,
    // 4 edges each direction (three attribution edges plus structural ChildOf),
    // nothing else entity/edge-shaped.
    assert_eq!(
        vault.store.entities.len(&rtxn)? - entities_before,
        4,
        "exactly the four closure entities persist"
    );
    assert_eq!(
        vault.store.edges_in.len(&rtxn)? - edges_before,
        4,
        "the reverse-edge mirror carries the same four edges"
    );
    drop(rtxn);
    assert_eq!(
        vault.targets(&msg, crate::edge::EdgeKind::PartOf, None)?,
        vec![turn]
    );
    assert_eq!(
        vault.targets(&summary, crate::edge::EdgeKind::DerivedFrom, None)?,
        vec![turn]
    );
    assert_eq!(
        vault.targets(&msg, crate::edge::EdgeKind::BelongsTo, None)?,
        vec![shell],
        "the message belongs to exactly the fresh conversation shell"
    );
    assert!(
        vault
            .targets(&msg, crate::edge::EdgeKind::AuthoredBy, None)?
            .is_empty(),
        "the authorship edge leaves the closure and must not reach base"
    );
    assert!(
        vault
            .sources(&actor, crate::edge::EdgeKind::AuthoredBy, None)?
            .is_empty(),
        "the actor gains no promoted in-edge"
    );
    session.close()?;
    Ok(())
}

/// D4: promote selects from the TYPED journal, never raw index keys —
/// shared index keys (a term both turns used) must not drag the sibling.
///
/// The shared term rides the MESSAGE of each turn and nothing else: the
/// summaries deliberately do not repeat it, so the hit count answers "whose
/// turn was promoted" rather than "how many documents does a turn make".
#[test]
fn promote_selects_from_typed_journal_not_raw_index_keys() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-journal").expect("enter session");
    session.bind_actor()?;
    let (turn_a, _m, _s) = session.witness_turn_with_summary("sharedterm alpha", "alpha recap")?;
    let (turn_b, _m2, _s2) = session.witness_turn_with_summary("sharedterm beta", "beta recap")?;
    session.promote_turn(&turn_a)?;
    let hits = vault.search_text("sharedterm", 10)?;
    assert_eq!(
        hits.len(),
        1,
        "the shared term must surface exactly the promoted turn's doc"
    );
    assert!(!vault.entity_exists(&turn_b)?);
    session.close()?;
    Ok(())
}

/// ONE-1730: promote retry is idempotent — a second promote of the same
/// turn changes nothing in base.
#[test]
fn promote_is_idempotent_on_retry() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-retry").expect("enter session");
    session.bind_actor()?;
    let (turn, _m, _s) = session.witness_turn("promote twice")?;
    let first = session.promote_turn(&turn)?;
    let census_after_first = full_db_census(&vault)?;
    // ONE-1730 acceptance "idempotent retry": the SECOND promote must
    // succeed (an impl that errors on retry fails here) and return the
    // identical outcome — same closure, same temp->canonical mapping.
    let second = session
        .promote_turn(&turn)
        .expect("idempotent retry must return Ok, not an error");
    assert_eq!(
        second, first,
        "the retry must return the first call's exact outcome"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_after_first,
        "a promote retry must not duplicate a single base row"
    );
    session.close()?;
    Ok(())
}

/// D4: learned_at is preserved from the journal (correct month window).
#[test]
fn promote_preserves_learned_at_from_journal() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-learned").expect("enter session");
    session.bind_actor()?;
    let in_room_learned_at = 1_234_567; // the seam pins the room clock here
    let (turn, _m, _s) = session.witness_turn_at("timestamped in-room", in_room_learned_at)?;
    session.promote_turn(&turn)?;
    assert_eq!(
        vault.get_learned_at(&turn)?,
        in_room_learned_at,
        "learned_at must ride the journal into base unchanged"
    );
    session.close()?;
    Ok(())
}

/// D4/R6: the promote txn commits subgraph + receipt + pm: markers as ONE
/// transaction — a crash right after commit still leaves the pickup marker
/// AND the full promoted subgraph (single-txn contract). The seam owns the
/// whole sequence so the session is LIVE at promote time (grok F6).
///
/// `sync`-gated because the artifact under test is one: `pm:` pickup markers
/// only exist on a sync build, so on a non-sync build this would assert the
/// absence of a feature rather than a defect. The single-transaction claim it
/// shares with the rest of the promote suite is covered feature-free by
/// `promote_replays_exactly_one_turn_subgraph`.
#[cfg(feature = "sync")]
#[test]
fn promote_crash_post_commit_leaves_pm_pickup_marker() -> Result<()> {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (reopened, closure, pm_markers) = seam::promote_then_crash_post_commit(tmp.path())?;
    assert_eq!(
        pm_markers, 1,
        "exactly one pm: marker per source window survives the crash"
    );
    assert_eq!(
        closure.len(),
        4,
        "the promote txn carried the full four-entity closure"
    );
    for id in &closure {
        assert!(
            reopened.entity_exists(id)?,
            "single-txn contract: every closure entity survives the crash"
        );
    }
    Ok(())
}

// ─── P6 · ONE-1731 — fence deletion sweep ────────────────────────────────

/// Acceptance: the fence-symbol census over the crate source returns ZERO
/// hits now that the P6 sweep has landed. Grep-shaped by design (the census IS
/// the contract); the count assertion lists every hit on failure.
///
/// The list is the ONE-1731 done-means repository-audit list verbatim — the ten
/// named symbols plus the three deleted typed error variants — extended during
/// the rebase with the durable-row constructors and vault-open apparatus the
/// sweep removed alongside them (`OFF_RECORD_OPEN_LOCK_FILE`,
/// `sweep_orphaned_off_record_fences`, `ensure_no_open_off_record_session`,
/// `tag_turn_off_record`). No inherited-fence symbol was found on the rebased
/// tree; its name stays pinned so a re-introduction fails here.
#[test]
fn fence_symbol_census_returns_zero_hits() {
    const FENCE_SYMBOLS: [&str; 16] = [
        "offrecord_fence:",
        "offrecord_inherited_fence",
        "off_record_fence_active",
        "off_record_visibility_hidden",
        "guard_off_record_",
        "off_record_fences_present",
        "OFF_RECORD_SESSION_MARKER_LINE",
        "scrub_off_record_fenced_carriers",
        "is_turn_off_record_fenced",
        "OffRecordTurnNotFenced",
        "OffRecordFencedTurnWriteRejected",
        "OffRecordExportRefused",
        "OFF_RECORD_OPEN_LOCK_FILE",
        "sweep_orphaned_off_record_fences",
        "ensure_no_open_off_record_session",
        "tag_turn_off_record",
    ];
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits: Vec<String> = Vec::new();
    let mut stack = vec![src_root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // The census excludes this oracle file itself: its symbol list
            // must not count as fence residue.
            if path.ends_with("branch_store_oracle/tests_promote.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            for symbol in FENCE_SYMBOLS {
                let count = text.matches(symbol).count();
                if count > 0 {
                    hits.push(format!("{}: {symbol} x{count}", path.display()));
                }
            }
        }
    }
    assert_eq!(
        hits.len(),
        0,
        "fence symbols must be fully deleted by the P6 sweep:\n{}",
        hits.join("\n")
    );
}

// ─── P7 · ONE-1732 — the previous ABI fails closed ───────────────────────

/// D9: a vault stamped at an older storage ABI version fails CLOSED on an
/// engine carrying the current one — no silent migration, no legacy decode;
/// typed ABI-gate error.
///
/// ONE-1754 narrowed D9 by exactly one value rather than repealing it. The
/// immediate predecessor now routes to the byte-space v3 re-key (the
/// panel-adjudicated carve-out: the strict gate would otherwise refuse every
/// pre-1754 vault BEFORE the re-key that makes it current could run, so the
/// rebuild policy would have no way to become true). Every OTHER stamp still
/// fails closed, which is what this oracle measures. Versions are DERIVED from
/// `STORAGE_ABI_VERSION`, so the next bump cannot leave a stale literal here.
#[test]
fn storage_abi_older_vault_fails_closed_on_current_engine() {
    let current = crate::store::STORAGE_ABI_VERSION;
    let older = current
        .checked_sub(2)
        .expect("the current storage ABI version has an older-than-predecessor");
    let tmp = tempfile::tempdir().expect("temp dir");
    // The empty directory stamps the OLDER version; the reopen below runs the
    // CURRENT one against that stamp.
    assert!(
        seam::open_with_abi_pair(tmp.path(), older, older).is_ok(),
        "fixture vault must open at the older ABI version"
    );
    let reopened = seam::open_with_abi_pair(tmp.path(), older, current);
    assert_eq!(
        reopened.err(),
        Some(seam::SeamError::AbiFailClosed),
        "an older-version vault must fail closed at the current ABI gate (rebuild policy)"
    );
}
