//! P3 ONE-1727 session-lifecycle tests and the P4a ONE-1728 reader-visibility, embedding-rule and taint-guard tests.

use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

use super::seam;
use super::tests_substrate::{full_db_census, seed_base_turn, temp_vault};

// ─── P3 · ONE-1727 — session lifecycle ────────────────────────────────────

/// R1: direct substrate writes and typed-journal entries are process-local.
/// Dropping every handle without close simulates a crash: reopening the same
/// path must show exact census equality across all 28 base DBs, and the
/// process-local session ref must be free for reuse.
#[test]
fn direct_substrate_crash_evaporation_leaves_zero_base_residue() -> Result<()> {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    let census_before = full_db_census(&vault)?;
    let session = seam::SessionVault::enter(&vault, "oracle-native-crash").expect("enter session");
    assert_eq!(
        seam::stage_direct_crash_payload(&session)?,
        (2, 1, 1, 2),
        "the crash fixture must contain exact overlay rows and journal ops"
    );

    drop(session);
    drop(vault);

    let reopened = Vault::open(tmp.path(), VaultConfig::default()).expect("reopen vault");
    assert_eq!(
        full_db_census(&reopened)?,
        census_before,
        "direct session writes must leave zero residue in all 28 base databases"
    );
    assert!(
        seam::SessionVault::enter(&reopened, "oracle-native-crash").is_ok(),
        "the evaporated session ref must read as free after reopen"
    );
    Ok(())
}

/// §4 master close test: transcript + context receipts deleted, floor
/// receipts kept (RECEIPTS-FOLLOW-TRANSCRIPT).
///
/// Both halves of the contract run in ONE room, because they are one
/// contract: close must delete the transcript AND spare the floor. A room
/// with no floor crossing proves only that close deletes — a close that
/// evaporated the floor along with everything else would pass it. So the
/// room makes exactly one durable crossing (`FloorWrites`, K1 op 1/3)
/// immediately before close, and the assertion is `floor_receipts_kept == 1`
/// while the transcript and receipt counts continue to hold.
#[test]
fn master_close_deletes_transcript_and_context_receipts_keeps_floor_receipts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-close").expect("enter session");
    // The witness door requires a base-resident actor, so bind it BEFORE the
    // baseline: the room must be charged for its own rows, not for its actor.
    session.bind_actor()?;
    let base_before = full_db_census(&vault)?;
    let (_turn, _msg, _summary) = session.witness_turn("close me")?;
    let _hits = session.search_text("close", 5)?;

    // ONE floor crossing, last thing before close: the row is durable by
    // design and is exactly what must NOT follow the transcript out.
    let floor_before = vault.store.gate_decisions(1_000)?.len();
    session.append_floor_egress_decision()?;
    assert_eq!(
        vault.store.gate_decisions(1_000)?.len(),
        floor_before + 1,
        "the crossing landed exactly one durable decision row"
    );

    let (transcript_deleted, context_receipts_deleted, floor_receipts_kept) = session.close()?;
    assert_eq!(transcript_deleted, 3, "turn + message + summary evaporate");
    assert_eq!(
        context_receipts_deleted, 1,
        "the retrieval-run receipt follows"
    );
    assert_eq!(
        floor_receipts_kept, 1,
        "the floor crossing SURVIVES the close that evaporated the room \
         around it — receipts follow the transcript, floor rows do not"
    );

    // Base is the baseline PLUS exactly the floor row: one `vault_meta` row
    // (this decision carries no grant_ref and no claim_id, so it writes no
    // index rows). Everything the room itself wrote is gone.
    let base_after = full_db_census(&vault)?;
    let mut expected = base_before;
    expected[11] += 1;
    assert_eq!(
        base_after, expected,
        "close leaves base as it was before the room, plus the one floor row"
    );
    Ok(())
}

/// §2/R4 crash = evaporation: dropping the process without close leaves
/// ZERO residue in any of the 28 base databases; the session reads as
/// not-found after reopen.
#[test]
fn crash_evaporation_leaves_zero_base_residue() -> Result<()> {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    let mut session = seam::SessionVault::enter(&vault, "oracle-crash").expect("enter session");
    session.bind_actor()?;
    let census_before = full_db_census(&vault)?;
    let (_turn, _msg, _summary) = session.witness_turn("evaporates")?;
    // THE CRASH: the session handle is dropped without `close()`, so no
    // close path, no evaporation bookkeeping, no receipt census runs.
    drop(session);
    let reopened = seam::crash_and_reopen(tmp.path(), vault)?;
    assert_eq!(
        full_db_census(&reopened)?,
        census_before,
        "no durable session trace may exist after a crash"
    );
    assert!(
        seam::SessionVault::enter(&reopened, "oracle-crash").is_ok(),
        "the session ref reads as free (not-found) after crash evaporation"
    );
    Ok(())
}

/// R10 kill-switch: `off_record_enabled = false` makes enter fail closed
/// with a typed error; no registry entry is created.
#[test]
fn kill_switch_makes_enter_fail_closed() {
    let (_tmp, vault) = temp_vault();
    let refused = seam::SessionVault::enter_with_kill_switch_off(&vault, "oracle-kill");
    assert_eq!(
        refused.err(),
        Some(seam::SeamError::KillSwitchDisabled),
        "enter must fail closed with the exact typed kill-switch refusal"
    );
}

/// §1a enter is single-shot per live session ref.
#[test]
fn enter_is_single_shot_per_session_ref() {
    let (_tmp, vault) = temp_vault();
    let _first = seam::SessionVault::enter(&vault, "oracle-single").expect("first enter");
    let second = seam::SessionVault::enter(&vault, "oracle-single");
    assert_eq!(
        second.err(),
        Some(seam::SeamError::SessionRefLive),
        "re-entering a live session ref must be the exact typed refusal"
    );
}

// ─── P4a · ONE-1728 — witness/retrieval, embedding rule, taint guard ─────

/// §4 base-leak sweep: every base reader family sees NOTHING of a populated
/// overlay. Family list mined from the wave-1 fence findings ledger:
/// `get_raw`-class raw reads FIRST (the R20 P1), then search/short-id (R14),
/// edge readers (R7), existence/enumeration + tree walks (R18),
/// `edge_exists` (R19), ScopedRead reads (R10), telemetry.
#[test]
fn base_leak_sweep_every_reader_family_sees_no_overlay_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let base_turn = seed_base_turn(&vault, 1_000);
    let mut session = seam::SessionVault::enter(&vault, "oracle-sweep").expect("enter session");
    let actor = session.bind_actor()?;
    let learned_before: std::collections::BTreeSet<_> = vault
        .entities_in_learned_range(0, u64::MAX)?
        .into_iter()
        .collect();
    let runs_before = vault.store.retrieval_runs(100)?.len();
    let short_id_rows_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.short_ids.len(&rtxn)?
    };
    let (turn, message, summary) = session.witness_turn("oraclesweepuniquetoken")?;

    // get_raw-class raw reads FIRST (ledger R20 P1: Vault::get_raw).
    assert_eq!(vault.get_raw(&turn)?, None, "get_raw must not see the room");
    assert_eq!(vault.get(&turn)?, None, "get must not see the room");
    assert!(vault.read_entity_header(&turn)?.is_none());

    // Existence / enumeration (ledger R18 family).
    assert!(!vault.entity_exists(&turn)?);
    assert!(vault.get_learned_at(&turn).is_err());
    let turns = vault.entities_by_type(crate::registry::ENTITY_TYPE_TURN)?;
    assert_eq!(
        turns,
        vec![base_turn],
        "type enumeration returns exactly the base turn"
    );
    // Baseline-relative, not absolute: `Vault::open` seeds its own rows (a
    // POLICY_MANIFEST among them), so the honest assertion is that the room
    // adds NOTHING to what base held before it — not that base holds some
    // hardcoded count.
    let learned: std::collections::BTreeSet<_> = vault
        .entities_in_learned_range(0, u64::MAX)?
        .into_iter()
        .collect();
    assert_eq!(
        learned, learned_before,
        "learned-range enumeration is unchanged by the room"
    );
    assert!(
        learned.contains(&actor) && learned.contains(&base_turn),
        "the baseline itself must still hold the seeded base rows"
    );

    // Edge readers + edge existence (ledger R7/R19 families).
    assert_eq!(
        vault
            .targets(&message, crate::edge::EdgeKind::PartOf, None)?
            .len(),
        0,
        "edge readers must not traverse session edges"
    );
    assert!(!vault.edge_exists(&message, crate::edge::EdgeKind::PartOf, &turn)?);

    // Tree walks (ledger R18: subtree/ancestors raw ChildOf walks).
    assert_eq!(vault.subtree(&turn, 4)?.len(), 0);
    assert_eq!(vault.ancestors(&turn)?.len(), 0);

    // Search (ledger R14 family). The token exists only in-room.
    assert_eq!(vault.search_text("oraclesweepuniquetoken", 10)?.len(), 0);

    // Short-id resolver (ledger R14 family): the room's session-local short
    // ref must not resolve through the BASE resolver, and the base
    // `short_ids` table must not have grown a row for it.
    let (session_short_id, session_hash) = session.session_short_ref(&turn)?;
    assert_eq!(
        vault
            .hydrate_short_id(&session_short_id, session_hash)?
            .map(|hydrated| hydrated.id),
        None,
        "session-local short ids must be invisible to the base resolver"
    );
    assert_eq!(
        {
            let rtxn = vault.store.env.read_txn()?;
            vault.store.short_ids.len(&rtxn)?
        },
        short_id_rows_before,
        "the base short_ids table must not grow from session allocations"
    );

    // ScopedRead family (ledger R10): a base-side scoped read surfaces zero
    // claims for the room's subject. The session side is asserted too — the
    // sweep's contract is "canonical sees base only, session sees the union",
    // and only checking the base half would also pass if the session handle
    // were blind.
    assert_eq!(
        seam::base_scoped_read_visible_claim_count(&vault, &turn)?,
        0,
        "base ScopedRead must surface zero claims for session content"
    );
    assert_eq!(
        session.session_scoped_read_visible_claim_count(&turn)?,
        0,
        "the room staged no claims, so its own ScopedRead surfaces none either"
    );

    // Telemetry: the base retrieval-run ledger gained EXACTLY the probe's
    // own row and nothing from the room. Base `search_text` persists one
    // retrieval-run row even for zero hits (pre-existing design oracle:
    // pipeline/tests.rs:973); ONE-1728's "retrieval-run rows land in the
    // overlay" governs SESSION-side reads only.
    assert_eq!(
        vault.store.retrieval_runs(100)?.len(),
        runs_before + 1,
        "base ledger delta must be exactly the base probe's own telemetry row"
    );

    // The union half: an IN-ROOM retrieval registers a row the room can read
    // back, while the base ledger above stays flat. Both directions matter —
    // "base gains nothing" alone would also hold if the row were dropped.
    let room_runs_before = session.retrieval_run_count()?;
    let _ = session.search_text("oraclesweepuniquetoken", 5)?;
    assert_eq!(
        session.retrieval_run_count()?,
        room_runs_before + 1,
        "a session retrieval registers exactly one overlay-local run row"
    );
    assert_eq!(
        vault.store.retrieval_runs(100)?.len(),
        runs_before + 1,
        "and the base telemetry ledger gains NOTHING from the in-room run"
    );

    // The summary carrier is equally invisible (fence transitivity class).
    assert_eq!(vault.get(&summary)?, None);

    session.close()?;
    Ok(())
}

/// Writes a CLAIM entity row plus its type-index row straight into base.
///
/// Bypassing every write door is the point: after the session door learned to
/// validate claim bodies (S1), a raw plant is the only way left to put a body
/// in the store that the validators would have refused — which is exactly the
/// state the census below has to be honest about.
fn plant_raw_claim_row(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<()> {
    let mut raw = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + body.len());
    raw.push(crate::registry::ENTITY_TYPE_CLAIM);
    raw.extend_from_slice(&1_u64.to_be_bytes()); // occurred.start
    raw.extend_from_slice(&1_u64.to_be_bytes()); // occurred.end
    raw.extend_from_slice(&1_u64.to_be_bytes()); // learned_at
    raw.extend_from_slice(body);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &raw)?;
        let type_key = crate::store::Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

/// The ScopedRead census SURFACES a claim body it cannot decode; it never
/// quietly lowers the count.
///
/// The count is EVIDENCE — the base and session halves of the R10 reader
/// family are compared for EQUALITY — so a silently partial count is worse
/// than no count at all: two halves that both drop the same unreadable row
/// report an agreement neither of them observed. `Err` is the only honest
/// answer to "how many claims are visible" when one of the rows cannot be
/// read at all.
#[test]
fn scoped_read_claim_census_surfaces_an_undecodable_body() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = seed_base_turn(&vault, 10);

    // Positive control FIRST: the census really does read bodies, so the
    // refusal below cannot pass vacuously on an empty enumeration.
    let legal = crate::claim::encode_claim_body(&crate::claim::ClaimBody::new(
        "dream.symbol",
        crate::claim::ClaimSubject::Entity(subject),
        rmpv::Value::from("a blue door"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    ))?;
    plant_raw_claim_row(&vault, &EntityId::now(), &legal)?;
    assert_eq!(
        seam::base_scoped_read_visible_claim_count(&vault, &subject)?,
        1,
        "the census must count a legal planted claim"
    );

    // A row whose header and type byte are both perfectly well formed and
    // whose BODY is not MessagePack at all.
    plant_raw_claim_row(&vault, &EntityId::now(), b"not a claim body")?;
    let refused = seam::base_scoped_read_visible_claim_count(&vault, &subject)
        .expect_err("an undecodable claim body must surface, never lower the count");
    assert_eq!(refused.kind(), crate::error::ErrorKind::InvalidClaimBody);
    Ok(())
}

/// D3 embedding rule: session flows never enqueue `pe:` markers or embed
/// job rows (base rows carrying raw text); generalized — no background
/// attempt rows reference overlay content.
///
/// The room stages a CLAIM, because CLAIM is the ONLY entity class the base
/// apply marks pending-embed (`batch.rs` op-loop CLAIM arm). A TURN/MESSAGE
/// witness alone would satisfy every assertion below even if the session path
/// enqueued freely, since neither type ever reaches the marker branch on
/// EITHER path — the test would be green for the wrong reason.
#[test]
fn no_pe_markers_or_embed_job_rows_for_session_content() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-embed").expect("enter session");
    session.bind_actor()?;
    let attempts_before = seam::attempt_row_counts(&vault)?;
    // No summary: the smallest witness program that still drives the session
    // write path, so nothing about this assertion rides on a second Text op.
    let (turn, message) = session.witness_turn_without_summary("embed me inline only")?;
    // The op the rule is actually about. Staged against the turn as subject
    // so the claim is genuine turn-scoped room content.
    let claim = session.stage_session_claim(&turn)?;
    // The claim REALLY landed in the room and nowhere else. Without this, a
    // staging call that silently wrote nothing would make every assertion
    // below trivially true — the failure mode this whole oracle exists to
    // catch, inverted.
    assert!(
        session.session_sees_entity(&claim)?,
        "the staged CLAIM is readable through the room's composed view"
    );
    assert_eq!(
        vault.get(&claim)?,
        None,
        "and base sees nothing of it — the claim is room content, so K6's \
         'zero jobs' claim below is about a row that actually exists"
    );

    let rtxn = vault.store.env.read_txn()?;
    let mut pe_rows = 0_usize;
    for row in vault.store.sync_state.prefix_iter(&rtxn, "pe:")? {
        row?;
        pe_rows += 1;
    }
    drop(rtxn);
    assert_eq!(
        pe_rows, 0,
        "no pe: pending-embedding marker for session content, INCLUDING the \
         staged CLAIM — the one op class base would have marked"
    );

    // All three background-job tables, not just `attempt_records`: a job whose
    // record row were suppressed while its ready/dedupe rows landed would
    // still be the room reaching the background worker.
    assert_eq!(
        seam::attempt_row_counts(&vault)?,
        attempts_before,
        "session flows create zero rows in attempt_records / attempt_ready / \
         attempt_dedupe"
    );

    // The reference half of the done-means: table counts alone would also pass
    // on a vault that merely held no jobs. This asks whether ANY job row —
    // embed queue, pe: marker, or attempt table — names one of the room's ids.
    assert_eq!(
        seam::job_rows_referencing(&vault, &[turn, message, claim])?,
        0,
        "no background job row may reference an overlay id"
    );

    session.close()?;
    Ok(())
}

/// D2 taint guard: a BASE batch op referencing a live-overlay id is
/// rejected atomically at the batch preflight (ports the spirit of
/// `production_summary_batch_rejects_a_live_fenced_source_atomically`).
#[test]
fn taint_guard_rejects_base_write_referencing_live_overlay_id() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-taint").expect("enter session");
    session.bind_actor()?;
    let (turn, _msg, _summary) = session.witness_turn("tainted")?;
    // The probe's own source is base setup, seeded before the census so the
    // census measures ONLY what the rejected batch would have written.
    let probe_source = seed_base_turn(&vault, 2_000);
    let census_before = full_db_census(&vault)?;
    let refused = seam::base_batch_referencing_overlay_id(&vault, &probe_source, &turn);
    assert_eq!(
        refused,
        Err(seam::SeamError::TaintedBaseWrite),
        "taint guard must reject with the exact typed refusal"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "the rejected batch must be atomic — zero base rows written"
    );
    session.close()?;
    Ok(())
}

/// D6: write-path gate decisions for session content stay overlay-local —
/// the base gate-decision ledger gains zero rows from the room.
#[test]
fn session_gate_decisions_never_persist_in_base() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let ledger_before = vault.store.gate_decisions(1_000)?.len();
    let mut session = seam::SessionVault::enter(&vault, "oracle-gate").expect("enter session");
    session.bind_actor()?;
    let (_turn, _msg, _summary) = session.witness_turn("gated in-room")?;
    session.close()?;
    assert_eq!(
        vault.store.gate_decisions(1_000)?.len(),
        ledger_before,
        "session write-path decisions must never reach the base ledger"
    );
    Ok(())
}

/// D5 mode flip: earlier off-record turns stay unextractable through base
/// readers AFTER flipping on-record (reads stay composed in-session only).
#[test]
fn off_record_turns_stay_unextractable_after_mode_flip() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-flip").expect("enter session");
    session.bind_actor()?;
    let (turn, _msg, _summary) = session.witness_turn("preflipsecret")?;

    // A route minted while OFF record names the pre-flip mode epoch.
    let stale_route = session.write_route()?;

    session.flip_on_record()?;
    assert_eq!(vault.get(&turn)?, None, "pre-flip turn stays out of base");
    assert_eq!(vault.search_text("preflipsecret", 10)?.len(), 0);

    // K10: the pre-flip route is refused by its OWN revalidation, with the
    // typed stale-route family — not silently honored against a mode the
    // caller no longer believes it is in.
    assert!(
        matches!(
            stale_route.revalidate(),
            Err(crate::error::Error::OffRecordOverlayLeaseClosed { .. })
        ),
        "a route minted before the flip must be refused by revalidate"
    );

    // Post-flip witness lands in BASE under the continuation shell, carrying
    // zero overlay references.
    let base_entities_after_flip = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.entities.len(&rtxn)?
    };
    let (base_turn, _, _) = session.witness_turn("postflippublic")?;
    assert!(
        vault.get(&base_turn)?.is_some(),
        "an on-record session witness lands in base"
    );
    assert!(
        {
            let rtxn = vault.store.env.read_txn()?;
            vault.store.entities.len(&rtxn)? > base_entities_after_flip
        },
        "the post-flip witness grew the base entity table"
    );

    // Flip BACK: new writes route to the overlay again, and the pre-flip
    // turns are still base-invisible.
    session.flip_off_record()?;
    let (reflip_turn, _, _) = session.witness_turn("postflipbacksecret")?;
    assert_eq!(
        vault.get(&reflip_turn)?,
        None,
        "after flip-back, new writes route to the overlay again"
    );
    assert_eq!(
        vault.get(&turn)?,
        None,
        "pre-flip turn is STILL out of base"
    );
    assert_eq!(vault.search_text("preflipsecret", 10)?.len(), 0);
    assert_eq!(vault.search_text("postflipbacksecret", 10)?.len(), 0);

    session.close()?;
    Ok(())
}
