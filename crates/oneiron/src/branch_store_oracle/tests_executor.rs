//! P4b ONE-1729 executor-binding tests: effect-level policy survives the binding, mid-run flips and stale handles refuse.

use crate::error::Result;

use super::seam;
use super::tests_substrate::{full_db_census, temp_vault};

// ─── P4b · ONE-1729 — executor binding keeps effect-level policy ─────────

/// Every durable memory verb ONE-1729's effect policy names.
const DURABLE_MEMORY_WRITE_VERBS: [&str; 4] = [
    "MemoryPutClaim",
    "MemorySupersedeClaim",
    "MemoryPutEdge",
    "MemoryWriteFixture",
];

/// D6: durable-memory-write verbs stay POLICY-rejected off-record — a plain
/// overlay-backed dispatcher would wrongly allow them ephemerally.
///
/// Each probe brackets the PUBLIC dispatch call: the census is captured
/// immediately before and immediately after the refusal, so the delta names
/// exactly what the forbidden effect did — base rows, gate decisions, pending
/// consent, and replay rows alike, since `full_db_census` counts `vault_meta`
/// where all three live. The check itself is module-private; bracketing
/// dispatch is the observable equivalent.
#[test]
fn durable_memory_write_verbs_stay_policy_rejected_off_record() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-policy").expect("enter session");
    session.bind_actor()?;
    for verb in DURABLE_MEMORY_WRITE_VERBS {
        let census_before = full_db_census(&vault)?;
        let session_before = session.session_artifact_census()?;
        assert_eq!(
            session.dispatch_executor_verb(verb),
            Err(seam::SeamError::PolicyMemoryWrite),
            "durable-memory verb {verb} must reject as the exact typed policy \
             refusal, not routing"
        );
        assert_eq!(
            full_db_census(&vault)?,
            census_before,
            "{verb} rejected off-record must leave zero base delta"
        );
        assert_eq!(
            session.session_artifact_census()?,
            session_before,
            "{verb} rejected off-record must leave zero OVERLAY delta either — \
             the answer is refusal, not ephemeral acceptance"
        );
    }
    session.close()?;
    Ok(())
}

/// D6, the other half: the same four verbs take the ORDINARY path once the
/// bound live session is on record, which is what makes the rejection above
/// mode-scoped POLICY rather than a permanent property of the dispatcher or a
/// side effect of overlay routing.
///
/// ONE-1936's stale-target guard is NOT on this merge base (implement-time
/// census: `dispatch_memory_supersede_claim` reaches
/// `supersede_claim_for_code_run_trap` with no target walk), so the partition
/// is asserted STRUCTURALLY: off record, the effect-policy refusal fires
/// before the supersede write transaction is ever entered, which the
/// zero-delta brackets above already prove.
#[test]
fn durable_memory_write_verbs_take_the_ordinary_path_after_flip() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-policy-flip").expect("enter");
    let actor = session.bind_actor()?;
    session.flip_on_record()?;

    // NOT ONE of the four still meets the effect policy. What answers now is
    // whatever the ORDINARY path answers — for the three gated verbs that is
    // the write gate, whose verdict is not an off-record concern and must not
    // be read as one.
    let claims_before = vault
        .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
        .len();
    for verb in DURABLE_MEMORY_WRITE_VERBS {
        assert_ne!(
            session.executor_verb_error_kind(verb),
            Some(crate::error::ErrorKind::OffRecordTalkOnly),
            "{verb} must no longer meet the off-record effect policy on record"
        );
    }
    // `MemoryWriteFixture` takes the ungated batch path, so it is the verb
    // that shows the ordinary route COMPLETING through the bound Session
    // storage rather than through `self.vault`. Asserted by IDENTITY, not by
    // a count: the gated verbs above also moved rows, and a count would let
    // one of them stand in for the row actually under test.
    let fixture_claim = session.dispatch_fixture_write()?;
    assert!(
        vault.get_claim(&fixture_claim)?.is_some(),
        "the on-record fixture write landed in base through the bound storage"
    );
    assert!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len()
            > claims_before,
        "and the base claim table grew rather than staying ephemeral"
    );
    assert!(
        vault.get(&actor)?.is_some(),
        "the bound actor is a base row throughout"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729 (R-20260807-02): guest-supplied turn_ref is rejected typed,
/// BEFORE construction, in both modes.
#[test]
fn guest_supplied_turn_ref_rejected() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-guest").expect("enter session");
    session.bind_actor()?;

    for mode in ["off-record", "post-flip on-record"] {
        let census_before = full_db_census(&vault)?;
        let session_before = session.session_artifact_census()?;
        let refused = session.dispatch_executor_verb("GuestTurnRef");
        assert_eq!(
            refused,
            Err(seam::SeamError::GuestTurnRef),
            "guest turn_ref must reject with the exact typed refusal ({mode})"
        );
        // Pre-CONSTRUCTION: no WitnessTurn was formed, so there is nothing to
        // roll back — not in base, not in the room.
        assert_eq!(
            full_db_census(&vault)?,
            census_before,
            "the refusal must precede every base write ({mode})"
        );
        assert_eq!(
            session.session_artifact_census()?,
            session_before,
            "the refusal must precede every overlay write ({mode})"
        );
        session.flip_on_record()?;
    }
    session.close()?;
    Ok(())
}

/// ONE-1729: executor speak-turns and code-run artifacts are overlay
/// members — present in-session, absent from base.
///
/// `bind_actor` runs BEFORE the census: the witness door proves its actor
/// exists in base before it writes, so that one row is baseline rather than
/// residue the executor appears to have left behind.
#[test]
fn executor_artifacts_and_speak_turns_live_in_overlay_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-exec").expect("enter session");
    session.bind_actor()?;
    let census_before = full_db_census(&vault)?;
    session
        .dispatch_executor_verb("Speak")
        .expect("speak is talk-only-legal off-record");
    // Positive half (codex F8): the artifacts EXIST through the session
    // view — a no-op dispatcher must fail here.
    assert_eq!(
        session.session_artifact_census()?,
        (1, 1, 1),
        "exactly one speak turn, one replay record, one raw-output row \
         must exist through the session view"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "speak turns / replay records / raw outputs must not land in base"
    );
    // The shell is a fresh 32-hex EntityId owned by the session, never the
    // reusable `session_ref` string, and the dispatcher READS it rather than
    // minting one per bind.
    let shells = session.session_message_shells()?;
    assert_eq!(shells.len(), 1, "the room is ONE conversation");
    assert_eq!(
        session.dispatcher_container_id()?,
        Some(shells[0]),
        "the executor's container is the session-owned shell"
    );
    assert_ne!(
        shells[0].to_hex(),
        "oracle-exec",
        "the shell is an entity id, not the session ref"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729 K-EXEC: all three utterance kinds go through the SAME session-side
/// witness entry and reuse exactly one session-bound shell across verbs and
/// across executor runs — the door is the only place turn events are formed.
#[test]
fn executor_utterances_share_one_session_shell() -> Result<()> {
    use crate::off_record::ExecutorUtterance;

    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-utterance").expect("enter");
    session.bind_actor()?;
    let census_before = full_db_census(&vault)?;

    for kind in [
        ExecutorUtterance::Speak,
        ExecutorUtterance::Think,
        ExecutorUtterance::Express,
    ] {
        session.witness_executor_utterance(kind, "in-room utterance", None)?;
    }
    // A second bound run, to prove the shell is the SESSION's and not the
    // run's: a per-run shell would show up as a second conversation here.
    session.dispatch_executor_verb("Speak").expect("second run");

    assert_eq!(
        session.session_artifact_census()?.0,
        4,
        "three utterances plus the second run's turn, all in-room"
    );
    assert_eq!(
        session.session_message_shells()?.len(),
        1,
        "one shell across every utterance kind and both runs"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "no utterance reaches base, and none is visible to a canonical reader"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729: an unknown ref and a handle that outlived its room fail with
/// DISTINCT typed refusals, and neither leaves anything behind.
#[test]
fn binding_a_dead_session_refuses_distinctly() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let census_before = full_db_census(&vault)?;
    assert_eq!(
        seam::bind_session(&vault, "never-entered"),
        Err(seam::SeamError::SessionNotFound),
        "an unknown session ref must name itself as not found"
    );
    let (stale, rebind) = seam::stale_handle_and_rebind_refusals(&vault, "oracle-bind-closed");
    assert_eq!(
        stale,
        seam::SeamError::SessionClosing,
        "a handle bound before close must refuse as closing, never write into a dead room"
    );
    assert_eq!(
        rebind,
        seam::SeamError::SessionNotFound,
        "and rebinding the same ref afterwards is a DIFFERENT refusal"
    );
    assert_ne!(
        stale, rebind,
        "the two bind refusals must stay variant-discriminable"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "a refused bind creates no registry entry, overlay, replay row, raw \
         output, turn, or gate decision"
    );
    Ok(())
}

/// ONE-1729: the executor refuses a mismatched storage/dispatcher pair at RUN
/// ENTRY, before `load_or_create_record` and before any read or write — in
/// BOTH directions, and even when the session refs compare equal because two
/// different vaults answer to the same binding.
#[test]
fn executor_refuses_mismatched_storage_dispatcher_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_other_tmp, other_vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-binding").expect("enter session");
    let census_before = full_db_census(&vault)?;

    for direction in seam::binding_mismatch_directions(&vault, &session, &other_vault)? {
        assert_eq!(
            direction.refusal.as_deref(),
            Some("executor storage/dispatcher binding mismatch"),
            "{} must refuse at run entry with the typed binding error",
            direction.name
        );
    }
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "a refused binding writes nothing"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729 (R-20260807-02 rider 2): the run's route is captured ONCE at run
/// entry; a flip before the apply is refused by that route's OWN revalidation
/// with the typed stale-route family, leaving the pre-flip room intact.
///
/// A path that silently re-minted a route per apply would pass the write here
/// and split the record across the flip; that is precisely what this refuses.
#[test]
fn run_entry_route_refuses_an_apply_across_a_mid_run_flip() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-route").expect("enter session");
    session.bind_actor()?;
    session
        .dispatch_executor_verb("Speak")
        .expect("pre-flip run");
    let room_before = session.session_artifact_census()?;
    let census_before = full_db_census(&vault)?;

    let refused = seam::apply_through_a_route_captured_before_a_flip(&session);
    assert_eq!(
        refused,
        Err(seam::SeamError::LeaseClosed),
        "the run-entry route must refuse its own apply after a mode flip"
    );
    assert_eq!(
        session.session_artifact_census()?,
        room_before,
        "the pre-flip room is intact — not split state"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "and nothing crossed into base under the stale route"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729: session `MemorySearch` applies through the run's captured route
/// too — its retrieval-run row is a durable write, so a mid-run flip refuses
/// it exactly as it refuses a replay write.
///
/// A search door that minted its own route would pass here while every
/// neighbouring apply on the same run refused, and would leave base telemetry
/// behind for a run whose record evaporates.
#[test]
fn run_entry_route_refuses_a_search_across_a_mid_run_flip() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-search-route").expect("enter session");
    let census_before = full_db_census(&vault)?;

    let refused = seam::search_through_a_route_captured_before_a_flip(&session);
    assert_eq!(
        refused,
        Err(seam::SeamError::LeaseClosed),
        "the run-entry route must refuse its own search after a mode flip"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "and no retrieval telemetry crossed into base under the stale route"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729: `witness_turn` refuses a mismatched storage/dispatcher pair
/// before it writes, because it is a write-capable entry point in its own
/// right — a pair that never calls `run` must not be able to land a turn.
#[test]
fn executor_witness_turn_refuses_a_mismatched_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session =
        seam::SessionVault::enter(&vault, "oracle-witness-binding").expect("enter session");
    session.bind_actor()?;
    let room_before = session.session_artifact_census()?;
    let census_before = full_db_census(&vault)?;

    assert_eq!(
        seam::witness_turn_with_mismatched_binding(&vault, &session)?.as_deref(),
        Some("executor storage/dispatcher binding mismatch"),
        "a write-capable entry point must run the binding check itself"
    );
    assert_eq!(
        session.session_artifact_census()?,
        room_before,
        "a refused witness leaves the room untouched"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "and writes nothing to base"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729: the session replay compare-and-set is ATOMIC, like its canonical
/// sibling — the compare reads inside the transaction that writes.
///
/// Two bound runs holding the same expected generation must not both be told
/// they won: a row that changed under a run is refused with the existing
/// concurrent-write error rather than silently overwritten.
#[test]
fn session_replay_compare_and_set_refuses_a_row_that_moved() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-replay-cas").expect("enter session");
    // On record, so the competing mutation reaches the same row the routed
    // put targets; the compare protocol under test is route-independent.
    session.flip_on_record()?;

    assert_eq!(
        seam::replay_put_racing_a_committed_change(&vault, &session)?,
        Some(crate::error::ErrorKind::ConcurrentWrite),
        "a replay row that moved between compare and put must refuse, not lose the update"
    );
    session.close()?;
    Ok(())
}
