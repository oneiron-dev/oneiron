//! Manifest lane appends, pack terminal receipts, and legacy backoff rows.

use super::*;
use crate::error::ArtifactError;

// ─── ONE-1737 · ARCH-0053 §3 attempt-alive pack manifest ────────────────

/// The pack is ALIVE: the manifest grows across the pending states and every
/// earlier row survives verbatim (§3, r5 — the one-and-done reading is
/// rejected).
#[test]
fn manifest_appends_across_the_live_attempt_and_never_mutates() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    let at_t0 = queue.append_manifest_entry(attempt.id, skill_entry("index", "1", 11))?;
    let ClaimOutcome::Claimed(_) = queue.claim(ClaimAttempt {
        lease_owner: "worker".to_owned(),
        now: 12,
    })?
    else {
        panic!("expected claim");
    };
    let at_mid = queue.append_manifest_entry(attempt.id, skill_entry("pdf", "3", 13))?;

    assert_eq!(at_t0.manifest().len(), 1);
    assert_eq!(at_mid.manifest().len(), 2);
    assert_eq!(
        at_mid.manifest()[0],
        at_t0.manifest()[0],
        "the t0 row survives the mid-run append verbatim"
    );
    assert_eq!(at_mid.manifest()[1].wire_form(), "pdf@3");
    assert_eq!(
        queue.get(attempt.id)?.expect("row persists").manifest(),
        at_mid.manifest(),
        "the manifest is durable, not in-memory"
    );
    Ok(())
}

/// Every terminal state refuses: a closed attempt's manifest is the evidence
/// its terminal receipt already projected, so appending would rewrite history.
#[test]
fn manifest_door_refuses_every_terminal_state() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let completed = enqueued(&queue, 10)?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker".to_owned(),
        now: 11,
    })?
    else {
        panic!("expected claim");
    };
    queue.complete(CompleteAttempt {
        id: completed.id,
        lease_owner: "worker".to_owned(),
        attempt_count: leased.attempt_count,
        now: 12,
    })?;

    let cancelled = enqueued(&queue, 20)?;
    queue.intervene(InterveneAttempt {
        id: cancelled.id,
        kind: AttemptInterventionKind::Cancel,
        actor: "operator".to_owned(),
        note: None,
        now: 21,
    })?;

    for (id, state) in [(completed.id, "completed"), (cancelled.id, "cancelled")] {
        let error = queue
            .append_manifest_entry(id, skill_entry("late", "9", 30))
            .expect_err("a terminal attempt refuses manifest appends");
        assert!(
            matches!(
                error,
                Error::Artifact(ArtifactError::InvalidAttemptQueueTransition {
                    action: "append_manifest_entry",
                    state: observed,
                }) if observed == state
            ),
            "expected a typed refusal naming {state}, got {error:?}"
        );
    }
    Ok(())
}

/// The append door does not touch `updated_at`: that field is the lease-expiry
/// clock, and turning a pack load into a lease heartbeat would silently change
/// reclaim timing.
#[test]
fn manifest_append_leaves_the_lease_clock_alone() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    let after = queue.append_manifest_entry(attempt.id, skill_entry("index", "1", 999))?;

    assert_eq!(after.updated_at, attempt.updated_at);
    Ok(())
}

/// The cap REFUSES; it never drains. This is the deliberate divergence from
/// `MAX_ATTEMPT_EVENTS_PER_RECORD`, whose drain would silently violate the
/// append-only invariant.
#[test]
fn manifest_refuses_at_the_cap_instead_of_dropping_the_oldest_row() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    // Seed a full manifest through the record path (appending 4096 rows one
    // door call at a time is a needless minute of LMDB writes).
    let mut record = queue.get(attempt.id)?.expect("row persists");
    record.manifest = (0..MAX_ATTEMPT_MANIFEST_ENTRIES)
        .map(|index| skill_entry(&format!("skill-{index}"), "1", 11))
        .collect();
    let first = record.manifest[0].clone();
    let encoded = encode_record(&record)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(())
    })?;

    let error = queue
        .append_manifest_entry(attempt.id, skill_entry("overflow", "1", 12))
        .expect_err("a full manifest refuses");

    assert!(matches!(
        error,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(ERR_MANIFEST_FULL))
    ));
    let after = queue.get(attempt.id)?.expect("row persists");
    assert_eq!(
        after.manifest().len(),
        MAX_ATTEMPT_MANIFEST_ENTRIES,
        "nothing was appended"
    );
    assert_eq!(
        after.manifest()[0],
        first,
        "and nothing was dropped: fail loud, never drain"
    );
    Ok(())
}

/// Malformed rows are refused at the door and at decode, so a corrupt manifest
/// cannot enter the store through either path.
#[test]
fn manifest_entries_are_validated() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    for (entry, expected) in [
        (skill_entry("", "1", 11), ERR_MANIFEST_REFERENCE_EMPTY),
        (skill_entry("skill", "", 11), ERR_MANIFEST_VERSION_EMPTY),
        (
            skill_entry(&"r".repeat(MAX_MANIFEST_REFERENCE_LEN + 1), "1", 11),
            ERR_MANIFEST_REFERENCE_TOO_LONG,
        ),
        (
            skill_entry("skill", &"v".repeat(MAX_MANIFEST_VERSION_LEN + 1), 11),
            ERR_MANIFEST_VERSION_TOO_LONG,
        ),
    ] {
        let error = queue
            .append_manifest_entry(attempt.id, entry)
            .expect_err("a malformed manifest row is refused");
        assert!(
            matches!(error, Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == expected),
            "expected {expected}, got {error:?}"
        );
    }
    assert!(
        queue
            .get(attempt.id)?
            .expect("row persists")
            .manifest()
            .is_empty()
    );
    Ok(())
}

/// REGRESSION (owner ruling R-20260807-04): the `reference@version` delimiter
/// is the FIRST `@`, and a reference may not contain one.
///
/// The old parse split from the RIGHT, so a legal `s@1@beta` row — skill `s`
/// at revision `1@beta` — read back as skill `s@1` at revision `beta`, and
/// attribution then credited or blamed a skill entity that never existed.
/// Rejecting `@` in the reference at the door is what makes the first-`@`
/// split lossless: the two halves cannot both be ambiguous.
#[test]
fn a_manifest_wire_form_splits_on_the_first_at_and_refs_may_not_hold_one() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    let versioned = queue.append_manifest_entry(attempt.id, skill_entry("s", "1@beta", 11))?;
    let wire = versioned.manifest()[0].wire_form();
    assert_eq!(wire, "s@1@beta");
    assert_eq!(
        ManifestEntry::parse_wire_form(&wire),
        Some(("s", "1@beta")),
        "the version keeps every `@` past the delimiter; the reference keeps none"
    );

    let error = queue
        .append_manifest_entry(attempt.id, skill_entry("s@1", "beta", 12))
        .expect_err("a reference carrying the delimiter is refused at the door");
    assert!(
        matches!(
            error,
            Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == ERR_MANIFEST_REFERENCE_HAS_AT
        ),
        "expected {ERR_MANIFEST_REFERENCE_HAS_AT}, got {error:?}"
    );

    assert_eq!(
        ManifestEntry::parse_wire_form("no-delimiter"),
        None,
        "a string carrying no `@` is not a wire form"
    );
    assert_eq!(
        queue
            .get(attempt.id)?
            .expect("row persists")
            .manifest()
            .len(),
        1,
        "the refused row never landed"
    );
    Ok(())
}

// ─── ONE-1737 · terminal pack receipt is stamped BY the queue ───────────

/// The terminal transition itself stamps the pack receipt: no caller opts in,
/// so no execute lane can forget it. The receipt carries the FULL accumulated
/// manifest, split by kind, in append order.
#[test]
fn completing_an_attempt_under_a_pack_stamps_its_terminal_receipt() -> Result<()> {
    let (_dir, vault, clock) = open_queue_at(10);

    let (receipt_id, receipt) = run_packed_attempt(&vault, |queue, id, generation| {
        clock.set(14);
        complete_at_14(queue, id, generation)
    })?;
    let receipt = receipt.expect("the terminal transition stamped a pack receipt");

    assert_eq!(receipt.receipt_id, receipt_id);
    assert_eq!(receipt.outcome, "completed");
    assert_eq!(receipt.occurred_at, 14, "the receipt is stamped at close");
    assert_eq!(receipt.actor.as_deref(), Some("worker"));
    assert_eq!(
        receipt.pack_manifest_skills(),
        Some(vec!["index@1".to_owned(), "pdf@3".to_owned()]),
        "both the t0 index and the mid-run pull are on the terminal receipt"
    );
    assert_eq!(
        receipt.pack_manifest_actor_claims(),
        Some(vec!["claim-a@2".to_owned()])
    );

    // …and it is on the RS1 receipt family, not only in its own ledger.
    let family = vault.receipts(crate::receipt::ReceiptQuery::new(16))?;
    assert_eq!(
        family
            .iter()
            .filter(|row| row.receipt_id == receipt_id)
            .count(),
        1,
        "the stamped receipt projects into the unified receipt family exactly once"
    );
    Ok(())
}
