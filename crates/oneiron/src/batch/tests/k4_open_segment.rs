//! The K4 taint guard over an open room segment.

use super::*;
use crate::error::OffRecordError;
use crate::session_overlay::TxnSegmentGuard;

/// Runs `write` on a single worker thread and returns the worker's outcome.
///
/// Drop the open segment before the scope joins, even on timeout, so a base
/// writer waiting on it can finish. Report a timeout only after joining.
fn run_base_write_on_worker(
    segment: Option<TxnSegmentGuard>,
    write: impl FnOnce() -> Result<()> + Send,
) -> Result<()> {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let received = std::thread::scope(|scope| {
        scope.spawn(|| {
            let _ = done_tx.send(write());
        });
        let received = done_rx.recv_timeout(std::time::Duration::from_secs(120));
        drop(segment);
        received
    });
    received.expect("the base write waited on the open room segment")
}

/// A base put at an id an open room segment restages is refused with the
/// taint error naming that id.
#[test]
fn a_base_put_at_an_id_an_open_room_segment_restages_is_refused() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let x = crate::test_util::entity(0x71);
    vault.put_entity(&x, ENTITY_TYPE_PERSON, test_time_range(5, 5), 6, b"person")?;
    let room = vault
        .off_record_session_vault()
        .enter("k4-open-put", OffRecordBackendClass::Local)?;
    let overlay = room.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        x.as_bytes(),
        b"room restage",
    )?;

    let outcome = run_base_write_on_worker(Some(segment), || {
        vault
            .batch()
            .put(
                &x,
                ENTITY_TYPE_PERSON,
                test_time_range(10, 10),
                11,
                b"base person",
            )
            .commit()
    });
    let err = outcome.expect_err("a base put at an id an open room segment restages is refused");
    assert_matches!(
        err,
        Error::OffRecord(OffRecordError::OffRecordTaintedBaseWrite { entity_ref })
            if entity_ref == x.to_hex()
    );
    room.close()?;
    Ok(())
}

/// A base text op on an id an open room segment restages is refused with the
/// taint error naming that id.
#[test]
fn a_base_text_op_on_an_id_an_open_room_segment_restages_is_refused() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let x = crate::test_util::entity(0x72);
    vault.put_entity(&x, ENTITY_TYPE_PERSON, test_time_range(5, 5), 6, b"person")?;
    let room = vault
        .off_record_session_vault()
        .enter("k4-open-text", OffRecordBackendClass::Local)?;
    let overlay = room.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        x.as_bytes(),
        b"room restage",
    )?;

    let outcome = run_base_write_on_worker(Some(segment), || {
        vault
            .batch()
            .text(&x, &[("body", "harbor lantern")])
            .commit()
    });
    let err =
        outcome.expect_err("a base text op on an id an open room segment restages is refused");
    assert_matches!(
        err,
        Error::OffRecord(OffRecordError::OffRecordTaintedBaseWrite { entity_ref })
            if entity_ref == x.to_hex()
    );
    room.close()?;
    Ok(())
}

/// An aborted room segment leaves no member behind: once its guard drops, the
/// same base put commits.
#[test]
fn an_aborted_room_segment_leaves_no_member_behind() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let x = crate::test_util::entity(0x73);
    vault.put_entity(&x, ENTITY_TYPE_PERSON, test_time_range(5, 5), 6, b"person")?;
    let room = vault
        .off_record_session_vault()
        .enter("k4-open-abort", OffRecordBackendClass::Local)?;
    let overlay = room.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        x.as_bytes(),
        b"room restage",
    )?;
    drop(segment);

    run_base_write_on_worker(None, || {
        vault
            .batch()
            .put(
                &x,
                ENTITY_TYPE_PERSON,
                test_time_range(10, 10),
                11,
                b"base person",
            )
            .commit()
    })?;
    room.close()?;
    Ok(())
}

/// A committed room member still refuses a base put with the taint error
/// naming that id.
#[test]
fn a_committed_room_member_still_refuses_a_base_put() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let x = crate::test_util::entity(0x74);
    vault.put_entity(&x, ENTITY_TYPE_PERSON, test_time_range(5, 5), 6, b"person")?;
    let room = vault
        .off_record_session_vault()
        .enter("k4-open-commit", OffRecordBackendClass::Local)?;
    let overlay = room.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        x.as_bytes(),
        b"room restage",
    )?;
    segment.commit()?;

    let outcome = run_base_write_on_worker(None, || {
        vault
            .batch()
            .put(
                &x,
                ENTITY_TYPE_PERSON,
                test_time_range(10, 10),
                11,
                b"base person",
            )
            .commit()
    });
    let err = outcome.expect_err("a base put at a committed room member is refused");
    assert_matches!(
        err,
        Error::OffRecord(OffRecordError::OffRecordTaintedBaseWrite { entity_ref })
            if entity_ref == x.to_hex()
    );
    room.close()?;
    Ok(())
}
