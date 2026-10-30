//! The hub's own `/v1/owner` routes and the off-record ones, one row per
//! method and path: the router and the OpenAPI document read these tables
//! (FIX 8931).

use axum::routing::{get, post, put};
use oneiron_contracts::code_run::vault_read::request_schema;

use super::schema::{
    backup_outcome_schema, cleanup_accepted_schema, cleanup_review_schema,
    cleanup_settings_body_schema, decide_cleanup_body_schema, decide_import_body_schema,
    decide_note_tombstone_body_schema, decide_run_body_schema, flip_off_record_body_schema,
    import_approved_schema, import_declined_schema, import_preview_schema,
    model_catalog_sync_schema, model_catalog_synced_schema, off_record_promoted_schema,
    off_record_saved_schema, off_record_session_schema, preview_import_body_schema,
    promote_off_record_body_schema, rehearsal_schema, rehearse_request_body_schema,
    restore_archived_body_schema, revert_cleanup_run_body_schema, run_resolved_schema,
    run_reverted_schema, save_off_record_body_schema, secret_scan_receipt_schema,
    set_model_catalog_body_schema, set_secret_scan_body_schema, tombstone_review_schema,
    tombstoned_schema,
};
use super::{
    CHANGED, OwnerRoute, OwnerTable, RestShape, accept_cleanup, accept_note_tombstone,
    approve_import, approve_run, cleanup_decide, cleanup_review, close_off_record,
    configure_cleanup, decline_import, decline_note_tombstone, decline_run, drill_failure,
    enter_off_record, export_persona, feedback_inbox, flip_off_record, healer_failures,
    healer_oversight, healer_residue, list_backups, model_catalog, note_tombstone_review,
    off_record_session, pack_drift_repairs, pending_runs, preview_feedback, preview_import,
    preview_persona, promote_off_record, read_graph_fs, rehearse_backup, reject_cleanup,
    restore_archived, revert_cleanup_run, review_run, run_housekeeping, save_off_record,
    secret_scan, send_feedback, set_model_catalog, set_secret_scan, status, sync_model_catalog,
    take_backup, witness_off_record,
};
use crate::owner::persona::{ExportRequest, Exported};

/// The routes the hub module serves itself.
pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/status",
                summary: "The kits this vault issued, the current one, and each private world's no-kit state here.",
                row: None,
                shape: None,
            },
            get(status),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/backups",
                summary: "List backups.",
                row: None,
                shape: None,
            },
            get(list_backups),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/backups",
                summary: "Take backup.",
                row: None,
                shape: Some(RestShape::no_body(backup_outcome_schema)),
            },
            post(take_backup),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/backups/rehearse",
                summary: "Rehearse backup.",
                row: None,
                shape: Some(RestShape::json(rehearse_request_body_schema, rehearsal_schema)),
            },
            post(rehearse_backup),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/maintain",
                summary: "Every housekeeping sweep now, due or not, as oneiron maintain runs them on a stopped vault.",
                row: None,
                shape: None,
            },
            post(run_housekeeping),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/secret-scan",
                summary: "Secret scan.",
                row: None,
                shape: None,
            },
            get(secret_scan),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/secret-scan",
                summary: "Set secret scan.",
                row: None,
                shape: Some(RestShape::json(
                    set_secret_scan_body_schema,
                    secret_scan_receipt_schema,
                )),
            },
            post(set_secret_scan),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/healer/oversight",
                summary: "Healer oversight.",
                row: None,
                shape: None,
            },
            get(healer_oversight),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/healer/failures",
                summary: "Healer failures.",
                row: None,
                shape: None,
            },
            get(healer_failures),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/healer/failures/drill",
                summary: "Drill failure.",
                row: None,
                shape: None,
            },
            get(drill_failure),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/healer/residue",
                summary: "The Coach's proposals still waiting for the owner, one row per source they were filed for (a failure case, a blocked report or a model issue), ordered by impact (OF-418 L4): a non-success source that unfinished TASKs wait on through recorded blocked_by edges first, then more distinct unfinished TASKs waiting, then a parked or STUCK source, then the oldest source. Each row lists its proposals, attempt, TASK, dependents and the edges that prove them, ids only, and every unproved part with a marker saying why it scores nothing. The grouped counts stay at /healer/failures.",
                row: None,
                shape: None,
            },
            get(healer_residue),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/imports/preview",
                summary: "Preview import.",
                row: None,
                shape: Some(RestShape::json(preview_import_body_schema, import_preview_schema)),
            },
            post(preview_import),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/imports/approve",
                summary: "Approve import.",
                row: None,
                shape: Some(RestShape::json(decide_import_body_schema, import_approved_schema)),
            },
            post(approve_import),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/imports/decline",
                summary: "Decline import.",
                row: None,
                shape: Some(RestShape::json(decide_import_body_schema, import_declined_schema)),
            },
            post(decline_import),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/runs",
                summary: "Pending runs.",
                row: None,
                shape: None,
            },
            get(pending_runs),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/runs/review",
                summary: "Review run.",
                row: None,
                shape: None,
            },
            get(review_run),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/runs/approve",
                summary: "Approve run.",
                row: None,
                shape: Some(
                    RestShape::json(decide_run_body_schema, run_resolved_schema)
                        .refusing(&[CHANGED]),
                ),
            },
            post(approve_run),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/runs/decline",
                summary: "Decline run.",
                row: None,
                shape: Some(
                    RestShape::json(decide_run_body_schema, run_resolved_schema)
                        .refusing(&[CHANGED]),
                ),
            },
            post(decline_run),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/cleanup",
                summary: "Cleanup review.",
                row: None,
                shape: None,
            },
            get(cleanup_review),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cleanup",
                summary: "Configure cleanup.",
                row: None,
                shape: Some(RestShape::json(cleanup_settings_body_schema, cleanup_review_schema)),
            },
            post(configure_cleanup),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cleanup/accept",
                summary: "Accept cleanup.",
                row: None,
                shape: Some(RestShape::json(decide_cleanup_body_schema, cleanup_accepted_schema)),
            },
            post(accept_cleanup),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cleanup/reject",
                summary: "Reject cleanup.",
                row: None,
                shape: Some(RestShape::json(decide_cleanup_body_schema, cleanup_review_schema)),
            },
            post(reject_cleanup),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cleanup/restore",
                summary: "Restore archived.",
                row: None,
                shape: Some(RestShape::json(restore_archived_body_schema, cleanup_review_schema)),
            },
            post(restore_archived),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cleanup/revert-run",
                summary: "Revert one whole cleanup run (OF-449): `attempt` (32 hex) names a run from the review's `runs`. Only the archive marks that run wrote are lifted, and each restored entry is kept at its revision so cleanup leaves it until it changes. Every entry answers `restored`, `already_restored`, `changed` or `unavailable` (with `reason`: `archived_again`, `unreadable`, `deleted` or `gone`) and `edited`; a delete or an erase is never undone. A repeat answers the stored result with `repeated: true`. An unknown run is not found; a run whose proposal still waits, or that ran before runs kept snapshots, is refused.",
                row: None,
                shape: Some(RestShape::json(revert_cleanup_run_body_schema, run_reverted_schema)),
            },
            post(revert_cleanup_run),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cleanup/review",
                summary: "Review one open cleanup proposal per item with full disclosure (FIX 1758): `proposal` (32 hex). Every slot answers in proposal order, an erased one too: its `state` (`eligible`, `changed`, `gone`, `unreadable` or `erased`), entity and kind, the 64-hex revision of its stored bytes, the arm's `evidence` read now, what `accept` does (`archive`, reversible by restore or run revert; `skip`; `nothing`; or `fails`, so reject that slot to decide the rest) and its full `content` through the owner's own reads (a completed attempt's whole stored row). `counts` covers all five kinds and erased slots. Nothing is truncated or stored. The review's `revision` can bind a decision. A proposal no longer open is changed.",
                row: Some("vault.cleanup.review"),
                shape: None,
            },
            post(cleanup_decide::review_proposal),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cleanup/decide",
                summary: "Decide one open cleanup proposal per item in one complete verdict (FIX 1758): `proposal`, `choices` with exactly one `accept` or `reject` for every slot the review lists (by `slot`), and an optional `expected_revision` that binds the decision to that review. Accepted slots are re-checked and archived as a whole accept does; rejected slots are left as they are, unpinned, and recorded as rejected on the decision's one digest. A verdict that accepts nothing records no digest, as a reject. Answers each slot's outcome (`archived`, `skipped`, `rejected` or `erased`) and the digest. A verdict that is not one choice per slot is invalid; a changed review or a proposal no longer open is changed. `/cleanup/accept` and `/cleanup/reject` still decide a whole proposal.",
                row: Some("vault.cleanup.decide"),
                shape: None,
            },
            post(cleanup_decide::decide_proposal),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/notes/tombstones",
                summary: "Note tombstone review.",
                row: None,
                shape: None,
            },
            get(note_tombstone_review),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/notes/tombstones/accept",
                summary: "Accept note tombstone.",
                row: None,
                shape: Some(
                    RestShape::json(decide_note_tombstone_body_schema, tombstoned_schema)
                        .refusing(&[CHANGED]),
                ),
            },
            post(accept_note_tombstone),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/notes/tombstones/decline",
                summary: "Decline note tombstone.",
                row: None,
                shape: Some(
                    RestShape::json(decide_note_tombstone_body_schema, tombstone_review_schema)
                        .refusing(&[CHANGED]),
                ),
            },
            post(decline_note_tombstone),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/persona",
                summary: "Preview persona.",
                row: None,
                shape: None,
            },
            get(preview_persona),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/persona/export",
                summary: "Export persona.",
                row: None,
                shape: Some(
                    RestShape::json(request_schema::<ExportRequest>, request_schema::<Exported>)
                        .refusing(&[
                            (
                                "400",
                                "`subject` is not an entity id, or the card cannot be issued as asked.",
                            ),
                            (
                                "409",
                                "The card changed after its preview (`changed_since_review`): preview it again and export that stamp.",
                            ),
                        ]),
                ),
            },
            post(export_persona),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/graph-fs",
                summary: "Read graph fs.",
                row: None,
                shape: None,
            },
            get(read_graph_fs),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/feedback/preview",
                summary: "Preview feedback.",
                row: None,
                shape: None,
            },
            post(preview_feedback),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/feedback/send",
                summary: "Send feedback.",
                row: None,
                shape: None,
            },
            post(send_feedback),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/feedback/inbox",
                summary: "Feedback inbox.",
                row: None,
                shape: None,
            },
            get(feedback_inbox),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/pack-drift",
                summary: "Pack drift repairs.",
                row: None,
                shape: None,
            },
            get(pack_drift_repairs),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/model-catalog",
                summary: "The catalog ref's sync policy, the revisions it has seen and trusted, and the installed pack.",
                row: None,
                shape: None,
            },
            get(model_catalog),
        ),
        (
            OwnerRoute {
                method: "put",
                path: "/model-catalog",
                summary: "Move the catalog ref's policy.",
                row: None,
                shape: Some(RestShape::json(
                    set_model_catalog_body_schema,
                    model_catalog_sync_schema,
                )),
            },
            put(set_model_catalog),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/model-catalog/sync",
                summary: "Fetch the catalog at its ref's policy and install it.",
                row: None,
                shape: Some(RestShape::no_body(model_catalog_synced_schema)),
            },
            post(sync_model_catalog),
        ),
    ]
}

/// The off-record routes [`super::off_record_routes`] nests apart.
pub(super) fn off_record_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/off-record",
                summary: "Off record session.",
                row: Some("vault.off_record.status"),
                shape: None,
            },
            get(off_record_session),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/off-record",
                summary: "Enter off record.",
                row: Some("vault.off_record.start"),
                shape: None,
            },
            post(enter_off_record),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/off-record/mode",
                summary: "Flip off record.",
                row: None,
                shape: Some(
                    RestShape::json(flip_off_record_body_schema, off_record_session_schema)
                        .refusing(&[CHANGED]),
                ),
            },
            post(flip_off_record),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/off-record/witness",
                summary: "Witness off record.",
                row: Some("vault.off_record.witness"),
                shape: None,
            },
            post(witness_off_record),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/off-record/promote",
                summary: "Promote off record.",
                row: None,
                shape: Some(
                    RestShape::json(promote_off_record_body_schema, off_record_promoted_schema)
                        .refusing(&[CHANGED]),
                ),
            },
            post(promote_off_record),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/off-record/save",
                summary: "Save off record.",
                row: None,
                shape: Some(
                    RestShape::json(save_off_record_body_schema, off_record_saved_schema)
                        .refusing(&[CHANGED]),
                ),
            },
            post(save_off_record),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/off-record/close",
                summary: "Close off record.",
                row: Some("vault.off_record.discard"),
                shape: None,
            },
            post(close_off_record),
        ),
    ]
}
