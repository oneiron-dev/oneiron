//! TASKS board tests: projection, row rendering, the overflow grammar, and render-state agreement.

use super::super::test_support::run_tree_node_with_worker_kind;
use super::*;
use crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::outbound::OutboundIntent;

fn intent(id: &str, status: TaskBoardStatus) -> TaskIntentPresence {
    TaskIntentPresence::new(id.to_owned(), status, None, false, Vec::new())
}

fn job(id: &str, status: TaskBoardStatus) -> JobPresence {
    JobPresence {
        id: id.to_owned(),
        kind: "sync".to_owned(),
        status,
        cancel_pathology: None,
    }
}

#[test]
fn fold_up_status_uses_total_precedence() {
    let cases = [
        (
            [TaskBoardStatus::Done, TaskBoardStatus::Running],
            TaskBoardStatus::Running,
        ),
        (
            [TaskBoardStatus::Done, TaskBoardStatus::Done],
            TaskBoardStatus::Done,
        ),
        (
            [TaskBoardStatus::Done, TaskBoardStatus::Failed],
            TaskBoardStatus::Failed,
        ),
        (
            [TaskBoardStatus::Running, TaskBoardStatus::Failed],
            TaskBoardStatus::Running,
        ),
        (
            [TaskBoardStatus::Scheduled, TaskBoardStatus::Queued],
            TaskBoardStatus::Scheduled,
        ),
        (
            [TaskBoardStatus::Queued, TaskBoardStatus::Done],
            TaskBoardStatus::Queued,
        ),
    ];

    for (index, (statuses, expected)) in cases.into_iter().enumerate() {
        let jobs = [job("first", statuses[0]), job("second", statuses[1])];
        assert_eq!(fold_up_status(&jobs), Some(expected), "case {index}");
    }
}

#[test]
fn fold_up_status_handles_empty_and_single_job() {
    assert_eq!(fold_up_status(&[]), None);
    for status in [
        TaskBoardStatus::Running,
        TaskBoardStatus::Failed,
        TaskBoardStatus::Scheduled,
        TaskBoardStatus::Queued,
        TaskBoardStatus::Done,
    ] {
        assert_eq!(fold_up_status(&[job("only", status)]), Some(status));
    }
}

fn connector_send_task() -> ConnectorSendTask {
    ConnectorSendTask {
        task_ref: EntityId::from_bytes([0x51; 16]).expect("task ref from 16 bytes"),
        assignee_ref: EntityId::from_bytes([0x52; 16]).expect("assignee ref from 16 bytes"),
        actor_ref: EntityId::from_bytes([0x53; 16]).expect("actor ref from 16 bytes"),
        actor_class: EdgeActorClass::Agent,
        intent: OutboundIntent {
            actor: "actor_a".to_owned(),
            on_behalf_of: None,
            verb: "send".to_owned(),
            channel: "channel_a".to_owned(),
            target: "target_a".to_owned(),
            content_ref: None,
            idempotency_key: None,
            dedupe_key: None,
            intent_source: "commitment".to_owned(),
            trigger_ref: "tr_1".to_owned(),
            job_ref: None,
        },
        originating_session_ref: None,
        attempt_started_node_id: None,
        outcome: None,
        // ONE-1768 hydrated clock authority. This board fixture is a
        // hostless send: absent everywhere, which is exactly what a
        // pre-change TASK body decodes to.
        utc_offset_minutes: None,
        iana_timezone: None,
        human_explicit_instant: false,
        apns_interruption_level: None,
        resolved_level: None,
        // Not a calendar invite, so no CAL-04 frozen body rides this TASK.
        calendar_invite: None,
        occurred_at: 1,
    }
}

#[test]
fn renders_tasks_section_as_one_line_rows_over_intents_and_bare_jobs() {
    let mut tk_a = intent("tk_a", TaskBoardStatus::Running);
    tk_a.realizing_jobs = vec![
        job("jb_1", TaskBoardStatus::Running),
        job("jb_2", TaskBoardStatus::Queued),
    ];
    let intents = [
        tk_a,
        intent("tk_b", TaskBoardStatus::Scheduled),
        intent("tk_q", TaskBoardStatus::Queued),
        intent("tk_d", TaskBoardStatus::Done),
    ];
    let bare_jobs = [job("jb_c", TaskBoardStatus::Running)];

    let section = render_tasks_section(&intents, &bare_jobs);

    assert_eq!(section.rows.len(), 5);
    let one_line_rows = section
        .rows
        .iter()
        .filter(|row| !row.line.is_empty() && row.line.lines().count() == 1)
        .count();
    assert_eq!(one_line_rows, 5);
    assert_eq!(section.rows.iter().filter(|row| row.is_intent).count(), 4);
    for (id, status, line) in [
        ("tk_b", TaskBoardStatus::Scheduled, "tk_b scheduled"),
        ("tk_q", TaskBoardStatus::Queued, "tk_q queued"),
        ("tk_d", TaskBoardStatus::Done, "tk_d done"),
    ] {
        let row = section
            .rows
            .iter()
            .find(|row| row.id == id)
            .unwrap_or_else(|| panic!("{id} row must be rendered"));
        assert_eq!(row.status, status);
        assert!(row.is_intent);
        assert_eq!(row.folded_job_count, 0);
        assert_eq!(row.line, line);
    }
    let tk_a_row = section
        .rows
        .iter()
        .find(|row| row.id == "tk_a")
        .expect("tk_a row must be rendered");
    assert_eq!(tk_a_row.status, TaskBoardStatus::Running);
    assert!(tk_a_row.is_intent);
    assert_eq!(tk_a_row.folded_job_count, 2);
    assert_eq!(tk_a_row.line, "tk_a running jobs=2");
    let jb_c_row = section
        .rows
        .iter()
        .find(|row| row.id == "jb_c")
        .expect("jb_c row must be rendered");
    assert_eq!(jb_c_row.status, TaskBoardStatus::Running);
    assert!(!jb_c_row.is_intent);
    assert_eq!(jb_c_row.folded_job_count, 0);
    assert_eq!(jb_c_row.line, "jb_c sync running");
}

#[test]
fn bridges_discriminate_bare_jobs_from_intent_rows() {
    let bare_node = run_tree_node_with_worker_kind(
        "11111111111111111111111111111111",
        None,
        RunTreeStatus::Running,
        "sync",
    );
    let bare = JobPresence::from_run_tree_node(&bare_node)
        .expect("running observed job must reach the board");
    assert_eq!(bare.id, "11111111111111111111111111111111");
    assert_eq!(bare.kind, "sync");
    assert_eq!(bare.status, TaskBoardStatus::Running);
    let cancelled_node = run_tree_node_with_worker_kind(
        "31313131313131313131313131313131",
        None,
        RunTreeStatus::Cancelled,
        "sync",
    );
    assert_eq!(JobPresence::from_run_tree_node(&cancelled_node), None);

    let completed_node = run_tree_node_with_worker_kind(
        "21212121212121212121212121212121",
        None,
        RunTreeStatus::Completed,
        "sync",
    );
    let running_node = run_tree_node_with_worker_kind(
        "22222222222222222222222222222222",
        None,
        RunTreeStatus::Running,
        "sync",
    );
    let realizing_jobs = vec![
        JobPresence::from_run_tree_node(&completed_node)
            .expect("completed observed job must reach the board"),
        JobPresence::from_run_tree_node(&running_node)
            .expect("running observed job must reach the board"),
    ];
    let connector_task = connector_send_task();
    let intent_read = TaskIntentPresence::from_connector_send_task(
        &connector_task,
        TaskBoardStatus::Running,
        realizing_jobs,
    );
    assert_eq!(intent_read.id, connector_task.task_ref.to_hex());
    assert_eq!(
        intent_read.label.as_deref(),
        Some(connector_task.intent.verb.as_str())
    );
    assert!(!intent_read.acked);
    assert_eq!(intent_read.realizing_jobs.len(), 2);

    let section = render_tasks_section(&[intent_read], &[bare]);

    assert_eq!(section.rows.len(), 2);
    assert_eq!(section.rows.iter().filter(|row| row.is_intent).count(), 1);
    assert!(section.rows[0].is_intent);
    assert_eq!(section.rows[0].folded_job_count, 2);
    assert!(!section.rows[1].is_intent);
    assert_eq!(section.rows[1].folded_job_count, 0);
    assert_eq!(section.rows[1].status, TaskBoardStatus::Running);
    assert_eq!(section.rows[1].line.matches("sync").count(), 1);
    assert_eq!(section.rows[1].line.matches("running").count(), 1);
}

#[test]
fn agent_dispatch_attempt_never_projects_into_tasks_jobs() {
    let node = run_tree_node_with_worker_kind(
        "agent_attempt",
        Some("researcher"),
        RunTreeStatus::Running,
        AGENT_DISPATCH_ATTEMPT_TYPE,
    );

    assert_eq!(JobPresence::from_run_tree_node(&node), None);
    let projected_jobs: Vec<JobPresence> = [node]
        .iter()
        .filter_map(JobPresence::from_run_tree_node)
        .collect();
    assert_eq!(projected_jobs.len(), 0);

    let section = render_tasks_section(&[], &projected_jobs);
    assert_eq!(section.rows.len(), 0);
}

#[test]
fn bare_job_bridge_renders_observed_dreamer_worker_kind() {
    let observed_node = run_tree_node_with_worker_kind(
        "jb_dreamer",
        None,
        RunTreeStatus::Running,
        "dreamer.consolidate",
    );

    let bare = JobPresence::from_run_tree_node(&observed_node)
        .expect("running observed dreamer job must reach the board");
    assert_eq!(bare.kind, "dreamer.consolidate");

    let section = render_tasks_section(&[], &[bare]);

    assert_eq!(section.rows.len(), 1);
    assert_eq!(
        section.rows[0].line,
        "jb_dreamer dreamer.consolidate running"
    );
    let raw_runner_tokens = section.rows[0]
        .line
        .split_whitespace()
        .filter(|token| *token == crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND)
        .count();
    assert_eq!(raw_runner_tokens, 0);
}

#[test]
fn failed_lane_surfaces_only_unacked_failures() {
    let unacked = intent("tk_failed_unacked", TaskBoardStatus::Failed);
    let mut acked = intent("tk_failed_acked", TaskBoardStatus::Failed);
    acked.acked = true;
    let mut done_acked = intent("tk_done_acked", TaskBoardStatus::Done);
    done_acked.acked = true;

    let section = render_tasks_section(&[unacked.clone(), acked.clone(), done_acked.clone()], &[]);

    assert_eq!(section.rows.len(), 2);
    let lane = failed_lane(&section);
    assert_eq!(lane.len(), 1);
    assert_eq!(lane[0].id, "tk_failed_unacked");
    assert_eq!(lane[0].status, TaskBoardStatus::Failed);

    let mut now_acked = unacked;
    now_acked.acked = true;
    let mut now_unacked = acked;
    now_unacked.acked = false;

    let flipped = render_tasks_section(&[now_acked, now_unacked, done_acked], &[]);

    assert_eq!(flipped.rows.len(), 2);
    let flipped_lane = failed_lane(&flipped);
    assert_eq!(flipped_lane.len(), 1);
    assert_eq!(flipped_lane[0].id, "tk_failed_acked");
    assert_eq!(flipped_lane[0].status, TaskBoardStatus::Failed);
}

#[test]
fn expand_unfolds_realizing_jobs_in_order() {
    let mut tk_a = intent("tk_a", TaskBoardStatus::Running);
    tk_a.realizing_jobs = vec![
        job("jb_1", TaskBoardStatus::Running),
        job("jb_2", TaskBoardStatus::Queued),
    ];

    let lines = expand_task(&tk_a);

    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "tk_a running jobs=2");
    assert_eq!(lines[1], "  jb_1 sync running");
    assert_eq!(lines[2], "  jb_2 sync queued");
    let job_lines = lines.iter().filter(|line| line.contains("jb_")).count();
    assert_eq!(job_lines, 2);
    let one_line_rows = lines
        .iter()
        .filter(|line| line.lines().count() == 1)
        .count();
    assert_eq!(one_line_rows, 3);
}

/// A hostile peer handle cannot split a row or mint a token that reads as
/// board structure. Control characters collapse and the remaining spacing
/// is folded, so the handle stays exactly ONE token.
#[test]
fn hostile_handles_cannot_split_rows_or_mint_board_structure() {
    let mut hostile = intent("tk_hostile", TaskBoardStatus::Queued);
    hostile.label = Some("ship\u{7}it".to_owned());
    hostile.assignee = Some("cc\nsecond done jobs=9".to_owned());
    hostile.result_ref = Some("tn_dead\u{9}beef ghost".to_owned());
    hostile.consult_result = Some(ConsultResultPresence::Abstained {
        result_ref: "tn_1".to_owned(),
        reason_ref: "cl_a\nb running".to_owned(),
    });

    let section = render_tasks_section(&[hostile.clone()], &[]);
    let expanded = expand_task(&hostile);

    assert_eq!(section.rows.len(), 1);
    let row = &section.rows[0];
    assert_eq!(row.line.lines().count(), 1);
    // The status axis is not forgeable from a handle.
    assert_eq!(
        row.line
            .split_whitespace()
            .filter(|token| *token == "queued")
            .count(),
        1
    );
    assert_eq!(
        row.line
            .split_whitespace()
            .filter(|token| *token == "done" || *token == "jobs=9")
            .count(),
        0
    );
    assert_eq!(
        row.line
            .split_whitespace()
            .filter(|token| token.starts_with("assignee="))
            .count(),
        1
    );
    for line in &expanded {
        assert_eq!(line.lines().count(), 1);
    }
    assert_eq!(
        expanded
            .iter()
            .flat_map(|line| line.split_whitespace())
            .filter(|token| *token == "running" || *token == "ghost")
            .count(),
        0
    );
}

/// An expired consult reads `failed` on the axis and `expired` as its
/// cause, and its expansion names WHERE the result lives without
/// interpolating any result body.
#[test]
fn expired_consult_row_names_its_cause_and_result_ref() {
    let mut expired = intent("tk_consult", TaskBoardStatus::Failed);
    expired.kind = Some(TaskKind::Consult);
    expired.assignee = Some("cc-second".to_owned());
    expired.terminal_disposition = Some(TaskTerminalDisposition::Expired);
    expired.result_ref = Some("aa00".to_owned());
    let mut answered = intent("tk_answered", TaskBoardStatus::Done);
    answered.kind = Some(TaskKind::Consult);
    answered.assignee = Some("cc-second".to_owned());
    answered.terminal_disposition = Some(TaskTerminalDisposition::Completed);
    answered.result_ref = Some("bb11".to_owned());
    answered.consult_result = Some(ConsultResultPresence::Answer {
        result_ref: "bb11".to_owned(),
        evidence_ref_count: 2,
    });

    let section = render_tasks_section(&[expired.clone(), answered.clone()], &[]);
    let lane = failed_lane(&section);
    let expired_expand = expand_task(&expired);
    let answered_expand = expand_task(&answered);

    assert_eq!(lane.len(), 1);
    assert_eq!(lane[0].id, "tk_consult");
    assert_eq!(lane[0].kind, Some(TaskKind::Consult));
    assert_eq!(
        lane[0].terminal_disposition,
        Some(TaskTerminalDisposition::Expired)
    );
    assert_eq!(lane[0].result_ref.as_deref(), Some("aa00"));
    assert_eq!(lane[0].line, "tk_consult assignee=cc-second failed expired");
    // `done` has exactly one cause, so a `completed` token would narrow
    // nothing; the answer's shape lives in the expansion instead.
    let answered_row = section
        .rows
        .iter()
        .find(|row| row.id == "tk_answered")
        .expect("answered consult row");
    assert_eq!(answered_row.line, "tk_answered assignee=cc-second done");
    assert_eq!(expired_expand.len(), 2);
    assert_eq!(expired_expand[1], "  result=aa00");
    assert_eq!(answered_expand.len(), 2);
    assert_eq!(answered_expand[1], "  result=bb11 answer evidence=2");
}

/// The pinned ONE-1888 ladder table. The board axis stays ONE-1699's five
/// values — deliberately distinct from the A2A base states — and the
/// ladder outcome rides beside it as cause tokens.
#[test]
fn ladder_outcomes_project_onto_the_pinned_board_lanes_and_tokens() {
    let table = [
        (
            LadderTerminalDisposition::Approved,
            TaskBoardStatus::Done,
            vec!["approved"],
        ),
        (
            LadderTerminalDisposition::Overridden,
            TaskBoardStatus::Done,
            vec!["overridden"],
        ),
        (
            LadderTerminalDisposition::Rejected,
            TaskBoardStatus::Failed,
            vec!["rejected"],
        ),
        (
            LadderTerminalDisposition::Failed,
            TaskBoardStatus::Failed,
            vec!["failed"],
        ),
        (
            LadderTerminalDisposition::Escalated,
            TaskBoardStatus::Queued,
            vec!["interrupted", "escalated"],
        ),
        (
            LadderTerminalDisposition::Countered,
            TaskBoardStatus::Failed,
            vec!["rejected", "countered"],
        ),
        (
            LadderTerminalDisposition::Abandoned,
            TaskBoardStatus::Failed,
            vec!["abandoned"],
        ),
    ];

    for (disposition, status, tokens) in table {
        let projection = ladder_board_projection(disposition);
        assert_eq!(projection.status, status, "{}", disposition.as_str());
        assert_eq!(projection.tokens, tokens, "{}", disposition.as_str());
    }
    // A rejection never reads as the failed CAUSE, and vice versa.
    assert_ne!(
        ladder_board_projection(LadderTerminalDisposition::Rejected).tokens,
        ladder_board_projection(LadderTerminalDisposition::Failed).tokens
    );
}

/// The row renders the ladder cause beside the status, never inside it,
/// and never duplicates a token the status already carries.
#[test]
fn ladder_rows_render_their_cause_without_duplicating_the_status() {
    let mut approved = intent("tk_approved", TaskBoardStatus::Done);
    approved.terminal_disposition = Some(TaskTerminalDisposition::Completed);
    approved.ladder_disposition = Some(LadderTerminalDisposition::Approved);
    let mut overridden = intent("tk_overridden", TaskBoardStatus::Done);
    overridden.terminal_disposition = Some(TaskTerminalDisposition::Completed);
    overridden.ladder_disposition = Some(LadderTerminalDisposition::Overridden);
    overridden.result_ref = Some("rc_1".to_owned());
    let mut ladder_failed = intent("tk_failed", TaskBoardStatus::Failed);
    ladder_failed.terminal_disposition = Some(TaskTerminalDisposition::Failed);
    ladder_failed.ladder_disposition = Some(LadderTerminalDisposition::Failed);
    let mut escalated = intent("tk_escalated", TaskBoardStatus::Queued);
    escalated.interrupted = true;

    let section = render_tasks_section(
        &[approved, overridden.clone(), ladder_failed, escalated],
        &[],
    );

    let line = |id: &str| {
        section
            .rows
            .iter()
            .find(|row| row.id == id)
            .unwrap_or_else(|| panic!("{id} renders"))
            .line
            .clone()
    };
    assert_eq!(line("tk_approved"), "tk_approved done approved");
    assert_eq!(line("tk_overridden"), "tk_overridden done overridden");
    // `failed` is already the status token, so the cause adds nothing.
    assert_eq!(line("tk_failed"), "tk_failed failed");
    // A durably interrupted row is not terminal; the pause is the cause.
    assert_eq!(line("tk_escalated"), "tk_escalated queued interrupted");
    // The override receipt is named in the expansion, never interpolated.
    assert_eq!(expand_task(&overridden)[1], "  result=rc_1");
}

/// A countered original renders as the immutable rejected row it is, and
/// its expansion names the successor rather than pretending to be it.
#[test]
fn a_countered_row_reads_as_rejected_and_names_its_successor() {
    let mut countered = intent("tk_countered", TaskBoardStatus::Failed);
    countered.kind = Some(TaskKind::Consult);
    countered.terminal_disposition = Some(TaskTerminalDisposition::Rejected);
    countered.ladder_disposition = Some(LadderTerminalDisposition::Countered);
    countered.result_ref = Some("rc_2".to_owned());
    countered.counter_task_ref = Some("tk_new".to_owned());

    let section = render_tasks_section(&[countered.clone()], &[]);
    let lane = failed_lane(&section);
    let expanded = expand_task(&countered);

    assert_eq!(lane.len(), 1);
    assert_eq!(lane[0].line, "tk_countered failed rejected countered");
    assert_eq!(lane[0].counter_task_ref.as_deref(), Some("tk_new"));
    assert_eq!(expanded[1], "  result=rc_2 counter=tk_new");
    // Distinct causes stay distinct on the shared failed lane.
    assert!(
        !lane[0]
            .line
            .split_whitespace()
            .any(|token| token == "abandoned" || token == "expired")
    );
}

// ── ONE-1873: bounded render + shared render-state read ─────────────

fn intents(count: usize) -> Vec<TaskIntentPresence> {
    (0..count)
        .map(|index| intent(&format!("tk_{index:03}"), TaskBoardStatus::Queued))
        .collect()
}

/// The pinned ARCH-0067 §8 additive grammar. An exact census and a
/// scan-capped lower bound must never read the same.
#[test]
fn overflow_line_follows_the_additive_grammar() {
    let line = |known_omitted_rows, source_exhausted| {
        TasksOverflow {
            known_omitted_rows,
            source_exhausted,
        }
        .line()
    };

    assert_eq!(line(0, true), None);
    assert_eq!(line(4, true).as_deref(), Some("tasks: +4 more"));
    assert_eq!(
        line(0, false).as_deref(),
        Some("tasks: more rows may exist (scan capped)")
    );
    assert_eq!(
        line(4, false).as_deref(),
        Some("tasks: +4 more (at least; scan capped)")
    );
    // A lower bound is never presentable as the exact count.
    assert_ne!(line(4, false), line(4, true));
}

/// An exhausted scan knows exactly what it dropped, so the footer is an
/// exact additive count and the concrete rows stop at the cap.
#[test]
fn exhausted_render_caps_rows_and_reports_an_exact_additive_count() {
    let section = TasksSection::render_with_cap(&intents(5), &[], true, 2);

    assert_eq!(section.rows.len(), 2);
    assert_eq!(section.rows[0].id, "tk_000");
    assert_eq!(section.rows[1].id, "tk_001");
    let overflow = section.overflow.expect("capped rows carry a footer");
    assert_eq!(overflow.known_omitted_rows, 3);
    assert!(overflow.source_exhausted);
    assert_eq!(overflow.line().as_deref(), Some("tasks: +3 more"));
}

/// The same omission count under a truncated scan is explicitly a LOWER
/// bound: entities the scan never inspected may add more.
#[test]
fn scan_capped_render_marks_the_count_as_a_lower_bound() {
    let section = TasksSection::render_with_cap(&intents(5), &[], false, 2);

    assert_eq!(section.rows.len(), 2);
    let overflow = section.overflow.expect("capped rows carry a footer");
    assert_eq!(overflow.known_omitted_rows, 3);
    assert!(!overflow.source_exhausted);
    assert_eq!(
        overflow.line().as_deref(),
        Some("tasks: +3 more (at least; scan capped)")
    );
}

/// A truncated scan whose visible prefix fits under the render cap must
/// not print a false exact `+0`; it says what it actually knows.
#[test]
fn scan_capped_render_without_omitted_rows_never_prints_a_false_zero() {
    let section = TasksSection::render_with_cap(&intents(1), &[], false, 5);

    assert_eq!(section.rows.len(), 1);
    let overflow = section
        .overflow
        .expect("an unexhausted scan always says so");
    assert_eq!(overflow.known_omitted_rows, 0);
    let line = overflow.line().expect("unexhausted scans render a footer");
    assert_eq!(line, "tasks: more rows may exist (scan capped)");
    assert!(!line.contains("+0"));
}

/// Nothing omitted and nothing unscanned means no footer at all — the
/// landed complete-set render is byte-identical to before.
#[test]
fn exhausted_render_under_the_cap_has_no_footer() {
    let section = TasksSection::render_with_cap(&intents(3), &[], true, 5);

    assert_eq!(section.rows.len(), 3);
    assert_eq!(section.overflow, None);
    assert_eq!(render_tasks_section(&intents(3), &[]), section);
}

/// Page-boundary arithmetic: the cap is an exact row bound at, below, and
/// above the boundary, and a zero cap sheds the whole section to a count.
#[test]
fn render_cap_boundaries_hold_exactly() {
    for (rows, cap, expected_rows, expected_omitted) in
        [(4, 5, 4, 0), (5, 5, 5, 0), (6, 5, 5, 1), (3, 0, 0, 3)]
    {
        let section = TasksSection::render_with_cap(&intents(rows), &[], true, cap);
        assert_eq!(section.rows.len(), expected_rows, "{rows} rows / cap {cap}");
        assert_eq!(
            section
                .overflow
                .map_or(0, |overflow| overflow.known_omitted_rows),
            expected_omitted,
            "{rows} rows / cap {cap}"
        );
    }
    // Empty input under any cap is an empty, footer-free section.
    assert_eq!(
        TasksSection::render_with_cap(&[], &[], true, 5),
        TasksSection {
            rows: Vec::new(),
            overflow: None,
        }
    );
}

/// The footer is structural, never work: it has no id, status, intent
/// flag, or folded-job count, and it can never appear as a `TaskRow`.
#[test]
fn the_overflow_footer_is_never_a_task_row() {
    let bare = [job("jb_1", TaskBoardStatus::Running)];
    let section = TasksSection::render_with_cap(&intents(4), &bare, false, 2);

    assert_eq!(section.rows.len(), 2);
    let line = section
        .overflow
        .expect("footer")
        .line()
        .expect("footer line");
    assert!(section.rows.iter().all(|row| row.line != line));
    assert!(section.rows.iter().all(|row| row.id != line));
    // One physical line, like every other renderer-owned line.
    assert_eq!(line.lines().count(), 1);
    // The acked-failure filter still runs BEFORE the cap, so a dropped row
    // is never counted as omitted-but-real.
    let mut acked_failure = intent("tk_gone", TaskBoardStatus::Failed);
    acked_failure.acked = true;
    let filtered = TasksSection::render_with_cap(&[acked_failure], &[], true, 1);
    assert_eq!(filtered.rows.len(), 0);
    assert_eq!(filtered.overflow, None);
}

/// The shared page read and the single-key wrappers must agree with each
/// other AND with the state the write verbs actually persisted.
#[test]
fn task_render_state_page_read_matches_legacy_wrappers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), crate::config::VaultConfig::default()).expect("open vault");
    let actor = EntityId::from_bytes([0xC1; 16]).expect("actor id");
    // acked-only, cancelled-only, both, neither.
    let rows: Vec<(EntityId, bool, bool)> = [
        (0xA1, true, false),
        (0xA2, false, true),
        (0xA3, true, true),
        (0xA4, false, false),
    ]
    .into_iter()
    .map(|(seed, acked, cancelled)| {
        (
            EntityId::from_bytes([seed; 16]).expect("task id"),
            acked,
            cancelled,
        )
    })
    .collect();
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    for (task_ref, acked, cancelled) in &rows {
        // Ack FIRST wherever both apply: an acknowledgement that merged in
        // before a cancellation must not read as "not cancelled".
        if *acked {
            ack_task_in_txn(&vault, &mut wtxn, *task_ref, actor, 100).expect("ack");
        }
        if *cancelled {
            cancel_task_in_txn(&vault, &mut wtxn, *task_ref, actor, 101).expect("cancel");
        }
    }
    wtxn.commit().expect("commit render state");

    // ONE transaction for the whole page, exactly as the board scan does.
    let shared: Vec<TaskRenderState> = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        rows.iter()
            .map(|(task_ref, _, _)| {
                TaskIntentPresence::render_state_in(&vault, &rtxn, *task_ref)
                    .expect("shared page read")
            })
            .collect()
    };

    for (state, (task_ref, acked, cancelled)) in shared.iter().zip(&rows) {
        // Ground truth first, so a swapped key prefix cannot hide behind
        // two readers that share the same mistake.
        assert_eq!(state.acked, *acked, "{}", task_ref.to_hex());
        assert_eq!(state.cancelled, *cancelled, "{}", task_ref.to_hex());
        assert_eq!(
            *state,
            TaskRenderState {
                acked: task_is_acked(&vault, *task_ref).expect("wrapper ack"),
                cancelled: task_is_cancelled(&vault, *task_ref).expect("wrapper cancel"),
            }
        );
    }
}

/// Cancel-wins is a property of the FACT SET, not of arrival order: the
/// same two facts in either order leave the same render state, and the
/// acknowledgement never clears the cancellation.
#[test]
fn cancel_wins_under_both_ack_cancel_orders() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), crate::config::VaultConfig::default()).expect("open vault");
    let actor = EntityId::from_bytes([0xC2; 16]).expect("actor id");
    let ack_first = EntityId::from_bytes([0xB1; 16]).expect("ack-first task id");
    let cancel_first = EntityId::from_bytes([0xB2; 16]).expect("cancel-first task id");

    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    ack_task_in_txn(&vault, &mut wtxn, ack_first, actor, 10).expect("ack");
    cancel_task_in_txn(&vault, &mut wtxn, ack_first, actor, 11).expect("cancel");
    cancel_task_in_txn(&vault, &mut wtxn, cancel_first, actor, 10).expect("cancel");
    ack_task_in_txn(&vault, &mut wtxn, cancel_first, actor, 11).expect("ack");
    wtxn.commit().expect("commit facts");

    for task_ref in [ack_first, cancel_first] {
        let state = task_render_state(&vault, task_ref).expect("render state");
        assert_eq!(
            state,
            TaskRenderState {
                acked: true,
                cancelled: true,
            },
            "{}",
            task_ref.to_hex()
        );
    }
}

#[test]
fn run_tree_status_maps_onto_board_status_axis() {
    let statuses = [
        (RunTreeStatus::Queued, Some(TaskBoardStatus::Queued)),
        (RunTreeStatus::Running, Some(TaskBoardStatus::Running)),
        (RunTreeStatus::Paused, Some(TaskBoardStatus::Scheduled)),
        (RunTreeStatus::Completed, Some(TaskBoardStatus::Done)),
        (RunTreeStatus::Failed, Some(TaskBoardStatus::Failed)),
        (RunTreeStatus::Cancelled, None),
    ];
    for (status, board_status) in statuses {
        assert_eq!(run_tree_board_status(status), board_status);
    }
}
