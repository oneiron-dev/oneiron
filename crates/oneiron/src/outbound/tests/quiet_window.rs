//! Quiet-window delivery, timezone fields, host refresh, human-explicit-instant override and APNS mapping.

use super::*;
use crate::error::RecordError;

/// ONE-1768 done-means `ambient_email_and_plain_chat_deliver_inside_window`.
///
/// The frozen ambient token set is exercised across EVERY channel it covers —
/// not one hostless email send — inside a live quiet window. Ambient verbs
/// deliver immediately and create no hold/retry row, and the plain-chat
/// promotion happens ONLY when the TASK carries the host-resolved level.
#[test]
fn ambient_email_and_plain_chat_deliver_inside_window() -> crate::Result<()> {
    // Every one of these manifests declares its verb Interrupt, so the ambient
    // classifier is the only thing that can promote them.
    for (channel, verb) in [
        ("email", "send"),
        ("slack", "send"),
        ("discord", "send"),
        ("telegram", "send"),
        ("line", "send"),
        ("line", "send_media"),
        ("imessage_mfb", "send"),
        ("imessage_mfb", "invite"),
        ("imessage_bridge", "send"),
        ("imessage_bridge", "send_media"),
    ] {
        let contract = outbound_verb_contract(channel, verb).expect("manifest verb");
        assert_eq!(
            contract.interruption_class,
            OutboundInterruptionClass::Interrupt,
            "{channel}/{verb} manifest must stay interrupt-declared"
        );
    }

    for (seed, channel, verb, resolved) in [
        // Seeds stay outside `PINNED_ID_BYTES` (and so do the `seed+1`/`seed+2`
        // ids `quiet_window_fixture` derives from them).
        (0x80_u8, "email", "send", None),
        (0x84, "slack", "send", None),
        (0xAC, "discord", "send", None),
        (
            0xB0,
            "telegram",
            "send",
            Some(DeliveryWindowResolvedLevel::PlainChat),
        ),
        (
            0xB4,
            "line",
            "send",
            Some(DeliveryWindowResolvedLevel::PlainChat),
        ),
        // G1768-01: a REAL, schedulable iMessage connector key riding the same
        // resolved-plain-chat promotion end to end, not just in the token table.
        (
            0xBC,
            "imessage_mfb",
            "send",
            Some(DeliveryWindowResolvedLevel::PlainChat),
        ),
    ] {
        let fixture = quiet_window_fixture(seed, channel, &[verb])?;
        let key = format!("ambient-{channel}-{verb}");
        fixture
            .vault
            .memory(fixture.actor, EdgeActorClass::Agent)
            .schedule_outbound_with_context(
                &one_1768_draft(channel, verb, &key),
                &crate::memory::OutboundScheduleContext {
                    utc_offset_minutes: Some(ONE_1768_QUIET_OFFSET),
                    iana_timezone: Some("Europe/Paris".to_owned()),
                    human_explicit_instant: false,
                    apns_interruption_level: None,
                    resolved_level: resolved,
                },
            )
            .unwrap_or_else(|err| panic!("{channel}/{verb} schedules: {err:?}"));

        let mut executor = RecordingExecutor::default();
        assert_eq!(
            fixture
                .vault
                .run_connector_task_executor(&mut executor, ONE_1768_EXECUTE_AT)
                .unwrap(),
            1,
            "{channel}/{verb} must execute inside the window"
        );
        assert_eq!(executor.calls.len(), 1, "{channel}/{verb} reaches the sink");

        let receipts = one_1768_receipts(&fixture.vault)?;
        assert_eq!(receipts.len(), 1, "{channel}/{verb} receipts once");
        let receipt = &receipts[0];
        assert_eq!(
            receipt_field(receipt, "window_ladder_rung"),
            Some("ambient"),
            "{channel}/{verb} wins on the ambient rung"
        );
        assert_eq!(
            receipt_field(receipt, "window_effective_action"),
            Some("deliver_now")
        );
        // Ambient verbs are outside the interrupt-only claim family entirely,
        // so nothing was even observed as restricting them.
        assert_eq!(
            receipt_field(receipt, "window_observed_action"),
            Some("deliver_now")
        );
        assert_eq!(receipt_field(receipt, "window_match"), Some("none"));
        assert_eq!(
            receipt_field(receipt, "utc_offset_minutes"),
            Some("60"),
            "{channel}/{verb} receipts its frozen offset"
        );

        // No hold, so no fresh retry row was minted.
        let attempts = one_1768_bridge_attempts(&fixture.vault)?;
        assert_eq!(attempts.len(), 1, "{channel}/{verb} mints no retry row");
        assert_eq!(
            attempts[0].state,
            crate::attempt_queue::AttemptState::Completed
        );
    }

    // Discriminating control: the SAME compatibility verb without a resolved
    // level is NOT promoted. The engine never guesses ambient from the string.
    let fixture = quiet_window_fixture(0xB8, "line", &["send"])?;
    fixture
        .vault
        .memory(fixture.actor, EdgeActorClass::Agent)
        .schedule_outbound_with_context(
            &one_1768_draft("line", "send", "unresolved-line"),
            &crate::memory::OutboundScheduleContext {
                utc_offset_minutes: Some(ONE_1768_QUIET_OFFSET),
                ..crate::memory::OutboundScheduleContext::default()
            },
        )
        .expect("unresolved line send schedules");
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        fixture
            .vault
            .run_connector_task_executor(&mut executor, ONE_1768_EXECUTE_AT)
            .unwrap(),
        0,
        "an unresolved compatibility send stays interrupt-class"
    );
    assert!(executor.calls.is_empty(), "no sink call while parked");
    let held = one_1768_receipts(&fixture.vault)?;
    assert_eq!(
        receipt_field(&held[0], "window_ladder_rung"),
        Some("interrupt_held")
    );

    // The same discriminating control on the REAL iMessage key: `imessage_mfb`
    // × `send` with NO resolved level stays exactly where its manifest put it.
    let unresolved_mfb = quiet_window_fixture(0xC4, "imessage_mfb", &["send"])?;
    unresolved_mfb
        .vault
        .memory(unresolved_mfb.actor, EdgeActorClass::Agent)
        .schedule_outbound_with_context(
            &one_1768_draft("imessage_mfb", "send", "unresolved-imessage-mfb"),
            &crate::memory::OutboundScheduleContext {
                utc_offset_minutes: Some(ONE_1768_QUIET_OFFSET),
                ..crate::memory::OutboundScheduleContext::default()
            },
        )
        .expect("unresolved imessage_mfb send schedules");
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        unresolved_mfb
            .vault
            .run_connector_task_executor(&mut executor, ONE_1768_EXECUTE_AT)
            .unwrap(),
        0,
        "an unresolved imessage_mfb send stays interrupt-class"
    );
    assert!(
        executor.calls.is_empty(),
        "no sink call while the mfb send is parked"
    );
    let mfb_held = one_1768_receipts(&unresolved_mfb.vault)?;
    let mfb_held = mfb_held.last().expect("mfb hold receipt");
    assert_eq!(
        receipt_field(mfb_held, "window_ladder_rung"),
        Some("interrupt_held")
    );
    // The hold is a REAL hold on the full path, not a silent drop: it stamps
    // its own retry_at, the queue re-arms at exactly that instant, and the TASK
    // is still alive with no outcome burned in.
    assert_eq!(
        receipt_field(mfb_held, "window_effective_action"),
        Some("hold")
    );
    let mfb_retry_at: u64 = receipt_field(mfb_held, "retry_at")
        .expect("a held mfb send stamps retry_at")
        .parse()
        .expect("retry_at is an instant");
    let mfb_attempts = one_1768_bridge_attempts(&unresolved_mfb.vault)?;
    let mfb_armed = mfb_attempts
        .iter()
        .find(|attempt| attempt.state == crate::attempt_queue::AttemptState::Scheduled)
        .expect("the held mfb send re-arms a fresh retry row");
    assert_eq!(
        mfb_armed.scheduled_at,
        Some(mfb_retry_at),
        "the mfb re-arm instant must equal the receipted retry_at"
    );
    assert!(
        unresolved_mfb
            .vault
            .connector_send_tasks()?
            .iter()
            .all(|task| task.outcome.is_none()),
        "a window hold never burns a terminal outcome onto the TASK"
    );

    // The frozen token set itself, asserted directly — including the two edges
    // the ruling calls out: email/send_media is NOT promoted, and a resolved
    // PUSH on a chat connector is NOT promoted.
    let intent_for = |channel: &str| {
        OutboundIntent::from_trigger(
            OutboundIntentDraft::new("agent", "send", channel, "target"),
            OutboundIntentTrigger::agent_immediate("token-set"),
        )
    };
    for (channel, verb, resolved, expected) in [
        ("slack", "send", None, true),
        ("slack", "send_media", None, true),
        ("discord", "send", None, true),
        ("discord", "send_media", None, true),
        ("email", "send", None, true),
        ("email", "send_media", None, false),
        (
            "telegram",
            "send",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            true,
        ),
        (
            "line",
            "send",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            true,
        ),
        ("telegram", "send", None, false),
        ("line", "send", None, false),
        (
            "telegram",
            "send",
            Some(DeliveryWindowResolvedLevel::Push),
            false,
        ),
        (
            "line",
            "send_media",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            false,
        ),
        (
            "apns",
            "push",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            false,
        ),
        (
            "voice",
            "call",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            false,
        ),
        (
            "linkedin",
            "send",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            false,
        ),
    ] {
        // The classifier reads only (connector, verb kind, resolved level), so
        // one real contract restamped with each verb kind isolates exactly that.
        let mut contract: OutboundVerbContract =
            (*outbound_verb_contract("email", "send").expect("email send contract")).clone();
        contract.kind = verb.to_owned();
        assert_eq!(
            outbound_delivery_window_is_chat_like_ambient(
                &intent_for(channel),
                &contract,
                resolved
            ),
            expected,
            "{channel} × {verb} (resolved {resolved:?}) ambient membership"
        );
    }

    // G1768-01: the iMessage family, asserted through its REAL shipping
    // connector keys and REAL manifest contracts — no restamping. `imessage`
    // alone is not a registered manifest, so a row named that would prove
    // nothing about anything schedulable.
    for (channel, verb, resolved, expected) in [
        (
            "imessage_mfb",
            "send",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            true,
        ),
        ("imessage_mfb", "send", None, false),
        (
            "imessage_mfb",
            "send",
            Some(DeliveryWindowResolvedLevel::Push),
            false,
        ),
        // Dedicated non-chat verbs stay interrupt-class even when resolved.
        (
            "imessage_mfb",
            "invite",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            false,
        ),
        (
            "imessage_bridge",
            "send",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            true,
        ),
        ("imessage_bridge", "send", None, false),
        (
            "imessage_bridge",
            "send",
            Some(DeliveryWindowResolvedLevel::Push),
            false,
        ),
        (
            "imessage_bridge",
            "send_media",
            Some(DeliveryWindowResolvedLevel::PlainChat),
            false,
        ),
    ] {
        let contract = outbound_verb_contract(channel, verb)
            .unwrap_or_else(|err| panic!("{channel}/{verb} is a real manifest verb: {err}"));
        assert_eq!(
            contract.interruption_class,
            OutboundInterruptionClass::Interrupt,
            "{channel}/{verb} manifest must stay interrupt-declared"
        );
        assert_eq!(
            outbound_delivery_window_is_chat_like_ambient(&intent_for(channel), contract, resolved),
            expected,
            "{channel} × {verb} (resolved {resolved:?}) ambient membership"
        );
    }
    Ok(())
}

/// ONE-1768 done-means `connector_task_timezone_fields_are_additive_and_legacy_safe`.
///
/// Two halves: a PRE-CHANGE body (one that never had the timezone keys) still
/// decodes, and a context-aware schedule round-trips every new field onto the
/// hydrated public TASK without disturbing the existing body keys.
#[test]
fn connector_task_timezone_fields_are_additive_and_legacy_safe() -> crate::Result<()> {
    // A legacy body: exactly the keys that existed before this ticket.
    let legacy = Value::Map(vec![
        (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
        (
            Value::from("schema_version"),
            Value::from(CONNECTOR_SEND_TASK_SCHEMA_VERSION),
        ),
        (
            Value::from("subkind"),
            Value::from(CONNECTOR_SEND_TASK_SUBKIND),
        ),
        (Value::from("actor_ref"), Value::from(entity(0x21).to_hex())),
        (Value::from("actor_class"), Value::from("agent")),
        (Value::from("verb"), Value::from("send")),
        (Value::from("channel"), Value::from("email")),
        (Value::from("target"), Value::from("counterparty:legacy")),
        (Value::from("on_behalf_of"), Value::Nil),
        (Value::from("content_ref"), Value::Nil),
        (Value::from("idempotency_key"), Value::Nil),
        (Value::from("dedupe_key"), Value::Nil),
        (Value::from("intent_source"), Value::from("agent_immediate")),
        (Value::from("trigger_ref"), Value::from("session:legacy")),
        (Value::from("job_ref"), Value::Nil),
        (Value::from("occurred_at"), Value::from(10_u64)),
    ]);
    let mut legacy_bytes = Vec::new();
    rmpv::encode::write_value(&mut legacy_bytes, &legacy).expect("legacy body encode");
    let decoded: ConnectorSendTaskBody =
        rmp_serde::from_slice(&legacy_bytes).expect("a pre-change TASK body must still decode");
    // Absent means unknown, never a fabricated clock or a free promotion.
    assert_eq!(decoded.utc_offset_minutes, None);
    assert_eq!(decoded.iana_timezone, None);
    assert!(!decoded.human_explicit_instant);
    assert_eq!(decoded.apns_interruption_level, None);
    assert_eq!(decoded.resolved_level, None);
    assert_eq!(decoded.occurred_at, 10);
    assert_eq!(decoded.channel, "email");

    // A hostless schedule re-encodes with NO new keys at all, so the wire shape
    // a pre-change reader sees is byte-identical to what it always saw.
    let hostless = quiet_window_fixture(0x24, "email", &["send"])?;
    hostless
        .vault
        .memory(hostless.actor, EdgeActorClass::Agent)
        .schedule_outbound(&one_1768_draft("email", "send", "legacy-shape"))
        .expect("hostless schedule");
    let hostless_task = hostless.vault.connector_send_tasks()?.remove(0);
    let hostless_body = hostless
        .vault
        .connector_send_task_task_body(hostless_task.task_ref)?;
    let hostless_bytes = rmp_serde::to_vec_named(&hostless_body).expect("encode");
    let hostless_map = rmpv::decode::read_value(&mut std::io::Cursor::new(&hostless_bytes))
        .expect("connector body decodes as a msgpack map");
    let keys = match &hostless_map {
        Value::Map(entries) => entries
            .iter()
            .filter_map(|(key, _)| key.as_str().map(str::to_owned))
            .collect::<Vec<_>>(),
        other => panic!("connector body must be a map, got {other:?}"),
    };
    for additive in [
        "utc_offset_minutes",
        "iana_timezone",
        "apns_interruption_level",
        "resolved_level",
    ] {
        assert!(
            !keys.contains(&additive.to_owned()),
            "{additive} must be elided when absent"
        );
    }
    assert_eq!(hostless_task.utc_offset_minutes, None);
    assert!(!hostless_task.human_explicit_instant);

    // A context-aware schedule round-trips every field onto the PUBLIC task row
    // hosts read, not just into a private body.
    let fixture = quiet_window_fixture(0x28, "apns", &["push"])?;
    fixture
        .vault
        .memory(fixture.actor, EdgeActorClass::Agent)
        .schedule_outbound_with_context(
            &one_1768_draft("apns", "push", "tz-roundtrip"),
            &crate::memory::OutboundScheduleContext {
                utc_offset_minutes: Some(-480),
                iana_timezone: Some("America/Los_Angeles".to_owned()),
                human_explicit_instant: true,
                apns_interruption_level: Some(DeliveryWindowApnsInterruptionLevel::TimeSensitive),
                resolved_level: Some(DeliveryWindowResolvedLevel::Push),
            },
        )
        .expect("context-aware schedule");
    let tasks = fixture.vault.connector_send_tasks()?;
    assert_eq!(
        tasks.len(),
        1,
        "connector_send_tasks() exposes the authority"
    );
    let task = &tasks[0];
    assert_eq!(task.utc_offset_minutes, Some(-480));
    assert_eq!(task.iana_timezone.as_deref(), Some("America/Los_Angeles"));
    assert!(task.human_explicit_instant);
    assert_eq!(
        task.apns_interruption_level,
        Some(DeliveryWindowApnsInterruptionLevel::TimeSensitive)
    );
    assert_eq!(task.resolved_level, Some(DeliveryWindowResolvedLevel::Push));
    // The point read agrees with the list read.
    assert_eq!(
        fixture
            .vault
            .connector_send_task(&task.task_ref)?
            .expect("point read"),
        *task
    );

    // Validation is fail-closed at the facade, before any TASK is written.
    let rejected = quiet_window_fixture(0x2C, "email", &["send"])?;
    for bad in [
        crate::memory::OutboundScheduleContext {
            iana_timezone: Some("Europe/Paris".to_owned()),
            ..Default::default()
        },
        crate::memory::OutboundScheduleContext {
            utc_offset_minutes: Some(841),
            ..Default::default()
        },
        crate::memory::OutboundScheduleContext {
            utc_offset_minutes: Some(60),
            iana_timezone: Some("  ".to_owned()),
            ..Default::default()
        },
    ] {
        assert!(
            rejected
                .vault
                .memory(rejected.actor, EdgeActorClass::Agent)
                .schedule_outbound_with_context(&one_1768_draft("email", "send", "rejected"), &bad,)
                .is_err(),
            "invalid clock authority must not schedule"
        );
    }
    assert!(
        rejected.vault.connector_send_tasks()?.is_empty(),
        "no TASK row survives a rejected schedule"
    );
    Ok(())
}

/// ONE-1768 done-means `delivery_window_claims_are_live_at_execute`.
///
/// The window verdict is NEVER frozen at schedule time. The claim is edited
/// after the TASK exists and the executor honors the NEW claim, while the TASK
/// keeps the same timezone snapshot it was scheduled with.
#[test]
fn delivery_window_claims_are_live_at_execute() -> crate::Result<()> {
    let fixture = quiet_window_fixture(0xC0, "telegram", &["send"])?;
    fixture
        .vault
        .memory(fixture.actor, EdgeActorClass::Agent)
        .schedule_outbound_with_context(
            &one_1768_draft("telegram", "send", "live-claims"),
            &crate::memory::OutboundScheduleContext {
                utc_offset_minutes: Some(ONE_1768_QUIET_OFFSET),
                iana_timezone: Some("Europe/Paris".to_owned()),
                ..Default::default()
            },
        )
        .expect("schedule under the quiet claim");
    let scheduled = fixture.vault.connector_send_tasks()?.remove(0);
    assert_eq!(scheduled.utc_offset_minutes, Some(ONE_1768_QUIET_OFFSET));

    // Under the claim as scheduled, execution parks.
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        fixture
            .vault
            .run_connector_task_executor(&mut executor, ONE_1768_EXECUTE_AT)
            .unwrap(),
        0
    );
    assert!(executor.calls.is_empty());
    let parked = one_1768_receipts(&fixture.vault)?;
    assert_eq!(
        receipt_field(parked.last().expect("hold receipt"), "window_ladder_rung"),
        Some("interrupt_held")
    );

    // Now EDIT the standing claim to a window that no longer covers 23:00.
    let mut edited = quiet_delivery_window_claim_body(0xC0);
    edited.value = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
        ),
        (
            Value::from("applies_to"),
            Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
        ),
        (
            Value::from("window"),
            Value::Map(vec![
                (Value::from("start_minute"), Value::from(2 * 60)),
                (Value::from("end_minute"), Value::from(3 * 60)),
            ]),
        ),
        (Value::from("tz"), Value::from("user-local")),
    ]);
    put_claim_body(&fixture.vault, 0xC2, &edited)?;

    // The next attempt reads the NEW claim and delivers. The retry row was
    // armed at the 08:00 window edge, so run at that instant.
    let edge = ONE_1768_EXECUTE_AT + 9 * 3_600;
    assert_eq!(
        fixture
            .vault
            .run_connector_task_executor(&mut executor, edge)
            .unwrap(),
        1,
        "the live claim, not the schedule-time verdict, decides"
    );
    assert_eq!(executor.calls.len(), 1);

    // Same TASK, same frozen snapshot: only policy moved.
    let executed = fixture
        .vault
        .connector_send_task(&scheduled.task_ref)?
        .expect("same task");
    assert_eq!(executed.utc_offset_minutes, Some(ONE_1768_QUIET_OFFSET));
    assert_eq!(executed.iana_timezone.as_deref(), Some("Europe/Paris"));
    assert_eq!(executed.outcome, Some(ConnectorSendTaskOutcome::Delivered));
    Ok(())
}

/// ONE-1768 done-means `host_refresh_rearms_a_held_task`.
///
/// A host touch replaces the offset on a HELD non-terminal TASK and the next
/// local-minute evaluation changes because of it. Refreshing a TERMINAL task is
/// rejected without rewriting it.
#[test]
fn host_refresh_rearms_a_held_task() -> crate::Result<()> {
    let fixture = quiet_window_fixture(0xC8, "telegram", &["send"])?;
    fixture
        .vault
        .memory(fixture.actor, EdgeActorClass::Agent)
        .schedule_outbound_with_context(
            &one_1768_draft("telegram", "send", "host-refresh"),
            &crate::memory::OutboundScheduleContext {
                utc_offset_minutes: Some(ONE_1768_QUIET_OFFSET),
                iana_timezone: Some("Europe/Paris".to_owned()),
                ..Default::default()
            },
        )
        .expect("schedule");
    let task_ref = fixture.vault.connector_send_tasks()?.remove(0).task_ref;

    // Local 23:00 under +60 ⇒ inside the quiet window ⇒ held.
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        fixture
            .vault
            .run_connector_task_executor(&mut executor, ONE_1768_EXECUTE_AT)
            .unwrap(),
        0
    );
    assert!(executor.calls.is_empty());
    let held = fixture
        .vault
        .connector_send_task(&task_ref)?
        .expect("held task");
    assert_eq!(held.outcome, None, "a hold is not terminal");

    // Refresh to an offset whose local minute at the SAME instant is 12:00 —
    // outside the window. 22:00 UTC + (-600) = 12:00.
    let refreshed = fixture.vault.refresh_connector_send_task_timezone(
        task_ref,
        -600,
        Some("Pacific/Marquesas"),
        ONE_1768_EXECUTE_AT,
    )?;
    assert_eq!(refreshed.utc_offset_minutes, Some(-600));
    assert_eq!(
        refreshed.iana_timezone.as_deref(),
        Some("Pacific/Marquesas")
    );
    assert_eq!(
        local_minute_of_day_at(ONE_1768_EXECUTE_AT, -600),
        12 * 60,
        "the refreshed offset changes the derived local minute"
    );

    // The next attempt evaluates under the refreshed clock and delivers.
    let edge = ONE_1768_EXECUTE_AT + 9 * 3_600;
    assert_eq!(
        fixture
            .vault
            .run_connector_task_executor(&mut executor, edge)
            .unwrap(),
        1
    );
    assert_eq!(executor.calls.len(), 1);
    let delivered = fixture
        .vault
        .connector_send_task(&task_ref)?
        .expect("delivered task");
    assert_eq!(delivered.outcome, Some(ConnectorSendTaskOutcome::Delivered));

    // A terminal TASK cannot be rewritten by a late host touch.
    let err = fixture
        .vault
        .refresh_connector_send_task_timezone(task_ref, 0, Some("UTC"), edge + 1)
        .expect_err("terminal refresh is rejected");
    assert!(
        matches!(err, Error::Record(RecordError::InvalidTaskBody(_))),
        "unexpected error: {err:?}"
    );
    let unchanged = fixture
        .vault
        .connector_send_task(&task_ref)?
        .expect("task survives the rejection");
    assert_eq!(unchanged.utc_offset_minutes, Some(-600));
    assert_eq!(
        unchanged.iana_timezone.as_deref(),
        Some("Pacific/Marquesas")
    );
    assert_eq!(unchanged.outcome, Some(ConnectorSendTaskOutcome::Delivered));

    // Out-of-range offsets are rejected on the refresh path too.
    assert!(
        fixture
            .vault
            .refresh_connector_send_task_timezone(task_ref, 841, None, edge + 2)
            .is_err()
    );
    Ok(())
}

/// ONE-1768 done-means `hostless_interrupt_hold_is_bounded_and_surfaced`.
///
/// A hostless schedule has no local minute, so the interrupt-class send fails
/// CLOSED: no sink call, no silent terminal failure, and — the ONE-1880 fix —
/// a CONCRETE `retry_at` on the receipt that matches the queue's re-arm and
/// grows 60 → 120 → … → 3,600 by `retry_of` chain depth, never by
/// `attempt_count` (which every fresh row resets to zero).
#[test]
fn hostless_interrupt_hold_is_bounded_and_surfaced() -> crate::Result<()> {
    use crate::attempt_queue::AttemptState;

    let fixture = quiet_window_fixture(0xD0, "telegram", &["send"])?;
    fixture
        .vault
        .memory(fixture.actor, EdgeActorClass::Agent)
        .schedule_outbound(&one_1768_draft("telegram", "send", "hostless-bound"))
        .expect("hostless schedule");
    let task_ref = fixture.vault.connector_send_tasks()?.remove(0).task_ref;
    assert_eq!(
        fixture
            .vault
            .connector_send_task(&task_ref)?
            .expect("task")
            .utc_offset_minutes,
        None,
        "hostless means no frozen clock"
    );

    let mut executor = RecordingExecutor::default();
    let mut now = ONE_1768_EXECUTE_AT;
    let mut observed_delays = Vec::new();
    for round in 0..8 {
        assert_eq!(
            fixture
                .vault
                .run_connector_task_executor(&mut executor, now)
                .unwrap(),
            0,
            "round {round} must not deliver"
        );
        assert!(
            executor.calls.is_empty(),
            "round {round}: fail-closed means NO sink call"
        );

        let receipt = one_1768_receipts(&fixture.vault)?
            .pop()
            .expect("every hold is surfaced as a receipt");
        assert_eq!(
            receipt_field(&receipt, "window_action"),
            Some("hold"),
            "round {round}"
        );
        assert_eq!(
            receipt_field(&receipt, "window_reason"),
            Some("local_minute_unavailable"),
            "round {round}"
        );
        assert_eq!(
            receipt_field(&receipt, "window_ladder_rung"),
            Some("missing_local_minute"),
            "round {round}"
        );
        // The bounded backoff is SURFACED, not merely queued.
        let surfaced: u64 = receipt_field(&receipt, "retry_at")
            .unwrap_or_else(|| panic!("round {round}: every executor hold stamps retry_at"))
            .parse()
            .expect("retry_at is an instant");
        assert!(surfaced > now + 1, "round {round}: never the 1-second loop");
        observed_delays.push(surfaced - now);

        // The queue re-arms at exactly the instant the receipt surfaced.
        let attempts = one_1768_bridge_attempts(&fixture.vault)?;
        let armed = attempts
            .iter()
            .find(|attempt| attempt.state == AttemptState::Scheduled)
            .expect("a fresh retry row is armed");
        assert_eq!(
            armed.scheduled_at,
            Some(surfaced),
            "round {round}: backoff_until must equal the receipted retry_at"
        );
        // ONE-1795: fresh rows reset attempt_count, so it can never be the
        // exponent. The lineage is.
        assert_eq!(armed.attempt_count, 0, "round {round}");
        assert_eq!(
            attempts.len(),
            round + 2,
            "round {round}: one fresh row per hold, all under one TASK"
        );
        assert!(
            armed.retry_of.is_some(),
            "round {round}: the retry lineage is explicit"
        );

        // Never a silent terminal failure.
        assert_eq!(
            fixture
                .vault
                .connector_send_task(&task_ref)?
                .expect("task stays alive")
                .outcome,
            None,
            "round {round}"
        );
        now = surfaced;
    }

    assert_eq!(
        observed_delays,
        vec![60, 120, 240, 480, 960, 1_920, 3_600, 3_600],
        "the delay doubles from 60s by chain depth and saturates at the 3,600s cap"
    );
    Ok(())
}

/// ONE-1768 done-means `human_explicit_instant_beats_standing_window_and_receipts_both`.
///
/// The lift is earned by TASK PROVENANCE, not by a caller-supplied seed: the
/// identical send without the explicit-instant bit parks under the same live
/// claim. The receipt carries BOTH the matched quiet-window evidence and the
/// winning rung — an override never erases the standing claim.
#[test]
fn human_explicit_instant_beats_standing_window_and_receipts_both() -> crate::Result<()> {
    // Control: no human-instant provenance ⇒ the standing window parks it.
    // 0x88 (not 0xE0): the fixture derives `seed+1`, and 0xE1 is pinned.
    let control = quiet_window_fixture(0x88, "telegram", &["send"])?;
    control
        .vault
        .memory(control.actor, EdgeActorClass::Agent)
        .schedule_outbound_with_context(
            &one_1768_draft("telegram", "send", "explicit-control"),
            &crate::memory::OutboundScheduleContext {
                utc_offset_minutes: Some(ONE_1768_QUIET_OFFSET),
                ..Default::default()
            },
        )
        .expect("control schedule");
    let mut control_executor = RecordingExecutor::default();
    assert_eq!(
        control
            .vault
            .run_connector_task_executor(&mut control_executor, ONE_1768_EXECUTE_AT)
            .unwrap(),
        0
    );
    assert!(control_executor.calls.is_empty());

    // The same send, same claim, same instant — but the TASK carries the
    // human-instant provenance.
    let fixture = quiet_window_fixture(0xE4, "telegram", &["send"])?;
    fixture
        .vault
        .memory(fixture.actor, EdgeActorClass::Agent)
        .schedule_outbound_with_context(
            &one_1768_draft("telegram", "send", "explicit-instant"),
            &crate::memory::OutboundScheduleContext {
                utc_offset_minutes: Some(ONE_1768_QUIET_OFFSET),
                iana_timezone: Some("Europe/Paris".to_owned()),
                human_explicit_instant: true,
                ..Default::default()
            },
        )
        .expect("explicit-instant schedule");
    let task = fixture.vault.connector_send_tasks()?.remove(0);
    assert!(
        task.human_explicit_instant,
        "the provenance lives on the TASK, not on the caller's request"
    );

    let mut executor = RecordingExecutor::default();
    assert_eq!(
        fixture
            .vault
            .run_connector_task_executor(&mut executor, ONE_1768_EXECUTE_AT)
            .unwrap(),
        1,
        "a human-chosen instant delivers through the standing window"
    );
    assert_eq!(executor.calls.len(), 1);

    let receipt = one_1768_receipts(&fixture.vault)?.remove(0);
    assert_eq!(
        receipt_field(&receipt, "window_ladder_rung"),
        Some("human_explicit_instant")
    );
    assert_eq!(
        receipt_field(&receipt, "window_effective_action"),
        Some("deliver_now")
    );
    // The standing policy is RECORDED, not erased.
    assert_eq!(
        receipt_field(&receipt, "window_observed_action"),
        Some("hold")
    );
    assert_eq!(
        receipt_field(&receipt, "window_match"),
        Some(PREDICATE_DELIVERY_WINDOW_QUIET)
    );
    assert_eq!(
        receipt_field(&receipt, "human_explicit_instant"),
        Some("true")
    );
    assert_eq!(receipt_field(&receipt, "utc_offset_minutes"), Some("60"));
    assert_eq!(
        receipt_field(&receipt, "iana_timezone"),
        Some("Europe/Paris")
    );

    // The claim itself is untouched: the override never mutates or deletes it.
    assert_eq!(
        stored_delivery_window_policy_claims(&fixture.vault, &[fixture.actor])?.len(),
        1
    );

    // Voice/ring is the non-degradable interrupt the ladder holds by default,
    // and it is never ambient regardless of any resolved level. It is asserted
    // at the ladder rather than end-to-end because `voice × call` is
    // additionally walled by the manifest's hold-to-proposal policy risk, which
    // is a different gate than this ticket's window door.
    let voice = outbound_verb_contract("voice", "call").expect("voice contract");
    assert!(voice.capability_vs_permission.policy_risk);
    let voice_intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent", "call", "voice", "+15550100"),
        OutboundIntentTrigger::agent_immediate("voice"),
    );
    assert!(!outbound_delivery_window_is_chat_like_ambient(
        &voice_intent,
        voice,
        Some(DeliveryWindowResolvedLevel::PlainChat)
    ));
    let quiet = quiet_delivery_window_policy();
    let ring_context = DeliveryWindowEvaluationContext::new(
        ONE_1768_EXECUTE_AT,
        23 * 60,
        DeliveryWindowVerbClass::Interrupt,
    )?
    .interrupt_surface("voice:call");
    let parked = DeliveryWindowEvaluator::resolve(&ring_context, std::slice::from_ref(&quiet));
    assert!(matches!(
        parked.effective,
        DeliveryWindowDecision::Hold {
            retry_at: Some(_),
            ..
        }
    ));
    let chosen = DeliveryWindowEvaluator::resolve(
        &ring_context.human_explicit_instant(),
        std::slice::from_ref(&quiet),
    );
    assert_eq!(chosen.effective, DeliveryWindowDecision::DeliverNow);
    assert!(matches!(
        chosen.observed,
        DeliveryWindowDecision::Hold { .. }
    ));
    Ok(())
}

#[test]
fn terminal_refresh_race_rejects_timezone_mutation_after_delivery() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x97);
    put_connector_task_actor(&vault, actor, 90)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x98),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    vault.register_connector_key(&entity(0x99), sends_per_day_key(5))?;
    let draft = crate::memory::OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "counterparty:refresh-race".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some("refresh-race".to_owned()),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:refresh-race".to_owned(),
        job_ref: None,
        occurred_at: Some(90),
    };
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&draft)
        .expect("schedule");
    let task_ref = vault
        .connector_send_tasks()?
        .into_iter()
        .next()
        .expect("task")
        .task_ref;
    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 91)
            .expect("execute"),
        1
    );
    let error = vault
        .refresh_connector_send_task_timezone(task_ref, 60, Some("Europe/Paris"), 92)
        .expect_err("terminal task must reject stale host refresh");
    assert!(error.to_string().contains("terminal connector task"));
    Ok(())
}

#[test]
fn b1_apns_sink_payload_maps_quiet_levels_exactly() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x91);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x92),
        &policy_manifest(&actor.to_hex(), "apns", &["push"]),
    )?;
    put_claim_body(&vault, 0x93, &quiet_delivery_window_claim_body(0x91))?;

    for (source, expected) in [
        (
            DeliveryWindowApnsInterruptionLevel::Active,
            DeliveryWindowApnsInterruptionLevel::Passive,
        ),
        (
            DeliveryWindowApnsInterruptionLevel::TimeSensitive,
            DeliveryWindowApnsInterruptionLevel::Active,
        ),
        (
            DeliveryWindowApnsInterruptionLevel::Passive,
            DeliveryWindowApnsInterruptionLevel::Passive,
        ),
        (
            DeliveryWindowApnsInterruptionLevel::Critical,
            DeliveryWindowApnsInterruptionLevel::Active,
        ),
    ] {
        let request = OutboundDispatchRequest::new(
            format!("outbound:b1:{source:?}"),
            format!("intent:b1:{source:?}"),
            OutboundIntent::from_trigger(
                OutboundIntentDraft::new("agent", "push", "apns", "device-token"),
                OutboundIntentTrigger::agent_immediate("b1"),
            ),
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            23 * 60 * 60,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
        .delivery_window_subject_ref(actor)
        .delivery_window_local_minute_of_day(23 * 60)
        .delivery_window_apns_interruption_level(source);
        let mut sink = RecordingExecutor::default();
        let result = vault
            .dispatch_outbound_intent(request, &mut sink)
            .expect("dispatch");
        assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        assert_eq!(sink.apns_levels, vec![Some(expected)]);
    }
    Ok(())
}

#[test]
fn b2_human_explicit_instant_observes_quiet_policy_but_executes() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x94);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x95),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    put_claim_body(&vault, 0x96, &quiet_delivery_window_claim_body(0x94))?;
    let request = OutboundDispatchRequest::new(
        "outbound:b2",
        "intent:b2",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("b2")),
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_subject_ref(actor)
    .delivery_window_local_minute_of_day(23 * 60)
    .delivery_window_human_explicit_instant();
    let mut sink = RecordingExecutor::default();
    let result = vault
        .dispatch_outbound_intent(request, &mut sink)
        .expect("dispatch");
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_observed_action")
            .map(String::as_str),
        Some("hold")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_effective_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_ladder_rung")
            .map(String::as_str),
        Some("human_explicit_instant")
    );
    assert_ne!(
        result
            .receipt
            .fields
            .get("window_match")
            .map(String::as_str),
        Some("none")
    );
    Ok(())
}
