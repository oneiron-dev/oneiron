//! Boundary regression tests for the napi facade surface.

use super::*;
use oneiron::{
    CalendarEventView, CalendarInviteSurfaceMethod, ClaimInput, ClaimListFilter, EntityId,
    TimeRange, Vault, VaultConfig,
};

fn reason<T: std::fmt::Debug>(result: BoundaryResult<T>) -> String {
    result.expect_err("expected N-API boundary error")
}

fn tz_draft(
    utc_offset_minutes: Option<f64>,
    iana_timezone: Option<&str>,
) -> NapiOutboundDraftInput {
    NapiOutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "counterparty:napi".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: None,
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:napi".to_owned(),
        job_ref: None,
        occurred_at: None,
        utc_offset_minutes,
        iana_timezone: iana_timezone.map(str::to_owned),
        human_explicit_instant: None,
        apns_interruption_level: None,
        resolved_level: None,
    }
}

/// ONE-1768 done-means (`napi_schedule_outbound_forwards_timezone_context`):
/// omitted fields preserve hostless behavior, valid fields convert, and
/// every invalid clock authority is rejected AT THE BOUNDARY — before the
/// draft can reach the facade and write a TASK or attempt.
#[test]
fn napi_schedule_context_conversion_fails_closed_on_invalid_clock_authority() {
    // Omitted ⇒ hostless: no offset, no label, no promotion.
    let hostless = outbound_schedule_context_to_engine(&tz_draft(None, None))
        .expect("omitted timezone fields stay hostless");
    assert_eq!(hostless.utc_offset_minutes, None);
    assert_eq!(hostless.iana_timezone, None);
    assert!(!hostless.human_explicit_instant);
    assert_eq!(hostless.apns_interruption_level, None);
    assert_eq!(hostless.resolved_level, None);

    // Valid offset + label convert intact.
    let valid =
        outbound_schedule_context_to_engine(&tz_draft(Some(-480.0), Some("America/Los_Angeles")))
            .expect("valid clock authority converts");
    assert_eq!(valid.utc_offset_minutes, Some(-480));
    assert_eq!(valid.iana_timezone.as_deref(), Some("America/Los_Angeles"));

    // IANA label without an offset is unusable.
    let err = reason(outbound_schedule_context_to_engine(&tz_draft(
        None,
        Some("Europe/Paris"),
    )));
    assert!(
        err.contains("iana_timezone requires utc_offset_minutes"),
        "got: {err}"
    );

    // Range is inclusive at both edges and closed just outside them.
    for edge in [-840.0, 840.0] {
        assert!(outbound_schedule_context_to_engine(&tz_draft(Some(edge), None)).is_ok());
    }
    for outside in [-841.0, 841.0, 1_440.0] {
        let err = reason(outbound_schedule_context_to_engine(&tz_draft(
            Some(outside),
            None,
        )));
        assert!(err.contains("-840..=840"), "got: {err}");
    }
    // Non-integer and non-finite offsets are not silently truncated.
    for bad in [30.5, f64::NAN, f64::INFINITY] {
        let err = reason(outbound_schedule_context_to_engine(&tz_draft(
            Some(bad),
            None,
        )));
        assert!(err.contains("finite integer"), "got: {err}");
    }

    // Blank and control-bearing labels are rejected.
    for bad_label in ["", "   ", "Europe/\u{7}Paris", "Europe/Paris\n"] {
        let err = reason(outbound_schedule_context_to_engine(&tz_draft(
            Some(60.0),
            Some(bad_label),
        )));
        assert!(err.contains("non-blank"), "{bad_label:?} got: {err}");
    }

    // Unknown enum labels fail closed rather than defaulting.
    let mut unknown_apns = tz_draft(Some(0.0), None);
    unknown_apns.apns_interruption_level = Some("shout".to_owned());
    assert!(
        reason(outbound_schedule_context_to_engine(&unknown_apns))
            .contains("unknown APNs interruption level")
    );

    let mut unknown_level = tz_draft(Some(0.0), None);
    unknown_level.resolved_level = Some("whisper".to_owned());
    assert!(
        reason(outbound_schedule_context_to_engine(&unknown_level))
            .contains("unknown resolved level")
    );

    // Known enum labels convert.
    let mut resolved = tz_draft(Some(0.0), None);
    resolved.resolved_level = Some("plain_chat".to_owned());
    resolved.human_explicit_instant = Some(true);
    let resolved = outbound_schedule_context_to_engine(&resolved).expect("known labels convert");
    assert!(resolved.human_explicit_instant);
    assert_eq!(
        resolved.resolved_level,
        Some(oneiron::delivery_window::DeliveryWindowResolvedLevel::PlainChat)
    );
}

/// F4: the blob base64 input is length-bounded BEFORE decode
/// allocation; an oversized input is rejected without allocating the
/// output vector.
#[test]
fn boundary_rejects_oversized_blob_base64_before_decoding() {
    let oversized = "A".repeat(MAX_NAPI_BLOB_BASE64_LEN + 8);
    let err = reason(decode_blob_base64(&oversized));
    assert!(err.contains("ceiling"), "got: {err}");

    assert_eq!(decode_blob_base64("aGVsbG8=").unwrap(), b"hello");
    assert!(decode_blob_base64("not base64!").is_err());
}

/// N1: queryBm25/recall honor the standard N-API query and result
/// caps (helpers shared with the systems layer in lib.rs).
#[test]
fn boundary_applies_search_caps_to_query_verbs() {
    let oversized_query = "q".repeat(crate::MAX_NAPI_QUERY_BYTES + 1);
    let err = reason(crate::validate_query_len(&oversized_query));
    assert!(err.contains("query must be <="), "got: {err}");

    let err = reason(crate::parse_search_limit(crate::MAX_NAPI_SEARCH_LIMIT + 1));
    assert!(err.contains("limit must be <="), "got: {err}");
    assert_eq!(
        crate::parse_search_limit(crate::MAX_NAPI_SEARCH_LIMIT).unwrap(),
        crate::MAX_NAPI_SEARCH_LIMIT as usize
    );
}

#[test]
fn boundary_rejects_negative_timestamps() {
    assert_eq!(ts_to_engine(0, "t").unwrap(), 0);
    assert_eq!(ts_to_engine(i64::MAX, "t").unwrap(), i64::MAX as u64);
    assert_eq!(
        reason(ts_to_engine(-1, "occurred_at")),
        "occurred_at must be a non-negative Unix timestamp"
    );
    assert_eq!(ts_opt_to_engine(None, "t").unwrap(), None);
}

#[test]
fn boundary_rejects_unknown_witness_author() {
    let turn = NapiWitnessTurn {
        conversation_ref: "00".repeat(16),
        turn_ref: None,
        messages: vec![NapiWitnessMessage {
            id: None,
            author: "assistant".to_owned(),
            message_type: "dialogue".to_owned(),
            content: "hi".to_owned(),
            metadata: None,
            is_visible: None,
            order: 0,
        }],
        occurred_at: 100,
    };
    let err = reason(witness_turn_to_engine(&turn));
    assert!(err.contains("user, companion, system"), "got: {err}");
}

/// ONE-1686: `metadata` that is not a JSON object is refused where the host
/// can read the reason. The engine refuses it too — this only makes the
/// message about the field the host actually typed.
#[test]
fn boundary_rejects_non_object_witness_metadata() {
    let turn = NapiWitnessTurn {
        conversation_ref: "00".repeat(16),
        turn_ref: None,
        messages: vec![NapiWitnessMessage {
            id: None,
            author: "user".to_owned(),
            message_type: "dialogue".to_owned(),
            content: "hi".to_owned(),
            metadata: Some(serde_json::json!(["side", "channel"])),
            is_visible: None,
            order: 0,
        }],
        occurred_at: 100,
    };
    let err = reason(witness_turn_to_engine(&turn));
    assert!(err.contains("metadata must be a JSON object"), "got: {err}");
}

/// ONE-1686 adversarial: direct N-API ingress is NOT a bypass.
///
/// The host DTO carries `author: "system"`, `isVisible: false` and metadata
/// that restates an envelope axis — a shape the conversion layer happily
/// converts, because the conversion layer is not the gate. The engine
/// witness door refuses it under a `human:` actor scope and leaves nothing
/// behind, while the same scope's ordinary user row lands.
///
/// Exercises the engine-typed helper directly so the test never links the
/// N-API runtime, exactly as the forget regression above does.
#[test]
fn napi_witness_ingress_cannot_smuggle_a_system_row_past_the_engine_ceiling() {
    use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};

    let dir = unique_vault_dir("witness-ceiling");
    let path = dir.to_str().expect("utf8 path").to_owned();
    let actor = EntityId::from_bytes([0x51; 16]).expect("actor id");
    let conversation = EntityId::from_bytes([0x52; 16]).expect("conversation id");

    {
        let vault = Vault::open(&path, VaultConfig::device()).expect("open vault");
        let time = oneiron::TimeRange { start: 1, end: 1 };
        vault
            .put_entity(&actor, ENTITY_TYPE_PERSON, time, 1, b"actor")
            .expect("put actor");
        let facade = vault.memory(actor, oneiron::EdgeActorClass::Human);

        let napi_message = |author: &str, order: u32| NapiWitnessMessage {
            id: None,
            author: author.to_owned(),
            message_type: "dialogue".to_owned(),
            content: format!("row-{order}"),
            metadata: None,
            is_visible: None,
            order,
        };

        // The honest turn crosses the boundary and lands.
        let honest = witness_turn_to_engine(&NapiWitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![napi_message("user", 0)],
            occurred_at: 700,
        })
        .expect("an ordinary user turn converts");
        facade.witness(&honest).expect("and lands");

        // The hostile turn converts just as happily — and the ENGINE stops
        // it. The conversion layer is a convenience, not the ceiling.
        let hostile = witness_turn_to_engine(&NapiWitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![
                napi_message("user", 0),
                NapiWitnessMessage {
                    is_visible: Some(false),
                    metadata: Some(serde_json::json!({"tool": "shell"})),
                    ..napi_message("system", 1)
                },
            ],
            occurred_at: 701,
        })
        .expect("the boundary converts the hostile shape");
        let err = facade
            .witness(&hostile)
            .expect_err("the engine ceiling refuses it");
        assert_eq!(err.code, oneiron::MEMORY_CODE_FORBIDDEN, "{err:?}");
        assert!(
            err.message
                .contains("gate.deny.witness_message.author_not_authorized"),
            "got: {}",
            err.message
        );

        // The metadata side channel is refused at the same door, for an
        // envelope whose AUTHORSHIP is beyond reproach: a nested key that
        // restates an envelope axis is a second, ungated copy of it.
        let side_channel = witness_turn_to_engine(&NapiWitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![NapiWitnessMessage {
                metadata: Some(serde_json::json!({"trace": {"author": "system"}})),
                ..napi_message("user", 0)
            }],
            occurred_at: 702,
        })
        .expect("the boundary converts the side-channel shape");
        let err = facade
            .witness(&side_channel)
            .expect_err("metadata may not restate an envelope axis");
        assert!(
            err.message
                .contains("gate.deny.witness_message.malformed_envelope"),
            "got: {}",
            err.message
        );

        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_MESSAGE)
                .expect("messages")
                .len(),
            1,
            "only the honest row survives; the refused batch landed nothing"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// #482c: a non-finite `minWeight` is rejected at the boundary. NaN would
/// otherwise disable the engine filter silently (every `weight < NaN` is
/// false) and ±Inf would over-apply it.
/// N-API parity: the bridge DTOs mirror the engine calendar DTOs field for
/// field, with the same meanings and the same EntityId encoding (hex, only
/// where an entity ref is part of the external schema at all).
#[test]
fn calendar_bridge_dtos_mirror_the_engine_surface() {
    let engine = CalendarEventView {
        event_ref: "44444444444444444444444444444444".to_owned(),
        name: Some("Design review".to_owned()),
        start_utc: Some(1_000),
        end_utc: Some(1_099),
        calendar_systems: vec!["google".to_owned()],
        blocks_time: true,
    };
    let bridged = calendar_event_from_engine(engine.clone()).expect("event crosses");
    assert_eq!(bridged.event_ref, engine.event_ref);
    assert_eq!(bridged.name, engine.name);
    assert_eq!(bridged.start_utc, Some(1_000));
    assert_eq!(bridged.end_utc, Some(1_099));
    assert_eq!(bridged.calendar_systems, engine.calendar_systems);
    assert!(bridged.blocks_time);

    // An unanchored EVENT stays unanchored rather than becoming epoch zero.
    let unanchored = calendar_event_from_engine(CalendarEventView {
        start_utc: None,
        end_utc: None,
        ..engine
    })
    .expect("unanchored event crosses");
    assert_eq!(unanchored.start_utc, None);
    assert_eq!(unanchored.end_utc, None);

    // The freebusy interval type carries occupancy only — there is no field
    // on this side of the bridge that could hold the internal source ref.
    let interval = NapiCalendarFreebusyInterval {
        start_utc: 1_000,
        end_utc: 1_100,
    };
    assert_eq!((interval.start_utc, interval.end_utc), (1_000, 1_100));

    // Selectors and ranges convert without inventing values.
    assert!(calendar_selectors_to_engine(None).is_empty());
    assert_eq!(
        calendar_selectors_to_engine(Some(vec![NapiCalendarSel {
            system: Some("google".to_owned()),
        }]))[0]
            .system
            .as_deref(),
        Some("google")
    );
    assert_eq!(
        calendar_range_to_engine(Some(NapiCalendarRange { start: 5, end: 9 })).expect("range"),
        Some(TimeRange { start: 5, end: 9 })
    );
    assert!(
        calendar_range_to_engine(Some(NapiCalendarRange { start: -1, end: 9 })).is_err(),
        "a negative bridge timestamp is a typed rejection, never a wrap"
    );

    // The invite method stays a closed set across the boundary.
    assert_eq!(
        CalendarInviteSurfaceMethod::parse("REQUEST"),
        Some(CalendarInviteSurfaceMethod::Request)
    );
    assert_eq!(
        CalendarInviteSurfaceMethod::parse("CANCEL"),
        Some(CalendarInviteSurfaceMethod::Cancel)
    );
    assert_eq!(CalendarInviteSurfaceMethod::parse("REPLY"), None);
}

#[test]
fn boundary_rejects_non_finite_min_weight() {
    assert_eq!(narrow_to_f32(0.5).expect("finite narrows"), 0.5_f32);
    assert!(narrow_to_f32(f64::NAN).is_err(), "NaN rejected");
    assert!(narrow_to_f32(f64::INFINITY).is_err(), "+Inf rejected");
    assert!(narrow_to_f32(f64::NEG_INFINITY).is_err(), "-Inf rejected");
    // A finite f64 beyond f32's range overflows to +Inf and is rejected.
    assert!(narrow_to_f32(f64::MAX).is_err(), "overflow-to-Inf rejected");
}

fn unique_vault_dir(tag: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("oneiron-napi-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp vault dir");
    dir
}

/// #471 regression: `forget({subjectRef, predicate})` drains EVERY active
/// match, not just the first page. Seeds 70 co-active claims (distinct
/// `scope` keeps supersession from collapsing them) and asserts the paging
/// loop retracts all of them. Exercises the engine-typed helper directly so
/// the test never links the N-API runtime (cdylib unit tests dead-strip
/// napi::Error only while it stays unreferenced).
#[test]
fn forget_drains_all_active_matches_beyond_one_page() {
    use oneiron::registry::ENTITY_TYPE_PERSON;

    // More than one page so the single-page bug leaves a remainder.
    const ACTIVE_CLAIMS: usize = FORGET_PAGE_SIZE + 6;

    let dir = unique_vault_dir("forget");
    let path = dir.to_str().expect("utf8 path").to_owned();
    let actor = EntityId::from_bytes([0x41; 16]).expect("actor id");
    let subject = EntityId::from_bytes([0x42; 16]).expect("subject id");

    // Scope the vault so its LMDB env closes before the temp dir removal.
    {
        let vault = Vault::open(&path, VaultConfig::device()).expect("open vault");
        let time = oneiron::TimeRange { start: 1, end: 1 };
        vault
            .put_entity(&actor, ENTITY_TYPE_PERSON, time, 1, b"actor")
            .expect("put actor");
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, time, 1, b"subject")
            .expect("put subject");
        let facade = vault.memory(actor, oneiron::EdgeActorClass::Human);
        for i in 0..ACTIVE_CLAIMS {
            facade
                .claim_upsert(&ClaimInput {
                    id: None,
                    predicate: "profile.city".to_owned(),
                    subject_ref: subject.to_hex(),
                    value: serde_json::json!(format!("city-{i}")),
                    confidence: 1.0,
                    source: "user_stated".to_owned(),
                    world_ref: None,
                    scope: Some(serde_json::json!({ "idx": i })),
                    valid_from: None,
                    valid_to: None,
                    occurred_at: Some(100),
                    learned_at: Some(100),
                    salience: None,
                })
                .expect("seed claim");
        }

        let count_active = || {
            facade
                .claim_list(&ClaimListFilter {
                    subject_ref: Some(subject.to_hex()),
                    predicate: Some("profile.city".to_owned()),
                    lifecycle: Some("active".to_owned()),
                    limit: 500,
                })
                .expect("claim_list")
                .len()
        };
        assert_eq!(
            count_active(),
            ACTIVE_CLAIMS,
            "seeded claims are all active before forget"
        );

        let receipts =
            forget_active_matches(&facade, &subject.to_hex(), "profile.city").expect("forget");
        assert_eq!(
            receipts.len(),
            ACTIVE_CLAIMS,
            "forget retracts every active match across pages"
        );
        assert_eq!(count_active(), 0, "subject+predicate is fully forgotten");
    }

    std::fs::remove_dir_all(&dir).ok();
}
