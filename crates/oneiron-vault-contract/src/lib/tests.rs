//! Wire-compat and validation test suite.

use super::*;

// Frozen v1 schemas model peers that have not learned Shed/Slim. Keep the
// original variant order and permissive unknown-field behavior here.

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum V1CtlRequest {
    PrepareReap,
    ReapAbort,
    AlarmDue { id: String, reason_tag: String },
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum V1CtlResponse {
    PrepareReap {
        quiescent: bool,
        ledger_rev: u64,
        next_wake: Vec<WakeEntry>,
    },
    Ping {
        ok: bool,
        vault: String,
        pid: u32,
        contract_version: u32,
    },
    Ok {
        ok: bool,
    },
}

/// A v3 vault's `Ping`: `readiness` is required (2f7f20393ac) and so is the
/// `vm_outbox_companion` key (6653544016b, #5236); every build-floor field
/// absent.
fn ping_v3() -> CtlResponse {
    CtlResponse::Ping {
        ok: true,
        vault: "v".into(),
        pid: 42,
        contract_version: CONTRACT_VERSION,
        readiness: ManagedReadiness::Ready,
        browser: None,
        managed_backup: None,
        settings_paths_revision: None,
        artifact_internal_host_revision: None,
        preview_origin_revision: None,
        slim_recovery_revision: None,
        vm_outbox_revision: None,
        vm_outbox_companion: None,
        relay_delete_revision: None,
        engine_instance: None,
        deletion: None,
    }
}

fn ctl_response_fixtures() -> Vec<(CtlResponse, &'static str)> {
    vec![
        (
            // The paged ledger (28c9b753f6d, #3940): prepare_reap names the
            // frozen report's head, not its entries.
            CtlResponse::PrepareReap {
                quiescent: false,
                ledger: LedgerReportHead {
                    rev: 7,
                    report_digest:
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                    total: 0,
                    artifact_origins_total: 0,
                },
            },
            r#"{"quiescent":false,"ledger":{"rev":7,"report_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","total":0,"artifact_origins_total":0}}"#,
        ),
        (
            ping_v3(),
            r#"{"ok":true,"vault":"v","pid":42,"contract_version":3,"readiness":{"state":"ready"},"vm_outbox_companion":null}"#,
        ),
        (CtlResponse::Ok { ok: true }, r#"{"ok":true}"#),
        (CtlResponse::Ok { ok: false }, r#"{"ok":false}"#),
        (
            CtlResponse::Slim {
                slim: true,
                status: ShedStatus::Entered,
                reclaimed_bytes: Some(4096),
                dropped_windows: Some(2),
                blocker: None,
            },
            r#"{"slim":true,"status":"entered","reclaimed_bytes":4096,"dropped_windows":2}"#,
        ),
        (
            CtlResponse::Slim {
                slim: true,
                status: ShedStatus::AlreadySlim,
                reclaimed_bytes: Some(0),
                dropped_windows: Some(0),
                blocker: None,
            },
            r#"{"slim":true,"status":"already_slim","reclaimed_bytes":0,"dropped_windows":0}"#,
        ),
        (
            CtlResponse::Slim {
                slim: true,
                status: ShedStatus::AlreadySlim,
                reclaimed_bytes: None,
                dropped_windows: None,
                blocker: None,
            },
            r#"{"slim":true,"status":"already_slim"}"#,
        ),
        (
            CtlResponse::Slim {
                slim: false,
                status: ShedStatus::Refused,
                reclaimed_bytes: None,
                dropped_windows: None,
                blocker: Some(ShedBlockerWire {
                    kind: "no_pending_outbound_step".into(),
                    detail: "no pending step".into(),
                }),
            },
            r#"{"slim":false,"status":"refused","blocker":{"kind":"no_pending_outbound_step","detail":"no pending step"}}"#,
        ),
        (
            CtlResponse::Slim {
                slim: false,
                status: ShedStatus::Refused,
                reclaimed_bytes: None,
                dropped_windows: None,
                blocker: Some(ShedBlockerWire {
                    kind: "multiple_pending_outbound_steps".into(),
                    detail: "2 pending steps".into(),
                }),
            },
            r#"{"slim":false,"status":"refused","blocker":{"kind":"multiple_pending_outbound_steps","detail":"2 pending steps"}}"#,
        ),
        (
            CtlResponse::Slim {
                slim: false,
                status: ShedStatus::Refused,
                reclaimed_bytes: None,
                dropped_windows: None,
                blocker: Some(ShedBlockerWire {
                    kind: "sync_window_busy".into(),
                    detail: "1 outstanding handle".into(),
                }),
            },
            r#"{"slim":false,"status":"refused","blocker":{"kind":"sync_window_busy","detail":"1 outstanding handle"}}"#,
        ),
        (
            CtlResponse::Slim {
                slim: true,
                status: ShedStatus::Refused,
                reclaimed_bytes: None,
                dropped_windows: None,
                blocker: Some(ShedBlockerWire {
                    kind: "already_slim_for_different_step".into(),
                    detail: "different step".into(),
                }),
            },
            r#"{"slim":true,"status":"refused","blocker":{"kind":"already_slim_for_different_step","detail":"different step"}}"#,
        ),
    ]
}

#[test]
fn reap_flow_byte_identical() {
    // A v1 conversation's requests stay byte-identical. Its replies no longer
    // do, by ruling: a v3 Ping requires `readiness` (2f7f20393ac) and the
    // `vm_outbox_companion` key (6653544016b, #5236), and the paged ledger
    // (28c9b753f6d, #3940) has prepare_reap answer `quiescent` and `ledger`.
    for request in [
        r#"{"op":"ping"}"#,
        r#"{"op":"prepare_reap"}"#,
        r#"{"op":"reap_abort"}"#,
    ] {
        let old_request: V1CtlRequest = serde_json::from_str(request).unwrap();
        let new_request: CtlRequest = serde_json::from_str(request).unwrap();
        new_request.validate().unwrap();
        assert_eq!(serde_json::to_string(&old_request).unwrap(), request);
        assert_eq!(serde_json::to_string(&new_request).unwrap(), request);
    }

    // reap_abort's reply is unchanged.
    let ok = r#"{"ok":true}"#;
    let old_ok: V1CtlResponse = serde_json::from_str(ok).unwrap();
    let new_ok: CtlResponse = serde_json::from_str(ok).unwrap();
    assert_eq!(serde_json::to_string(&old_ok).unwrap(), ok);
    assert_eq!(serde_json::to_string(&new_ok).unwrap(), ok);
    new_ok.validate().unwrap();

    // Ruled (2f7f20393ac): a v1 Ping carries no readiness, so it is no Ping.
    let v1_ping = r#"{"ok":true,"vault":"v","pid":42,"contract_version":1}"#;
    let old_ping: V1CtlResponse = serde_json::from_str(v1_ping).unwrap();
    assert_eq!(serde_json::to_string(&old_ping).unwrap(), v1_ping);
    let V1CtlResponse::Ping {
        contract_version, ..
    } = old_ping
    else {
        panic!("a v1 Ping decodes as a v1 Ping");
    };
    assert!(!supports_slim(contract_version));
    let new_ping: CtlResponse = serde_json::from_str(v1_ping).unwrap();
    assert!(
        !matches!(new_ping, CtlResponse::Ping { .. }),
        "{new_ping:?}"
    );

    // Ruled (28c9b753f6d): a v1 prepare_reap reply names no ledger report and
    // matches no variant.
    let v1_reap = r#"{"quiescent":true,"ledger_rev":7,"next_wake":[{"id":"w1","at":{"kind":"exact","at":7},"reason_tag":"tag"}]}"#;
    let old_reap: V1CtlResponse = serde_json::from_str(v1_reap).unwrap();
    assert_eq!(serde_json::to_string(&old_reap).unwrap(), v1_reap);
    assert!(serde_json::from_str::<CtlResponse>(v1_reap).is_err());

    // A v3 vault's Ping is the v1 Ping apart from the advertised version and
    // the fields v3 requires, and the v1 response schema still reads it.
    let new_reply = ping_v3();
    new_reply.validate().unwrap();
    let encoded = serde_json::to_string(&new_reply).unwrap();
    assert_eq!(
        encoded,
        v1_ping.replace(
            "\"contract_version\":1}",
            &format!(
                "\"contract_version\":{CONTRACT_VERSION},\"readiness\":{{\"state\":\"ready\"}},\"vm_outbox_companion\":null}}"
            )
        )
    );
    let v1_decoded: V1CtlResponse = serde_json::from_str(&encoded).unwrap();
    assert!(
        matches!(
            v1_decoded,
            V1CtlResponse::Ping { contract_version, .. } if contract_version == CONTRACT_VERSION
        ),
        "{v1_decoded:?}"
    );
}

#[test]
fn alarm_due_wire_bytes_unchanged() {
    let wire = r#"{"op":"alarm_due","id":"w1","reason_tag":"cron"}"#;
    let old: V1CtlRequest = serde_json::from_str(wire).unwrap();
    let new: CtlRequest = serde_json::from_str(wire).unwrap();
    new.validate().unwrap();
    assert!(matches!(new, CtlRequest::AlarmDue { .. }));
    assert_eq!(serde_json::to_string(&old).unwrap(), wire);
    assert_eq!(serde_json::to_string(&new).unwrap(), wire);
}

#[test]
fn ctl_version_gating() {
    assert_eq!(SLIM_CONTRACT_VERSION, 2);
    // v3 is the typed ctl refusal's (c66727bf2a7, #3266).
    assert_eq!(CONTRACT_VERSION, 3);
    for (version, supported) in [
        (0, false),
        (1, false),
        (2, true),
        (3, true),
        (u32::MAX, true),
    ] {
        assert_eq!(supports_slim(version), supported);
        // A Ping carries `readiness` (2f7f20393ac) and the
        // `vm_outbox_companion` key (6653544016b); without them it is no Ping.
        let wire = format!(
            r#"{{"ok":true,"vault":"v","pid":42,"contract_version":{version},"readiness":{{"state":"ready"}},"vm_outbox_companion":null}}"#
        );
        let CtlResponse::Ping {
            contract_version, ..
        } = serde_json::from_str(&wire).unwrap()
        else {
            panic!("Ping must not decode as Ok");
        };
        assert_eq!(supports_slim(contract_version), supported);
    }
    for (cause, spelling) in [
        (ShedCause::LongOutboundWait, "long_outbound_wait"),
        (ShedCause::MemoryPressure, "memory_pressure"),
    ] {
        for waited_secs in [0, 1, u64::MAX] {
            let request = CtlRequest::Shed {
                cause,
                waited_secs,
                wait_id: None,
            };
            let wire =
                format!(r#"{{"op":"shed","cause":"{spelling}","waited_secs":{waited_secs}}}"#);
            assert_eq!(serde_json::to_string(&request).unwrap(), wire);
            assert_eq!(request.validate().is_ok(), waited_secs > 0);
            assert!(serde_json::from_str::<V1CtlRequest>(&wire).is_err());
            let decoded: CtlRequest = serde_json::from_str(&wire).unwrap();
            assert_eq!(decoded.validate().is_ok(), waited_secs > 0);
            assert!(matches!(
                decoded,
                CtlRequest::Shed { cause: c, waited_secs: w, .. } if c == cause && w == waited_secs
            ));
        }
    }
}

#[test]
fn ctl_response_untagged_invariant_holds() {
    for (response, expected) in ctl_response_fixtures() {
        response.validate().unwrap();
        let encoded = serde_json::to_string(&response).unwrap();
        assert_eq!(encoded, expected);
        let decoded: CtlResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            std::mem::discriminant(&decoded),
            std::mem::discriminant(&response),
            "{encoded}"
        );
        decoded.validate().unwrap();
        assert_eq!(serde_json::to_string(&decoded).unwrap(), expected);
        if matches!(response, CtlResponse::Slim { .. }) {
            assert!(serde_json::from_str::<V1CtlResponse>(&encoded).is_err());
        }
    }
}

#[test]
fn credentials_pin_dek_then_token_bytes_and_accept_independent_frames_only() {
    const DEK: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const TOKEN: [u8; 32] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];
    const FRAME: &[u8;64] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf";
    const OTHER: &[u8; 64] = b"0123456789abcdef0123456789abcdefABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
    let mut written = Vec::new();
    write_credentials(&mut written, &DEK, &TOKEN).unwrap();
    assert_eq!(written.as_slice(), FRAME.as_slice());
    // Reader input is authored bytes, never `written`.
    let read = read_credentials(&FRAME[..]).unwrap();
    assert_eq!(read.dek, DEK);
    assert_eq!(read.token, TOKEN);
    let read = read_credentials(&OTHER[..]).unwrap();
    assert_eq!(&read.dek, b"0123456789abcdef0123456789abcdef");
    assert_eq!(&read.token, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef");
    assert!(read_credentials(&FRAME[..63]).is_err());
    let mut trailing = FRAME.to_vec();
    trailing.push(0xff);
    assert!(read_credentials(trailing.as_slice()).is_err());
}

#[test]
fn token_debug_redacted() {
    let t = TokenHex::new("deadbeef".into());
    let debug = format!("{t:?}");
    assert_eq!(t.expose(), "deadbeef");

    for secret in ["deadbeef", "0123456789abcdef", "fedcba9876543210"] {
        let token = TokenHex::new(secret.into());
        let token_debug = format!("{token:?}");
        assert_eq!(token.expose(), secret);
        assert_eq!(token_debug, debug);
        assert!(!debug.contains(secret));
    }
}

#[test]
fn token_ct_eq() {
    let a = TokenHex::from_token(&[0xabu8; TOKEN_LEN]);
    let b = TokenHex::from_token(&[0xabu8; TOKEN_LEN]);
    let c = TokenHex::from_token(&[0xacu8; TOKEN_LEN]);
    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
    // hex case must not matter — compare decoded bytes, not strings
    let upper = TokenHex::new("AB".repeat(TOKEN_LEN));
    assert!(a.ct_eq(&upper));
    // malformed hex compares unequal, never panics
    assert!(!a.ct_eq(&TokenHex::new("zz".into())));
    assert!(!a.ct_eq(&TokenHex::new(String::new())));
}

/// The contract's guarantee that validate() and the line cap agree: a
/// maximal validator-passing message must still fit MAX_CTL_LINE. Control
/// bytes are rejected precisely because their 6-char `\u00XX` escapes
/// would break this bound; the worst remaining JSON expansion is the
/// 2-char escapes for `"` and `\`, exercised here.
#[test]
fn max_valid_wake_list_fits_ctl_line() {
    let entry = WakeEntry {
        id: "\\".repeat(MAX_WAKE_ID),
        at: Schedule::Window {
            start: u64::MAX - 1,
            end: u64::MAX,
        },
        reason_tag: "\"".repeat(MAX_REASON_TAG),
    };
    entry.validate().unwrap();
    // The wake list travels in ledger pages since 28c9b753f6d (#3940, FIX
    // 9549): a page holds at most MAX_LEDGER_PAGE_ENTRIES rows, and
    // prepare_reap answers the report's head alone.
    let entries = vec![entry; MAX_LEDGER_PAGE_ENTRIES];
    validate_wake_entries(&entries).unwrap();
    let digest = "f".repeat(64);

    let resp = serde_json::to_string(&CtlResponse::PrepareReap {
        quiescent: false,
        ledger: LedgerReportHead {
            rev: u64::MAX,
            report_digest: digest.clone(),
            total: u64::MAX,
            artifact_origins_total: u64::MAX,
        },
    })
    .unwrap();
    assert!(
        resp.len() <= MAX_CTL_LINE,
        "prepare_reap line {} exceeds cap",
        resp.len()
    );

    let push = serde_json::to_string(&LedgerUpdate {
        op: "ledger_update".into(),
        vault: "x".repeat(63),
        token: TokenHex::from_token(&[0xffu8; TOKEN_LEN]),
        page: LedgerPage {
            rev: u64::MAX,
            report_digest: digest,
            total: u64::MAX,
            artifact_origins_total: u64::MAX,
            offset: u64::MAX - u64::MAX % MAX_LEDGER_PAGE_ENTRIES as u64,
            entries,
            artifact_origins: Vec::new(),
            training: ManagedTrainingSetting {
                on: true,
                allow_opt_out: true,
                revision: "f".repeat(64),
                set_by: Some("f".repeat(32)),
            },
        },
    })
    .unwrap();
    assert!(
        push.len() <= MAX_CTL_LINE,
        "ledger_update line {} exceeds cap",
        push.len()
    );
}

/// CMT-2 (ONE-1539): the commitment recurrence enum is a NESTED addition.
/// The root wake `Schedule` and `WakeEntry` stay byte-identical alongside
/// the nested vocabulary's own tagged shape. SLIM, not recurrence, now
/// accounts for the v2 wire version.
#[test]
fn commitment_schedule_enum_is_nested_and_leaves_the_wake_ledger_alone() {
    use super::commitment::{QuotaWindow, Schedule as CommitmentSchedule};

    // SLIM (v2) and then the typed ctl refusal (v3, c66727bf2a7) account for
    // the wire version; the recurrence enum moved none.
    assert_eq!(SLIM_CONTRACT_VERSION, 2);
    assert_eq!(CONTRACT_VERSION, 3);

    // Root fixtures, byte for byte.
    assert_eq!(
        serde_json::to_string(&Schedule::Exact { at: 7 }).unwrap(),
        r#"{"kind":"exact","at":7}"#
    );
    assert_eq!(
        serde_json::to_string(&Schedule::Window { start: 1, end: 2 }).unwrap(),
        r#"{"kind":"window","start":1,"end":2}"#
    );
    assert_eq!(
        serde_json::to_string(&WakeEntry {
            id: "w1".into(),
            at: Schedule::Exact { at: 7 },
            reason_tag: "tag".into(),
        })
        .unwrap(),
        r#"{"id":"w1","at":{"kind":"exact","at":7},"reason_tag":"tag"}"#
    );

    // The nested vocabulary: same `tag = "kind"` / snake_case convention,
    // its own namespace, and no variant name shared with the root enum.
    for (value, json) in [
        (
            CommitmentSchedule::Once { due: 10 },
            r#"{"kind":"once","due":10}"#,
        ),
        (
            CommitmentSchedule::Interval {
                period: 86_400,
                anchor: 100,
            },
            r#"{"kind":"interval","period":86400,"anchor":100}"#,
        ),
        (
            CommitmentSchedule::Quota {
                count: 3,
                window: QuotaWindow::IsoWeek {
                    tz: "Europe/London".into(),
                },
            },
            r#"{"kind":"quota","count":3,"window":{"kind":"iso_week","tz":"Europe/London"}}"#,
        ),
        (
            CommitmentSchedule::Rrule {
                rrule_string: "FREQ=WEEKLY".into(),
                tz: "UTC".into(),
            },
            r#"{"kind":"rrule","rrule_string":"FREQ=WEEKLY","tz":"UTC"}"#,
        ),
    ] {
        assert_eq!(serde_json::to_string(&value).unwrap(), json);
        assert_eq!(
            serde_json::from_str::<CommitmentSchedule>(json).unwrap(),
            value
        );
    }

    // A root-schedule payload is NOT a commitment schedule and vice versa:
    // the two enums never silently cross-deserialize.
    assert!(serde_json::from_str::<CommitmentSchedule>(r#"{"kind":"exact","at":7}"#).is_err());
    assert!(serde_json::from_str::<Schedule>(r#"{"kind":"once","due":10}"#).is_err());
}
