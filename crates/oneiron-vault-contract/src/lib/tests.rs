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

fn ctl_response_fixtures() -> Vec<(CtlResponse, &'static str)> {
    vec![
        (
            CtlResponse::PrepareReap {
                quiescent: false,
                ledger_rev: 7,
                next_wake: vec![],
            },
            r#"{"quiescent":false,"ledger_rev":7,"next_wake":[]}"#,
        ),
        (
            CtlResponse::Ping {
                ok: true,
                vault: "v".into(),
                pid: 42,
                contract_version: CONTRACT_VERSION,
            },
            r#"{"ok":true,"vault":"v","pid":42,"contract_version":2}"#,
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
    // A v1 conversation stays byte-identical apart from the advertised
    // version in the Ping reply. The v1 response schema accepts v2 Ping.
    for (request, reply) in [
        (
            r#"{"op":"ping"}"#,
            r#"{"ok":true,"vault":"v","pid":42,"contract_version":1}"#,
        ),
        (
            r#"{"op":"prepare_reap"}"#,
            r#"{"quiescent":true,"ledger_rev":7,"next_wake":[{"id":"w1","at":{"kind":"exact","at":7},"reason_tag":"tag"}]}"#,
        ),
        (r#"{"op":"reap_abort"}"#, r#"{"ok":true}"#),
    ] {
        let old_request: V1CtlRequest = serde_json::from_str(request).unwrap();
        let new_request: CtlRequest = serde_json::from_str(request).unwrap();
        new_request.validate().unwrap();
        assert_eq!(serde_json::to_string(&old_request).unwrap(), request);
        assert_eq!(serde_json::to_string(&new_request).unwrap(), request);

        let old_reply: V1CtlResponse = serde_json::from_str(reply).unwrap();
        let mut new_reply: CtlResponse = serde_json::from_str(reply).unwrap();
        assert_eq!(serde_json::to_string(&old_reply).unwrap(), reply);
        assert_eq!(serde_json::to_string(&new_reply).unwrap(), reply);
        if let CtlResponse::Ping {
            contract_version, ..
        } = &mut new_reply
        {
            assert!(!supports_slim(*contract_version));
            *contract_version = CONTRACT_VERSION;
        }
        new_reply.validate().unwrap();
        let encoded = serde_json::to_string(&new_reply).unwrap();
        assert_eq!(
            encoded,
            reply.replace("\"contract_version\":1", "\"contract_version\":2")
        );
        let v1_decoded: V1CtlResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(serde_json::to_string(&v1_decoded).unwrap(), encoded);
    }
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
    assert_eq!(CONTRACT_VERSION, 2);
    for (version, supported) in [
        (0, false),
        (1, false),
        (2, true),
        (3, true),
        (u32::MAX, true),
    ] {
        assert_eq!(supports_slim(version), supported);
        let wire = format!(r#"{{"ok":true,"vault":"v","pid":42,"contract_version":{version}}}"#);
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
            let request = CtlRequest::Shed { cause, waited_secs };
            let wire =
                format!(r#"{{"op":"shed","cause":"{spelling}","waited_secs":{waited_secs}}}"#);
            assert_eq!(serde_json::to_string(&request).unwrap(), wire);
            assert_eq!(request.validate().is_ok(), waited_secs > 0);
            assert!(serde_json::from_str::<V1CtlRequest>(&wire).is_err());
            let decoded: CtlRequest = serde_json::from_str(&wire).unwrap();
            assert_eq!(decoded.validate().is_ok(), waited_secs > 0);
            assert!(matches!(
                decoded,
                CtlRequest::Shed { cause: c, waited_secs: w } if c == cause && w == waited_secs
            ));
        }
    }
}

#[test]
fn shed_request_rejects_malformed_json() {
    for wire in [
        r#"{"op":"future_op"}"#,
        r#"{"op":"shed","waited_secs":1}"#,
        r#"{"op":"shed","cause":"memory_pressure"}"#,
        r#"{"op":"shed","cause":"future_cause","waited_secs":1}"#,
        r#"{"op":"shed","cause":"LongOutboundWait","waited_secs":1}"#,
        r#"{"op":"shed","cause":null,"waited_secs":1}"#,
        r#"{"op":"shed","cause":7,"waited_secs":1}"#,
        r#"{"op":"shed","cause":"memory_pressure","waited_secs":null}"#,
        r#"{"op":"shed","cause":"memory_pressure","waited_secs":"1"}"#,
        r#"{"op":"shed","cause":"memory_pressure","waited_secs":true}"#,
        r#"{"op":"shed","cause":"memory_pressure","waited_secs":-1}"#,
        r#"{"op":"shed","cause":"memory_pressure","waited_secs":1.5}"#,
        r#"{"op":"shed","cause":"memory_pressure","waited_secs":18446744073709551616}"#,
    ] {
        assert!(serde_json::from_str::<CtlRequest>(wire).is_err(), "{wire}");
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
fn slim_response_field_combinations_validate() {
    for status in [
        ShedStatus::Entered,
        ShedStatus::AlreadySlim,
        ShedStatus::Refused,
    ] {
        for slim in [false, true] {
            for reclaimed_bytes in [None, Some(0), Some(u64::MAX)] {
                for dropped_windows in [None, Some(0), Some(u64::MAX)] {
                    for kind in [
                        None,
                        Some("no_pending_outbound_step"),
                        Some("multiple_pending_outbound_steps"),
                        Some("sync_window_busy"),
                        Some("already_slim_for_different_step"),
                        Some("future_blocker"),
                    ] {
                        let response = CtlResponse::Slim {
                            slim,
                            status,
                            reclaimed_bytes,
                            dropped_windows,
                            blocker: kind.map(|kind| ShedBlockerWire {
                                kind: kind.into(),
                                detail: "detail".into(),
                            }),
                        };
                        let valid = matches!(
                            (status, slim, reclaimed_bytes, dropped_windows, kind),
                            (ShedStatus::Entered, true, Some(_), Some(_), None)
                                | (ShedStatus::AlreadySlim, true, Some(_), Some(_), None)
                                | (ShedStatus::AlreadySlim, true, None, None, None)
                                | (
                                    ShedStatus::Refused,
                                    false,
                                    None,
                                    None,
                                    Some(
                                        "no_pending_outbound_step"
                                            | "multiple_pending_outbound_steps"
                                            | "sync_window_busy"
                                    )
                                )
                                | (
                                    ShedStatus::Refused,
                                    true,
                                    None,
                                    None,
                                    Some("already_slim_for_different_step")
                                )
                                | (ShedStatus::Refused, _, None, None, Some("future_blocker"))
                        );
                        assert_eq!(response.validate().is_ok(), valid, "{response:?}");
                        let wire = serde_json::to_string(&response).unwrap();
                        let decoded: CtlResponse = serde_json::from_str(&wire).unwrap();
                        assert_eq!(decoded.validate().is_ok(), valid, "{wire}");
                    }
                }
            }
        }
    }
}

#[test]
fn slim_absent_optionals_serialize_as_absent_keys() {
    for (response, _) in ctl_response_fixtures() {
        let json = serde_json::to_value(&response).unwrap();
        if let CtlResponse::Slim {
            reclaimed_bytes,
            dropped_windows,
            blocker,
            ..
        } = response
        {
            assert!(
                json.get("ok").is_none(),
                "Slim must never be shadowed by Ok"
            );
            for (key, present) in [
                ("reclaimed_bytes", reclaimed_bytes.is_some()),
                ("dropped_windows", dropped_windows.is_some()),
                ("blocker", blocker.is_some()),
            ] {
                assert_eq!(json.get(key).is_some(), present, "{key}: {json}");
                assert!(!json.get(key).is_some_and(serde_json::Value::is_null));
            }
        }
    }
    // Null optionals decode as None, but are never emitted as null.
    let response: CtlResponse = serde_json::from_str(
        r#"{"slim":true,"status":"already_slim","reclaimed_bytes":null,"dropped_windows":null,"blocker":null}"#,
    )
    .unwrap();
    response.validate().unwrap();
    assert_eq!(
        serde_json::to_string(&response).unwrap(),
        r#"{"slim":true,"status":"already_slim"}"#
    );
}

#[test]
fn slim_response_rejects_malformed_json() {
    for wire in [
        r#"{}"#,
        r#"{"slim":true}"#,
        r#"{"status":"entered"}"#,
        r#"{"slim":"true","status":"entered"}"#,
        r#"{"slim":null,"status":"already_slim"}"#,
        r#"{"slim":true,"status":"future_status"}"#,
        r#"{"slim":true,"status":"AlreadySlim"}"#,
        r#"{"slim":true,"status":null}"#,
        r#"{"slim":true,"status":1}"#,
        r#"{"slim":true,"status":"entered","reclaimed_bytes":-1,"dropped_windows":0}"#,
        r#"{"slim":true,"status":"entered","reclaimed_bytes":18446744073709551616,"dropped_windows":0}"#,
        r#"{"slim":true,"status":"entered","reclaimed_bytes":1.5,"dropped_windows":0}"#,
        r#"{"slim":true,"status":"entered","reclaimed_bytes":"1","dropped_windows":0}"#,
        r#"{"slim":true,"status":"entered","reclaimed_bytes":0,"dropped_windows":-1}"#,
        r#"{"slim":true,"status":"entered","reclaimed_bytes":0,"dropped_windows":18446744073709551616}"#,
        r#"{"slim":true,"status":"entered","reclaimed_bytes":0,"dropped_windows":1.5}"#,
        r#"{"slim":true,"status":"entered","reclaimed_bytes":0,"dropped_windows":"1"}"#,
        r#"{"slim":false,"status":"refused","blocker":{}}"#,
        r#"{"slim":false,"status":"refused","blocker":{"kind":"sync_window_busy"}}"#,
        r#"{"slim":false,"status":"refused","blocker":{"detail":"busy"}}"#,
        r#"{"slim":false,"status":"refused","blocker":{"kind":null,"detail":"busy"}}"#,
        r#"{"slim":false,"status":"refused","blocker":{"kind":"sync_window_busy","detail":1}}"#,
        r#"{"slim":false,"status":"refused","blocker":"sync_window_busy"}"#,
    ] {
        assert!(serde_json::from_str::<CtlResponse>(wire).is_err(), "{wire}");
    }
}

#[test]
fn shed_blocker_wire_kind_spellings_are_pinned() {
    for (kind, wire) in [
        (
            "no_pending_outbound_step",
            r#"{"kind":"no_pending_outbound_step","detail":"detail"}"#,
        ),
        (
            "multiple_pending_outbound_steps",
            r#"{"kind":"multiple_pending_outbound_steps","detail":"detail"}"#,
        ),
        (
            "sync_window_busy",
            r#"{"kind":"sync_window_busy","detail":"detail"}"#,
        ),
        (
            "already_slim_for_different_step",
            r#"{"kind":"already_slim_for_different_step","detail":"detail"}"#,
        ),
    ] {
        let blocker = ShedBlockerWire {
            kind: kind.into(),
            detail: "detail".into(),
        };
        assert_eq!(serde_json::to_string(&blocker).unwrap(), wire);
        assert_eq!(
            serde_json::from_str::<ShedBlockerWire>(wire).unwrap(),
            blocker
        );
    }
}

#[test]
fn shed_blocker_wire_preserves_unknown_kinds() {
    for (slim, wire) in [
        (
            false,
            r#"{"slim":false,"status":"refused","blocker":{"kind":"future_blocker","detail":"wait for \"adapter\""}}"#,
        ),
        (
            true,
            r#"{"slim":true,"status":"refused","blocker":{"kind":"future_blocker","detail":"wait for \"adapter\""}}"#,
        ),
    ] {
        let response: CtlResponse = serde_json::from_str(wire).unwrap();
        response.validate().unwrap();
        let serialized = serde_json::to_string(&response).unwrap();
        let serialized_response: CtlResponse = serde_json::from_str(&serialized).unwrap();
        for response in [response, serialized_response] {
            let CtlResponse::Slim {
                slim: decoded_slim,
                status: ShedStatus::Refused,
                blocker: Some(blocker),
                ..
            } = response
            else {
                panic!("unknown blocker must remain displayable");
            };
            assert_eq!(decoded_slim, slim);
            assert_eq!(blocker.kind, "future_blocker");
            assert_eq!(blocker.detail, "wait for \"adapter\"");
        }
    }
}

#[test]
fn credentials_roundtrip() {
    let dek = [7u8; DEK_LEN];
    let token = [9u8; TOKEN_LEN];
    let mut buf = Vec::new();
    write_credentials(&mut buf, &dek, &token).unwrap();
    assert_eq!(buf.len(), CREDENTIALS_LEN);
    let creds = read_credentials(&buf[..]).unwrap();
    assert_eq!(creds.dek, dek);
    assert_eq!(creds.token, token);
}

#[test]
fn credentials_reject_short_and_long() {
    assert!(read_credentials(&[0u8; 63][..]).is_err());
    assert!(read_credentials(&[0u8; 65][..]).is_err());
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
fn hex_roundtrip() {
    let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
    assert_eq!(hex(&bytes), "000fa5ff");
    assert_eq!(from_hex("000fa5ff").unwrap(), bytes.to_vec());
}

/// TokenHex is #[serde(transparent)]: the wire shape must stay byte-identical
/// to the plain String field it replaced (contract version 1 unchanged).
#[test]
fn ledger_update_wire_shape() {
    let u = LedgerUpdate {
        op: "ledger_update".into(),
        vault: "v".into(),
        token: TokenHex::new("aa".into()),
        rev: 1,
        entries: vec![],
    };
    let j = serde_json::to_value(&u).unwrap();
    assert_eq!(j["token"], "aa");
    let back: LedgerUpdate = serde_json::from_str(
        r#"{"op":"ledger_update","vault":"v","token":"aa","rev":1,"entries":[]}"#,
    )
    .unwrap();
    assert_eq!(back.token.expose(), "aa");
}

#[test]
fn vault_names() {
    assert!(valid_vault_name("test-vault"));
    assert!(valid_vault_name("a"));
    assert!(!valid_vault_name(""));
    assert!(!valid_vault_name("-a"));
    assert!(!valid_vault_name("a-"));
    assert!(!valid_vault_name("A"));
    assert!(!valid_vault_name("a.b"));
    assert!(!valid_vault_name(&"x".repeat(64)));
}

#[test]
fn from_hex_rejects_malformed() {
    assert!(from_hex("abc").is_none()); // odd length
    assert!(from_hex("zz").is_none()); // non-hex
    assert!(from_hex("€a").is_none()); // even byte length, non-ASCII: must not panic
}

#[test]
fn ledger_update_validate() {
    let mut u = LedgerUpdate {
        op: "ledger_update".into(),
        vault: "v".into(),
        token: TokenHex::from_token(&[0u8; TOKEN_LEN]),
        rev: 1,
        entries: vec![],
    };
    u.validate().unwrap();

    u.op = "nope".into();
    assert!(u.validate().is_err());
    u.op = "ledger_update".into();

    u.vault = "../x".into();
    assert!(u.validate().is_err());
    u.vault = "v".into();

    u.token = TokenHex::new("zz".into());
    assert!(u.validate().is_err());
    u.token = TokenHex::from_token(&[0u8; TOKEN_LEN]);

    u.entries = (0..=MAX_LEDGER_ENTRIES)
        .map(|i| WakeEntry {
            id: format!("e{i}"),
            at: Schedule::Exact { at: 0 },
            reason_tag: String::new(),
        })
        .collect();
    assert!(u.validate().is_err());
    // Same list through the shared helper (the prepare_reap path).
    assert!(validate_wake_entries(&u.entries).is_err());
    assert!(validate_wake_entries(&u.entries[..1]).is_ok());
}

#[test]
fn wake_fields_reject_control_bytes() {
    let mut e = WakeEntry {
        id: "ok".into(),
        at: Schedule::Exact { at: 0 },
        reason_tag: "tag".into(),
    };
    e.validate().unwrap();
    e.id = "a\nb".into();
    assert!(e.validate().is_err());
    e.id = "ok".into();
    e.reason_tag = "t\u{0}g".into();
    assert!(e.validate().is_err());
}

#[test]
fn ctl_request_validate() {
    let ok = CtlRequest::AlarmDue {
        id: "e1".into(),
        reason_tag: "cron".into(),
    };
    ok.validate().unwrap();
    CtlRequest::Ping.validate().unwrap();
    let bad = [
        CtlRequest::AlarmDue {
            id: String::new(),
            reason_tag: String::new(),
        },
        CtlRequest::AlarmDue {
            id: "e1".into(),
            reason_tag: "x".repeat(MAX_REASON_TAG + 1),
        },
        CtlRequest::AlarmDue {
            id: "e\u{1b}1".into(),
            reason_tag: String::new(),
        },
    ];
    for req in bad {
        assert!(req.validate().is_err());
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
    let entries = vec![entry; MAX_LEDGER_ENTRIES];
    validate_wake_entries(&entries).unwrap();

    let resp = serde_json::to_string(&CtlResponse::PrepareReap {
        quiescent: false,
        ledger_rev: u64::MAX,
        next_wake: entries.clone(),
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
        rev: u64::MAX,
        entries,
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

    assert_eq!(CONTRACT_VERSION, SLIM_CONTRACT_VERSION);

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
