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

