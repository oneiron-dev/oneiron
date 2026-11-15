//! K-proof (oracle) for PLAN-UC-04 stage 1.3: the outbound intent id keeps its bytes.
//!
//! `derive_intent_id` now takes its preimage from the kept sorted-JSON encoder
//! (`crate::llm::canonical_json_bytes`) and starts its plain BLAKE3 through the
//! fingerprint crate's K door (`purposes::outbound_intent_ledger::INTENT_ID`). The id is
//! the intent ledger's row key and idempotency key, so it must give main's bytes for
//! every call. `base` below is a copy of main's body
//! (`crates/oneiron/src/outbound_intent_ledger/dispatch.rs:60-117` at ea1e495a6605); it
//! differs from those lines only in its indentation.
//!
//! The identity holds no float, no option and no list of variable length, so the
//! fixture table has no NaN, `None` or empty-list row. Its field order (attempt_id,
//! call_seq, server, tool, payload_hash) is not sorted, so every row checks the key sort.

use oneiron::attempt_queue::AttemptId;
use oneiron::outbound_intent_ledger::derive_intent_id;

// Not formatted, so the copy stays line for line equal to main's.
#[rustfmt::skip]
mod base {
    use oneiron::attempt_queue::AttemptId;
    use oneiron::outbound_intent_ledger::{IntentLedgerError, IntentLedgerResult};

    pub fn derive_intent_id(
        attempt_id: AttemptId,
        call_seq: u64,
        server: &str,
        tool: &str,
        payload_hash: &[u8; 32],
    ) -> IntentLedgerResult<[u8; 32]> {
        use std::collections::BTreeMap;

        use serde::Serialize;
        use serde_json::{Map as JsonMap, Value as JsonValue};

        #[derive(Serialize)]
        struct IntentIdentity<'a> {
            attempt_id: &'a [u8; 16],
            call_seq: u64,
            server: &'a str,
            tool: &'a str,
            payload_hash: &'a [u8; 32],
        }

        fn canonicalize_json(value: JsonValue) -> JsonValue {
            match value {
                JsonValue::Array(values) => {
                    JsonValue::Array(values.into_iter().map(canonicalize_json).collect())
                }
                JsonValue::Object(entries) => {
                    let mut sorted = BTreeMap::new();
                    for (key, value) in entries {
                        sorted.insert(key, canonicalize_json(value));
                    }
                    let mut canonical = JsonMap::new();
                    for (key, value) in sorted {
                        canonical.insert(key, value);
                    }
                    JsonValue::Object(canonical)
                }
                scalar => scalar,
            }
        }

        fn canonical_hash<T: Serialize>(value: &T) -> IntentLedgerResult<[u8; 32]> {
            const FAILED: &str = "outbound intent identity canonicalization failed";
            let value =
                serde_json::to_value(value).map_err(|_| IntentLedgerError::InvalidRecord(FAILED))?;
            let bytes = serde_json::to_vec(&canonicalize_json(value))
                .map_err(|_| IntentLedgerError::InvalidRecord(FAILED))?;
            Ok(*blake3::hash(&bytes).as_bytes())
        }

        canonical_hash(&IntentIdentity {
            attempt_id: attempt_id.as_bytes(),
            call_seq,
            server,
            tool,
            payload_hash,
        })
    }
}

struct Fixture {
    name: &'static str,
    attempt_id: [u8; 16],
    call_seq: u64,
    server: &'static str,
    tool: &'static str,
    payload_hash: [u8; 32],
}

fn fixtures() -> Vec<Fixture> {
    let counting: [u8; 16] = std::array::from_fn(|at| at as u8);
    vec![
        Fixture {
            name: "zeros and empty strings",
            attempt_id: [0; 16],
            call_seq: 0,
            server: "",
            tool: "",
            payload_hash: [0; 32],
        },
        Fixture {
            name: "u64::MAX and all-ones bytes",
            attempt_id: [0xff; 16],
            call_seq: u64::MAX,
            server: "mcp.example",
            tool: "send_email",
            payload_hash: [0xff; 32],
        },
        Fixture {
            name: "unicode, quotes, backslash, NUL and control text",
            attempt_id: counting,
            call_seq: 1,
            server: "\u{65e5}\u{672c}-\u{1f600}",
            tool: "say \"hi\"\\\u{0}\n\t\u{7f}",
            payload_hash: std::array::from_fn(|at| (at * 7) as u8),
        },
        Fixture {
            name: "first integer past 2^53",
            attempt_id: counting,
            call_seq: (1 << 53) + 1,
            server: "s",
            tool: "t",
            payload_hash: [0x5a; 32],
        },
    ]
}

#[test]
fn the_intent_id_keeps_main_bytes() {
    let fresh = AttemptId::now();
    let mut ids = std::collections::BTreeSet::new();
    for fixture in fixtures() {
        let attempt_id = AttemptId::from_bytes(&fixture.attempt_id).expect("16 bytes");
        let head = derive_intent_id(
            attempt_id,
            fixture.call_seq,
            fixture.server,
            fixture.tool,
            &fixture.payload_hash,
        )
        .expect("head id");
        let expected = base::derive_intent_id(
            attempt_id,
            fixture.call_seq,
            fixture.server,
            fixture.tool,
            &fixture.payload_hash,
        )
        .expect("base id");
        assert_eq!(head, expected, "fixture {}", fixture.name);
        ids.insert(head);
    }
    assert_eq!(
        ids.len(),
        fixtures().len(),
        "distinct fixtures give distinct ids"
    );

    // A fresh time-ordered attempt id, as production mints one.
    let head = derive_intent_id(fresh, 7, "server", "tool", &[1; 32]).expect("head id");
    let expected = base::derive_intent_id(fresh, 7, "server", "tool", &[1; 32]).expect("base id");
    assert_eq!(head, expected, "fresh attempt id");
}
