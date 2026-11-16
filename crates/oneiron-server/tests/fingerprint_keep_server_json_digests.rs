//! K-proof (oracle) for PLAN-UC-04 stage 6.4c: the oneiron-server sorted-JSON digests keep
//! their bytes.
//!
//! The training pins the server takes again (a question head's definition check, a probe's
//! token pin and a held-out case's input pin) now start through one helper under 6.4a's
//! `purposes::training_pack::PIN`; the meeting-audio command's host revision and ASR
//! selection receipt digest under `purposes::meeting_audio`; and an MCP call's page-argument
//! digest under `purposes::mcp::PAGE_ARGUMENTS`, whose held-content twin writes that
//! purpose's tag. Targets, export checks and verifier logs keep the training pins, the
//! meeting-audio command names its host and its ASR route by its digests, and a continuable
//! page keeps its digest and mints its cursor over it. So each must give main's bytes for
//! every value.
//!
//! The `base_*` modules hold main's lines at 41c9d7ffe245, copied by range (each range is named
//! above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only
//! in indentation. The few lines around the copies are the imports main's lines name, a
//! stand-in for each value they read (with only the fields they read or write), and a
//! wrapper for each private fn, or fn body part, they come from.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test fingerprint_keep_server_json_digests`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_server::mcp::mcp_page_argument_digest;
use oneiron_server::test_doors::fingerprint_keep_server_json_digests as door;
use serde_json::{Value, json};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_question_evaluation {
    use oneiron::Error;
    use serde_json::Value;

    // main 41c9d7ffe245: crates/oneiron-server/src/ai_host/training_pack/question_evaluation.rs:21-23
    fn invalid(detail: &str) -> Error {
        Error::InvalidConfig(detail.into())
    }

    /// The field of main's held-out `Row` that the case input pin reads.
    pub(crate) struct Row {
        pub(crate) input: Value,
    }

    /// The field of main's `CaseLog` that the case input pin fills.
    struct CaseLog {
        input_blake3: [u8; 32],
    }

    /// Main's pin of a held-out case's input, lines of `evaluate` there.
    pub(crate) fn main_case_input_pin(row: &Row) -> oneiron::Result<[u8; 32]> {
        // main 41c9d7ffe245: crates/oneiron-server/src/ai_host/training_pack/question_evaluation.rs:226-227
                let bytes = oneiron::llm::canonical_json_bytes(&row.input)
                    .map_err(|_| invalid("question input could not be encoded"))?;
        let case = CaseLog {
            // main 41c9d7ffe245: crates/oneiron-server/src/ai_host/training_pack/question_evaluation.rs:230-230
                        input_blake3: *blake3::hash(&bytes).as_bytes(),
        };
        Ok(case.input_blake3)
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_classifier {
    use serde_json::Value;

    /// The fields of main's `QuestionTarget` that the definition check reads.
    pub(crate) struct QuestionTarget {
        pub(crate) definition: Value,
        pub(crate) definition_blake3: [u8; 32],
    }

    /// Main's token pin of a probe's windows, the last lines of `tokens_blake3` there.
    pub(crate) fn main_tokens_pin(windows: Vec<Vec<u32>>) -> anyhow::Result<[u8; 32]> {
        // main 41c9d7ffe245: crates/oneiron-server/src/oneironer/local/classifier.rs:109-110
                let bytes = oneiron::llm::canonical_json_bytes(&windows)?;
                Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Main's definition check: its lines of `QuestionHead::load`, the encoding and the one
    /// clause of the load check that compares the pin.
    pub(crate) fn main_definition_matches(question: &QuestionTarget) -> anyhow::Result<bool> {
        // main 41c9d7ffe245: crates/oneiron-server/src/oneironer/local/classifier.rs:169-169
                let definition = oneiron::llm::canonical_json_bytes(&question.definition)?;
        Ok(true
            // main 41c9d7ffe245: crates/oneiron-server/src/oneironer/local/classifier.rs:174-174
                            && blake3::hash(&definition).as_bytes() == &question.definition_blake3
        )
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_meeting_audio {
    // main 41c9d7ffe245: crates/oneiron-server/src/commands/owner/meeting_audio.rs:27-27
    use sha2::{Digest, Sha256};

    // main 41c9d7ffe245: crates/oneiron-server/src/commands/owner/meeting_audio.rs:309-311
    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    /// Main's meeting-audio digest, which is private there.
    pub(crate) fn main_digest(bytes: &[u8]) -> String {
        digest(bytes)
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_paging {
    use oneiron_server::mcp::mcp_canonical_json;
    use serde::Serialize;

    // main 41c9d7ffe245: crates/oneiron-server/src/mcp/paging.rs:489-502
    #[must_use]
    pub fn mcp_page_argument_digest<T: Serialize>(arguments: &T) -> [u8; 32] {
        let mut value =
            serde_json::to_value(arguments).expect("endpoint tool arguments are plain JSON data");
        if let Some(object) = value.as_object_mut() {
            object.remove("page");
        }
        let canonical = mcp_canonical_json(&value);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.mcp.page-arguments.v2");
        hasher.update(&(canonical.len() as u64).to_be_bytes());
        hasher.update(canonical.as_bytes());
        *hasher.finalize().as_bytes()
    }

    // main 41c9d7ffe245: crates/oneiron-server/src/mcp/paging.rs:515-538
    pub(crate) fn mcp_page_argument_digest_held<T: Serialize>(
        arguments: &T,
        content_len: u64,
        write_content: impl FnOnce(&mut blake3::Hasher) -> std::io::Result<()>,
    ) -> std::io::Result<[u8; 32]> {
        let mut value = serde_json::to_value(arguments)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("page");
        }
        // The canonical text with the content's empty string, then with the
        // content's own string in its place.
        let placeholder = mcp_canonical_json(&value).len() as u64;
        let len = placeholder.saturating_sub(2).saturating_add(content_len);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.mcp.page-arguments.v2");
        hasher.update(&len.to_be_bytes());
        oneiron::receipt::write_call_json_with_member_path(
            &mut hasher,
            &value,
            &["arguments", "spec", "content_base64"],
            write_content,
        )?;
        Ok(*hasher.finalize().as_bytes())
    }
}

/// JSON values at the sorted JSON's edges: null, booleans, empty and nested containers,
/// unsorted keys (an empty one and one with a NUL), integers at their limits, fractions, a
/// negative zero, escapes, non-ASCII and long text, and a deep nest.
fn json_values() -> Vec<Value> {
    let mut deep = json!("leaf");
    for depth in 0..48 {
        deep = if depth % 2 == 0 {
            json!([deep])
        } else {
            json!({ "k": deep })
        };
    }
    vec![
        Value::Null,
        json!(true),
        json!(false),
        json!(""),
        json!("a"),
        json!("\u{0}\"\\\n\t\u{1f}"),
        json!("\u{ff}\u{1F600} non-ASCII"),
        json!(0),
        json!(-1),
        json!(u64::MAX),
        json!(i64::MIN),
        json!(0.5),
        json!(-0.0),
        json!(1e300),
        json!(f64::MIN_POSITIVE),
        json!([]),
        json!({}),
        json!([null, 1, "two", [3], { "four": 4 }]),
        json!({ "zeta": 1, "alpha": 2, "Mu": 3, "": 4, "a\u{0}": 5 }),
        json!({ "outer": { "b": [1, 2], "a": { "d": null, "c": true } } }),
        json!({ "question": "Is this a reply?", "labels": ["no", "yes"], "threshold": 0.25 }),
        json!({ "text": "k".repeat(4_096) }),
        deep,
    ]
}

/// Token windows: none, empty ones, one id, ids at u32's limits, a renderer's
/// prefix and suffix around a run, and two long windows.
fn token_windows() -> Vec<Vec<Vec<u32>>> {
    vec![
        vec![],
        vec![vec![]],
        vec![vec![], vec![]],
        vec![vec![0]],
        vec![vec![u32::MAX, 0, 1]],
        vec![vec![101, 2023, 102]],
        vec![vec![101, 7, 102], vec![101, 8, 102]],
        vec![(0..512).collect(), (512..1_024).collect()],
    ]
}

/// What the meeting-audio command hashes: the sorted JSON of a native host's capability
/// pins and of a selection receipt's shape, and plain byte rows (empty, JSON scalars,
/// bytes that are not UTF-8, a long run).
fn meeting_audio_rows() -> Vec<Vec<u8>> {
    let units = BTreeMap::from([
        ("asr".to_owned(), vec!["whisper-small@r1".to_owned()]),
        (
            "diarization".to_owned(),
            vec!["pyannote@r2".to_owned(), "vad@r0".to_owned()],
        ),
    ]);
    let components = BTreeMap::from([("ctranslate2".to_owned(), "c".repeat(64))]);
    let host = oneiron::llm::canonical_json_bytes(&(
        &"a".repeat(64),
        &components,
        &None::<String>,
        &Some("b".repeat(64)),
        &units,
    ))
    .expect("the pins encode");
    let host_bare = oneiron::llm::canonical_json_bytes(&(
        &String::new(),
        &BTreeMap::<String, String>::new(),
        &Some(String::new()),
        &None::<String>,
        &BTreeMap::<String, Vec<String>>::new(),
    ))
    .expect("the pins encode");
    let selection = oneiron::llm::canonical_json_bytes(&json!({
        "owner": "0123456789abcdef0123456789abcdef",
        "vault_path": "/vaults/owner",
        "authority_vault": null,
        "run_instance": "meeting-audio:00",
        "voice_precedence": "vault_first",
        "selected": { "model": "whisper-small@r1", "locality": "on_device" },
        "host_route": { "origin": "meeting-audio-command", "revision": "native:00" },
        "host_revision": "d".repeat(64),
        "unit_models": units,
    }))
    .expect("the receipt encodes");
    vec![
        host,
        host_bare,
        selection,
        Vec::new(),
        b"null".to_vec(),
        b"[]".to_vec(),
        vec![0xff, 0x00, 0x80],
        vec![b'x'; 65_536],
    ]
}

#[test]
fn the_server_purposes_keep_main_s_recipes() {
    let pin = purposes::training_pack::PIN;
    assert_eq!(
        (pin.hash(), pin.tag_mode()),
        (LegacyHash::Blake3, TagMode::NotHashed)
    );
    for purpose in [
        purposes::meeting_audio::HOST_REVISION,
        purposes::meeting_audio::ASR_SELECTION_RECEIPT,
    ] {
        assert_eq!(
            (purpose.hash(), purpose.tag_mode()),
            (LegacyHash::Sha256, TagMode::NotHashed)
        );
    }
    let page = purposes::mcp::PAGE_ARGUMENTS;
    assert_eq!(
        (page.hash(), page.tag_mode(), page.tag()),
        (
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            "oneiron.mcp.page-arguments.v2"
        )
    );
}

#[test]
fn the_training_pins_keep_their_bytes() {
    let values = json_values();
    let mut pins = BTreeSet::new();
    for value in &values {
        let head = door::training_pin(value).expect("a JSON value has sorted JSON");
        let row = base_question_evaluation::Row {
            input: value.clone(),
        };
        assert_eq!(
            base_question_evaluation::main_case_input_pin(&row).expect("main pins the input"),
            head,
            "case input {value}"
        );
        let mut question = base_classifier::QuestionTarget {
            definition: value.clone(),
            definition_blake3: head,
        };
        assert!(
            base_classifier::main_definition_matches(&question).expect("main encodes it"),
            "definition {value}"
        );
        question.definition_blake3[31] ^= 1;
        assert!(
            !base_classifier::main_definition_matches(&question).expect("main encodes it"),
            "definition {value} with another pin"
        );
        pins.insert(head);
    }
    assert_eq!(pins.len(), values.len(), "each value has its own pin");
}

#[test]
fn the_token_pins_keep_their_bytes() {
    let windows = token_windows();
    let mut pins = BTreeSet::new();
    for window in &windows {
        let head = door::training_pin(window).expect("token ids have sorted JSON");
        assert_eq!(
            base_classifier::main_tokens_pin(window.clone()).expect("main pins the windows"),
            head,
            "windows {window:?}"
        );
        pins.insert(head);
    }
    assert_eq!(pins.len(), windows.len(), "each window set has its own pin");
}

#[test]
fn the_meeting_audio_digests_keep_their_bytes() {
    let rows = meeting_audio_rows();
    let mut digests = BTreeSet::new();
    for bytes in &rows {
        let main = base_meeting_audio::main_digest(bytes);
        assert_eq!(main.len(), 64, "64 hex digits");
        for purpose in [
            purposes::meeting_audio::HOST_REVISION,
            purposes::meeting_audio::ASR_SELECTION_RECEIPT,
        ] {
            assert_eq!(
                door::meeting_audio_digest(purpose, bytes),
                main,
                "{} over {} bytes",
                purpose.tag(),
                bytes.len()
            );
        }
        digests.insert(main);
    }
    assert_eq!(digests.len(), rows.len(), "each row has its own digest");
}

#[test]
fn the_page_argument_digest_keeps_its_bytes() {
    let mut rows = json_values();
    rows.extend([
        json!({ "page": { "limit": 5 } }),
        json!({ "query": "tasks", "page": { "limit": 5, "cursor": "mcpc1:00" } }),
        json!({ "query": "tasks" }),
        json!({ "page": null, "query": "tasks" }),
        json!({ "query": "tasks", "pages": 2 }),
        json!({ "nested": { "page": 1 } }),
        json!([{ "page": 1 }]),
        json!({ "arguments": { "spec": { "content_base64": "QUJD" } }, "tool": "vault.files.write" }),
    ]);
    for arguments in &rows {
        assert_eq!(
            mcp_page_argument_digest(arguments),
            base_paging::mcp_page_argument_digest(arguments),
            "arguments {arguments}"
        );
    }
    assert_eq!(
        mcp_page_argument_digest(&json!({ "query": "tasks", "page": { "limit": 5 } })),
        mcp_page_argument_digest(&json!({ "query": "tasks" })),
        "the page member is not in the digest"
    );
}

#[test]
fn the_held_page_argument_digest_keeps_its_bytes() {
    let shapes = [
        json!({ "arguments": { "spec": { "content_base64": "" } } }),
        json!({
            "tool": "vault.files.write",
            "arguments": {
                "spec": { "path": "a/b.txt", "content_base64": "", "zeta": [1, 2] },
                "alpha": true
            },
            "page": { "limit": 3 }
        }),
        json!({
            "arguments": { "spec": { "": "", "content": "x\u{0}\"", "content_base64": "" }, "z": {} },
            "a": null,
            "\u{ff}": -0.5
        }),
    ];
    let contents = [
        String::new(),
        "QQ==".to_owned(),
        "QUJD".to_owned(),
        "AAAA".repeat(1_024),
    ];
    let mut digests = BTreeSet::new();
    for payload in &shapes {
        for content in &contents {
            let text = serde_json::to_string(content).expect("a string encodes");
            let write = |hasher: &mut blake3::Hasher| -> std::io::Result<()> {
                hasher.update(text.as_bytes());
                Ok(())
            };
            let len = text.len() as u64;
            let head = door::mcp_page_argument_digest_held(payload, len, write)
                .expect("the payload names the content");
            let main = base_paging::mcp_page_argument_digest_held(payload, len, write)
                .expect("the payload names the content");
            assert_eq!(
                head,
                main,
                "payload {payload} with {} content bytes",
                content.len()
            );
            let mut whole = payload.clone();
            whole["arguments"]["spec"]["content_base64"] = Value::String(content.clone());
            assert_eq!(
                head,
                base_paging::mcp_page_argument_digest(&whole),
                "the whole payload {whole} on main"
            );
            digests.insert(head);
        }
    }
    assert_eq!(digests.len(), shapes.len() * contents.len());
    let bare = json!({ "arguments": { "other": 1 } });
    let write = |hasher: &mut blake3::Hasher| -> std::io::Result<()> {
        hasher.update(b"\"\"");
        Ok(())
    };
    assert!(door::mcp_page_argument_digest_held(&bare, 2, write).is_err());
    assert!(base_paging::mcp_page_argument_digest_held(&bare, 2, write).is_err());
}
