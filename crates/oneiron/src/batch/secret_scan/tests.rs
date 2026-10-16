use super::*;
use crate::error::GateError;

/// Review r11 (Sol R11-1, P1): the walk read each map key from a copy, so
/// maps nested in their keys held a copy of everything inside at every
/// level: 128 such levels around an array of nils held over a hundred copies
/// of the array at once, past what an install's room counts a decoded byte
/// at. A key is read in place now, and nesting in keys costs what nesting in
/// values does; a credential deep in a key is still refused.
#[test]
fn maps_nested_in_their_keys_cost_what_maps_nested_in_their_values_do() {
    use crate::session_overlay::hygiene_tests::peak_allocated;
    const LEVELS: usize = 128;
    const NILS: u32 = 64 * 1024;
    let mut nils = vec![0xdd];
    nils.extend_from_slice(&NILS.to_be_bytes());
    nils.resize(5 + NILS as usize, 0xc0);
    // {{{[nil, …]: nil}: nil} …: nil}
    let mut in_keys = vec![0x81; LEVELS];
    in_keys.extend_from_slice(&nils);
    in_keys.extend(std::iter::repeat_n(0xc0, LEVELS));
    // {nil: {nil: {… [nil, …]}}}
    let mut in_values = [0x81, 0xc0].repeat(LEVELS);
    in_values.extend_from_slice(&nils);
    let (scanned, keys) = peak_allocated(|| scan_write_payload(&in_keys));
    scanned.expect("no credential in the keys");
    let (scanned, values) = peak_allocated(|| scan_write_payload(&in_values));
    scanned.expect("no credential in the values");
    assert!(
        keys <= 2 * values,
        "nested in keys held {keys} bytes at once; in values, {values}"
    );

    let mut key = rmpv::Value::Map(vec![(
        rmpv::Value::from("password"),
        rmpv::Value::Binary(b"private fixture".to_vec()),
    )]);
    for _ in 0..LEVELS {
        key = rmpv::Value::Map(vec![(key, rmpv::Value::Nil)]);
    }
    let mut deep = Vec::new();
    rmpv::encode::write_value(&mut deep, &key).expect("encode");
    let error = scan_payload(&deep).expect_err("a credential deep in a key");
    assert!(
        matches!(error, Error::Gate(GateError::GateWriteRejected { reason_codes, .. })
        if reason_codes.contains(&"gate.secret_scan.sensitive_env"))
    );
}

#[test]
fn credential_fields_cannot_hide_behind_messagepack_binary_or_json_escapes() {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(
        &mut bytes,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("password"),
            rmpv::Value::Binary(b"private fixture".to_vec()),
        )]),
    )
    .unwrap();
    for payload in [&bytes[..], &br#"{"pass\u0077ord":"private fixture"}"#[..]] {
        let error = scan_payload(payload).expect_err("typed credential field");
        assert!(
            matches!(error, Error::Gate(GateError::GateWriteRejected { reason_codes, .. })
            if reason_codes.contains(&"gate.secret_scan.sensitive_env"))
        );
    }
}

#[test]
fn scan_payload_rejects_exact_length_secret_prefixes_with_suffix_labels() {
    for (payload, expected_reason) in [
        ("id=AKIA0123456789ABCDEF_suffix", REASON_AWS_ACCESS_KEY_ID),
        (
            "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz_suffix",
            REASON_GITHUB_TOKEN,
        ),
        (
            "key=AIza0123456789abcdefghijklmnopqrstuvwxy_suffix",
            REASON_GOOGLE_API_KEY,
        ),
        (
            "token=sk-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL_suffix",
            REASON_OPENAI_KEY,
        ),
    ] {
        let err = scan_payload(payload.as_bytes())
            .expect_err("exact-length secret prefix with suffix label must reject");

        match err {
            Error::Gate(GateError::GateWriteRejected { reason_codes, .. }) => {
                assert_eq!(reason_codes.as_slice(), &[REASON_DETECTED, expected_reason]);
            }
            other => panic!("expected GateWriteRejected, got {other:?}"),
        }
    }
}

#[test]
fn scan_batch_ops_rejects_phonetic_secret_payload() {
    let dir = tempfile::tempdir().expect("vault tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).expect("open vault");
    let txn = vault.store.env.read_txn().expect("read txn");
    let err = scan_batch_ops(
        &vault.store,
        &txn,
        &[BatchOp::Phonetic {
            id: crate::entity_id::EntityId::now(),
            codes: vec!["token=ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_owned()],
        }],
    )
    .expect_err("known GitHub token fixture in phonetic payload must reject");

    match err {
        Error::Gate(GateError::GateWriteRejected { reason_codes, .. }) => {
            assert_eq!(
                reason_codes.as_slice(),
                &[REASON_DETECTED, REASON_GITHUB_TOKEN]
            );
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

/// Base64 of an English sentence, not a key: the body shape a real block has.
const SYNTHETIC_KEY_BODY: &str =
    "U3ludGhldGljIGZpeHR1cmUgYm9keSBmb3IgdGhlIHNlY3JldCBzY2FuIHRlc3RzLiBJdCBpcyBub3QgYSBrZXku";

fn write_reason(payload: &str) -> Option<&'static str> {
    match scan_payload(payload.as_bytes()) {
        Ok(_) => None,
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
            assert_eq!(reason_codes.first(), Some(&REASON_DETECTED));
            reason_codes.get(1).copied()
        }
        Err(other) => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

/// BIP39 reference vectors (bitcoin/bips, trezor/python-mnemonic): public test
/// phrases whose last word carries a valid checksum. They guard no funds.
const VALID_PHRASES: [&str; 4] = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
];

#[test]
fn checksum_valid_seed_lists_reject_and_checksum_invalid_lists_pass() {
    for phrase in VALID_PHRASES {
        for layout in [
            phrase.to_owned(),
            format!("My recovery words: {phrase}."),
            phrase
                .split(' ')
                .enumerate()
                .map(|(index, word)| format!("{}. {word}", index + 1))
                .collect::<Vec<_>>()
                .join("\n"),
            format!("{{\"words\": \"{phrase}\"}}"),
        ] {
            assert_eq!(
                write_reason(&layout),
                Some("gate.secret_scan.mnemonic"),
                "{layout}"
            );
        }
    }
    for invalid in [
        // The last word breaks the checksum of an otherwise valid vector.
        "legal winner thank year wave sausage worth useful legal winner thank year",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "drive turn valley ocean coffee garden window yellow orange basket camera rocket",
    ] {
        assert_eq!(write_reason(invalid), None, "{invalid}");
        assert_eq!(scan_file_content("", invalid.as_bytes()), None, "{invalid}");
    }
}

#[test]
fn a_labelled_or_listed_seed_counts_but_a_long_word_list_does_not() {
    let phrase = VALID_PHRASES[0];
    // `note` is itself a list word; the phrase still stands on its own line.
    for labelled in [
        format!("note:\n{phrase}"),
        format!("Wallet backup:\n{phrase}"),
    ] {
        assert_eq!(
            write_reason(&labelled),
            Some("gate.secret_scan.mnemonic"),
            "{labelled}"
        );
    }
    // A label line that is a list word, over a numbered one-word-per-line list.
    let numbered = phrase
        .split(' ')
        .enumerate()
        .map(|(index, word)| format!("{}) {word}", index + 1))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        write_reason(&format!("note\n{numbered}")),
        Some("gate.secret_scan.mnemonic")
    );
    assert_eq!(
        write_reason(&phrase.replace(' ', ", ")),
        Some("gate.secret_scan.mnemonic")
    );
    // Thirty common list words, one per line: never offered as windows.
    let groceries = "apple\nbanana\nbread\nbutter\ncheese\nchicken\ncoffee\ncorn\negg\n\
                     fish\nflour\ngarlic\nhoney\nlemon\nlettuce\nmango\nmilk\nmushroom\n\
                     noodle\nolive\nonion\norange\npepper\npotato\nrice\nsalad\nsalt\n\
                     sugar\ntomato\nwine";
    assert_eq!(write_reason(groceries), None);
    assert_eq!(scan_file_content("", groceries.as_bytes()), None);
}

#[test]
fn a_list_word_run_inside_prose_is_not_a_seed_but_the_same_run_on_its_own_is() {
    let phrase = VALID_PHRASES[0];
    let prose = format!("We talked through {phrase} it and moved on.");
    assert_eq!(write_reason(&prose), None);
    assert_eq!(scan_file_content("", prose.as_bytes()), None);
    // Twin: the same checksum-valid run standing as its own line.
    let own_line = format!("We talked it through.\n{phrase}\nAfterwards we moved on.");
    assert_eq!(write_reason(&own_line), Some("gate.secret_scan.mnemonic"));
    // A census-shaped sentence: twelve list words in a row, inside prose.
    let sentence = "Honestly you can easily drive away before lunch since hotel room service \
                    will be ready, she said.";
    assert_eq!(write_reason(sentence), None);
}

#[test]
fn write_door_assignments_need_real_secret_material() {
    for placeholder in [
        "password=password",
        "this.password = password",
        "DB_PASSWORD: secret",
        "- MYSQL_ROOT_PASSWORD=secret",
        "password: test",
        "password = changeme",
        "token: dummy",
        "api_key=<your-key>",
        "password=<influxdb_password>",
        "token=$TOKEN",
        "MYSQL_PASSWORD=${MYSQL_PASSWORD}",
        "api_key: YOUR_API_KEY",
        "aws_secret_access_key = YOUR_SECRET_KEY",
        "password = your_password",
        "api_key=xxxxxxxxxxxxxxxx",
        "secret: example-key-0123456789",
        "api_key = my_api_key",
        "password: str",
        "token = string",
        "X-Shopify-Access-Token: access_token",
        "X-TOKEN: this.apiKey",
        "API-Key: process.env.WEATHER_API_KEY",
        "hashed_password = Column(String(128))",
        "token = request.headers['Authorization']",
        "Authorization: Bearer",
        "Authorization: `Bearer ${token}`",
        "private_key: ~/.ssh/id_ed25519",
        "new_password = prompt(\"Please enter your new password\")",
    ] {
        assert_eq!(write_reason(placeholder), None, "{placeholder}");
    }
    for real in [
        "DB_PASSWORD=t7Rk2pLq9WzX",
        "password: Xq7-not-for-memory-42",
        "SERVICE_API_KEY=0123456789abcdef0123456789abcdef",
        "MAILER_API_KEY = 4f9c2e7a1b8d3f6e0a5c9b2d7e1f4a8c3b6d9e2f",
        "Authorization: Bearer q8Zt3NcV2mXp7LkR4sJd",
        "export ACCESS_TOKEN=\"vT9q2LmX8rKz4WpN6sHd1cYb\"",
    ] {
        assert_eq!(
            write_reason(real),
            Some("gate.secret_scan.sensitive_env"),
            "{real}"
        );
    }
}

#[test]
fn serve_and_export_keep_the_wide_assignment_rule() {
    // Release doors redact any non-placeholder value under a credential name,
    // even when the write door would have stored it.
    for unfamiliar in ["api_key = 'residual-file-credential'", "password=password"] {
        assert_eq!(write_reason(unfamiliar), None, "{unfamiliar}");
        assert_eq!(
            scan_file_content("", unfamiliar.as_bytes()),
            Some("gate.secret_scan.sensitive_env"),
            "{unfamiliar}"
        );
    }
    let mut value = serde_json::json!({ "password": "password" });
    assert!(sanitize_credentials(&mut value, true));
    assert_eq!(value, serde_json::json!({ "password": null }));
    // A typed credential field at the write door still refuses a real value
    // and passes only a placeholder.
    assert_eq!(
        write_reason(r#"{"password":"fixture-super-secret"}"#),
        Some("gate.secret_scan.sensitive_env")
    );
    assert_eq!(write_reason(r#"{"password":"changeme"}"#), None);
}

#[test]
fn the_write_door_needs_a_real_key_block_and_release_doors_keep_the_header_rule() {
    for not_a_key in [
        "Paste the line -----BEGIN RSA PRIVATE KEY----- at the top of the file.".to_owned(),
        "-----BEGIN PRIVATE KEY-----\nsynthetic-not-a-key\n-----END PRIVATE KEY-----".to_owned(),
        "The file starts with `-----BEGIN PRIVATE KEY-----` and ends with \
         `-----END PRIVATE KEY-----`, with the key in between."
            .to_owned(),
        format!("-----BEGIN PRIVATE KEY-----\n{SYNTHETIC_KEY_BODY}"),
        "-----BEGIN PRIVATE KEY-----\nMIIEow...\n-----END PRIVATE KEY-----".to_owned(),
    ] {
        assert_eq!(write_reason(&not_a_key), None, "{not_a_key}");
        // A line-at-a-time scanner (the pre-receive door) sees a header
        // without its body; release doors keep refusing on the header alone.
        assert_eq!(
            scan_file_content("", not_a_key.as_bytes()),
            Some(REASON_PRIVATE_KEY)
        );
    }
    for key in [
        format!("-----BEGIN PRIVATE KEY-----\n{SYNTHETIC_KEY_BODY}\n-----END PRIVATE KEY-----"),
        format!(
            "intro\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: \
             AES-128-CBC,00FF\n\n{}\n{}\n-----END RSA PRIVATE KEY-----\noutro",
            &SYNTHETIC_KEY_BODY[..48],
            &SYNTHETIC_KEY_BODY[48..]
        ),
        format!(
            "KEY = \"-----BEGIN EC PRIVATE KEY-----\\n{SYNTHETIC_KEY_BODY}\\n-----END EC PRIVATE KEY-----\""
        ),
        format!(
            "key = \"-----BEGIN OPENSSH PRIVATE KEY-----\\n\" +\n  \"{}\\n\" +\n  \"{}\\n\" +\n  \
             \"-----END OPENSSH PRIVATE KEY-----\"",
            &SYNTHETIC_KEY_BODY[..48],
            &SYNTHETIC_KEY_BODY[48..]
        ),
    ] {
        assert_eq!(write_reason(&key), Some(REASON_PRIVATE_KEY), "{key}");
        assert_eq!(
            scan_file_content("", key.as_bytes()),
            Some(REASON_PRIVATE_KEY)
        );
    }
}

/// Provider token shapes, assembled at run time so no literal in the source
/// matches a provider pattern.
#[test]
fn every_provider_token_shape_still_rejects() {
    let body36 = "0123456789abcdefghijklmnopqrstuvwxyz";
    for (token, reason) in [
        (
            ["AK", "IA0123456789ABCDEF"].concat(),
            REASON_AWS_ACCESS_KEY_ID,
        ),
        (["gh", "p_", body36].concat(), REASON_GITHUB_TOKEN),
        (["gh", "o_", body36].concat(), REASON_GITHUB_TOKEN),
        (
            ["github", "_pat_", body36, body36].concat(),
            REASON_GITHUB_TOKEN,
        ),
        (
            ["AI", "za", "0123456789abcdefghijklmnopqrstuvwxy"].concat(),
            REASON_GOOGLE_API_KEY,
        ),
        (["sk", "-proj-", body36].concat(), REASON_OPENAI_KEY),
        (["xo", "xb-", body36].concat(), REASON_SLACK_TOKEN),
        (["sk", "_live_", body36].concat(), REASON_STRIPE_KEY),
    ] {
        let prose = format!("the value is {token} for now");
        assert_eq!(write_reason(&prose), Some(reason), "{reason}");
        assert_eq!(scan_file_content("", prose.as_bytes()), Some(reason));
    }
}

/// F23 (H49, H66): a credential keeps its reason after leading token bytes
/// (one letter, `_`, `-`), while snake and kebab prose holding a provider
/// prefix inside a word (Sol R1: or a whole word) is not read as a key.
#[test]
fn a_credential_after_leading_token_bytes_still_rejects() {
    let body36 = "0123456789abcdefghijklmnopqrstuvwxyz";
    for (token, reason) in [
        (
            ["AK", "IA0123456789ABCDEF"].concat(),
            REASON_AWS_ACCESS_KEY_ID,
        ),
        (["gh", "p_", body36].concat(), REASON_GITHUB_TOKEN),
        (
            ["github", "_pat_", body36, body36].concat(),
            REASON_GITHUB_TOKEN,
        ),
        (
            ["AI", "za", "0123456789abcdefghijklmnopqrstuvwxy"].concat(),
            REASON_GOOGLE_API_KEY,
        ),
        (
            ["sk", "-", body36, "ABCDEFGHIJKL"].concat(),
            REASON_OPENAI_KEY,
        ),
        (["sk", "-proj-", body36].concat(), REASON_OPENAI_KEY),
        (["xo", "xb-", body36].concat(), REASON_SLACK_TOKEN),
        (["sk", "_live_", body36].concat(), REASON_STRIPE_KEY),
        (["rk", "_live_", body36].concat(), REASON_STRIPE_KEY),
    ] {
        for lead in ["X", "_", "-", "x9_"] {
            let prose = format!("the value is {lead}{token} for now");
            assert_eq!(write_reason(&prose), Some(reason), "{lead}{reason}");
            assert_eq!(scan_file_content("", prose.as_bytes()), Some(reason));
        }
    }
    for prose in [
        "highs_and_lows_of_the_quarterly_market_report_for_this_year",
        "risk_live_monitoring_dashboard_configuration_v2",
        "task-assessment-for-the-quarterly-planning-meeting-notes-and-more-words",
        "task-proj-quarterly-planning-meeting-notes-and-more-words",
    ] {
        assert_eq!(write_reason(prose), None, "{prose}");
    }
}

/// A token-shaped name assembled at run time, so no literal in the source
/// matches a provider pattern.
fn token_shape() -> String {
    format!("gh{}_{}", 'p', "0123456789abcdefghijklmnopqrstuvwxyz")
}

#[test]
fn a_credential_shaped_json_key_is_read_like_a_value() {
    // The escape keeps the raw text from spelling the token; the decoded key does.
    let token = token_shape();
    let escaped = format!(r#"{{"gh\u0070{}":"note"}}"#, &token[3..]);
    assert_eq!(
        write_reason(&escaped),
        Some("gate.secret_scan.sensitive_env")
    );
    let mut fields = serde_json::Map::new();
    fields.insert("safe".to_owned(), "kept".into());
    fields.insert(token, "note".into());
    let mut value = serde_json::Value::Object(fields);
    assert!(sanitize_credentials(&mut value, false));
    assert_eq!(value, serde_json::json!({ "safe": "kept" }));
}

#[test]
fn a_repeated_json_key_cannot_hide_its_first_value_from_the_write_door() {
    // The first key is escaped, so no text rule reads it: only a reading that
    // keeps both members does.
    let payload = r#"{"pass\u0077ord":"Xq7-not-for-memory-42","password":"[redacted]"}"#;
    assert_eq!(
        write_reason(payload),
        Some("gate.secret_scan.sensitive_env")
    );
}

#[test]
fn a_secret_split_over_array_items_is_read_whole() {
    let words: Vec<rmpv::Value> = VALID_PHRASES[1].split(' ').map(rmpv::Value::from).collect();
    let mut key_lines = vec![rmpv::Value::from("-----BEGIN PRIVATE KEY-----")];
    key_lines.extend(
        SYNTHETIC_KEY_BODY
            .as_bytes()
            .chunks(48)
            .map(|line| rmpv::Value::from(std::str::from_utf8(line).unwrap())),
    );
    key_lines.push(rmpv::Value::from("-----END PRIVATE KEY-----"));
    for (field, items) in [("words", words), ("key", key_lines)] {
        let value = rmpv::Value::Map(vec![(rmpv::Value::from(field), rmpv::Value::Array(items))]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).unwrap();
        assert!(scan_payload(&bytes).is_err(), "{field}");
        let mut served = value.clone();
        assert!(
            sanitize_messagepack_credentials(&mut served, false),
            "{field}"
        );
        assert_eq!(
            served,
            rmpv::Value::Map(vec![(
                rmpv::Value::from(field),
                rmpv::Value::from("[redacted]")
            )])
        );
    }
    // Ordinary lists stay readable.
    let mut tags = serde_json::json!({ "tags": ["travel", "japan", "spring"] });
    assert!(!sanitize_credentials(&mut tags, false));
}

#[test]
fn a_recovery_phrase_wrapped_over_lines_is_still_a_phrase() {
    for phrase in VALID_PHRASES {
        let words: Vec<&str> = phrase.split(' ').collect();
        let half = words.len() / 2;
        let wrapped = format!("{}\n{}", words[..half].join(" "), words[half..].join(" "));
        assert_eq!(
            write_reason(&wrapped),
            Some("gate.secret_scan.mnemonic"),
            "{wrapped}"
        );
        assert_eq!(
            scan_file_content("", wrapped.as_bytes()),
            Some("gate.secret_scan.mnemonic")
        );
    }
    // A markdown list of short phrases is still prose.
    let words: Vec<&str> = VALID_PHRASES[1].split(' ').collect();
    let listed = words
        .chunks(2)
        .map(|pair| format!("- {}", pair.join(" ")))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(write_reason(&listed), None, "{listed}");
}

#[test]
fn a_placeholder_word_inside_a_password_does_not_make_it_a_placeholder() {
    for real in [
        r#"{"password":"Q7xk2Lp9dummyZ84mWv3"}"#,
        r#"{"password":"Q7xk2Lp9exampleZ84mW"}"#,
        r#"{"password":"yourQ7xk2Lp9Z84mWv3"}"#,
        "password=Q7xk2Lp9dummyZ84mWv3",
        "password=Q7xk2xxxxLp9Z84mWv3",
    ] {
        assert_eq!(
            write_reason(real),
            Some("gate.secret_scan.sensitive_env"),
            "{real}"
        );
    }
    for stand_in in [
        r#"{"password":"dummy-password-1"}"#,
        r#"{"api_key":"your-api-key-here"}"#,
        r#"{"token":"${TOKEN}"}"#,
        r#"{"password":"change_me"}"#,
        r#"{"token":"...abcd"}"#,
    ] {
        assert_eq!(write_reason(stand_in), None, "{stand_in}");
    }
}

#[test]
fn a_private_key_joined_from_literals_on_one_line_is_a_key() {
    let (first, rest) = SYNTHETIC_KEY_BODY.split_at(48);
    let source = format!(
        "k = \"-----BEGIN PRIVATE KEY-----\\n\" + \"{first}\\n\" + \"{rest}\\n\" + \
         \"-----END PRIVATE KEY-----\""
    );
    assert_eq!(write_reason(&source), Some(REASON_PRIVATE_KEY), "{source}");
}

/// An inert refinement receipt: magic, two ids, then the receipt JSON.
fn refinement_carrier(question: &str) -> Vec<u8> {
    let mut bytes = b"oneiron.refinement-receipt.v1\0".to_vec();
    bytes.extend_from_slice(&[7; 32]);
    bytes.extend_from_slice(
        serde_json::json!({ "kind": "skill", "receipt": { "question": question } })
            .to_string()
            .as_bytes(),
    );
    bytes
}

#[test]
fn a_framed_receipt_is_read_through_its_frame() {
    let carrier = refinement_carrier("password=Xq7-not-for-memory-42 merge?");
    assert!(scan_payload(&carrier).is_err());
    assert_eq!(
        scan_file_content("", &carrier),
        Some("gate.secret_scan.sensitive_env")
    );
    let plain = refinement_carrier("merge the two skills?");
    assert!(scan_payload(&plain).is_ok());
    assert_eq!(scan_file_content("", &plain), None);
}

#[test]
fn a_body_nested_past_its_decoder_is_refused_by_name() {
    // rmpv recurses once per level up to its 1024 cap; a debug build's frames
    // need a deeper stack than a test thread's to get there.
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            let member = r#"{"pass\u0077ord":"private fixture"}"#;
            let json = format!("{}{member}{}", "[".repeat(129), "]".repeat(129));
            let mut messagepack = vec![0x91; 1100];
            rmpv::encode::write_value(
                &mut messagepack,
                &rmpv::Value::Map(vec![(
                    rmpv::Value::from("password"),
                    rmpv::Value::from("private fixture"),
                )]),
            )
            .unwrap();
            for (payload, reason) in [
                (json.as_bytes(), REASON_JSON_TOO_DEEP),
                (&messagepack[..], REASON_MESSAGEPACK_TOO_DEEP),
            ] {
                let error = scan_payload(payload).expect_err(reason);
                assert!(
                    matches!(&error, Error::Gate(GateError::GateWriteRejected { reason_codes, .. })
                    if reason_codes.contains(&reason)),
                    "{error:?}"
                );
            }
            // As deep as the decoder reads, a body is read member by member,
            // and brackets in text that is no JSON are text.
            let readable = format!("{}{}", "[".repeat(127), "]".repeat(127));
            assert!(scan_payload(readable.as_bytes()).is_ok());
            let source = format!("[{}]", ["'['"; 127].join(","));
            assert!(scan_payload(source.as_bytes()).is_ok());
        })
        .unwrap()
        .join()
        .unwrap();
}
