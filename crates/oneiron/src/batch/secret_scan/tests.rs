use super::*;
use crate::error::GateError;

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
fn scan_payload_rejects_known_secret_fixture() {
    let err = scan_payload(b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz")
        .expect_err("known GitHub token fixture must reject");

    match err {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => {
            assert_eq!(outcome, "deny");
            assert_eq!(
                reason_codes.as_slice(),
                &[REASON_DETECTED, REASON_GITHUB_TOKEN]
            );
            assert!(reason_codes.iter().all(|code| code.starts_with("gate.")));
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
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
fn scan_payload_allows_secret_prefix_embedded_in_larger_identifier() {
    for payload in [
        "pack=myghp_0123456789abcdefghijklmnopqrstuvwxyz_label",
        "pack=myAKIA0123456789ABCDEF_label",
        "pack=myAIza0123456789abcdefghijklmnopqrstuvwxy_label",
        "pack=mysk-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL_label",
    ] {
        scan_payload(payload.as_bytes())
            .expect("embedded secret-like prefix in larger identifier is not a token");
    }
}

#[test]
fn scan_payload_rejects_pgp_private_key_armor() {
    let err = scan_payload(
        format!(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: fixture\n\n{SYNTHETIC_KEY_BODY}\n=AbCd\n-----END PGP PRIVATE KEY BLOCK-----"
        )
        .as_bytes(),
    )
    .expect_err("PGP private key armor must reject");

    match err {
        Error::Gate(GateError::GateWriteRejected { reason_codes, .. }) => {
            assert_eq!(
                reason_codes.as_slice(),
                &[REASON_DETECTED, REASON_PRIVATE_KEY]
            );
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
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

#[test]
fn scan_payload_marks_redacted_payload_as_structurally_secret_nulled() {
    let manifest = scan_payload(b"api_key=[REDACTED]").expect("redacted payload is safe");

    assert!(manifest.payloads());
    assert!(manifest.structural_placeholders());
}

#[test]
fn scan_payload_marks_export_manifest_redaction_fields_as_secret_nulled() {
    let manifest =
        scan_payload(br#"{"secrets_nulled":{"payloads":true,"structural_placeholders":true}}"#)
            .expect("export manifest marker payload is safe");

    assert!(manifest.payloads());
    assert!(manifest.structural_placeholders());
}

#[test]
fn scan_payload_keeps_legacy_redaction_fields_as_secret_nulled() {
    let manifest = scan_payload(br#"{"secret_nulled":true,"structurally_secret_nulled":true}"#)
        .expect("legacy manifest marker payload is safe");

    assert!(manifest.payloads());
    assert!(manifest.structural_placeholders());
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
