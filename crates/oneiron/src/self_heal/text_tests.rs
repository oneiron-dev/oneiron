use super::*;
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::test_util::open_test_vault_with;

fn draft() -> DiagnosticEvent {
    let facts = [DiagnosticObservation {
        source_ref: EntityId::from_bytes([2; 16]).unwrap(),
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [2; 32],
        observed_at: 1_000,
    }];
    ConsentDeniedDetector
        .detect(&DiagnosticWorkingSet {
            scope_ref: "scope.consent",
            observations: &facts,
        })
        .remove(0)
}

fn replace_field(body: &[u8], key: &str, value: Value) -> Vec<u8> {
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut Cursor::new(body)).unwrap() else {
        panic!("body map");
    };
    entries
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some(key))
        .unwrap()
        .1 = value;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).unwrap();
    bytes
}

#[test]
fn diagnostic_escape_requires_exact_writer_form() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let body = encode_diagnostic_event_body(&draft())?;
    let id = EntityId::from_bytes([3; 16])?;
    for hostile in [
        r"\u{9}",
        r"\u{009}",
        r"\u{00009}",
        r"\u{00ad}",
        r"\u{00aD}",
        r"\u{000AD}",
        r"\u{D800}",
        r"\u{DFFF}",
        r"\u{110000}",
        r"\u{FFFFFF}",
        r"\u{0041}",
        r"\u{005C}",
        r"\u{1F600}",
        r"\u{E0000}",
        r"\u{0E0001}",
        r"\u{}",
        r"\u{0009",
        r"\u{0009}\u{41}",
        r"\u{e007f}",
    ] {
        let bytes = replace_field(&body, "untrusted_detail", Value::from(hostile));
        assert_eq!(
            decode_diagnostic_event_body(&bytes).unwrap_err().kind(),
            ErrorKind::InvalidDiagnosticBody,
            "{hostile}"
        );
        assert_eq!(
            validate_diagnostic_event_body_bytes(&bytes)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidDiagnosticBody
        );
        let err = vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_DIAGNOSTIC,
                TimeRange {
                    start: 1_000,
                    end: u64::MAX,
                },
                1_000,
                &bytes,
            )
            .commit()
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidDiagnosticBody);
        assert!(vault.get_raw(&id)?.is_none());
    }
    for raw in [
        "\t",
        "\u{AD}",
        "\u{E0001}",
        "\u{E007F}",
        r"\u{9}",
        r"\u{00ad}",
    ] {
        let mut event = draft();
        event.untrusted_detail = Some(raw.to_owned());
        let bytes = encode_diagnostic_event_body(&event)?;
        validate_diagnostic_event_body_bytes(&bytes)?;
        let decoded = decode_diagnostic_event_body(&bytes)?;
        assert_eq!(encode_stored_diagnostic_event_body(&decoded)?, bytes);
    }
    Ok(())
}

#[test]
fn diagnostic_unicode_tag_controls_fail_closed() -> Result<()> {
    let canonical = encode_diagnostic_event_body(&draft())?;
    for code in std::iter::once(0xE0001).chain(0xE0020..=0xE007F) {
        let tag = char::from_u32(code).unwrap();
        let text = format!("before{tag}after");
        let mut event = draft();
        event.untrusted_detail = Some(text.clone());
        let bytes = encode_diagnostic_event_body(&event)?;
        validate_diagnostic_event_body_bytes(&bytes)?;
        let decoded = decode_diagnostic_event_body(&bytes)?;
        assert_eq!(
            decoded.untrusted_detail,
            Some(format!("before\\u{{{code:04X}}}after"))
        );
        assert_eq!(encode_stored_diagnostic_event_body(&decoded)?, bytes);
        for key in [
            "untrusted_detail",
            "replay_run_ref",
            "replay_checkpoint_ref",
            "expected",
            "actual",
            "delta",
        ] {
            let hostile = replace_field(&canonical, key, Value::from(text.clone()));
            assert_eq!(
                decode_diagnostic_event_body(&hostile).unwrap_err().kind(),
                ErrorKind::InvalidDiagnosticBody,
                "{key} U+{code:X}"
            );
        }
        for value in [
            Value::from(text.clone()),
            Value::Map(vec![(Value::from(text.clone()), Value::Nil)]),
        ] {
            event.expected = value;
            assert!(encode_diagnostic_event_body(&event).is_err());
        }
        assert!(
            validate_working_set(&DiagnosticWorkingSet {
                scope_ref: &text,
                observations: &[],
            })
            .is_err()
        );
    }
    Ok(())
}
