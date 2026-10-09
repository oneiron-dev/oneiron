use super::*;
use crate::error::ErrorKind;

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
