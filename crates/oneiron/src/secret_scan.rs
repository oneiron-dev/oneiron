use super::BatchOp;
use super::export::ExportManifest;
use crate::error::{Error, Result};

const REASON_DETECTED: &str = "gate.secret_scan.detected";
const REASON_AWS_ACCESS_KEY_ID: &str = "gate.secret_scan.aws_access_key_id";
const REASON_GITHUB_TOKEN: &str = "gate.secret_scan.github_token";
const REASON_GOOGLE_API_KEY: &str = "gate.secret_scan.google_api_key";
const REASON_OPENAI_KEY: &str = "gate.secret_scan.openai_key";
const REASON_PRIVATE_KEY: &str = "gate.secret_scan.private_key";
const REASON_SLACK_TOKEN: &str = "gate.secret_scan.slack_token";
const REASON_STRIPE_KEY: &str = "gate.secret_scan.stripe_key";

pub(crate) fn scan_batch_ops(ops: &[BatchOp]) -> Result<()> {
    for op in ops {
        match op {
            BatchOp::Put { data, .. } => {
                let _manifest = scan_payload(data)?;
            }
            BatchOp::ClaimCandidate {
                candidate,
                envelope,
                ..
            } => {
                let body = (**candidate).clone().into_claim_body(envelope);
                let data = crate::claim::encode_claim_body(&body)?;
                let _manifest = scan_payload(&data)?;
            }
            BatchOp::Text { fields, .. } => {
                for (_, value) in fields {
                    let _manifest = scan_payload(value.as_bytes())?;
                }
            }
            BatchOp::Phonetic { codes, .. } => {
                for code in codes {
                    let _manifest = scan_payload(code.as_bytes())?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn scan_payload(data: &[u8]) -> Result<ExportManifest> {
    let haystack = String::from_utf8_lossy(data);
    let manifest = ExportManifest::from_redacted(has_redaction_marker(&haystack));
    if let Some(reason) = detect_secret(&haystack) {
        return Err(secret_scan_error(reason));
    }
    Ok(manifest)
}

fn secret_scan_error(reason: &'static str) -> Error {
    Error::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec![REASON_DETECTED, reason],
    }
}

fn has_redaction_marker(haystack: &str) -> bool {
    let lower = haystack.to_ascii_lowercase();
    [
        "[redacted]",
        "[secret redacted]",
        "<redacted>",
        "secret_nulled",
        "structurally_secret_nulled",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn detect_secret(haystack: &str) -> Option<&'static str> {
    if contains_private_key_marker(haystack) {
        return Some(REASON_PRIVATE_KEY);
    }

    haystack
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')))
        .find_map(classify_token)
}

fn contains_private_key_marker(haystack: &str) -> bool {
    haystack.contains("-----BEGIN ") && haystack.contains(" PRIVATE KEY-----")
}

fn classify_token(token: &str) -> Option<&'static str> {
    if is_aws_access_key_id(token) {
        Some(REASON_AWS_ACCESS_KEY_ID)
    } else if is_github_token(token) {
        Some(REASON_GITHUB_TOKEN)
    } else if is_google_api_key(token) {
        Some(REASON_GOOGLE_API_KEY)
    } else if is_openai_key(token) {
        Some(REASON_OPENAI_KEY)
    } else if is_slack_token(token) {
        Some(REASON_SLACK_TOKEN)
    } else if is_stripe_key(token) {
        Some(REASON_STRIPE_KEY)
    } else {
        None
    }
}

fn is_aws_access_key_id(token: &str) -> bool {
    token.len() == 20
        && (token.starts_with("AKIA") || token.starts_with("ASIA"))
        && token
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn is_github_token(token: &str) -> bool {
    ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .any(|prefix| suffix_matches(token, prefix, 36, true, is_ascii_token_body))
        || suffix_matches(token, "github_pat_", 70, false, is_ascii_token_body)
}

fn is_google_api_key(token: &str) -> bool {
    suffix_matches(token, "AIza", 35, true, is_ascii_token_body)
}

fn is_openai_key(token: &str) -> bool {
    suffix_matches(token, "sk-proj-", 32, false, is_ascii_token_body)
        || suffix_matches(token, "sk-", 48, true, is_ascii_token_body)
}

fn is_slack_token(token: &str) -> bool {
    ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"]
        .iter()
        .any(|prefix| suffix_matches(token, prefix, 24, false, is_ascii_token_body))
}

fn is_stripe_key(token: &str) -> bool {
    suffix_matches(token, "sk_live_", 24, false, is_ascii_token_body)
        || suffix_matches(token, "rk_live_", 24, false, is_ascii_token_body)
}

fn suffix_matches(
    token: &str,
    prefix: &str,
    suffix_len: usize,
    exact_len: bool,
    allowed: fn(u8) -> bool,
) -> bool {
    let Some(suffix) = token.strip_prefix(prefix) else {
        return false;
    };
    if exact_len {
        suffix.len() == suffix_len && suffix.bytes().all(allowed)
    } else {
        suffix.len() >= suffix_len && suffix.bytes().all(allowed)
    }
}

fn is_ascii_token_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_payload_rejects_known_secret_fixture() {
        let err = scan_payload(b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz")
            .expect_err("known GitHub token fixture must reject");

        match err {
            Error::GateWriteRejected {
                outcome,
                reason_codes,
            } => {
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
    fn scan_batch_ops_rejects_phonetic_secret_payload() {
        let err = scan_batch_ops(&[BatchOp::Phonetic {
            id: crate::types::EntityId::now(),
            codes: vec!["token=ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_owned()],
        }])
        .expect_err("known GitHub token fixture in phonetic payload must reject");

        match err {
            Error::GateWriteRejected { reason_codes, .. } => {
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

        assert!(manifest.redacted());
        assert!(manifest.structurally_secret_nulled());
    }
}
