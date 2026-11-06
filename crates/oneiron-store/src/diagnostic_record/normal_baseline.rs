//! Normal-baseline predicate tokens retained by gate receipts.

/// Gate receipts keep the original predicate, not the claim value. The fact
/// survives ordinary claim edits and is cleared by receipt redaction.
pub fn normal_baseline_token(predicate: &str) -> String {
    format!("tripwire_normal_v2:{predicate}")
}

pub fn normal_baseline_predicate(token: &str) -> Option<&str> {
    let predicate = token.strip_prefix("tripwire_normal_v2:")?;
    crate::write_envelope::claim_predicate::validate_predicate(predicate, true).ok()?;
    Some(predicate)
}
