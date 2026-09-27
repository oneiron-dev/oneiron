//! Vault-resident office-package admission budgets (DEC-0005).

use oneiron_docedit::edit_roundtrip::limits::DocumentLimits;
use rmpv::Value;

/// Engine-authored default POLICY_MANIFEST row. These are not organ constants:
/// a trusted holder-authored manifest may replace them (widen or narrow).
pub(super) fn default_document_limits() -> DocumentLimits {
    DocumentLimits::new(256 * 1024 * 1024, 1024 * 1024 * 1024)
        .expect("default document limits fit the ZIP32 representation")
}

pub(super) fn encode_document_limits(limits: DocumentLimits) -> Value {
    Value::Map(vec![
        (
            Value::from("entry_bytes"),
            Value::from(limits.entry_bytes()),
        ),
        (
            Value::from("package_bytes"),
            Value::from(limits.package_bytes()),
        ),
    ])
}

pub(super) fn decode_document_limits(value: &Value) -> Option<DocumentLimits> {
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() != 2 {
        return None;
    }
    let mut entry = None;
    let mut package = None;
    for (key, value) in entries {
        match key.as_str()? {
            "entry_bytes" if entry.is_none() => entry = Some(value.as_u64()?),
            "package_bytes" if package.is_none() => package = Some(value.as_u64()?),
            _ => return None,
        }
    }
    DocumentLimits::new(entry?, package?)
}

pub(super) fn narrow_limits(a: DocumentLimits, b: DocumentLimits) -> DocumentLimits {
    DocumentLimits::new(
        a.entry_bytes().min(b.entry_bytes()),
        a.package_bytes().min(b.package_bytes()),
    )
    .expect("minimum of validated document budgets remains valid")
}
