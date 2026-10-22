//! The Rewrite a `host.wake` pre-hook may make (ARCH-0080 §5): add material
//! for the wake, and nothing else (FIX 8722). The host's own args (the wake
//! kind, its scope and the queue head) stay exactly the host's. The one
//! member a hook may add is `material`, a list of non-empty texts, and a
//! later hook in the chain only adds to what an earlier one added, as a
//! `host.compact` pin only adds to the keep list. The pass re-validates the
//! final args and re-gates each text through the secret write-wall's scan
//! before the material rides it; a rewrite that fails either is refused, as
//! every changed host arg was before.

use serde_json::{Map, Value};

use crate::Vault;

/// The one member a `host.wake` Rewrite may add.
const MATERIAL: &str = "material";

/// The refusal of a rewrite that touches the host's own args.
const HOST_ARGS: &str = "a host verb's args are the host's";

/// The refusal of material that is not a list of texts.
const NOT_TEXTS: &str = "host.wake material is a list of non-empty texts";

/// Whether `after` is a Rewrite of `before` a `host.wake` pre-hook may make:
/// every host arg unchanged, and `material`, when present, only added to.
/// Every transport's chain checks it beside its own rewrite admission.
///
/// # Errors
///
/// The refusal's reason, for the hook's receipt.
pub(crate) fn check_host_wake_rewrite(before: &Value, after: &Value) -> Result<(), String> {
    added_material(before, after).map(drop)
}

/// The material `after` holds once it is a permitted rewrite of `before`.
pub(super) fn added_material(before: &Value, after: &Value) -> Result<Vec<String>, String> {
    let (Value::Object(host), Value::Object(rewritten)) = (before, after) else {
        return Err(HOST_ARGS.to_owned());
    };
    let kept = host
        .iter()
        .filter(|(key, _)| key.as_str() != MATERIAL)
        .all(|(key, value)| rewritten.get(key) == Some(value));
    let widened = rewritten
        .keys()
        .any(|key| key != MATERIAL && !host.contains_key(key));
    if !kept || widened {
        return Err(HOST_ARGS.to_owned());
    }
    let earlier = material_of(host)?;
    let material = material_of(rewritten)?;
    if !material.starts_with(&earlier) {
        return Err("a host.wake rewrite only adds material".to_owned());
    }
    Ok(material)
}

/// The material a rewrite's `material` member names.
fn material_of(args: &Map<String, Value>) -> Result<Vec<String>, String> {
    match args.get(MATERIAL) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) if !text.trim().is_empty() => Ok(text.clone()),
                _ => Err(NOT_TEXTS.to_owned()),
            })
            .collect(),
        Some(_) => Err(NOT_TEXTS.to_owned()),
    }
}

/// The pass's own check of a rewrite: permitted, and every text it adds
/// clears the secret write-wall's scan in the vault's own snapshot. The
/// reason never quotes the material.
pub(super) fn admit_wake_rewrite(
    vault: &Vault,
    before: &Value,
    after: &Value,
) -> Result<(), String> {
    let material = added_material(before, after)?;
    if material.is_empty() {
        return Ok(());
    }
    let txn = vault
        .store
        .env
        .read_txn()
        .map_err(|_| "host.wake material could not be checked".to_owned())?;
    for text in &material {
        crate::batch::secret_scan::scan_content_in_txn(&vault.store, &txn, text.as_bytes())
            .map_err(|_| "host.wake material may not carry a secret".to_owned())?;
    }
    Ok(())
}
