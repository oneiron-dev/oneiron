//! The pin door's shape check (pass 33, door 2's refusals): what a pin must
//! look like before it is hashed and stored. The node judges the rest
//! against its own template: the allow-list, the ceilings, the scope.

use super::{
    DeviceKind, PIN_ARG_BYTES_MAX, PIN_ARGS_MAX, PIN_OUTPUTS_MAX, REQUEST_DEVICE_CLAIMS_MAX,
    ScopeKind, WorkloadPin,
};

/// The grammar of a name a pin carries: a template, a device kind outside
/// the built ones, a device feature.
const NAME_GRAMMAR: &str = "a name of 1-64 characters a-z, 0-9, '-', '_' or '.'";

/// Whether `text` is `len` lower-hex characters.
fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `path` is a plain relative path: not empty, not absolute, no
/// empty, `.` or `..` part, no backslash and no NUL.
fn is_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Whether `text` follows [`NAME_GRAMMAR`].
fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
}

/// Why `pin` has the wrong shape, if it does (door 2's refusals). The node
/// judges the rest against its own template: the allow-list, the ceilings,
/// the scope.
pub(super) fn check_pin_shape(pin: &WorkloadPin) -> Result<(), String> {
    if !is_name(&pin.template) {
        return Err(format!("template is {NAME_GRAMMAR}"));
    }
    if !is_lower_hex(&pin.template_digest, 64) {
        return Err("template_digest is a content hash in 64 lower hex".into());
    }
    if !is_lower_hex(&pin.commit, 40) {
        return Err("commit is a revision in 40 lower hex".into());
    }
    if !is_lower_hex(&pin.contract_sha256, 64) {
        return Err("contract_sha256 is a sha256 in 64 lower hex".into());
    }
    if !is_relative_path(&pin.contract_path) {
        return Err("contract_path is a relative path inside the checkout".into());
    }
    if !is_relative_path(&pin.entry) {
        return Err("entry is a relative path inside the checkout".into());
    }
    if pin.args.len() > PIN_ARGS_MAX {
        return Err(format!("args carries at most {PIN_ARGS_MAX} strings"));
    }
    if pin.args.iter().map(String::len).sum::<usize>() > PIN_ARG_BYTES_MAX {
        return Err(format!(
            "args carries at most {PIN_ARG_BYTES_MAX} bytes together"
        ));
    }
    if pin.args.iter().any(|arg| arg.contains('\0')) {
        return Err("an argument holds no NUL".into());
    }
    if pin.request.maximum_secs == 0 {
        return Err("request.maximum_secs is above 0".into());
    }
    // The general request (pass 34 row G1): a CPU-only run claims no device;
    // a claim of 0 devices would take no lease, so it is refused here.
    if pin.request.devices.len() > REQUEST_DEVICE_CLAIMS_MAX {
        return Err(format!(
            "request.devices carries at most {REQUEST_DEVICE_CLAIMS_MAX} claims"
        ));
    }
    for claim in &pin.request.devices {
        if claim.count == 0 {
            return Err("a device claim's count is at least 1".into());
        }
        if let DeviceKind::Other(kind) = &claim.kind
            && !is_name(kind)
        {
            return Err(format!(
                "a device kind beyond gpu, npu and fpga is {NAME_GRAMMAR}"
            ));
        }
        if !claim.features.iter().all(|feature| is_name(feature)) {
            return Err(format!("a device feature is {NAME_GRAMMAR}"));
        }
    }
    if let ScopeKind::Container { image } = &pin.scope {
        let pinned = image
            .split_once("@sha256:")
            .is_some_and(|(name, digest)| !name.is_empty() && is_lower_hex(digest, 64));
        if !pinned {
            return Err("a container image is pinned as name@sha256:<64 lower hex>".into());
        }
    }
    if pin.outputs.len() > PIN_OUTPUTS_MAX {
        return Err(format!("outputs declares at most {PIN_OUTPUTS_MAX}"));
    }
    let mut names: Vec<&str> = pin
        .outputs
        .iter()
        .map(|output| output.name.as_str())
        .collect();
    if names.iter().any(|name| !is_relative_path(name)) {
        return Err("an output name is a relative path".into());
    }
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("output names are distinct".into());
    }
    Ok(())
}
