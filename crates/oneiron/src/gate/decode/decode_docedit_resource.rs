//! Strict three-field document resource policy row decoder (FIX 10590).
use super::decode_map_util::required_value;
use crate::gate::docedit_resource::DoceditResourcePolicy;
use rmpv::Value;

pub(in crate::gate) fn parse_docedit_resource_policy(
    value: &Value,
) -> Option<DoceditResourcePolicy> {
    const KEYS: [&str; 3] = ["archive_bytes", "part_bytes", "expanded_bytes"];
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() != KEYS.len()
        || entries
            .iter()
            .any(|(key, _)| !key.as_str().is_some_and(|name| KEYS.contains(&name)))
    {
        return None;
    }
    let mut values = [0usize; 3];
    for (i, key) in KEYS.iter().enumerate() {
        let n = required_value(entries, key)?.as_u64()?;
        values[i] = usize::try_from(n).ok().filter(|n| *n > 0)?;
    }
    // ZIP32 output uses u32 offsets. Policy must never promise a limit the
    // parser cannot represent.
    if values[0] > u32::MAX as usize {
        return None;
    }
    Some(DoceditResourcePolicy {
        archive_bytes: values[0],
        part_bytes: values[1],
        expanded_bytes: values[2],
    })
}
