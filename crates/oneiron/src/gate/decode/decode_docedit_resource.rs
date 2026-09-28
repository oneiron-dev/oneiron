//! Strict six-field document resource policy row decoder.
use super::decode_map_util::required_value;
use crate::gate::docedit_resource::DoceditResourcePolicy;
use rmpv::Value;

pub(in crate::gate) fn parse_docedit_resource_policy(
    value: &Value,
) -> Option<DoceditResourcePolicy> {
    const KEYS: [&str; 6] = [
        "archive_bytes",
        "entries",
        "part_bytes",
        "expanded_bytes",
        "xml_depth",
        "xml_nodes",
    ];
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
    let mut values = [0usize; 6];
    for (i, key) in KEYS.iter().enumerate() {
        let n = required_value(entries, key)?.as_u64()?;
        values[i] = usize::try_from(n).ok().filter(|n| *n > 0)?;
    }
    // ZIP32 output uses u32 offsets; Expat accepts one c_int-sized input.
    // Policy must never promise a limit the parser cannot represent.
    if values[0] > u32::MAX as usize
        || values[1] >= u16::MAX as usize
        || values[2] > i32::MAX as usize
        || values[5] > u32::MAX as usize
    {
        return None;
    }
    Some(DoceditResourcePolicy {
        archive_bytes: values[0],
        entries: values[1],
        part_bytes: values[2],
        expanded_bytes: values[3],
        xml_depth: values[4],
        xml_nodes: values[5],
    })
}
