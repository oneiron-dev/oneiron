//! Stored MessagePack bytes under native source disclosure checks.

use crate::error::{Error, Result};
use crate::store::known_value_index::KnownValues;

/// A native primary is MessagePack, read at its stored widths, with every
/// map entry retained. A projected JSON verdict is not its physical witness.
pub(super) fn body_readable(bytes: &[u8], known: Option<&KnownValues>) -> Result<bool> {
    let tree = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
        .map_err(|_| Error::CorruptedIndex("skill edit verdict body"))?;
    if crate::batch::secret_scan::write_tree_hit(bytes, None).is_some()
        || crate::batch::secret_scan::release_body_reads_whole_as_stored(&tree, bytes)
    {
        return Ok(false);
    }
    let Some(known) = known else {
        return Ok(true);
    };
    if !known.spans(bytes).is_empty() {
        return Ok(false);
    }
    let mut text = zeroize::Zeroizing::new(Vec::new());
    let mut pending = vec![&tree];
    while let Some(value) = pending.pop() {
        let leaf = match value {
            rmpv::Value::String(value) => Some(value.as_bytes()),
            rmpv::Value::Binary(bytes) | rmpv::Value::Ext(_, bytes) => Some(bytes.as_slice()),
            rmpv::Value::Array(values) => {
                let bytes = values
                    .iter()
                    .map(|value| value.as_u64().and_then(|value| u8::try_from(value).ok()))
                    .collect::<Option<Vec<_>>>()
                    .map(zeroize::Zeroizing::new);
                match bytes {
                    Some(bytes) if !bytes.is_empty() => {
                        if !known.spans(&bytes).is_empty() {
                            return Ok(false);
                        }
                        text.extend_from_slice(&bytes);
                        text.push(b'\n');
                    }
                    _ => pending.extend(values.iter().rev()),
                }
                None
            }
            rmpv::Value::Map(entries) => {
                for (key, value) in entries.iter().rev() {
                    pending.push(value);
                    pending.push(key);
                }
                None
            }
            _ => None,
        };
        if let Some(leaf) = leaf {
            if !known.spans(leaf).is_empty() {
                return Ok(false);
            }
            text.extend_from_slice(leaf);
            text.push(b'\n');
        }
    }
    Ok(known.spans(&text).is_empty())
}
