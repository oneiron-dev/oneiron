//! MESSAGE metadata: the nesting and reserved-key walk, and the size measure against the `[limits]` rows.

use super::*;

/// What one MESSAGE's metadata measures against its `[limits]` rows (ABC
/// rows 53 and 56): the most nodes, keys and values together, and the most
/// canonical MessagePack bytes, any one of its three parts holds (the
/// entries other than `import`, an import's provenance, and the source row's
/// own `import` it carries, FIX 7777).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WitnessMetadataMeasure {
    /// Keys and values, recursively, of the largest part.
    pub nodes: u64,
    /// Canonical MessagePack bytes of the largest part.
    pub bytes: u64,
}

impl WitnessMetadataMeasure {
    /// Tells `watch` what this metadata measured: past the
    /// `witness_metadata_nodes` or `witness_metadata_bytes` row it asks
    /// whether everything is okay, and the metadata is kept whole.
    pub fn report(self, watch: &LimitWatch) {
        watch.measure(EngineLimit::WitnessMetadataNodes, self.nodes);
        watch.measure(EngineLimit::WitnessMetadataBytes, self.bytes);
    }
}

/// The metadata of canonical MESSAGE `body`, measured, when the body carries
/// metadata that is a well-formed map; `None` for a body without metadata or
/// one that does not decode. Run where a put stores the row, after its
/// envelope is proven, so a crossing asks once per stored row.
pub fn witness_metadata_measure(body: &[u8]) -> Option<WitnessMetadataMeasure> {
    let mut cursor = body;
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return None;
    };
    let metadata = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(BODY_KEY_METADATA))
        .map(|(_, value)| value)?;
    measure_metadata_map(metadata)
}

/// Measures every part of `metadata` and keeps the largest, or `None` when it
/// is not a well-formed metadata map.
fn measure_metadata_map(metadata: &Value) -> Option<WitnessMetadataMeasure> {
    let parts = metadata_parts(metadata)?;
    let mut measure = WitnessMetadataMeasure::default();
    for (index, part) in parts.iter().enumerate() {
        let mut walk = MetadataWalk::default();
        if !walk.part(part, index == IMPORT_PART) {
            return None;
        }
        measure.nodes = measure.nodes.max(walk.nodes);
        measure.bytes = measure.bytes.max(walk.bytes);
    }
    Some(measure)
}

/// Whether `metadata` is a well-formed metadata map: string keys only, no
/// reserved envelope-axis name at any depth, no opaque value kind, nesting
/// within [`MAX_WITNESS_METADATA_DEPTH`]. Its size is measured, never refused
/// ([`witness_metadata_measure`]).
pub(super) fn valid_metadata_map(metadata: &Value) -> bool {
    measure_metadata_map(metadata).is_some()
}

/// Where the `import` part sits in [`metadata_parts`].
const IMPORT_PART: usize = 1;

/// The three parts of `metadata` that are measured each on its own (FIX
/// 7777): the entries other than `import`; the `import` entry, an import's
/// provenance, without its `source_import`; and that `source_import` value,
/// measured as the `import` entry it was in the source row. An archive import
/// adds its provenance to a source row whose own metadata, its own `import`
/// value included, may already be large, and none of the three counts toward
/// another. `None` when `metadata` is not a map.
fn metadata_parts(metadata: &Value) -> Option<[Vec<(&Value, &Value)>; 3]> {
    let Value::Map(entries) = metadata else {
        return None;
    };
    let mut rest = Vec::new();
    let mut import = Vec::new();
    let mut carried = Vec::new();
    for (key, value) in entries {
        if key.as_str() != Some(METADATA_KEY_IMPORT) {
            rest.push((key, value));
            continue;
        }
        let Value::Map(provenance) = value else {
            import.push((key, value));
            continue;
        };
        import.push((key, value));
        for (name, source) in provenance {
            if name.as_str() == Some(IMPORT_KEY_SOURCE_IMPORT) {
                carried.push((key, source));
            }
        }
    }
    Some([rest, import, carried])
}

/// One part's walk: well-formedness, and its nodes and canonical encoded
/// bytes counted as it goes, with checked sums and no encoding allocated.
#[derive(Default)]
struct MetadataWalk {
    nodes: u64,
    bytes: u64,
}

impl MetadataWalk {
    /// Walks one part, a map of `entries`. In the `import` part
    /// (`provenance`), an `import` entry holding a provenance map is walked
    /// without its `source_import`, which is its own part.
    fn part(&mut self, entries: &[(&Value, &Value)], provenance: bool) -> bool {
        self.count_node();
        self.add(map_header_len(entries.len()));
        entries.iter().all(|(key, value)| {
            let Some(name) = key.as_str() else {
                return false;
            };
            if !self.key(name) {
                return false;
            }
            match value {
                Value::Map(import) if provenance && name == METADATA_KEY_IMPORT => {
                    self.count_node();
                    let own: Vec<_> = import
                        .iter()
                        .filter(|(inner, _)| inner.as_str() != Some(IMPORT_KEY_SOURCE_IMPORT))
                        .collect();
                    self.add(map_header_len(own.len()));
                    own.iter().all(|(inner, entry)| {
                        inner.as_str().is_some_and(|inner| self.key(inner)) && self.value(entry, 2)
                    })
                }
                _ => self.value(value, 1),
            }
        })
    }

    /// One map key: nonempty, no control character, no reserved axis name;
    /// counted as a node and its string encoding.
    fn key(&mut self, key: &str) -> bool {
        if key.is_empty()
            || key.chars().any(char::is_control)
            || RESERVED_METADATA_KEYS.contains(&key)
        {
            return false;
        }
        self.count_node();
        self.add(str_len(key.len()));
        true
    }

    /// One value at `depth` (the part's root map is depth 0).
    fn value(&mut self, value: &Value, depth: usize) -> bool {
        if depth > MAX_WITNESS_METADATA_DEPTH {
            return false;
        }
        self.count_node();
        match value {
            Value::Nil | Value::Boolean(_) => {
                self.add(1);
                true
            }
            Value::Integer(integer) => {
                self.add(integer_len(integer));
                true
            }
            Value::F32(_) => {
                self.add(5);
                true
            }
            Value::F64(_) => {
                self.add(9);
                true
            }
            Value::String(text) => text.as_str().is_some_and(|text| {
                self.add(str_len(text.len()));
                true
            }),
            // Binary and Ext are byte channels no JSON-shaped metadata can
            // produce; accepting them would reopen the side channel one layer
            // down.
            Value::Binary(_) | Value::Ext(_, _) => false,
            Value::Array(items) => {
                self.add(array_header_len(items.len()));
                items.iter().all(|item| self.value(item, depth + 1))
            }
            Value::Map(entries) => {
                self.add(map_header_len(entries.len()));
                entries.iter().all(|(key, entry)| {
                    key.as_str().is_some_and(|key| self.key(key)) && self.value(entry, depth + 1)
                })
            }
        }
    }

    fn count_node(&mut self) {
        self.nodes = self.nodes.saturating_add(1);
    }

    fn add(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// Encoded bytes of a MessagePack string of `len` bytes, as `rmp` writes it:
/// fixstr, str8, str16 or str32 header, then the bytes.
fn str_len(len: usize) -> u64 {
    let header = match len {
        0..32 => 1,
        32..256 => 2,
        256..65_536 => 3,
        _ => 5,
    };
    header + len as u64
}

/// Encoded bytes of a MessagePack array header for `len` items.
fn array_header_len(len: usize) -> u64 {
    match len {
        0..16 => 1,
        16..65_536 => 3,
        _ => 5,
    }
}

/// Encoded bytes of a MessagePack map header for `len` entries.
fn map_header_len(len: usize) -> u64 {
    array_header_len(len)
}

/// Encoded bytes of `integer` in the smallest form `rmp` writes it in.
fn integer_len(integer: &rmpv::Integer) -> u64 {
    if let Some(value) = integer.as_u64() {
        return match value {
            0..128 => 1,
            128..256 => 2,
            256..65_536 => 3,
            65_536..4_294_967_296 => 5,
            _ => 9,
        };
    }
    match integer.as_i64().unwrap_or(i64::MIN) {
        -32..0 => 1,
        -128..-32 => 2,
        -32_768..-128 => 3,
        -2_147_483_648..-32_768 => 5,
        _ => 9,
    }
}
