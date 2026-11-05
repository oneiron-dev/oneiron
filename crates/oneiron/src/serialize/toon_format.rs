//! Core half of `serialize::toon_format`: its store-layer items live in `oneiron_store::serialize::toon_format` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::serialize::toon_format::*;

use super::json_format::section_object;
use super::pack_entry::PreparedEntity;
use super::types::{GroupKey, TOON_MAX_DEPTH};
use super::yaml_format::write_indent;
use serde_json::{Map, Number, Value};

pub(super) fn encode_toon_section(
    groups: &[(GroupKey, Vec<PreparedEntity>)],
    handles: &mut super::handles::Handles,
) -> String {
    if groups.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    write_toon_object(&mut out, &section_object(groups, false, handles), 0);
    out
}
