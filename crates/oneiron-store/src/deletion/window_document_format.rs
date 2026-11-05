//! The window-document format marker a native NOTE carrier writes, read by
//! the publish path to choose a history-free snapshot.

use loro::{LoroDoc, LoroValue};

pub const FORMAT_KEY: &str = "@note-sync";

pub fn is_native(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key("documents"))
        && doc.get_map("documents").get(FORMAT_KEY).is_some()
}
