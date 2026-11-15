//! Disclosure's catalogue keys (DESIGN 15-setting-primitive, stage 4): the owner's model-channel
//! ceilings.

use super::DisclosureBand;
use crate::setting::{ItemDomain, Kind};

/// The dials a ceiling row may name: `agent:<hex>/<class>` or `owner:<hex>/<class>`, where the
/// class is one data class or `*` for the whole connection.
const MODEL_CONNECTION_DIAL: ItemDomain = ItemDomain {
    name: "model connection and data class",
    admits: super::model_channel::is_dial_item,
};

fn no_dial() -> Option<DisclosureBand> {
    None
}

crate::setting::setting_keys! {
    /// The owner's band ceiling on what one model connection is shown, for one data class or
    /// for the whole connection (`*`). With no row for the class, the connection's row decides;
    /// with neither, the reader's own default does: the vault owner's connection sees up to
    /// `restricted`, an agent's up to `public`.
    pub(crate) MODEL_CEILING: Option<DisclosureBand> = "disclosure.model_ceiling" {
        kind: Kind::new(no_dial),
        item: Some(MODEL_CONNECTION_DIAL),
    };
}
