//! The setting keys `clipboard` declares (Setting stage 1): the crate's build script lists each
//! row in the setting catalogue.

use super::ClipboardRetention;
use crate::setting::Kind;

crate::setting::setting_keys! {
    /// The owner's ordinary Clipboard cleanup arms: a size cap on clip text, the low-disk arm,
    /// and an age in days. `None` turns the size or age arm off; zero is a real size or age,
    /// not another spelling of off. Only the low-disk arm is on unless the owner sets it. It
    /// changes no world privacy or private-copy policy, and holds no clip text. It stands as
    /// the live vault holds it: a restore never brings back an arm the owner has since turned
    /// off (ARCH-0038).
    pub(crate) RETENTION: ClipboardRetention = "clipboard.retention" {
        kind: Kind::new(ClipboardRetention::default),
    };
}
