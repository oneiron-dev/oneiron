//! The `models.install.allow_noncommercial_licences` row (its rule and reader: the parent
//! module). It sits in a file named `setting_keys.rs`, the only name build.rs reads catalogue rows
//! from.

use super::{refuse_off_self_host, refused};
use crate::setting::{Kind, SettingSync, lower_is_tighter};

crate::setting::setting_keys! {
    /// Whether this self-hosted node installs a model whose licence is non-commercial or not in
    /// the server's licence table (default false: the download is refused before any byte).
    /// True is looser: such a download starts, and its install record keeps the class it was
    /// admitted under. A conditional licence still needs its named decision. A choice about
    /// this machine; a node that is not self-hosted refuses true (the server's model install).
    pub(crate) MODELS_INSTALL_ALLOW_NONCOMMERCIAL_LICENCES: bool =
        "models.install.allow_noncommercial_licences" {
        kind: Kind::new(refused)
            .strictest(refused)
            .tighter(lower_is_tighter::<bool>),
        sync: SettingSync::Install,
        on_change: Some(refuse_off_self_host),
    };
}
