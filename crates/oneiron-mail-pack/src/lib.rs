//! `oneiron-mail-pack`: the lifted half of `oneiron::mail_pack` (core split; plan
//! lanes/kimi/OPUS-STORE/CORE-SPLIT-PLAN-20261107.md). It sits above `oneiron`: every `crate::x` path in
//! the moved code resolves through the glob below to `oneiron::x`, unless this crate defines `x`.
//! lift_mover.py checks that no local item shadows a core one; the lints catch a second glob re-export
//! of the same name and a private item hiding a public glob re-export.
#![deny(ambiguous_glob_reexports, hidden_glob_reexports)]

#[allow(unused_imports)]
pub(crate) use oneiron::*;

pub mod mail_pack;

/// The extension traits that carry methods of core types which moved here.
pub mod ext {
    pub use crate::mail_pack::MailPackImporterVaultExt;
    pub use crate::mail_pack::MailPackLocalSyncVaultExt;
    pub use crate::mail_pack::MailPackPackVaultExt;
}
