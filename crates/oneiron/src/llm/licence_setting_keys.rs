//! The model install's owner Setting key (owner principle, 16 Nov 00:44: a restriction that is
//! not a correctness fix ships as a good default plus an owner opt-out; lead ruling
//! GENUI-OPTOUT-MODEL-LICENCE = A, 16 Nov 03:21). The default is today's refusal. The owner
//! changes the value; an agent's change, either way, waits on the owner's approval.
//!
//! The owner's standing grant is "any licence that does not hurt us, never non-commercial weights
//! on our hosted service": on a node our cloud hosts, a model runs inside our paid service. So the
//! key is a choice about this machine, honoured only where the vault is self-hosted: elsewhere the
//! owner's true is refused when it is set, and the reader reads false whatever a row says (a row
//! a restore brings never passes the set's hook).
//!
//! Direction: admitting more licences is looser. A row that does not decode reads as false.

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingChange, SettingSync, lower_is_tighter};
use crate::{HostingPrivacyPosture, Vault};

/// What a node that is not self-hosted answers the owner's true with.
pub const NONCOMMERCIAL_LICENCES_HOSTED_REFUSAL: &str = "models.install.allow_noncommercial_licences \
     is honoured only on a self-hosted node: the owner's standing grant is never non-commercial \
     weights on our hosted service";

/// Non-commercial and unknown licences stay refused: today's rule, and the strictest value.
fn refused() -> bool {
    false
}

/// Refuses the owner's true on a vault that is not self-hosted.
fn refuse_off_self_host(
    vault: &Vault,
    _txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    let admits = change
        .value
        .as_ref()
        .and_then(Kind::<bool>::decode)
        .unwrap_or(false);
    if admits && vault.privacy_posture() != HostingPrivacyPosture::SelfHostLocal {
        return Err(Error::InvalidConfig(
            NONCOMMERCIAL_LICENCES_HOSTED_REFUSAL.to_owned(),
        ));
    }
    Ok(())
}

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

/// Whether `vault`'s owner admits non-commercial and unknown model licences on this node, read
/// now: false on a vault that is not self-hosted, whatever a row says.
///
/// # Errors
///
/// Storage errors.
pub fn noncommercial_model_licences_admitted(vault: &Vault) -> Result<bool> {
    if vault.privacy_posture() != HostingPrivacyPosture::SelfHostLocal {
        return Ok(false);
    }
    let txn = vault.store.env.read_txn()?;
    Ok(MODELS_INSTALL_ALLOW_NONCOMMERCIAL_LICENCES
        .read_in_txn(vault, &txn, &[], None)?
        .value)
}
