//! The native mail pack's served inboxes (OF-519, FIX 2096): while the pack
//! is Active, its check Verified and the host names its `[native_mail]`
//! server, the host keeps the pack connected with the stored credential and
//! reads every active native mail identity's inbox each built-in pass. Each
//! message's raw bytes go to the quarantine directory; the vault keeps only
//! their references. Sends leave through the served sink's email transport.

use std::collections::BTreeMap;

use oneiron::channel_identity_provider::native_mail::NativeMailPack;
use oneiron::channel_identity_provider::stalwart::{
    StalwartClient, StalwartInboxCursor, StalwartQuarantine,
};
use oneiron::skill_hub::pack_catalog::CheckedBuiltinConnection;
use oneiron::{EntityId, Vault};

use super::checks::native_mail_authorization;
use crate::config::NativeMailConfig;

/// The built-in native mail pack's channel, connection and credential
/// (packs/builtin/native_mail/PACK.md).
pub(super) const NATIVE_MAIL_CHANNEL: &str = "native_mail";
pub(super) const NATIVE_MAIL_CONNECTION: &str = "mail-server";
const NATIVE_MAIL_AUTHORIZATION: &str = "native_mail.authorization";

/// The connected pack, with what it was built from, and each identity's
/// read progress, kept across passes in memory.
#[derive(Default)]
pub(crate) struct NativeMailInboxes {
    pack: Option<(String, NativeMailPack)>,
    cursors: BTreeMap<EntityId, StalwartInboxCursor>,
}

impl NativeMailInboxes {
    /// The pack the last pass connected, if any.
    pub(super) fn pack(&self) -> Option<&NativeMailPack> {
        self.pack.as_ref().map(|(_, pack)| pack)
    }

    /// One pass: the pack follows its check and the host's server, then
    /// every active identity's inbox is read. `basis` names the check the
    /// pack would be built from; `None` drops it.
    pub(super) fn pass(
        &mut self,
        vault: &Vault,
        checked: Option<(CheckedBuiltinConnection, String)>,
        config: &NativeMailConfig,
    ) {
        let Some((checked, basis)) = checked else {
            if self.pack.take().is_some() {
                tracing::info!("native mail inboxes no longer served");
            }
            return;
        };
        let basis = format!("{basis}:{}:{}", config.session_url, config.domain_id);
        if self.pack.as_ref().is_none_or(|(kept, _)| *kept != basis) {
            self.pack = connect(vault, &checked, config).map(|pack| {
                tracing::info!("native mail inboxes served");
                (basis, pack)
            });
        }
        let Some((_, pack)) = &self.pack else {
            return;
        };
        let Some(dir) = config.quarantine_dir() else {
            tracing::info!(
                "[native_mail] names no quarantine_dir and this host has no data directory; inboxes are not read"
            );
            return;
        };
        let quarantine = match StalwartQuarantine::new(&dir) {
            Ok(quarantine) => quarantine,
            Err(error) => {
                tracing::warn!(%error, dir = %dir.display(), "the native mail quarantine is unavailable; inboxes are not read");
                return;
            }
        };
        match pack.poll_inboxes(
            vault,
            config.placement,
            &mut self.cursors,
            &quarantine,
            vault.now_recorded_at(),
        ) {
            Ok(read) => {
                if read.admitted > 0 {
                    tracing::info!(admitted = read.admitted, "native mail admitted");
                }
                for (identity, error) in read.failed {
                    tracing::warn!(identity = %identity.to_hex(), %error, "a native mail inbox read failed; it is read again next pass");
                }
                for (identity, set_aside) in read.set_aside {
                    tracing::warn!(identity = %identity.to_hex(), %set_aside, "a native mail message kept failing and was set aside; the inbox reads on");
                }
            }
            Err(error) => tracing::warn!(%error, "native mail identities unreadable"),
        }
    }
}

/// The pack on a client connected to the host's server with the stored
/// credential, read inside the credential door. The client keeps the header
/// in this host's memory only.
fn connect(
    vault: &Vault,
    checked: &CheckedBuiltinConnection,
    config: &NativeMailConfig,
) -> Option<NativeMailPack> {
    let placement = config
        .stalwart()
        .map_err(|error| tracing::warn!(%error, "[native_mail] is invalid; inboxes are not read"))
        .ok()?;
    let secret = checked
        .connection
        .secrets
        .iter()
        .find(|secret| secret.name == NATIVE_MAIL_AUTHORIZATION)?
        .clone();
    let mut connected = None;
    if let Err(error) =
        vault.inject_secret_at_door(&secret.name, &secret.effector, &mut |value: &[u8]| {
            connected = Some(StalwartClient::connect(
                placement.clone(),
                native_mail_authorization(value)?,
            ));
            Ok(())
        })
    {
        tracing::warn!(%error, "the native mail credential is unreadable; inboxes are not read");
        return None;
    }
    match connected? {
        Ok(client) => NativeMailPack::new(client)
            .map_err(|error| tracing::warn!(%error, "the native mail pack did not start"))
            .ok(),
        Err(error) => {
            tracing::warn!(%error, "the mail server refused the connection; inboxes are not read");
            None
        }
    }
}
