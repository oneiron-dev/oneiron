//! The owner's undo-send window (DEC-0006 #undo-send; owner ruling REV-8 = B,
//! 2026-10-09): how long a send waits on each outbound channel before it
//! goes, while a person can still take it back (Engine RULING 02:57, 13 Nov:
//! every send through the channel's enqueue, whoever sends it). One row holds it.
//! An absent row is off: every send goes out at once until a person sets a
//! length ("it can be off by default and we surface that they can set
//! delay").
//!
//! One length covers every channel ("set for all channels at once"); a
//! length for one channel replaces it there ("only per channel for power
//! users/detailed settings"). Both sit on the consent surface, the registry
//! of DEC-0006 invariant 9, never on a third one. A length is a send delay,
//! not a grant lifetime (DEC-0006, reading not ruled), so no ask offers a
//! duration.
//!
//! It is the catalogue key `outbound.undo_send` (`settings::setting_keys`):
//! the owner alone sets it, through `vault.settings.set`, and every change is
//! one `SETTING_CHANGE` row. The read (`vault.consent.undo_send`) answers the
//! owner, with the first agent send through each channel: the send that
//! carries the one-line hint that a delay can be set. The hold itself, the
//! undo and the list of sends in a window live in `outbound::undo_send`.

use serde::{Deserialize, Serialize};

use super::setting_keys::UNDO_SEND;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
use crate::outbound::{UndoSendFirstAgentSend, outbound_capability_manifest};
use crate::setting::SettingValue;

/// The connector whose sends never take a window: a legal send (prepare and
/// send for signature) has no delay proof in the act table (ARCH-0082
/// #act-table, "Legal: prepare and send for signature ... D: no").
pub const UNDO_SEND_EXCLUDED_CHANNEL: &str = "esign";

/// The read verb's name, as a refusal names it.
const READ_VERB: &str = "vault.consent.undo_send";

/// The owner's undo-send window: the value of the key `outbound.undo_send`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoSendSetting {
    /// Seconds a send waits on every channel before it goes; 0 is off: it
    /// goes at once.
    pub all_channels_secs: u32,
    /// Lengths for single channels, each replacing `all_channels_secs` on its
    /// channel. Each names a registered outbound connector once (`email`,
    /// `slack`, ...), never `esign`.
    #[serde(default)]
    pub channels: Vec<UndoSendChannelLength>,
}

/// One channel's own window length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoSendChannelLength {
    /// The outbound connector, as its capability manifest names it.
    pub channel: String,
    /// Seconds a send on this channel waits; 0 is off.
    pub secs: u32,
}

/// `vault.consent.undo_send`'s answer: the setting in force, and the first
/// agent send through each channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoSendSettings {
    /// As [`UndoSendSetting::all_channels_secs`]; 0 while the owner has set
    /// none.
    pub all_channels_secs: u32,
    /// As [`UndoSendSetting::channels`], in channel order.
    pub channels: Vec<UndoSendChannelLength>,
    /// The first agent send through each channel, held or not, in channel
    /// order: a surface shows the one-line hint that a delay can be set on
    /// that send.
    pub first_agent_sends: Vec<UndoSendFirstAgentSend>,
}

impl UndoSendSetting {
    /// The setting as it is stored: each channel in its manifest spelling,
    /// in channel order.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a channel no outbound connector
    /// registers, [`UNDO_SEND_EXCLUDED_CHANNEL`], or a channel named twice.
    /// No length is refused: the owner sets the window he wants (Engine
    /// RULING 02:57, 13 Nov: "Never add limits to the owner's rulings").
    pub fn normalized(&self) -> Result<Self> {
        let mut channels = Vec::with_capacity(self.channels.len());
        for length in &self.channels {
            let Some(manifest) = outbound_capability_manifest(&length.channel) else {
                return Err(Error::InvalidConfig(format!(
                    "the undo-send window names {:?}, which is no outbound channel",
                    length.channel
                )));
            };
            let channel = manifest.connector.clone();
            if channel == UNDO_SEND_EXCLUDED_CHANNEL {
                return Err(Error::InvalidConfig(
                    "a legal send for signature takes no undo-send window".to_owned(),
                ));
            }
            channels.push(UndoSendChannelLength {
                channel,
                secs: length.secs,
            });
        }
        channels.sort_by(|left, right| left.channel.cmp(&right.channel));
        if let Some(pair) = channels
            .windows(2)
            .find(|pair| pair[0].channel == pair[1].channel)
        {
            return Err(Error::InvalidConfig(format!(
                "the undo-send window names {:?} twice",
                pair[0].channel
            )));
        }
        Ok(Self {
            all_channels_secs: self.all_channels_secs,
            channels,
        })
    }

    /// The seconds a send on `channel` (its manifest spelling) waits: its
    /// own length, else the all-channel length.
    #[must_use]
    pub fn secs_for(&self, channel: &str) -> u32 {
        self.channels
            .iter()
            .find(|length| length.channel == channel)
            .map_or(self.all_channels_secs, |length| length.secs)
    }
}

impl SettingValue for UndoSendSetting {
    /// The setting as [`Self::normalized`] stores it.
    fn check(self) -> Result<Self> {
        self.normalized()
    }
}

/// The setting in `txn`: the owner's row, or off while there is none.
pub(crate) fn undo_send_setting_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<UndoSendSetting> {
    Ok(UNDO_SEND.read_in_txn(vault, txn, &[], None)?.value)
}

impl Vault {
    /// The owner's undo-send window and the first agent send through each
    /// channel, under the owner's proof.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, and storage errors.
    pub fn undo_send_settings_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<UndoSendSettings> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let setting = undo_send_setting_in_txn(self, &txn)?;
        Ok(UndoSendSettings {
            all_channels_secs: setting.all_channels_secs,
            channels: setting.channels,
            first_agent_sends: crate::outbound::undo_send_first_agent_sends_in_txn(self, &txn)?,
        })
    }
}

/// `vault.consent.undo_send` on the embedded owner's handle.
///
/// # Errors
///
/// A handle that is not the vault owner's, and storage errors.
pub fn read_undo_send_embedded(memory: &Memory<'_>) -> MemoryResult<UndoSendSettings> {
    Ok(memory
        .vault()
        .undo_send_settings_as_owner(&memory.embedded_owner(READ_VERB)?)?)
}
