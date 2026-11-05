//! The pack's own folder, as the engine ships it, and the one check every
//! source door makes: the pack is installed Active.

use crate::consent::AuthenticatedOwner;
use crate::memory::hook_regen_doors::PackPutReceipt;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallStatus};
use crate::{Result, Vault};

/// The pack's name, as its PACK.md declares it.
pub const MAIL_CALENDAR_PACK_NAME: &str = "oneiron.mail_calendar";

/// The engine's Mail & Calendar pack folder: its manifest and its two
/// skills. The owner installs it ([`Vault::install_mail_calendar_pack`]);
/// nothing installs it on its own.
#[must_use]
pub fn mail_calendar_pack_files() -> Vec<HubFile> {
    vec![
        HubFile::new(
            "PACK.md",
            include_str!("../../../../packs/mail_calendar/PACK.md").as_bytes(),
        ),
        HubFile::new(
            "skills/mail-calendar/SKILL.md",
            include_str!("../../../../packs/mail_calendar/skills/mail-calendar/SKILL.md")
                .as_bytes(),
        ),
        HubFile::new(
            "skills/setup/SKILL.md",
            include_str!("../../../../packs/mail_calendar/skills/setup/SKILL.md").as_bytes(),
        ),
    ]
}

impl Vault {
    /// Owner door: installs the engine's own Mail & Calendar pack folder
    /// through the ordinary owner install ([`Vault::put_pack`]). Installing
    /// it connects nothing and grants nothing; each source is connected by
    /// its own person, or, for a group address, by an Owner or an Admin.
    pub fn install_mail_calendar_pack(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<PackInstallDisposition> {
        self.put_pack(owner, mail_calendar_pack_files())
    }
}

/// `vault.mail.pack.install`: the vault's embedded owner installs the
/// engine's own Mail & Calendar pack folder, as `vault.packs.put` would put
/// it. Anyone else is refused as the owner door refuses them.
pub fn install_mail_calendar_pack_embedded(memory: &Memory<'_>) -> MemoryResult<PackPutReceipt> {
    Ok(memory
        .put_pack_as_embedded_owner(mail_calendar_pack_files())?
        .into())
}

/// Refuses a source door while the pack is not installed Active.
pub(super) fn require_pack_active_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
    let active = vault
        .mounted_pack_in_txn(txn, MAIL_CALENDAR_PACK_NAME)?
        .is_some_and(|receipt| receipt.status == PackInstallStatus::Active);
    if active {
        return Ok(());
    }
    Err(MemoryError::bad_request_with(
        "the Mail & Calendar pack is not installed",
        &["Install the oneiron.mail_calendar pack, then connect the source."],
    ))
}
