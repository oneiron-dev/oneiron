//! The campaign sticky sender's pack Setting key (owner ruling PACK-SETTINGS-ALL = B; Engine
//! RULING 23:20 15 Nov, PACK-KEYS-CAMPAIGN-PRESET-LOCKS = A, C06): whether a member-channel whose
//! stored sender is dead moves to the proposed sender, or waits for a human restart. The default
//! is today's: a human restarts it (`send_hygiene::StickySenderOutcome::RestartRequired`). The
//! owner changes the value; an agent's change waits on the owner's approval.
//!
//! Direction: false is tighter. With true a person is mailed from an address they have not had
//! mail from, so turning it on is a loosening and needs the owner's device yes. Each rotation then
//! writes the member's new head and a notice to every vault owner, so the identity change stays
//! visible. A row that does not decode reads as false.
//!
//! The copy review skip key (lead ruling COPY-REVIEW-JUDGE-BY-DEFAULT = B, 21 Nov 13:2x): one
//! item per campaign, off by default, so copy review governs each campaign until the owner turns
//! it off for that campaign. Turning it on is a loosening (unreviewed copy goes out), so it is the
//! owner's move through the confirm sheet; an agent's change waits on the owner's answer.

use crate::error::Result;
use crate::setting::{ItemDomain, Kind, SettingScope};
use crate::store::Store;
use crate::{EntityId, Vault};

const fn restart_required() -> bool {
    false
}

/// Off: copy review governs the campaign.
const fn copy_review_kept() -> bool {
    false
}

/// Whether `item` names a campaign: an entity ref in lower-case hex, the one spelling the Gate
/// reads, so no row sits under another spelling of the same ref.
fn is_campaign_ref(item: &str) -> bool {
    EntityId::from_hex(item).is_ok_and(|campaign_ref| campaign_ref.to_hex() == item)
}

/// The confirm sheet's line for turning copy review off for one campaign: the campaign it names,
/// as the vault holds it when the sheet is read.
fn copy_review_skip_loosening_note(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    _scope: &SettingScope,
    item: Option<&str>,
) -> Result<Option<String>> {
    let Some(campaign_ref) = item.and_then(|item| EntityId::from_hex(item).ok()) else {
        return Ok(None);
    };
    let record = super::surface::load_registered_campaign_in_txn(&vault.store, txn, campaign_ref)?;
    Ok(Some(match record {
        Some(record) => format!(
            "The campaign \"{}\" sends its copy with no copy review.",
            record.definition.name
        ),
        None => "No campaign has this ref yet: the row skips copy review for none.".to_owned(),
    }))
}

crate::setting::setting_keys! {
    /// Rotate a campaign member-channel off its dead sticky sender (default false: the binding
    /// returns a restart for a human and writes nothing). true: the binding moves the
    /// member-channel to the proposed sender, and every vault owner gets a notice naming the
    /// person, the dead sender and the new one. false is tighter. An unreadable row reads as
    /// false.
    pub(crate) CAMPAIGN_SENDER_ROTATE_ON_DEAD: bool = "campaign.sender.rotate_on_dead" {
        kind: Kind::new(restart_required)
            .strictest(restart_required)
            .lower(),
    };
    /// Skip copy review for this campaign (ARCH-0059 #copy-review; lead ruling
    /// COPY-REVIEW-JUDGE-BY-DEFAULT = B, 21 Nov). One item per campaign, named by its ref in
    /// hex. Off by default: the campaign's copy is reviewed before each send. On: the
    /// campaign's sends go out with no copy review, whatever voice guide or review mode it
    /// names. false is tighter. Turning it on is a loosening: the owner makes it through the
    /// confirm sheet, and an agent's change waits on the owner's answer. An unreadable row
    /// reads as false.
    pub(crate) CAMPAIGN_COPY_REVIEW_SKIP: bool = "campaign.copy_review.skip" {
        kind: Kind::new(copy_review_kept)
            .strictest(copy_review_kept)
            .lower(),
        item: Some(ItemDomain { name: "campaign refs", admits: is_campaign_ref }),
        loosening_note: Some(copy_review_skip_loosening_note),
    };
}

/// Whether the owner lets a dead sticky sender rotate, in `txn`, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn sender_rotates_on_dead_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(CAMPAIGN_SENDER_ROTATE_ON_DEAD
        .read_in_txn(vault, txn, &[], None)?
        .value)
}

/// Whether the owner turned copy review off for `campaign_ref`, in `txn`, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn copy_review_skipped_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    campaign_ref: EntityId,
) -> Result<bool> {
    Ok(CAMPAIGN_COPY_REVIEW_SKIP
        .read_in_dbs_txn(store, txn, &[], Some(&campaign_ref.to_hex()))?
        .value)
}
