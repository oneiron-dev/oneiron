//! The consultancy preset's pack Setting keys (owner ruling PACK-SETTINGS-ALL = B; Engine RULING
//! 23:20 15 Nov, PACK-KEYS-CAMPAIGN-PRESET-LOCKS = A, C02 and C03): the no-show bump delay and
//! the dispositions of three coded replies. Each default is the ratified preset value the
//! validator holds a pack to. A loaded preset carries the owner's values in their place
//! ([`super::load_campaign_preset`]). The owner changes a value; an agent's change waits on the
//! owner's approval.
//!
//! Direction: these keys decide when and whether a person is contacted again. Less or later
//! future contact is tighter. A row that does not decode reads as the tightest value: the bump
//! never comes, and the reply suppresses the member.

use serde::{Deserialize, Serialize};

use super::validate::ratified_disposition;
use crate::campaign::stage::{NO_SHOW_BUMP_AFTER_SECS, ReplyCode, ReplyDisposition};
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, higher_is_tighter};

/// The longest delay: about 285 million years, so never in practice, and a number every SDK
/// carries exactly. An unreadable row reads as this.
const NEVER_SECS: u64 = (1 << 53) - 1;

/// Seconds from a no-show to the bump: at least 1 (the same-day reschedule comes first) and at
/// most [`NEVER_SECS`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct NoShowBumpAfterSecs(pub(crate) u64);

impl SettingValue for NoShowBumpAfterSecs {
    fn check(self) -> Result<Self> {
        if (1..=NEVER_SECS).contains(&self.0) {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "a no-show bump delay is 1 to {NEVER_SECS} seconds"
            )))
        }
    }
}

/// What one coded reply does, as the ladder's own [`ReplyDisposition`]: `{"kind": "exit"}`, or
/// `{"kind": "promote", "stage": "<stage key>"}` for a stage the preset's ladder declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct ReplyDispositionChoice(pub(crate) ReplyDisposition);

impl SettingValue for ReplyDispositionChoice {}

impl ReplyDispositionChoice {
    /// Future contact a disposition leads to, least first: suppress, exit, record only, snooze,
    /// route to a referral, promote.
    fn contact_rank(&self) -> u8 {
        match &self.0 {
            ReplyDisposition::Suppress => 0,
            ReplyDisposition::Exit => 1,
            ReplyDisposition::RecordOnly => 2,
            ReplyDisposition::Snooze => 3,
            ReplyDisposition::RouteReferral => 4,
            ReplyDisposition::Promote { .. } => 5,
        }
    }
}

/// Less future contact is tighter.
fn less_contact_is_tighter(a: &ReplyDispositionChoice, b: &ReplyDispositionChoice) -> bool {
    a.contact_rank() <= b.contact_rank()
}

fn ratified_bump_after() -> NoShowBumpAfterSecs {
    NoShowBumpAfterSecs(NO_SHOW_BUMP_AFTER_SECS)
}

fn never() -> NoShowBumpAfterSecs {
    NoShowBumpAfterSecs(NEVER_SECS)
}

fn ratified_referral() -> ReplyDispositionChoice {
    ReplyDispositionChoice(ratified_disposition(ReplyCode::Referral))
}

fn ratified_objection() -> ReplyDispositionChoice {
    ReplyDispositionChoice(ratified_disposition(ReplyCode::Objection))
}

fn ratified_not_interested() -> ReplyDispositionChoice {
    ReplyDispositionChoice(ratified_disposition(ReplyCode::NotInterested))
}

fn suppress() -> ReplyDispositionChoice {
    ReplyDispositionChoice(ReplyDisposition::Suppress)
}

crate::setting::setting_keys! {
    /// Seconds from a no-show to the bump, after the same-day reschedule (default 259200, the
    /// ratified D+3). Longer is tighter: the person is asked again no sooner than this. An
    /// unreadable row reads as never.
    pub(crate) CAMPAIGN_NO_SHOW_BUMP_AFTER: NoShowBumpAfterSecs =
        "campaign.no_show.bump_after_secs" {
        kind: Kind::new(ratified_bump_after)
            .strictest(never)
            .tighter(higher_is_tighter::<NoShowBumpAfterSecs>),
    };
    /// What a referral reply does (default route_referral). Less future contact is tighter:
    /// suppress, exit, record_only, snooze, route_referral, promote. An unreadable row reads as
    /// suppress.
    pub(crate) CAMPAIGN_REPLY_REFERRAL_DISPOSITION: ReplyDispositionChoice =
        "campaign.reply.referral_disposition" {
        kind: Kind::new(ratified_referral)
            .strictest(suppress)
            .tighter(less_contact_is_tighter),
    };
    /// What an objection reply does (default record_only). Less future contact is tighter:
    /// suppress, exit, record_only, snooze, route_referral, promote. An unreadable row reads as
    /// suppress.
    pub(crate) CAMPAIGN_REPLY_OBJECTION_DISPOSITION: ReplyDispositionChoice =
        "campaign.reply.objection_disposition" {
        kind: Kind::new(ratified_objection)
            .strictest(suppress)
            .tighter(less_contact_is_tighter),
    };
    /// What a not-interested reply does (default exit). Less future contact is tighter:
    /// suppress, exit, record_only, snooze, route_referral, promote. An unreadable row reads as
    /// suppress.
    pub(crate) CAMPAIGN_REPLY_NOT_INTERESTED_DISPOSITION: ReplyDispositionChoice =
        "campaign.reply.not_interested_disposition" {
        kind: Kind::new(ratified_not_interested)
            .strictest(suppress)
            .tighter(less_contact_is_tighter),
    };
}

/// The owner's consultancy preset values in force, read in one transaction.
pub(super) struct ConsultancyPresetChoices {
    /// The no-show bump delay.
    pub(super) bump_after_secs: u64,
    /// The disposition of each owner-chosen reply code.
    pub(super) reply_dispositions: [(ReplyCode, ReplyDisposition); 3],
}

/// The owner's consultancy preset values in `txn`, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn consultancy_preset_choices_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<ConsultancyPresetChoices> {
    let disposition = |key: &crate::setting::Setting<ReplyDispositionChoice>| {
        key.read_in_txn(vault, txn, &[], None)
            .map(|resolved| resolved.value.0)
    };
    Ok(ConsultancyPresetChoices {
        bump_after_secs: CAMPAIGN_NO_SHOW_BUMP_AFTER
            .read_in_txn(vault, txn, &[], None)?
            .value
            .0,
        reply_dispositions: [
            (
                ReplyCode::Referral,
                disposition(&CAMPAIGN_REPLY_REFERRAL_DISPOSITION)?,
            ),
            (
                ReplyCode::Objection,
                disposition(&CAMPAIGN_REPLY_OBJECTION_DISPOSITION)?,
            ),
            (
                ReplyCode::NotInterested,
                disposition(&CAMPAIGN_REPLY_NOT_INTERESTED_DISPOSITION)?,
            ),
        ],
    })
}
