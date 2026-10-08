//! No decision the engine makes from rows a restore brings back permits more
//! than it does now (ARCH-0038: historical authority is not present-day
//! permission).
//!
//! The row classes decide what each row of a restored vault holds. A decision
//! that folds many rows (a party's first contact in id order, the claims an
//! edge reaches, a person a party name resolves to) can still change when no
//! single authority row did. So once the restored vault is open, each decision
//! below is asked of the live vault and of the restored one, through the
//! reader the engine itself decides with, for every subject either vault can
//! ask it about. A restore under which any answer permits more than it does
//! now is refused. One that changes no answer restores, however much content
//! it brings back; so does one that only narrows an answer, as dropping a
//! contact made since the backup leaves that party's sends held as cold.
//!
//! A decision about one entity (who may read a claim, whether a task's ask
//! is stale) is asked only of entities both vaults hold: one only one vault
//! holds is content the restore returns or drops (RD-20). A decision about
//! a subject no single row is (a party name, a holder set) is asked of every
//! subject either vault names.
use crate::ports::EntityStoreRead;
use crate::{EntityId, Error, Result, Vault};
use std::collections::BTreeSet;

mod artifacts;
mod audience;
mod campaign;
mod consent;
mod counterparty;
mod notifications;
mod reads;
mod skills;
mod tasks;
mod worlds;

/// One decision the engine makes from rows a restore can change.
trait Decision {
    /// What it is asked about.
    type Subject: Ord;
    /// What it answers.
    type Answer;
    /// Every subject either vault can ask it about.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>>;
    /// Its answer in `vault` for each of `subjects`, in order, through the
    /// engine's own reader; `None` where the reader fails, which the engine
    /// treats as a refusal.
    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>>;
    /// Whether `restored` permits anything `live` does not.
    fn loosens(live: &Self::Answer, restored: &Self::Answer) -> bool;
    /// The answer that permits nothing, which a reader that fails stands
    /// for; `None` where no answer permits nothing, and every answer past a
    /// failed read permits more.
    fn refusal() -> Option<Self::Answer> {
        None
    }
}

/// Whether `D` permits more for any subject in the restored vault than in the
/// live one. A reader that fails permits nothing.
fn loosened<D: Decision>(current: &Vault, restored: &Vault) -> Result<bool> {
    let subjects = D::subjects([current, restored])?;
    let live = D::answers(current, &subjects)?;
    let restored = D::answers(restored, &subjects)?;
    let refusal = D::refusal();
    Ok(live.iter().zip(&restored).any(|answers| match answers {
        (_, None) => false,
        (None, Some(restored)) => refusal
            .as_ref()
            .is_none_or(|refusal| D::loosens(refusal, restored)),
        (Some(live), Some(restored)) => D::loosens(live, restored),
    }))
}

/// A check of one decision on the live and the restored vault.
type Check = fn(&Vault, &Vault) -> Result<bool>;

/// Every decision a restore may not loosen, by the name a refusal gives it.
const DECISIONS: &[(&str, Check)] = &[
    (
        "counterparty contacts and their consents",
        loosened::<counterparty::SendContacts>,
    ),
    (
        "do-not-contact rulings",
        loosened::<counterparty::DoNotContact>,
    ),
    ("send overrides", loosened::<counterparty::SendOverrides>),
    (
        "campaign compliance rules",
        loosened::<campaign::CampaignCompliance>,
    ),
    ("record audiences", loosened::<audience::RecordAudiences>),
    ("disclosure clamps", loosened::<audience::DisclosureClamps>),
    ("disclosure tiers", loosened::<audience::DisclosureTiers>),
    ("leader chat admissions", loosened::<audience::LeaderChats>),
    ("project verdicts", loosened::<audience::ProjectVerdicts>),
    ("relationship reads", loosened::<reads::RelationshipReads>),
    ("claim read grants", loosened::<reads::ClaimGrants>),
    (
        "verified slip claim reads",
        loosened::<reads::SlipClaimGrants>,
    ),
    ("private note reads", loosened::<reads::NoteReads>),
    ("diary link reads", loosened::<reads::DiaryLinks>),
    ("record positions", loosened::<reads::RecordPositions>),
    (
        "task owners and cancellations",
        loosened::<tasks::TaskAuthority>,
    ),
    ("stale task asks", loosened::<tasks::StaleAsks>),
    ("dispatchable agents", loosened::<tasks::DispatchableAgents>),
    ("resident agent wakes", loosened::<tasks::ResidentWakes>),
    ("agent approval ceilings", loosened::<tasks::AgentCeilings>),
    ("ask authority holders", loosened::<tasks::AskHolders>),
    ("skill activations", loosened::<skills::SkillActivations>),
    (
        "installed script packs",
        loosened::<skills::InstalledScriptPacks>,
    ),
    (
        "sender reputation offers",
        loosened::<consent::MailReputation>,
    ),
    (
        "shared coreference links",
        loosened::<consent::SharedCoreference>,
    ),
    (
        "delivery-window restrictions",
        loosened::<consent::DeliveryWindows>,
    ),
    (
        "public booking publications",
        loosened::<consent::BookingPublications>,
    ),
    (
        "signing principal autonomy",
        loosened::<consent::PrincipalAutonomy>,
    ),
    (
        "e-sign ceremony states",
        loosened::<consent::EsignCeremonies>,
    ),
    (
        "calendar invitation consent",
        loosened::<consent::CalendarInviteConsent>,
    ),
    (
        "world selection authority",
        loosened::<worlds::WorldSelections>,
    ),
    (
        "notification recipients",
        loosened::<notifications::NotificationRecipients>,
    ),
    (
        "artifact taint admissions",
        loosened::<artifacts::ArtifactTaints>,
    ),
];

/// Refuses a restored vault in which a decision permits more than it does in
/// `current`.
pub(super) fn refuse_loosened_decisions(current: &Vault, restored: &Vault) -> Result<()> {
    let mut loosened = Vec::new();
    for (what, check) in DECISIONS {
        if check(current, restored)? {
            loosened.push(*what);
        }
    }
    if loosened.is_empty() {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "restoring this checkpoint would roll back {} changed since it was taken; restore it beside the vault instead",
        loosened.join(", ")
    )))
}

/// Every entity of `kind` both vaults hold. A decision about one entity is
/// asked only of these: one only one vault holds is content returning with
/// the restore, or leaving with it.
fn held_by_both(vaults: [&Vault; 2], kind: u8) -> Result<BTreeSet<EntityId>> {
    let [live, restored] = vaults.map(|vault| held(vault, kind));
    Ok(live?.intersection(&restored?).copied().collect())
}

/// Every entity of `kind` either vault holds.
fn held_by_either(vaults: [&Vault; 2], kind: u8) -> Result<BTreeSet<EntityId>> {
    let [live, restored] = vaults.map(|vault| held(vault, kind));
    Ok(live?.union(&restored?).copied().collect())
}

/// Every entity of `kind` `vault` holds.
fn held(vault: &Vault, kind: u8) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    vault
        .store
        .port_entity_ids_by_type(&txn, kind, None)?
        .collect()
}

/// A string field of a claim's map value.
fn field<'a>(value: &'a rmpv::Value, name: &str) -> Option<&'a str> {
    match value {
        rmpv::Value::Map(fields) => fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .and_then(|(_, value)| value.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
