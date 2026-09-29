//! Human-calibrated judge asks and the append-only label anchor.
//!
//! The engine proposes questions, not answers. Only an authenticated human
//! pick over a delivered ask writes a label. A digest delivers each ask once;
//! the owner's funded minutes balance defaults to zero (fail closed).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, LegacyJson, Raw, RawValue, SideTable};

/// Proposed calibration asks, keyed by the ask id (the digest of its immutable question).
const ASKS: SideTable<[u8; 32], JudgeAsk, LegacyJson> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_JUDGE_ASK);

/// The label anchor: one human pick per ask, keyed by the ask id.
const LABELS: SideTable<[u8; 32], JudgeLabel, LegacyJson> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_JUDGE_LABEL);

/// An owner's funded judge-ask minutes, keyed by the owner id. An absent row is zero.
const MINUTES: SideTable<EntityId, JudgeMinutes, Raw> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_JUDGE_MINUTES);

/// [`MINUTES`]'s row: the balance as a big-endian `u32`.
struct JudgeMinutes(u32);

impl RawValue for JudgeMinutes {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_be_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        <[u8; 4]>::try_from(bytes)
            .map(|raw| Self(u32::from_be_bytes(raw)))
            .map_err(|_| Error::CorruptedIndex("judge minutes budget").into())
    }
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid judge calibration ask or pick".into())
}

/// The evidence for raising a calibration question. Both kinds have two
/// explicit alternatives, so an uncertainty does not silently supply a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeAskReason {
    RevisionDisagreement,
    Uncertainty,
}

/// One question for the responsible human. `id` binds its complete immutable
/// question; `delivered_at` is only a delivery marker, never an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeAsk {
    pub id: [u8; 32],
    #[serde(with = "crate::serialize::entity_ref")]
    pub skill: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    pub responsible: EntityId,
    pub campaign: String,
    pub evidence: String,
    pub reason: JudgeAskReason,
    pub option_a: String,
    pub option_b: String,
    pub delivered_at: Option<u64>,
}

/// One human pick is one immutable calibration label. No score, model output,
/// or digest delivery can mint this row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeLabel {
    pub ask: JudgeAsk,
    pub chosen: String,
    pub picked_at: u64,
    pub principal_ref: String,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}
fn valid_text(value: &str, limit: u32) -> bool {
    !value.trim().is_empty() && value.len() <= usize::try_from(limit).unwrap_or(usize::MAX)
}

/// Propose an A/B ask when two judge revisions disagree on the same evidence.
/// The options are their distinct revision answers, not answers supplied by
/// this module. Repeating the same question returns its original identity.
pub fn ask_judge_disagreement(
    vault: &Vault,
    skill: EntityId,
    responsible: EntityId,
    campaign: &str,
    evidence: &str,
    earlier: &str,
    later: &str,
) -> Result<JudgeAsk> {
    propose(
        vault,
        skill,
        responsible,
        campaign,
        evidence,
        JudgeAskReason::RevisionDisagreement,
        [earlier, later],
    )
}

/// Propose an A/B ask over an uncertain judgment. The caller must present two
/// distinct alternatives; uncertainty itself never votes for either one.
pub fn ask_judge_uncertainty(
    vault: &Vault,
    skill: EntityId,
    responsible: EntityId,
    campaign: &str,
    evidence: &str,
    option_a: &str,
    option_b: &str,
) -> Result<JudgeAsk> {
    propose(
        vault,
        skill,
        responsible,
        campaign,
        evidence,
        JudgeAskReason::Uncertainty,
        [option_a, option_b],
    )
}

fn propose(
    vault: &Vault,
    skill: EntityId,
    responsible: EntityId,
    campaign: &str,
    evidence: &str,
    reason: JudgeAskReason,
    [option_a, option_b]: [&str; 2],
) -> Result<JudgeAsk> {
    if option_a == option_b {
        return Err(invalid());
    }
    let identity = encode(&(
        skill.to_hex(),
        responsible.to_hex(),
        campaign,
        evidence,
        reason,
        option_a,
        option_b,
    ))?;
    let id = *blake3::hash(&identity).as_bytes();
    let question = JudgeAsk {
        id,
        skill,
        responsible,
        campaign: campaign.into(),
        evidence: evidence.into(),
        reason,
        option_a: option_a.into(),
        option_b: option_b.into(),
        delivered_at: None,
    };
    vault.with_write_txn(|txn| {
        let policy = super::policy::resolved_in_txn(vault, &*txn)?;
        if [campaign, evidence, option_a, option_b]
            .iter()
            .any(|text| !valid_text(text, policy.max_context_bytes))
        {
            return Err(invalid());
        }
        if !matches!(
            crate::vault::live_entity_row_in_txn(&vault.store, &*txn, &skill)?,
            crate::vault::LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_SKILL,
                ..
            }
        ) || !matches!(
            crate::vault::live_entity_row_in_txn(&vault.store, &*txn, &responsible)?,
            crate::vault::LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_PERSON,
                ..
            }
        ) || vault.entity_lifecycle_state_in_txn(&*txn, &responsible)?
            != crate::identity_topology::EntityLifecycleState::Active
        {
            return Err(invalid());
        }
        if let Some(existing) = ASKS.get(&vault.store, &*txn, &id)? {
            if existing.id != id
                || existing.skill != skill
                || existing.responsible != responsible
                || existing.reason != reason
                || existing.campaign != campaign
                || existing.evidence != evidence
                || existing.option_a != option_a
                || existing.option_b != option_b
            {
                return Err(Error::CorruptedIndex("judge ask identity"));
            }
            return Ok(existing);
        }
        ASKS.put(&vault.store, txn, &id, &question)?;
        Ok(question)
    })
}

/// Set the remaining minutes of new judge questions for this human. Each ask
/// costs the resolved manifest's `ask_minutes` at delivery. The balance is not reset on
/// cadence; zero disables delivery until an authenticated owner replenishes it.
pub fn set_judge_digest_minutes(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    minutes: u32,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        crate::dreamer_runner::maintenance::validate_owner_in_txn(vault, &*txn, owner)?;
        MINUTES.put(&vault.store, txn, &owner.actor(), &JudgeMinutes(minutes))
    })
}

/// List labels for one skill and campaign. The persisted anchor is only these
/// rows, never the proposed asks. Order is stable by ask identity.
pub fn judge_label_anchor(
    vault: &Vault,
    skill: EntityId,
    campaign: &str,
) -> Result<Vec<JudgeLabel>> {
    let txn = vault.store.env.read_txn()?;
    let mut labels = Vec::new();
    for row in LABELS.iter_from(&vault.store, &txn, &[])? {
        let (key, label) = row?;
        if key != label.ask.id {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        if label.ask.skill == skill && label.ask.campaign == campaign {
            labels.push(label);
        }
    }
    Ok(labels)
}

/// Ingest an authenticated human's A/B pick, at most once for an ask. A
/// conflicting second pick fails rather than changing an existing label.
pub fn record_judge_pick(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    ask_id: [u8; 32],
    choose_b: bool,
    at: u64,
) -> Result<JudgeLabel> {
    vault.with_write_txn(|txn| {
        crate::dreamer_runner::maintenance::validate_owner_in_txn(vault, &*txn, owner)?;
        let ask = ASKS
            .get(&vault.store, &*txn, &ask_id)?
            .ok_or(Error::EntityNotFound)?;
        if ask.id != ask_id || ask.responsible != owner.actor() || ask.delivered_at.is_none() {
            return Err(invalid());
        }
        let chosen = if choose_b {
            ask.option_b.clone()
        } else {
            ask.option_a.clone()
        };
        if let Some(previous) = LABELS.get(&vault.store, &*txn, &ask_id)? {
            if previous.ask != ask || previous.chosen != chosen {
                return Err(invalid());
            }
            return Ok(previous);
        }
        let label = JudgeLabel {
            ask,
            chosen,
            picked_at: at,
            principal_ref: owner.principal_ref().into(),
        };
        LABELS.put(&vault.store, txn, &ask_id, &label)?;
        Ok(label)
    })
}

/// Digest integration: include at most the owner's funded minutes of pending
/// asks, debit the resolved manifest cost per ask, and mark only those asks delivered in the
/// same transaction as the digest. Failure restores both balance and asks.
pub(crate) fn take_digest_asks_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    at: u64,
) -> Result<Vec<JudgeAsk>> {
    let minutes = MINUTES
        .get(&vault.store, &*txn, &owner)?
        .map_or(0, |balance| balance.0);
    if minutes == 0 {
        return Ok(Vec::new());
    }
    let cost = super::policy::resolved_in_txn(vault, &*txn)?.ask_minutes;
    let slots = minutes / cost;
    if slots == 0 {
        return Ok(Vec::new());
    }
    let mut selected = Vec::new();
    for row in ASKS.iter_from(&vault.store, &*txn, &[])? {
        let (key, mut ask) = row?;
        if key != ask.id {
            return Err(Error::CorruptedIndex("judge ask identity"));
        }
        if ask.responsible == owner && ask.delivered_at.is_none() {
            ask.delivered_at = Some(at);
            selected.push(ask);
            if selected.len() >= usize::try_from(slots).unwrap_or(usize::MAX) {
                break;
            }
        }
    }
    if !selected.is_empty() {
        let count = u32::try_from(selected.len())
            .map_err(|_| Error::ArithmeticOverflow("judge ask minutes"))?;
        let spent = count
            .checked_mul(cost)
            .ok_or(Error::ArithmeticOverflow("judge ask minutes"))?;
        let remaining = minutes
            .checked_sub(spent)
            .ok_or(Error::ArithmeticOverflow("judge ask minutes"))?;
        MINUTES.put(&vault.store, txn, &owner, &JudgeMinutes(remaining))?;
        for ask in &selected {
            ASKS.put(&vault.store, txn, &ask.id, ask)?;
        }
    }
    Ok(selected)
}
