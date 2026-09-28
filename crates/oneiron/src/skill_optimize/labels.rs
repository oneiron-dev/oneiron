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

const ASK_PREFIX: &[u8] = b"skill_optimize:judge_ask:v1:";
const LABEL_PREFIX: &[u8] = b"skill_optimize:judge_label:v1:";
const BUDGET_PREFIX: &[u8] = b"settings:skill_optimize:judge_minutes:v1:";

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

fn ask_key(id: &[u8; 32]) -> Vec<u8> {
    [ASK_PREFIX, id].concat()
}
fn label_key(id: &[u8; 32]) -> Vec<u8> {
    [LABEL_PREFIX, id].concat()
}
fn budget_key(owner: EntityId) -> Vec<u8> {
    [BUDGET_PREFIX, owner.as_bytes()].concat()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| Error::CorruptedIndex("judge calibration row"))
}
fn valid_text(value: &str, limit: u32) -> bool {
    !value.trim().is_empty() && value.len() <= usize::try_from(limit).unwrap_or(usize::MAX)
}

fn validate_live_owner(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> Result<()> {
    owner.revalidate_in_txn(vault, txn)?;
    if !matches!(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, &owner.actor())?,
        crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            ..
        }
    ) || vault.entity_lifecycle_state_in_txn(txn, &owner.actor())?
        != crate::identity_topology::EntityLifecycleState::Active
    {
        return Err(Error::Gate(
            crate::error::GateError::ConsentOwnerNotAuthenticated(
                "judge calibration requires a live human owner",
            ),
        ));
    }
    Ok(())
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
        if let Some(raw) = vault.store.vault_meta.get(&*txn, &ask_key(&id))? {
            let existing: JudgeAsk = decode(&raw)?;
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
        vault
            .store
            .vault_meta
            .put(txn, &ask_key(&id), &encode(&question)?)?;
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
        validate_live_owner(vault, &*txn, owner)?;
        vault
            .store
            .vault_meta
            .put(txn, &budget_key(owner.actor()), &minutes.to_be_bytes())?;
        Ok(())
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
    for row in vault.store.vault_meta.prefix_iter(&txn, LABEL_PREFIX)? {
        let (key, bytes) = row?;
        let label: JudgeLabel = decode(&bytes)?;
        if key != label_key(&label.ask.id) {
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
        validate_live_owner(vault, &*txn, owner)?;
        let raw = vault
            .store
            .vault_meta
            .get(&*txn, &ask_key(&ask_id))?
            .ok_or(Error::EntityNotFound)?;
        let ask: JudgeAsk = decode(&raw)?;
        if ask.id != ask_id || ask.responsible != owner.actor() || ask.delivered_at.is_none() {
            return Err(invalid());
        }
        let chosen = if choose_b {
            ask.option_b.clone()
        } else {
            ask.option_a.clone()
        };
        if let Some(raw) = vault.store.vault_meta.get(&*txn, &label_key(&ask_id))? {
            let previous: JudgeLabel = decode(&raw)?;
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
        vault
            .store
            .vault_meta
            .put(txn, &label_key(&ask_id), &encode(&label)?)?;
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
    let minutes = vault
        .store
        .vault_meta
        .get(&*txn, &budget_key(owner))?
        .map(|raw| {
            <[u8; 4]>::try_from(raw.as_ref())
                .map(u32::from_be_bytes)
                .map_err(|_| Error::CorruptedIndex("judge minutes budget"))
        })
        .transpose()?
        .unwrap_or(0);
    let cost = super::policy::resolved_in_txn(vault, &*txn)?.ask_minutes;
    let slots = minutes / cost;
    if slots == 0 {
        return Ok(Vec::new());
    }
    let mut selected = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&*txn, ASK_PREFIX)? {
        let (key, raw) = row?;
        let mut ask: JudgeAsk = decode(&raw)?;
        if key != ask_key(&ask.id) {
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
        vault
            .store
            .vault_meta
            .put(txn, &budget_key(owner), &remaining.to_be_bytes())?;
        for ask in &selected {
            vault
                .store
                .vault_meta
                .put(txn, &ask_key(&ask.id), &encode(ask)?)?;
        }
    }
    Ok(selected)
}
