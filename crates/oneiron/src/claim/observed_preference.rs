//! The engine's observed-preference bar and stated-answer matching.

use std::collections::BTreeSet;

use rmpv::Value;

use super::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::Vault;
use crate::compaction::turn_session_membership_in_txn;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::serialize::msgpack_value_to_json;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Distinct observations an Observed preference needs: ARCH-0003's minting
/// rule, "three observations across two or more sessions". The owner's
/// `claim.observed_preference.min_observations` moves it for a preference
/// whose subject is the owner; every other person keeps it.
pub(crate) const OBSERVED_PREFERENCE_MIN_OBSERVATIONS: usize = 3;

/// Distinct sessions those observations must span: the same rule's "two or
/// more sessions". The owner's `claim.observed_preference.min_sessions` moves
/// it for a preference whose subject is the owner.
pub(crate) const OBSERVED_PREFERENCE_MIN_SESSIONS: usize = 2;

/// The value of `claim.observed_preference.min_observations` and
/// `.min_sessions`: a count of at least 1.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ObservedPreferenceCount(pub(crate) u32);

impl crate::setting::SettingValue for ObservedPreferenceCount {
    /// A count is at least 1: an Observed stamp always rests on an observation.
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(crate::error::Error::InvalidConfig(
                "an observed-preference count is at least 1".into(),
            ))
        }
    }
}

/// The bar one Observed preference meets: distinct observations, and the
/// distinct sessions they span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObservedPreferenceBar {
    pub(crate) observations: usize,
    pub(crate) sessions: usize,
}

impl ObservedPreferenceBar {
    /// ARCH-0003's minting rule: three observations across two sessions.
    pub(crate) const CANON: Self = Self {
        observations: OBSERVED_PREFERENCE_MIN_OBSERVATIONS,
        sessions: OBSERVED_PREFERENCE_MIN_SESSIONS,
    };

    /// Whether `observations` distinct observations across `sessions`
    /// distinct sessions meet the bar.
    pub(crate) const fn met_by(self, observations: usize, sessions: usize) -> bool {
        observations >= self.observations && sessions >= self.sessions
    }
}

/// The bar for a preference about `subject`, read in `txn`: the owner's
/// `claim.observed_preference.min_observations` and `.min_sessions` when
/// `subject` is a live owner of this vault, ARCH-0003's three across two for
/// every other person (Engine RULING RESTRICTION-WAVE-8-ROWS, C96 = C). At
/// the defaults no owner census is read, so the bar is the canon one exactly
/// as before.
///
/// # Errors
///
/// Storage errors, and an unreadable count row.
pub(crate) fn observed_preference_bar_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<ObservedPreferenceBar> {
    let count = |value: ObservedPreferenceCount| usize::try_from(value.0).unwrap_or(usize::MAX);
    let owners = ObservedPreferenceBar {
        observations: count(
            super::setting_keys::OBSERVED_PREFERENCE_OBSERVATIONS
                .read_in_txn(vault, txn, &[], None)?
                .value,
        ),
        sessions: count(
            super::setting_keys::OBSERVED_PREFERENCE_SESSIONS
                .read_in_txn(vault, txn, &[], None)?
                .value,
        ),
    };
    if owners == ObservedPreferenceBar::CANON
        || !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, subject)?
    {
        return Ok(ObservedPreferenceBar::CANON);
    }
    Ok(owners)
}

/// Whether `predicate` is in the `preference.*` family.
pub(crate) fn is_preference_predicate(predicate: &str) -> bool {
    predicate.starts_with(super::lifecycle::PREFERENCE_PREDICATE_PREFIX)
}

/// Whether `evidence` holds enough distinct live, nonimported user TURNs
/// witnessed into distinct live SESSIONs for a preference about `subject`
/// ([`observed_preference_bar_in_txn`]), read on the writer's snapshot.
pub(crate) fn observed_preference_support_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    evidence: &[EntityId],
) -> Result<bool> {
    let mut observations = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    for turn in evidence {
        if !user_turn_in_txn(vault, txn, turn)? {
            continue;
        }
        let Some(session) = turn_session_membership_in_txn(&vault.store, txn, turn)? else {
            continue;
        };
        if !is_live(vault, txn, &session, ENTITY_TYPE_SESSION)? {
            continue;
        }
        observations.insert(*turn);
        sessions.insert(session);
    }
    Ok(observed_preference_bar_in_txn(vault, txn, subject)?
        .met_by(observations.len(), sessions.len()))
}

fn user_turn_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, id)?
    else {
        return Ok(false);
    };
    let facts = crate::dreamer_consolidation::decode_turn_body(&body);
    Ok(!facts.imported
        && matches!(
            crate::dreamer_runner::dreamer_turn_role(
                facts.speaker.as_deref(),
                &vault.config.assistant_display_names,
            ),
            crate::dreamer_runner::DreamerTurnRole::User
        ))
}

fn is_live(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId, entity_type: u8) -> Result<bool> {
    Ok(matches!(
        live_entity_row_in_txn(&vault.store, txn, id)?,
        LiveEntityRow::Live { entity_type: found, .. } if found == entity_type
    ))
}

/// The standing UserStated preference claims on `observed`'s key whose
/// answer differs: Active, Auto or Approved, valid now, with the same
/// subject, predicate, world, relationships, scope, facet and project.
pub(crate) fn stated_preference_peers_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    observed: &ClaimBody,
) -> Result<Vec<EntityId>> {
    let ClaimSubject::Entity(subject) = &observed.subject else {
        return Ok(Vec::new());
    };
    if !is_preference_predicate(&observed.predicate) {
        return Ok(Vec::new());
    }
    let standing_at = vault.store.clock.now_recorded_at();
    let scope = observed.scope.as_ref().map(msgpack_value_to_json);
    let mut peers = Vec::new();
    for peer in vault.claims_for_subject_in_txn(txn, subject)? {
        let Some(stated) = vault.get_claim_in_txn(txn, &peer)? else {
            continue;
        };
        if stated.source == Some(ClaimSource::UserStated)
            && stated.lifecycle == ClaimLifecycleStatus::Active
            && matches!(
                stated.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            && stated.subject == observed.subject
            && stated.predicate == observed.predicate
            && stated.world == observed.world
            && stated.rel == observed.rel
            && stated.scope.as_ref().map(msgpack_value_to_json) == scope
            && stated.scope_facet == observed.scope_facet
            && stated.scope_project == observed.scope_project
            && !stated.valid_from.is_some_and(|start| start > standing_at)
            && !stated.valid_to.is_some_and(|end| end <= standing_at)
            && !preference_answers_agree(&observed.value, &stated.value)
        {
            peers.push(peer);
        }
    }
    Ok(peers)
}

/// OF-023: whether an observed preference gives the stated one's answer.
/// Canon names a normalized answer key without pinning it, so this is the
/// one place that decides: text compares blind to case and spacing (the
/// Dreamer's `normalize_text` rule), maps compare whatever their key order,
/// and every other value, structured qualifiers included, must match.
pub(crate) fn preference_answers_agree(observed: &Value, stated: &Value) -> bool {
    match (observed, stated) {
        (Value::String(a), Value::String(b)) => match (a.as_str(), b.as_str()) {
            (Some(a), Some(b)) => fold_answer_text(a) == fold_answer_text(b),
            _ => a == b,
        },
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| preference_answers_agree(a, b))
        }
        (Value::Map(a), Value::Map(b)) => {
            a.len() == b.len() && a.iter().all(|(k, v)| entry_agrees(b, k, v))
        }
        _ => observed == stated,
    }
}

/// Whether `map` holds `key` with an answer that agrees with `value`.
fn entry_agrees(map: &[(Value, Value)], key: &Value, value: &Value) -> bool {
    map.iter()
        .find(|(k, _)| k == key)
        .is_some_and(|(_, v)| preference_answers_agree(v, value))
}

fn fold_answer_text(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}
