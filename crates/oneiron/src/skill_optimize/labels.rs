//! Human-calibrated judge asks and the append-only label anchor.
//!
//! The engine proposes questions, not answers. Only an authenticated human
//! pick over a delivered ask writes a label. A digest delivers each ask once;
//! the owner's funded minutes balance defaults to zero (fail closed). Eval
//! label asks draw on the same balance, after the judge asks.
//!
//! The judge's rubric is the active shared `judge` skill's text. A change to
//! that text re-pins the judge (ARCH-0042 "The edit re-pins the judge") and
//! stamps every standing label as a pending re-check. A pending label stays in
//! the anchor and keeps its freshness until the Coach's next pass asks whether
//! the pick still fits the new rubric. A fit clears the stamp. A conflict, or
//! an answer the Coach cannot give, takes the label out of the anchor until
//! its person re-grades it ("Labels that conflict with the new rubric wait
//! for re-grade").

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, LegacyJson, Named, Raw, RawValue, SideTable};

/// Proposed calibration asks, keyed by the ask id (the digest of its immutable question).
const ASKS: SideTable<[u8; 32], JudgeAsk, LegacyJson> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_JUDGE_ASK);

/// The label anchor: one human pick per ask, keyed by the ask id.
const LABELS: SideTable<[u8; 32], JudgeLabel, LegacyJson> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_JUDGE_LABEL);

/// An owner's funded judge-ask minutes, keyed by the owner id. An absent row is zero.
const MINUTES: SideTable<EntityId, JudgeMinutes, Raw> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_JUDGE_MINUTES);

/// The judge's rubric pin: the rubric text the label anchor was last
/// reconciled with.
const RUBRIC_PIN: SideTable<(), JudgeRubricPin, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_JUDGE_RUBRIC);

/// The bootstrap judge skill: its instructions are the rubric every skill edit
/// is judged by (ARCH-0053: "The judge (the rubric) ... A skill").
pub(crate) const JUDGE_SKILL_ID: &str = "judge";

/// The package file whose text is the rubric.
const SKILL_FILE: &str = "SKILL.md";

/// The two answers of a re-grade ask: the pick still fits the edited rubric
/// (the pick's own words follow), or the case is asked again.
const REGRADE_KEEP: &str = "It still fits the new rubric: ";
const REGRADE_ASK_AGAIN: &str = "Ask me this case again";

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
    /// Whether a pick a rubric edit left waiting still fits the new rubric.
    /// Only [`record_judge_label_regrade`] answers it; it never mints a label.
    RubricRecheck,
    /// The case of a pick its person re-graded as no longer fitting, asked
    /// again under the new rubric: an ordinary A/B ask.
    RubricRegrade,
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
    /// The label a re-grade or a re-ask is about, and the rubric it is asked
    /// under; part of the ask's identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regrade: Option<JudgeRegrade>,
}

/// What a [`JudgeAskReason::RubricRecheck`] or
/// [`JudgeAskReason::RubricRegrade`] ask is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeRegrade {
    /// The label's ask id.
    pub label: [u8; 32],
    /// The rubric's text digest.
    pub rubric: [u8; 32],
}

/// One human pick is one immutable calibration label. No score, model output,
/// or digest delivery can mint this row. A rubric edit marks it for a
/// re-check; it never changes the pick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeLabel {
    pub ask: JudgeAsk,
    pub chosen: String,
    pub picked_at: u64,
    pub principal_ref: String,
    /// Where an edit of the judge's rubric left this pick; `None` while no
    /// edit since it was picked or last found fitting is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recheck: Option<JudgeLabelRecheck>,
}

/// A label's re-check after an edit of the judge's rubric. Each `rubric` is
/// the rubric text's digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeLabelRecheck {
    /// Stamped by the edit: still in the anchor, with its freshness, until
    /// the Coach's next pass checks it.
    Pending { rubric: [u8; 32] },
    /// The Coach found it conflicting with the rubric, or could not tell: out
    /// of the anchor until its person answers `ask`, the re-grade ask (`None`
    /// when that ask could not be put to them).
    Waiting {
        rubric: [u8; 32],
        ask: Option<[u8; 32]>,
    },
    /// Its person answered `ask` that it still fits: back in the anchor, its
    /// pick time unchanged.
    Kept { rubric: [u8; 32], ask: [u8; 32] },
    /// Its person answered `ask` that it does not: out of the anchor for
    /// good; `fresh` asks the case again.
    Replaced {
        rubric: [u8; 32],
        ask: [u8; 32],
        fresh: [u8; 32],
    },
}

impl JudgeLabel {
    /// Whether the pick is in its skill's anchor: every label but one a
    /// rubric edit left waiting for, or replaced by, its person's re-grade.
    fn in_anchor(&self) -> bool {
        !matches!(
            self.recheck,
            Some(JudgeLabelRecheck::Waiting { .. } | JudgeLabelRecheck::Replaced { .. })
        )
    }

    /// Whether the Coach owes the pick a check against `rubric`, the pinned
    /// one: stamped under it, or kept by its person under an earlier one.
    fn recheck_due(&self, rubric: [u8; 32]) -> bool {
        match self.recheck {
            Some(JudgeLabelRecheck::Pending { rubric: stamped }) => stamped == rubric,
            Some(JudgeLabelRecheck::Kept { rubric: kept, .. }) => kept != rubric,
            None | Some(JudgeLabelRecheck::Waiting { .. } | JudgeLabelRecheck::Replaced { .. }) => {
                false
            }
        }
    }
}

/// [`RUBRIC_PIN`]'s row: the rubric the judge is pinned on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JudgeRubricPin {
    /// The rubric text's digest.
    digest: [u8; 32],
    /// The `judge` skill revision the text was read from, and its version.
    skill: EntityId,
    version: String,
    pinned_at: u64,
}

/// The judge's rubric as the replay judge reads it: the active shared
/// revision of the bootstrap `judge` skill and its instruction text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgeRubric {
    pub skill: EntityId,
    pub version: String,
    pub text: String,
    /// The text's BLAKE3 digest; a version-only edit leaves it unchanged.
    pub digest: [u8; 32],
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
    options: [&str; 2],
) -> Result<JudgeAsk> {
    let question = ask_identity(
        skill,
        responsible,
        campaign,
        evidence,
        reason,
        options,
        None,
    )?;
    vault.with_write_txn_grouped(|txn| propose_in_txn(vault, txn, question))
}

/// The ask these words make, its id bound to all of them and to the label and
/// rubric a re-grade is about; not yet delivered.
fn ask_identity(
    skill: EntityId,
    responsible: EntityId,
    campaign: &str,
    evidence: &str,
    reason: JudgeAskReason,
    [option_a, option_b]: [&str; 2],
    regrade: Option<JudgeRegrade>,
) -> Result<JudgeAsk> {
    if option_a == option_b {
        return Err(invalid());
    }
    let words = (
        skill.to_hex(),
        responsible.to_hex(),
        campaign,
        evidence,
        reason,
        option_a,
        option_b,
    );
    let identity = match regrade {
        None => encode(&words)?,
        Some(of) => encode(&(words, of.label, of.rubric))?,
    };
    let id = *blake3::hash(&identity).as_bytes();
    Ok(JudgeAsk {
        id,
        skill,
        responsible,
        campaign: campaign.into(),
        evidence: evidence.into(),
        reason,
        option_a: option_a.into(),
        option_b: option_b.into(),
        delivered_at: None,
        regrade,
    })
}

/// [`propose`]'s checks and write, in the caller's transaction.
fn propose_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    question: JudgeAsk,
) -> Result<JudgeAsk> {
    let JudgeAsk {
        id,
        skill,
        responsible,
        reason,
        ..
    } = question;
    let (campaign, evidence) = (question.campaign.as_str(), question.evidence.as_str());
    let (option_a, option_b) = (question.option_a.as_str(), question.option_b.as_str());
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
            || existing.regrade != question.regrade
        {
            return Err(Error::CorruptedIndex("judge ask identity"));
        }
        return Ok(existing);
    }
    ASKS.put(&vault.store, txn, &id, &question)?;
    Ok(question)
}

/// Set the remaining minutes of new judge questions for this human. Each ask
/// costs the resolved manifest's `ask_minutes` at delivery, and each eval label
/// ask the minutes it was asked at. The balance is not reset on cadence; zero
/// disables delivery until an authenticated owner replenishes it.
pub fn set_judge_digest_minutes(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    minutes: u32,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let actor =
            crate::dreamer_runner::maintenance::validate_person_in_txn(vault, &*txn, owner)?;
        MINUTES.put(&vault.store, txn, &actor, &JudgeMinutes(minutes))
    })
}

/// This human's remaining judge-ask minutes; zero until they fund some.
pub fn judge_digest_minutes(vault: &Vault, owner: &AuthenticatedOwner) -> Result<u32> {
    let txn = vault.store.env.read_txn()?;
    let actor = crate::dreamer_runner::maintenance::validate_person_in_txn(vault, &txn, owner)?;
    Ok(MINUTES
        .get(&vault.store, &txn, &actor)?
        .map_or(0, |balance| balance.0))
}

/// What one person's funded minutes leave room for: how many more asks their
/// digests can carry beyond the ones already waiting, and every question
/// already put to them, delivered or not, as (skill, campaign, evidence).
pub(crate) struct JudgeAskRoom {
    pub(crate) room: usize,
    pub(crate) asked: std::collections::BTreeSet<(EntityId, String, String)>,
}

/// [`JudgeAskRoom`] for `person`. A person who funded no minutes has no room.
pub(crate) fn judge_ask_room(vault: &Vault, person: EntityId) -> Result<JudgeAskRoom> {
    let txn = vault.store.env.read_txn()?;
    let minutes = MINUTES
        .get(&vault.store, &txn, &person)?
        .map_or(0, |balance| balance.0);
    let cost = super::policy::resolved_in_txn(vault, &txn)?.ask_minutes;
    let slots = usize::try_from(minutes / cost).unwrap_or(usize::MAX);
    let mut waiting = 0_usize;
    let mut asked = std::collections::BTreeSet::new();
    for row in ASKS.iter_from(&vault.store, &txn, &[])? {
        let (key, ask) = row?;
        if key != ask.id {
            return Err(Error::CorruptedIndex("judge ask identity"));
        }
        if ask.responsible == person {
            waiting += usize::from(ask.delivered_at.is_none());
            asked.insert((ask.skill, ask.campaign, ask.evidence));
        }
    }
    Ok(JudgeAskRoom {
        room: slots.saturating_sub(waiting),
        asked,
    })
}

/// `skill` and every revision it superseded, through admitted succession
/// (`Supersedes`, new to old): the revisions whose human picks are this
/// revision's anchor. A fork is another skill and carries none.
fn label_lineage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let mut lineage = BTreeSet::from([skill]);
    let mut next = vec![skill];
    while let Some(revision) = next.pop() {
        for older in vault.filtered_edge_peers(
            txn,
            crate::ports::EdgeDirection::Out,
            &revision,
            EdgeKind::Supersedes,
            Some(crate::registry::ENTITY_TYPE_SKILL),
        )? {
            if lineage.insert(older) {
                next.push(older);
            }
        }
    }
    Ok(lineage)
}

/// List labels for one skill and campaign, the picks its superseded
/// revisions took included. The persisted anchor is only these rows, never
/// the proposed asks, and never a pick a rubric edit left waiting on its
/// person's re-grade. Order is stable by ask identity.
pub fn judge_label_anchor(
    vault: &Vault,
    skill: EntityId,
    campaign: &str,
) -> Result<Vec<JudgeLabel>> {
    let txn = vault.store.env.read_txn()?;
    let lineage = label_lineage_in_txn(vault, &txn, skill)?;
    let mut labels = Vec::new();
    for row in LABELS.iter_from(&vault.store, &txn, &[])? {
        let (key, label) = row?;
        if key != label.ask.id {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        if label.in_anchor() && lineage.contains(&label.ask.skill) && label.ask.campaign == campaign
        {
            labels.push(label);
        }
    }
    Ok(labels)
}

/// Every label in one skill's anchor, whatever campaign asked it and
/// whichever of its superseded revisions it was asked on: the human picks
/// the skill-edit gate measures the judge against. Order is stable by ask
/// identity.
pub(crate) fn skill_label_anchor(vault: &Vault, skill: EntityId) -> Result<Vec<JudgeLabel>> {
    let txn = vault.store.env.read_txn()?;
    let lineage = label_lineage_in_txn(vault, &txn, skill)?;
    let mut labels = Vec::new();
    for row in LABELS.iter_from(&vault.store, &txn, &[])? {
        let (key, label) = row?;
        if key != label.ask.id {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        if label.in_anchor() && lineage.contains(&label.ask.skill) {
            labels.push(label);
        }
    }
    Ok(labels)
}

/// How many labels the whole anchor gained after `since`, by pick time: the
/// fresh human picks a judge rubric revision counts. A pick pending a
/// re-check counts by its original pick time; one waiting on a re-grade does
/// not count.
pub(crate) fn anchor_labels_since_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    since: u64,
) -> Result<u64> {
    let mut fresh = 0_u64;
    for row in LABELS.iter_from(&vault.store, txn, &[])? {
        let (key, label) = row?;
        if key != label.ask.id {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        fresh += u64::from(label.in_anchor() && label.picked_at > since);
    }
    Ok(fresh)
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
    vault.with_write_txn_grouped(|txn| {
        let actor =
            crate::dreamer_runner::maintenance::validate_person_in_txn(vault, &*txn, owner)?;
        pick_in_txn(vault, txn, owner, actor, ask_id, choose_b, at)
    })
}

/// [`record_judge_pick`] for an `actor` the caller already validated.
fn pick_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    actor: EntityId,
    ask_id: [u8; 32],
    choose_b: bool,
    at: u64,
) -> Result<JudgeLabel> {
    let ask = ASKS
        .get(&vault.store, &*txn, &ask_id)?
        .ok_or(Error::EntityNotFound)?;
    // A re-grade ask's answer is the re-grade door's, never a label.
    if ask.id != ask_id
        || ask.responsible != actor
        || ask.delivered_at.is_none()
        || ask.reason == JudgeAskReason::RubricRecheck
    {
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
    // A pick made after a rubric edit stands under the new rubric: re-pin
    // first, so the edit's stamp reaches only the picks made before it.
    repin_before_pick_in_txn(vault, txn, at)?;
    let label = JudgeLabel {
        ask,
        chosen,
        picked_at: at,
        principal_ref: owner.person_principal_ref_in_txn(vault, &*txn)?.into(),
        recheck: None,
    };
    LABELS.put(&vault.store, txn, &ask_id, &label)?;
    Ok(label)
}

/// An owner's hand-test pick on a judge swap's disagreement, as a label in
/// the skill's anchor: the ask (the two judges' answers on one kept case) is
/// proposed for the picker, delivered by the swap's notice at
/// `delivered_at`, and answered, in one transaction. Like every label it is
/// final: the same pick again returns it, and another one fails.
#[expect(clippy::too_many_arguments, reason = "one ask, delivered and answered")]
pub(crate) fn record_judge_swap_label(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    skill: EntityId,
    campaign: &str,
    evidence: &str,
    [option_a, option_b]: [&str; 2],
    choose_b: bool,
    delivered_at: u64,
    at: u64,
) -> Result<JudgeLabel> {
    vault.with_write_txn_grouped(|txn| {
        let actor =
            crate::dreamer_runner::maintenance::validate_person_in_txn(vault, &*txn, owner)?;
        let mut ask = propose_in_txn(
            vault,
            txn,
            ask_identity(
                skill,
                actor,
                campaign,
                evidence,
                JudgeAskReason::RevisionDisagreement,
                [option_a, option_b],
                None,
            )?,
        )?;
        if ask.delivered_at.is_none() {
            ask.delivered_at = Some(delivered_at);
            ASKS.put(&vault.store, txn, &ask.id, &ask)?;
        }
        pick_in_txn(vault, txn, owner, actor, ask.id, choose_b, at)
    })
}

/// The judge's rubric: from the bootstrap `judge` skill, through admitted
/// succession (`Supersedes`, new to old) to its newest revision, when that
/// revision is live, shared, active and approved. The text is its stored
/// package's SKILL.md, or a native revision's own instructions. `None` when no
/// such revision or text exists.
pub(crate) fn judge_rubric_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<JudgeRubric>> {
    let mut head = EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[JUDGE_SKILL_ID.as_bytes()],
    )?;
    let mut seen = BTreeSet::from([head]);
    loop {
        let newer = vault.filtered_edge_peers(
            txn,
            crate::ports::EdgeDirection::In,
            &head,
            EdgeKind::Supersedes,
            Some(crate::registry::ENTITY_TYPE_SKILL),
        )?;
        // Admitted succession is linear; the least id settles a fork in it.
        let Some(next) = newer.into_iter().filter(|id| !seen.contains(id)).min() else {
            break;
        };
        seen.insert(next);
        head = next;
    }
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &head)?.is_live() {
        return Ok(None);
    }
    let record = match vault.read_skill_record_in_txn(txn, &head) {
        Ok(record) => record,
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if record.skill_id != JUDGE_SKILL_ID
        || crate::skill::resident_of(&record)?.is_some()
        || !crate::skill::skill_loadable(&record)
    {
        return Ok(None);
    }
    let text = match vault.runtime_skill_package_in_txn(txn, &head, &record)? {
        Some(package) => package
            .files
            .into_iter()
            .find(|file| file.path == SKILL_FILE)
            .and_then(|file| String::from_utf8(file.content).ok()),
        None if record.source != crate::claim::ClaimSource::Imported
            && record.forked_from.is_none() =>
        {
            Some(record.desc.clone())
        }
        None => None,
    };
    Ok(text.map(|text| JudgeRubric {
        skill: head,
        version: record.version,
        digest: *blake3::hash(text.as_bytes()).as_bytes(),
        text,
    }))
}

/// [`judge_rubric_in_txn`] in a read transaction of its own: the rubric the
/// replay judge reads beside every case.
pub fn judge_rubric(vault: &Vault) -> Result<Option<JudgeRubric>> {
    let txn = vault.store.env.read_txn()?;
    judge_rubric_in_txn(vault, &txn)
}

/// Re-pin the judge on `rubric`. The first pin is only recorded. A moved
/// digest stamps every label in the anchor as pending under the new rubric,
/// a pending one included; a label waiting on its person's re-grade keeps
/// waiting. Returns how many labels it stamped.
fn repin_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    rubric: &JudgeRubric,
    at: u64,
) -> Result<usize> {
    let pinned = RUBRIC_PIN.get(&vault.store, &*txn, &())?;
    if pinned
        .as_ref()
        .is_some_and(|pin| pin.digest == rubric.digest)
    {
        return Ok(0);
    }
    RUBRIC_PIN.put(
        &vault.store,
        txn,
        &(),
        &JudgeRubricPin {
            digest: rubric.digest,
            skill: rubric.skill,
            version: rubric.version.clone(),
            pinned_at: at,
        },
    )?;
    if pinned.is_none() {
        return Ok(0);
    }
    let mut stamped = Vec::new();
    for row in LABELS.iter_from(&vault.store, &*txn, &[])? {
        let (key, mut label) = row?;
        if key != label.ask.id {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        if label.in_anchor() {
            label.recheck = Some(JudgeLabelRecheck::Pending {
                rubric: rubric.digest,
            });
            stamped.push(label);
        }
    }
    for label in &stamped {
        LABELS.put(&vault.store, txn, &label.ask.id, label)?;
    }
    Ok(stamped.len())
}

/// [`repin_in_txn`] on the rubric as it reads now, before a pick. An
/// unreadable rubric leaves the pin as it was: the pick still stands, and the
/// Coach's next pass re-pins.
fn repin_before_pick_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, at: u64) -> Result<()> {
    match judge_rubric_in_txn(vault, &*txn) {
        Ok(Some(rubric)) => {
            repin_in_txn(vault, txn, &rubric, at)?;
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, "the judge rubric is unreadable; a pick left the pin as it was");
        }
    }
    Ok(())
}

/// What the host's checker made of one pending pick against the new rubric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JudgeLabelFit {
    /// The pick still fits the rubric.
    Fits,
    /// The pick conflicts with the rubric.
    Conflicts,
    /// A model was asked and gave no answer to stand on.
    Unknown,
    /// No model was asked: the pick stays pending for a later pass.
    Unavailable,
}

/// One pending pick as the host's checker reads it: the label (its question,
/// its two options and the person's pick) and the rubric to check it against.
#[derive(Debug, Clone, Copy)]
pub struct JudgeLabelRecheckRequest<'a> {
    pub label: &'a JudgeLabel,
    pub rubric: &'a JudgeRubric,
}

/// The host's side of a re-check: one model call per pending pick, made
/// outside any vault transaction.
pub trait JudgeLabelChecker {
    fn check(&self, request: &JudgeLabelRecheckRequest<'_>) -> Result<JudgeLabelFit>;
}

/// What one re-check pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JudgeLabelRecheckReport {
    /// Labels the pass's re-pin stamped pending.
    pub stamped: u32,
    /// Pending picks found still fitting: their stamp cleared.
    pub fits: u32,
    /// Picks found conflicting, or not judged: out of the anchor, waiting on
    /// their person's re-grade.
    pub waiting: u32,
    /// Picks left pending: past the pass's limit, unasked, or moved meanwhile.
    pub pending: u32,
}

/// The Coach's re-check pass: re-pin the judge on its rubric's current text,
/// then put at most `limit` pending picks to `checker`, each settled in its own
/// transaction.
pub(crate) fn recheck_judge_labels(
    vault: &Vault,
    checker: &dyn JudgeLabelChecker,
    limit: usize,
    at: u64,
) -> Result<JudgeLabelRecheckReport> {
    let Some((rubric, stamped)) = vault.with_write_txn_grouped(|txn| {
        let Some(rubric) = judge_rubric_in_txn(vault, &*txn)? else {
            return Ok(None);
        };
        let stamped = repin_in_txn(vault, txn, &rubric, at)?;
        Ok(Some((rubric, stamped)))
    })?
    else {
        return Ok(JudgeLabelRecheckReport::default());
    };
    let mut report = JudgeLabelRecheckReport {
        stamped: u32::try_from(stamped).unwrap_or(u32::MAX),
        ..JudgeLabelRecheckReport::default()
    };
    let due = {
        let txn = vault.store.env.read_txn()?;
        let mut due = Vec::new();
        for row in LABELS.iter_from(&vault.store, &txn, &[])? {
            let (key, label) = row?;
            if key != label.ask.id {
                return Err(Error::CorruptedIndex("judge label identity"));
            }
            if label.recheck_due(rubric.digest) {
                due.push(label);
            }
        }
        due
    };
    let mut asked = 0_usize;
    for label in due {
        if asked >= limit {
            report.pending += 1;
            continue;
        }
        let fit = checker.check(&JudgeLabelRecheckRequest {
            label: &label,
            rubric: &rubric,
        })?;
        if fit == JudgeLabelFit::Unavailable {
            report.pending += 1;
            continue;
        }
        asked += 1;
        match vault
            .with_write_txn_grouped(|txn| settle_recheck_in_txn(vault, txn, &label, &rubric, fit))?
        {
            Some(true) => report.fits += 1,
            Some(false) => report.waiting += 1,
            None => report.pending += 1,
        }
    }
    Ok(report)
}

/// One checker answer on `label` against `rubric`, while neither moved since
/// the pass read them. A fit clears the stamp and keeps the pick time. A
/// conflict or an unknown answer takes the pick out of the anchor and asks its
/// person to re-grade it. `Some(fits)`, or `None` when either moved.
fn settle_recheck_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    label: &JudgeLabel,
    rubric: &JudgeRubric,
    fit: JudgeLabelFit,
) -> Result<Option<bool>> {
    let pinned = RUBRIC_PIN.get(&vault.store, &*txn, &())?;
    let current = LABELS.get(&vault.store, &*txn, &label.ask.id)?;
    if current.as_ref() != Some(label) || pinned.is_none_or(|pin| pin.digest != rubric.digest) {
        return Ok(None);
    }
    let fits = fit == JudgeLabelFit::Fits;
    let mut settled = label.clone();
    settled.recheck = if fits {
        None
    } else {
        Some(JudgeLabelRecheck::Waiting {
            rubric: rubric.digest,
            ask: regrade_ask_in_txn(vault, txn, label, rubric.digest)?,
        })
    };
    LABELS.put(&vault.store, txn, &label.ask.id, &settled)?;
    Ok(Some(fits))
}

/// Put `label`'s re-grade ask to its person: does the pick still fit the
/// rubric `rubric`? `None` when it cannot be put (the person is no longer
/// active, the skill is gone, or the words pass the context bound); the pick
/// then waits with no ask.
fn regrade_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    label: &JudgeLabel,
    rubric: [u8; 32],
) -> Result<Option<[u8; 32]>> {
    let keep = format!("{REGRADE_KEEP}{}", label.chosen);
    let question = ask_identity(
        label.ask.skill,
        label.ask.responsible,
        &label.ask.campaign,
        &label.ask.evidence,
        JudgeAskReason::RubricRecheck,
        [keep.as_str(), REGRADE_ASK_AGAIN],
        Some(JudgeRegrade {
            label: label.ask.id,
            rubric,
        }),
    )?;
    match propose_in_txn(vault, txn, question) {
        Ok(ask) => Ok(Some(ask.id)),
        Err(Error::InvalidConfig(_) | Error::EntityNotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// What a re-grade did: the label as it now stands and, when its person said
/// the pick no longer fits, the fresh ask of its case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgeLabelRegrade {
    pub label: JudgeLabel,
    pub fresh: Option<JudgeAsk>,
}

/// The responsible person's answer to a delivered re-grade ask. `still_fits`
/// puts the pick back in the anchor, its pick time unchanged. Otherwise the
/// pick leaves the anchor for good and its case is asked again: a fresh A/B
/// ask under the pinned rubric, which the digest delivers like any other. The
/// same answer again returns the same outcome; the other one fails.
pub fn record_judge_label_regrade(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    ask_id: [u8; 32],
    still_fits: bool,
) -> Result<JudgeLabelRegrade> {
    vault.with_write_txn_grouped(|txn| {
        let actor =
            crate::dreamer_runner::maintenance::validate_person_in_txn(vault, &*txn, owner)?;
        let ask = ASKS
            .get(&vault.store, &*txn, &ask_id)?
            .ok_or(Error::EntityNotFound)?;
        let Some(of) = ask.regrade.filter(|_| {
            ask.id == ask_id
                && ask.responsible == actor
                && ask.delivered_at.is_some()
                && ask.reason == JudgeAskReason::RubricRecheck
        }) else {
            return Err(invalid());
        };
        let mut label = LABELS
            .get(&vault.store, &*txn, &of.label)?
            .ok_or(Error::EntityNotFound)?;
        if label.ask.id != of.label {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        let state = label.recheck;
        match state {
            Some(JudgeLabelRecheck::Waiting {
                rubric,
                ask: Some(waiting),
            }) if waiting == ask_id && rubric == of.rubric => {}
            Some(JudgeLabelRecheck::Kept { ask: kept, .. }) if kept == ask_id && still_fits => {
                return Ok(JudgeLabelRegrade { label, fresh: None });
            }
            Some(JudgeLabelRecheck::Replaced {
                ask: replaced,
                fresh,
                ..
            }) if replaced == ask_id && !still_fits => {
                let fresh = ASKS.get(&vault.store, &*txn, &fresh)?;
                return Ok(JudgeLabelRegrade { label, fresh });
            }
            _ => return Err(invalid()),
        }
        let fresh = if still_fits {
            label.recheck = Some(JudgeLabelRecheck::Kept {
                rubric: of.rubric,
                ask: ask_id,
            });
            None
        } else {
            let pinned = RUBRIC_PIN
                .get(&vault.store, &*txn, &())?
                .map_or(of.rubric, |pin| pin.digest);
            let fresh = propose_in_txn(
                vault,
                txn,
                ask_identity(
                    label.ask.skill,
                    label.ask.responsible,
                    &label.ask.campaign,
                    &label.ask.evidence,
                    JudgeAskReason::RubricRegrade,
                    [label.ask.option_a.as_str(), label.ask.option_b.as_str()],
                    Some(JudgeRegrade {
                        label: of.label,
                        rubric: pinned,
                    }),
                )?,
            )?;
            label.recheck = Some(JudgeLabelRecheck::Replaced {
                rubric: of.rubric,
                ask: ask_id,
                fresh: fresh.id,
            });
            Some(fresh)
        };
        LABELS.put(&vault.store, txn, &of.label, &label)?;
        Ok(JudgeLabelRegrade { label, fresh })
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

/// The digest's second draw on the same balance, after
/// [`take_digest_asks_in_txn`]: the owner's pending eval label asks, each
/// debited the minutes it was asked at, while what remains covers them. A zero
/// balance carries none; marks and debit share the digest's transaction.
pub(crate) fn take_digest_eval_asks_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    at: u64,
) -> Result<Vec<super::EvalLabelAsk>> {
    let minutes = MINUTES
        .get(&vault.store, &*txn, &owner)?
        .map_or(0, |balance| balance.0);
    if minutes == 0 {
        return Ok(Vec::new());
    }
    let (selected, spent) = vault.take_eval_label_asks_in_txn(txn, owner, at, minutes)?;
    if !selected.is_empty() {
        let remaining = minutes
            .checked_sub(spent)
            .ok_or(Error::ArithmeticOverflow("judge ask minutes"))?;
        MINUTES.put(&vault.store, txn, &owner, &JudgeMinutes(remaining))?;
    }
    Ok(selected)
}
