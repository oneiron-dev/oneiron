//! One durable proactivity digest per vault cadence, with intent-bound urgent wakes.
//! A regular digest also carries the cleanup cron's after-notice (OF-449),
//! the NOTE tombstone review's open proposals (OF-073) and the Dreamer's
//! applied-maintenance after-notice (FIX 3226) and the drafter line (FIX
//! 14977).
//! Each digest is stored once, under a stable locator with a content hash
//! (FIX 2332), and every read, answer and delivery of it is its viewer's
//! own view, screened of private thread words they do not read (FIX 6411).
use super::{invalid, setting_keys};
use crate::limit_ask::EngineLimit;
use crate::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope, SettingSource,
    SettingValue,
};
use crate::side_table::{self, LegacyJson, SideTable};
#[cfg(test)]
use crate::{ClaimApprovalStatus, ClaimSource};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
mod after_notice;
mod assembly;
mod pending;
mod policy;
pub(super) mod policy_author;
mod private_sources;
mod urgent;
mod view;
pub use after_notice::{APPLIED_GROUP, APPLIED_VIEW, DigestApplied, DigestAppliedItem};
use pending::{pending_proposals, unseen_cleanup, unseen_note_tombstones, unseen_offers};
pub use policy::{ProactivityPolicyBasis, ProactivityPolicyFiling};
pub(super) use policy::{ProactivityPolicyInverse, revert_policy_in_txn};
pub use private_sources::DigestPrivateSource;
use urgent::DigestAudience;
pub(crate) use urgent::{
    ASSESSMENT_KEY, CANDIDATE_KEY, emit_urgent_proactivity_digest, json_field, unlent_assessment,
};
pub use urgent::{
    DIGEST_ASSESS_FACET, DIGEST_ASSESS_UNLENT_PARK_REASON, DIGEST_URGENT_FACET, DigestHarmAsk,
    DigestHarmCandidate, DigestHarmJudgeInput, DigestHarmResult, DigestNeededBefore,
    DigestVersionRef, UrgentDigestAssessment,
};
pub use view::{DigestReadRequest, ProactivityDigestView};
const STATE: SideTable<(), DigestState, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_STATE);
const DIGEST: SideTable<[u8; 32], ProactivityDigest, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_DIGEST);

/// Whether a masked copy of a `DREAMER_PROACTIVITY_DIGEST` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn dreamer_proactivity_digest_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<ProactivityDigest, LegacyJson>(bytes)
}

/// Per-recipient time of the last digest that delivered judge or eval label asks.
const JUDGE_ASK_MARK: SideTable<EntityId, u64, side_table::Raw> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_JUDGE_ASKS);
/// Generic proposed claim written through the existing gated agent memory
/// verb. It changes NO settings until the owner confirms its exact revision;
/// a Dreamer-born one too ([`Vault::file_dreamer_proactivity_policy`]). Only
/// the field a Coach's live digest-settings Grant covers applies at once
/// ([`Vault::file_coach_proactivity_policy`], FIX 8712), and the owner
/// reverts it.
pub const PROACTIVITY_POLICY_REQUEST_PREDICATE: &str = "dreamer.proactivity.policy_request";
/// Producer name of a delivered digest's inbox NOTIFICATION.
pub const DIGEST_NOTIFICATION_PRODUCER: &str = "dreamer.digest";
/// The derived group pending training offers (OF-577) render under.
pub const TRAINING_OFFER_GROUP: &str = "coach.training_offer";
#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_runner::maintenance::digest::{
    CLEANUP_GROUP, DigestOffer, DigestProposal, NOTE_TOMBSTONE_GROUP, ProactivityCadence,
};

/// The cleanup line's view: the owner cleanup surface, where every archive
/// restores.
pub const CLEANUP_VIEW: &str = "/v1/owner/cleanup";
/// The NOTE tombstone line's view: the owner's tombstone review, where each
/// proposal is accepted or declined.
pub const NOTE_TOMBSTONE_VIEW: &str = "/v1/owner/notes/tombstones";
/// The derived group the recipient's judge asks (OF-420) render under.
pub const JUDGE_ASK_GROUP: &str = "coach.judge_ask";
/// The derived group the recipient's eval label asks render under.
pub const EVAL_LABEL_ASK_GROUP: &str = "coach.eval_label_ask";
/// Agent-authored, owner-confirmed presentation row. Templates and voice are
/// data, not engine-owned prompt or persona text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProactivityPresentation {
    /// Maps the derived facet group to a display group.
    pub group_aliases: BTreeMap<String, String>,
    /// Uses `{group}` for the display group.
    pub group_template: String,
    /// Uses `{summary}` and `{ref}` for each item.
    pub item_template: String,
    /// A host-facing style hint; the host owns voice rendering.
    pub voice_style: String,
    /// Derived groups eligible for a pre-cadence urgent delivery.
    pub urgent_groups: Vec<String>,
}
impl ProactivityPresentation {
    fn validate(&self) -> Result<()> {
        let blank = |text: &String| text.trim().is_empty();
        if !self.group_template.contains("{group}")
            || !self.item_template.contains("{summary}")
            || !self.item_template.contains("{ref}")
            || self
                .group_aliases
                .iter()
                .any(|(key, value)| blank(key) || blank(value))
            || self.urgent_groups.iter().any(blank)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Measures the row against its `[limits]` rows (OF-520): its aliases and
    /// urgent groups, and its longest template, style or group name. Past one
    /// the vault's port asks, and the row is kept whole.
    fn measure(&self, vault: &Vault) {
        for items in [self.group_aliases.len(), self.urgent_groups.len()] {
            let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
        }
        let mut longest = self.group_template.len().max(self.item_template.len());
        longest = longest.max(self.voice_style.len());
        for (key, value) in &self.group_aliases {
            longest = longest.max(key.len()).max(value.len());
        }
        for group in &self.urgent_groups {
            longest = longest.max(group.len());
        }
        let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
    }
}
impl SettingValue for ProactivityPresentation {
    fn check(self) -> Result<Self> {
        self.validate()?;
        Ok(self)
    }
}

/// Seconds between two regular digests, at least one: the value of the setting
/// `dreamer.proactivity.period`, the field of [`ProactivityCadence`] a holder of the maintenance
/// cadence class moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct ProactivityPeriod(pub u64);

impl SettingValue for ProactivityPeriod {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            return Err(invalid());
        }
        Ok(self)
    }
}

/// How the regular digest is delivered: the value of the setting `dreamer.proactivity.delivery`,
/// the owner's fields of [`ProactivityCadence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProactivityDelivery {
    /// The digest groups its items by facet.
    pub group_by_facet: bool,
    /// An urgent item may go out before the period ends.
    pub urgent_breakthrough: bool,
}

impl SettingValue for ProactivityDelivery {}

/// The shipped cadence (`digest_defaults.json`): the defaults of the period and delivery settings.
fn shipped_cadence() -> ProactivityCadence {
    serde_json::from_str(include_str!("digest_defaults.json"))
        .expect("the shipped digest_defaults.json decodes")
}

/// The default of `dreamer.proactivity.period`.
pub(super) fn shipped_period() -> ProactivityPeriod {
    ProactivityPeriod(shipped_cadence().period_secs)
}

/// The default of `dreamer.proactivity.delivery`.
pub(super) fn shipped_delivery() -> ProactivityDelivery {
    let cadence = shipped_cadence();
    ProactivityDelivery {
        group_by_facet: cadence.group_by_facet,
        urgent_breakthrough: cadence.urgent_breakthrough,
    }
}

/// The shipped presentation (`digest_presentation_defaults.json`): the default of
/// `dreamer.proactivity.presentation`.
pub(super) fn shipped_presentation() -> ProactivityPresentation {
    serde_json::from_str(include_str!("digest_presentation_defaults.json"))
        .expect("the shipped digest_presentation_defaults.json decodes")
}

/// The `after_commit` of the digest's settings: the host re-reads the cadence and presentation in
/// force and re-arms its deadline, as each old setter signalled after its commit.
pub(super) fn notify_proactivity_settings(vault: &Vault) {
    vault.store.notify_proactivity_changes();
}

/// The `after_commit` of `dreamer.proactivity.presentation`: measures the presentation now in
/// force against its `[limits]` rows, as its old setter did, then signals the host.
pub(super) fn measure_presentation_and_notify(vault: &Vault) {
    if let Ok(txn) = vault.store.env.read_txn() {
        if let Ok(presentation) = load_presentation(vault, &txn) {
            presentation.measure(vault);
        }
    }
    notify_proactivity_settings(vault);
}

/// Typed request payload for the existing `vault.claims.put` agent verb.
/// The host may build it from a chat request; no natural-language parser or
/// product persona is embedded in the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProactivityPolicyRequest {
    pub cadence: ProactivityCadence,
    pub presentation: ProactivityPresentation,
}
impl ProactivityPolicyRequest {
    pub fn claim_value(&self) -> Result<String> {
        if self.cadence.period_secs == 0 {
            return Err(invalid());
        }
        self.presentation.validate()?;
        serde_json::to_string(self).map_err(|_| invalid())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProactivityPolicyProposal {
    pub request: ProactivityPolicyRequest,
    pub revision: [u8; 32],
}
/// The cleanup cron's after-notice (ARCH-0073 §5): what it archived since
/// the last digest that carried it, and the proposals that wait for the
/// owner. Counts come from recorded decisions, never from the archive's size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestCleanup {
    /// The cleanup decisions this line reports, by id.
    pub decisions: Vec<String>,
    pub archived: u64,
    /// Candidates the accept or the run re-checked and left alone.
    pub skipped: u64,
    /// The open proposals this line reports, by id.
    pub proposals: Vec<String>,
    /// Records those proposals would archive.
    pub proposed: u64,
    pub view: String,
}
impl DigestCleanup {
    /// The rendered items: "archived N", then what waits for review.
    fn summaries(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.decisions.is_empty() {
            out.push(format!("{CLEANUP_GROUP}: archived {}", self.archived));
        }
        if !self.proposals.is_empty() {
            out.push(format!(
                "{CLEANUP_GROUP}: {} to archive wait for review",
                self.proposed
            ));
        }
        out
    }
}
/// The NOTE tombstone review's open proposals no digest carried yet. The
/// line only points at them; the owner accepts or declines each at the view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestNoteTombstones {
    /// The proposals this line reports, as `<note>:<proposed_at>`: a NOTE
    /// archived again is a new proposal.
    pub proposals: Vec<String>,
    pub view: String,
}
impl DigestNoteTombstones {
    fn summary(&self) -> String {
        format!(
            "{NOTE_TOMBSTONE_GROUP}: {} archived NOTEs wait for a tombstone review",
            self.proposals.len()
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactivityDigest {
    /// The stable locator the digest is stored under, and that its
    /// notifications and the board pointer name (FIX 2332): the hash of the
    /// digest as assembled, chosen once. It is not a hash of what the digest
    /// shows; [`Self::content_hash`] checks that.
    pub id: [u8; 32],
    /// BLAKE3 of the digest as stored, after the side-row wall masked it:
    /// its locator and every other field but this one (FIX 2332). Every read
    /// checks it.
    pub content_hash: [u8; 32],
    pub created_at: u64,
    /// The authenticated reader the asks are addressed to; `None` for the
    /// ownerless timer projection, which carries no asks.
    #[serde(with = "crate::serialize::entity_ref::optional")]
    pub recipient: Option<EntityId>,
    pub urgent: bool,
    pub groups: BTreeMap<String, Vec<DigestProposal>>,
    pub judge_asks: Vec<crate::skill_optimize::JudgeAsk>,
    /// The recipient's eval label asks, paid from what the judge asks left.
    pub eval_label_asks: Vec<crate::skill_optimize::EvalLabelAsk>,
    /// Pending training offers not carried by an earlier digest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offers: Vec<DigestOffer>,
    /// The cleanup line, on a regular digest with cleanup news.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<DigestCleanup>,
    /// The NOTE tombstone line, on a regular digest with open proposals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note_tombstones: Option<DigestNoteTombstones>,
    /// The applied-maintenance after-notice, on a regular digest with
    /// applied writes no digest carried yet (FIX 3226).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<DigestApplied>,
    /// The drafter line, on a regular digest with drafter events no digest
    /// carried yet (FIX 14977).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drafter: Option<crate::drafter::DigestDrafter>,
    /// The Coach's agent-health cards opened, updated or settled since the
    /// last regular digest (OF-568), concern first and newest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health_cards: Vec<super::agent_health::ConcernCardSummary>,
    pub rendered: String,
    pub voice_style: String,
    /// The presentation the digest was rendered under, which a viewer's
    /// view rebuilds its text with (FIX 6411).
    pub presentation: ProactivityPresentation,
    /// The witness an urgent digest was delivered under (FIX 8955): the
    /// `dreamer.digest.urgent` job whose input keeps the ladder's or the
    /// host-built answer with its full receipt (FIX 10942). `None` for every
    /// other digest.
    pub witness: Option<crate::attempt_queue::AttemptId>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestState {
    last_regular: Option<u64>,
    last_digest_id: Option<[u8; 32]>,
    seen: BTreeMap<String, [u8; 32]>,
    /// Training offers a digest already carried. An offer is immutable, so
    /// its id is enough.
    #[serde(default)]
    offers_seen: std::collections::BTreeSet<String>,
    /// Cleanup decisions and proposals a digest already carried.
    #[serde(default)]
    cleanup_seen: std::collections::BTreeSet<String>,
    /// NOTE tombstone proposals a digest already carried.
    #[serde(default)]
    note_tombstones_seen: std::collections::BTreeSet<String>,
    /// Applied maintenance receipts a digest already carried.
    #[serde(default)]
    applied_seen: std::collections::BTreeSet<String>,
    /// The newest drafter event a digest already carried (FIX 14977).
    #[serde(default, with = "crate::serialize::entity_ref::optional")]
    drafter_seen: Option<EntityId>,
    /// Results an urgent digest carried, by the one owner it went to (FIX
    /// 8952): they leave that owner's own digests, and every other reader's
    /// digest still carries them.
    urgent_seen: BTreeMap<String, BTreeMap<String, [u8; 32]>>,
    /// The harm questions the ladder answered, by basis (FIX 8950), each a
    /// current candidate's when the last answer landed: a host that restarts
    /// asks none of them again.
    answered_assessments: std::collections::BTreeSet<String>,
}
impl DigestState {
    /// Whether an urgent digest carried the claim `claim_hex` at `revision`
    /// to `recipient`.
    fn urgent_seen_by(&self, recipient: EntityId, claim_hex: &str, revision: &[u8; 32]) -> bool {
        self.urgent_seen
            .get(&recipient.to_hex())
            .and_then(|seen| seen.get(claim_hex))
            == Some(revision)
    }
}
impl Vault {
    /// Subscribe before the first deadline read. Every notification means
    /// "re-read committed state", never "deliver a wake".
    pub fn subscribe_proactivity_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.store.proactivity_updates.subscribe()
    }

    /// Next armed cadence, only while there is unseen pending work. The host
    /// arms its existing deadline timer from this row; no engine poll exists.
    pub fn next_proactivity_digest_at(&self) -> Result<Option<u64>> {
        let authority = self.dreamer_authority()?.entity_ref();
        let offers = crate::skill_optimize::pending_training_offers(self)?;
        let txn = self.store.env.read_txn()?;
        let cadence = load_cadence(self, &txn)?;
        let state = load_state(self, &txn)?;
        // Validate the same presentation bytes assembly will consume. An
        // unreadable template must not arm an instantly repeating deadline.
        load_presentation(self, &txn)?;
        if self.store.proactivity_digest_suspended() {
            return Ok(None);
        }
        let cadence_at = state
            .last_regular
            .map_or(0, |last| last.saturating_add(cadence.period_secs));
        if pending_proposals(self, &txn, authority, &state, &cadence, None)?.is_empty()
            && unseen_offers(&offers, &state).is_empty()
            && unseen_cleanup(self, &txn, &state)?.is_none()
            && unseen_note_tombstones(self, &txn, &state)?.is_none()
            && after_notice::unseen_in_txn(self, &txn, &state.applied_seen)?.is_none()
            && !crate::drafter::unseen_drafter_line_in_txn(&self.store, &txn, state.drafter_seen)?
                .is_some_and(|line| line.arms())
        {
            // Health cards alone arm it too (FIX 1979). A card touched since
            // the last regular digest joins the first digest whose period
            // `[from, at)` holds it, so one touched at the deadline or later
            // arms a second past its time, never an empty deadline that
            // repeats.
            let from = state.last_regular.unwrap_or(0);
            return Ok(super::agent_health::agent_health_cards_in_txn(self, &txn)?
                .iter()
                .filter_map(|card| super::agent_health::card_touched_in(card, from, u64::MAX))
                .min()
                .map(|at| cadence_at.max(at.saturating_add(1))));
        }
        Ok(Some(cadence_at))
    }

    /// The deadline source calls this on a timer wake. No owner credential is
    /// minted by the background job: this is a projection, not a policy edit.
    /// Judge and eval label asks stay pending here; they reach only their
    /// responsible human's authenticated digest read.
    pub fn emit_due_proactivity_digest(
        &self,
        now: u64,
        local_node_id: u64,
    ) -> Result<Option<ProactivityDigest>> {
        let store = crate::dreamer_runner::DreamerRunnerStore::new(self);
        if store
            .home_node_designation()?
            .is_none_or(|home| home.node_id != local_node_id)
            || store
                .local_home_node_candidate(false, false, false)?
                .node_id
                != local_node_id
        {
            return Ok(None);
        }
        let generation = self.store.proactivity_generation();
        let result = self.assemble_proactivity_digest(DigestAudience::Timer, now);
        if result.is_err() {
            self.store
                .suspend_proactivity_digest_if_unchanged(generation);
        }
        result
    }

    /// Builds a display projection only. Pending decisions remain pending.
    /// The urgent assessment comes from the host: a yes on the owner's own
    /// live, approved stated intent breaks the cadence (OF-194).
    /// The answer is the recipient's own view of the digest (FIX 6411).
    pub fn proactivity_digest(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        now: u64,
        urgent: Option<&UrgentDigestAssessment>,
    ) -> Result<Option<ProactivityDigestView>> {
        let audience = DigestAudience::Owner(owner, urgent);
        let Some(digest) = self.assemble_proactivity_digest(audience, now)? else {
            return Ok(None);
        };
        let viewer = digest.recipient.ok_or_else(invalid)?;
        let txn = self.store.env.read_txn()?;
        Ok(Some(view::digest_view_for_in(self, &txn, &digest, viewer)))
    }

    /// Test-only fault seam: a corrupt digest row must not block independent
    /// due attempts in the host supervisor.
    #[cfg(feature = "test-support")]
    pub fn corrupt_proactivity_state_for_test(&self) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            STATE.put_undecodable(&self.store, txn, &(), b"invalid digest state")?;
            Ok(())
        })
    }

    /// The latest digest as stored, verified and unscreened: the canonical
    /// object, for a test. A person reads
    /// [`Vault::latest_proactivity_digest_view`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn latest_proactivity_digest(&self) -> Result<Option<ProactivityDigest>> {
        let txn = self.store.env.read_txn()?;
        let Some(id) = load_state(self, &txn)?.last_digest_id else {
            return Ok(None);
        };
        view::read_digest_in(self, &txn, id)
    }

    /// One digest as stored, verified by its locator and its content hash
    /// (FIX 2332) and unscreened: the canonical object, for a test. A person
    /// reads [`Vault::proactivity_digest_view`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn read_proactivity_digest(&self, id: [u8; 32]) -> Result<Option<ProactivityDigest>> {
        let txn = self.store.env.read_txn()?;
        view::read_digest_in(self, &txn, id)
    }
}

// FIX [LIBTEST-QUARANTINE-DREAMER-RUNNER-MAINTENANCE-DIGEST-TESTS]: the lib test target's type check fails here (1 errors: E0308 x1); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests;

/// The cadence in force: the period and delivery settings, each its default where unset.
fn load_cadence(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProactivityCadence> {
    let row = compose_cadence(
        setting_keys::PROACTIVITY_PERIOD
            .read_in_txn(vault, txn, &[], None)?
            .value,
        setting_keys::PROACTIVITY_DELIVERY
            .read_in_txn(vault, txn, &[], None)?
            .value,
    );
    if row.period_secs == 0 {
        return Err(invalid());
    }
    Ok(row)
}

fn compose_cadence(period: ProactivityPeriod, delivery: ProactivityDelivery) -> ProactivityCadence {
    ProactivityCadence {
        period_secs: period.0,
        group_by_facet: delivery.group_by_facet,
        urgent_breakthrough: delivery.urgent_breakthrough,
    }
}

/// The cadence as set: `None` while neither the period nor the delivery has a row, so the
/// defaults decide. A policy request's basis and inverse name the rows so.
fn cadence_row_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<ProactivityCadence>> {
    let period = setting_keys::PROACTIVITY_PERIOD.read_in_txn(vault, txn, &[], None)?;
    let delivery = setting_keys::PROACTIVITY_DELIVERY.read_in_txn(vault, txn, &[], None)?;
    if period.source == SettingSource::Default && delivery.source == SettingSource::Default {
        return Ok(None);
    }
    Ok(Some(compose_cadence(period.value, delivery.value)))
}

/// The presentation as set: `None` while it has no row, so the default decides.
fn presentation_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<ProactivityPresentation>> {
    let read = setting_keys::PROACTIVITY_PRESENTATION.read_in_txn(vault, txn, &[], None)?;
    Ok((read.source != SettingSource::Default).then_some(read.value))
}

/// Changes one of the digest's settings in `txn` as `caller`: `Some` sets its value row, `None`
/// clears it. An owner's or the engine's change applies; the caller signals the host after its
/// commit.
fn set_digest_setting_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    caller: SettingCaller<'_>,
    key: &str,
    value: Option<serde_json::Value>,
    why: Option<&str>,
) -> Result<()> {
    let request = SetSetting {
        key: key.to_owned(),
        item: None,
        scope: SettingScope::Vault,
        mode: SettingMode::Value,
        value,
        expected_revision: None,
        why: why.map(str::to_owned),
        check_in_ref: None,
    };
    match vault.set_setting_in_txn(txn, caller, &request)? {
        SetSettingOutcome::Applied { .. } => Ok(()),
        SetSettingOutcome::Pending { .. } => Err(crate::Error::InvariantViolation(
            "an owner's or the engine's digest setting change waits on a check-in",
        )),
    }
}

fn setting_json(value: impl Serialize) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| invalid())
}

/// Sets the cadence in `txn` as `caller`, as its two settings: `None` clears both.
fn set_cadence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    caller: SettingCaller<'_>,
    cadence: Option<&ProactivityCadence>,
    why: Option<&str>,
) -> Result<()> {
    let (period, delivery) = match cadence {
        Some(cadence) => (
            Some(ProactivityPeriod(cadence.period_secs)),
            Some(setting_json(ProactivityDelivery {
                group_by_facet: cadence.group_by_facet,
                urgent_breakthrough: cadence.urgent_breakthrough,
            })?),
        ),
        None => (None, None),
    };
    set_period_in_txn(vault, txn, caller, period, why)?;
    set_digest_setting_in_txn(
        vault,
        txn,
        caller,
        setting_keys::PROACTIVITY_DELIVERY.spec.name,
        delivery,
        why,
    )
}

/// Sets the period alone in `txn` as `caller` (`None` clears it).
fn set_period_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    caller: SettingCaller<'_>,
    period: Option<ProactivityPeriod>,
    why: Option<&str>,
) -> Result<()> {
    let value = period.map(setting_json).transpose()?;
    set_digest_setting_in_txn(
        vault,
        txn,
        caller,
        setting_keys::PROACTIVITY_PERIOD.spec.name,
        value,
        why,
    )
}

/// Sets the presentation in `txn` as `caller`: `None` clears it.
fn set_presentation_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    caller: SettingCaller<'_>,
    presentation: Option<&ProactivityPresentation>,
    why: Option<&str>,
) -> Result<()> {
    let value = presentation.map(setting_json).transpose()?;
    set_digest_setting_in_txn(
        vault,
        txn,
        caller,
        setting_keys::PROACTIVITY_PRESENTATION.spec.name,
        value,
        why,
    )
}

fn load_state(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<DigestState> {
    Ok(STATE.get(&vault.store, txn, &())?.unwrap_or_default())
}
fn load_ask_mark(vault: &Vault, txn: &heed::RoTxn<'_>, actor: &EntityId) -> Result<Option<u64>> {
    JUDGE_ASK_MARK
        .get(&vault.store, txn, actor)
        .map_err(|error| match error {
            crate::Error::Store(crate::error::StoreError::SideTableRow { .. }) => invalid(),
            other => other,
        })
}
/// The presentation in force: the owner's setting, else the shipped one.
fn load_presentation(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProactivityPresentation> {
    let row = setting_keys::PROACTIVITY_PRESENTATION
        .read_in_txn(vault, txn, &[], None)?
        .value;
    row.validate()?;
    Ok(row)
}

impl crate::store::Store {
    /// Only post-commit callers signal; the watch value carries no user data.
    pub(crate) fn notify_proactivity_changes(&self) {
        let mut suspended = self
            .proactivity_suspended
            .lock()
            .expect("digest watch lock");
        *suspended = None;
        self.proactivity_updates.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }

    fn proactivity_generation(&self) -> u64 {
        *self.proactivity_updates.borrow()
    }

    fn proactivity_digest_suspended(&self) -> bool {
        let suspended = self
            .proactivity_suspended
            .lock()
            .expect("digest watch lock");
        *suspended == Some(self.proactivity_generation())
    }

    fn suspend_proactivity_digest_if_unchanged(&self, generation: u64) {
        let mut suspended = self
            .proactivity_suspended
            .lock()
            .expect("digest watch lock");
        if self.proactivity_generation() == generation {
            *suspended = Some(generation);
        }
    }
}
