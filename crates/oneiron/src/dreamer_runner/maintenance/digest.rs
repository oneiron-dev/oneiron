//! One durable proactivity digest per vault cadence, with intent-bound urgent wakes.
//! A regular digest also carries the cleanup cron's after-notice (OF-449),
//! the NOTE tombstone review's open proposals (OF-073) and the Dreamer's
//! applied-maintenance after-notice (FIX 3226).
//! Each digest is stored once, under a stable locator with a content hash
//! (FIX 2332), and every read, answer and delivery of it is its viewer's
//! own view, screened of private thread words they do not read (FIX 6411).
use super::invalid;
use crate::limit_ask::EngineLimit;
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
pub use view::ProactivityDigestView;
const CADENCE: SideTable<(), ProactivityCadence, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_CADENCE);
const STATE: SideTable<(), DigestState, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_STATE);
const DIGEST: SideTable<[u8; 32], ProactivityDigest, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_DIGEST);
const PRESENTATION: SideTable<(), ProactivityPresentation, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_PRESENTATION);
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
/// The derived group the cleanup line (ARCH-0073, OF-449) renders under.
pub const CLEANUP_GROUP: &str = "dreamer.cleanup";
/// The cleanup line's view: the owner cleanup surface, where every archive
/// restores.
pub const CLEANUP_VIEW: &str = "/v1/owner/cleanup";
/// The derived group the NOTE tombstone line (OF-073, FIX 2419) renders
/// under.
pub const NOTE_TOMBSTONE_GROUP: &str = "note.tombstone";
/// The NOTE tombstone line's view: the owner's tombstone review, where each
/// proposal is accepted or declined.
pub const NOTE_TOMBSTONE_VIEW: &str = "/v1/owner/notes/tombstones";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactivityCadence {
    pub period_secs: u64,
    pub group_by_facet: bool,
    pub urgent_breakthrough: bool,
}
/// Agent-authored, owner-confirmed presentation row. Templates and voice are
/// data, not engine-owned prompt or persona text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// Typed request payload for the existing `vault.claims.put` agent verb.
/// The host may build it from a chat request; no natural-language parser or
/// product persona is embedded in the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestProposal {
    #[serde(with = "crate::serialize::entity_ref")]
    pub claim_ref: EntityId,
    pub revision: [u8; 32],
    pub summary: String,
    /// The private thread turns its words were drawn from when its digest
    /// was assembled (FIX 6411): a viewer reads it only while it reads each
    /// one, whatever its claim's ancestry says later. Empty for words off
    /// every private thread.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_sources: Vec<DigestPrivateSource>,
    /// A private source its ancestry declared did not resolve when its
    /// digest was assembled: no view carries it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unverified: bool,
}
/// One pending training offer the digest carries to the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestOffer {
    #[serde(with = "crate::serialize::entity_ref")]
    pub offer: EntityId,
    /// The offer digest the owner's answer binds.
    pub digest: String,
    pub summary: String,
}
/// The cleanup cron's after-notice (ARCH-0073 §5): what it archived since
/// the last digest that carried it, and the proposals that wait for the
/// owner. Counts come from recorded decisions, never from the archive's size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn set_proactivity_cadence(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        row: &ProactivityCadence,
    ) -> Result<()> {
        if row.period_secs == 0 {
            return Err(invalid());
        }
        self.with_write_txn_grouped(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            CADENCE.put(&self.store, txn, &(), row)?;
            Ok(())
        })?;
        self.store.notify_proactivity_changes();
        Ok(())
    }
    /// An agent may draft this row in chat; only the authenticated owner's
    /// confirmation writes it. Edits affect the next digest, not past rows.
    pub fn set_proactivity_presentation(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        row: &ProactivityPresentation,
    ) -> Result<()> {
        row.validate()?;
        row.measure(self);
        self.with_write_txn_grouped(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            PRESENTATION.put(self, txn, &(), row)?;
            Ok(())
        })?;
        self.store.notify_proactivity_changes();
        Ok(())
    }

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

    /// Fault injection for a presentation-only failure after a deadline has
    /// already been selected. The row remains corrupt until explicitly edited.
    #[cfg(feature = "test-support")]
    pub fn corrupt_proactivity_presentation_for_test(&self) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            PRESENTATION.put_undecodable(&self.store, txn, &(), b"invalid presentation")?;
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

#[cfg(test)]
mod tests;

fn load_cadence(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProactivityCadence> {
    let row: ProactivityCadence = match CADENCE.get(&vault.store, txn, &())? {
        Some(row) => row,
        None => {
            serde_json::from_str(include_str!("digest_defaults.json")).map_err(|_| invalid())?
        }
    };
    if row.period_secs == 0 {
        return Err(invalid());
    }
    Ok(row)
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
fn load_presentation(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProactivityPresentation> {
    let row: ProactivityPresentation = match PRESENTATION.get(&vault.store, txn, &())? {
        Some(row) => row,
        None => serde_json::from_str(include_str!("digest_presentation_defaults.json"))
            .map_err(|_| invalid())?,
    };
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
