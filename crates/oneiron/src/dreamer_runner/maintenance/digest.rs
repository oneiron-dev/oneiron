//! One durable proactivity digest per vault cadence, with intent-bound urgent wakes.
//! A regular digest also carries the cleanup cron's after-notice (OF-449).
use super::invalid;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
const CADENCE: SideTable<(), ProactivityCadence, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_CADENCE);
const STATE: SideTable<(), DigestState, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_STATE);
const DIGEST: SideTable<[u8; 32], ProactivityDigest, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_DIGEST);
const PRESENTATION: SideTable<(), ProactivityPresentation, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_PRESENTATION);
const POLICY_CONFIRMED: SideTable<EntityId, [u8; 32], side_table::Raw> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_CONFIRMED);
/// Per-recipient time of the last digest that delivered judge or eval label asks.
const JUDGE_ASK_MARK: SideTable<EntityId, u64, side_table::Raw> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_JUDGE_ASKS);
/// Generic proposed claim written through the existing gated agent memory
/// verb. It changes NO settings until the owner confirms its exact revision.
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
        if self.group_template.len() > 1024
            || !self.group_template.contains("{group}")
            || self.item_template.len() > 1024
            || !self.item_template.contains("{summary}")
            || !self.item_template.contains("{ref}")
            || self.voice_style.len() > 1024
            || self.group_aliases.len() > 64
            || self.urgent_groups.len() > 64
            || self.group_aliases.iter().any(|(key, value)| {
                key.trim().is_empty()
                    || key.len() > 128
                    || value.trim().is_empty()
                    || value.len() > 128
            })
            || self
                .urgent_groups
                .iter()
                .any(|group| group.trim().is_empty() || group.len() > 128)
        {
            return Err(invalid());
        }
        Ok(())
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrgentDigestWake {
    pub intent_ref: EntityId,
    pub needed_before: u64,
    pub waiting_harms_intent: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestProposal {
    #[serde(with = "crate::serialize::entity_ref")]
    pub claim_ref: EntityId,
    pub revision: [u8; 32],
    pub summary: String,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactivityDigest {
    pub id: [u8; 32],
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
    /// The Coach's agent-health cards opened, updated or settled since the
    /// last regular digest (OF-568), concern first and newest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health_cards: Vec<super::agent_health::ConcernCardSummary>,
    pub rendered: String,
    pub voice_style: String,
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
        self.with_write_txn_grouped(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            PRESENTATION.put(self, txn, &(), row)?;
            Ok(())
        })?;
        self.store.notify_proactivity_changes();
        Ok(())
    }

    /// Resolve an agent-authored, still-pending policy claim for exact owner
    /// review. An ordinary claim alone has no settings authority.
    pub fn proactivity_policy_proposal(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        claim_ref: EntityId,
    ) -> Result<ProactivityPolicyProposal> {
        let txn = self.store.env.read_txn()?;
        let actor = super::validate_person_in_txn(self, &txn, owner)?;
        load_policy_proposal(self, &txn, actor, claim_ref)
    }

    /// Confirm the exact proposal the host showed the authenticated owner.
    /// Both policy rows and a replay marker commit together; an agent claim
    /// cannot edit either row directly, nor replay an old confirmation.
    pub fn confirm_proactivity_policy_proposal(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        claim_ref: EntityId,
        expected_revision: [u8; 32],
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let actor = super::validate_owner_in_txn(self, txn, owner)?;
            if POLICY_CONFIRMED.contains(&self.store, &*txn, &claim_ref)? {
                return Err(invalid());
            }
            let proposal = load_policy_proposal(self, &*txn, actor, claim_ref)?;
            if proposal.revision != expected_revision {
                return Err(invalid());
            }
            CADENCE.put(&self.store, txn, &(), &proposal.request.cadence)?;
            PRESENTATION.put(self, txn, &(), &proposal.request.presentation)?;
            POLICY_CONFIRMED.put(&self.store, txn, &claim_ref, &expected_revision)?;
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
        if pending_proposals(self, &txn, authority, &state, &cadence)?.is_empty()
            && unseen_offers(&offers, &state).is_empty()
            && unseen_cleanup(self, &txn, &state)?.is_none()
        {
            return Ok(None);
        }
        Ok(Some(state.last_regular.map_or(0, |last| {
            last.saturating_add(cadence.period_secs)
        })))
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
        let result = self.assemble_proactivity_digest(None, now, None);
        if result.is_err() {
            self.store
                .suspend_proactivity_digest_if_unchanged(generation);
        }
        result
    }

    /// Builds a display projection only. Pending decisions remain pending.
    /// The urgent assessment comes from the host, but must name a live,
    /// approved intent whose deadline is before the next cadence boundary.
    pub fn proactivity_digest(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        now: u64,
        urgent: Option<&UrgentDigestWake>,
    ) -> Result<Option<ProactivityDigest>> {
        self.assemble_proactivity_digest(Some(owner), now, urgent)
    }

    fn assemble_proactivity_digest(
        &self,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        now: u64,
        urgent: Option<&UrgentDigestWake>,
    ) -> Result<Option<ProactivityDigest>> {
        let authority = self.dreamer_authority()?.entity_ref();
        let pending_offers = crate::skill_optimize::pending_training_offers(self)?;
        // Read before the write, as the offers are; the period's start is
        // known once the state is.
        let cards = self.agent_health_cards_between(0, now)?;
        self.with_write_txn_grouped(|txn| {
            let recipient = owner
                .map(|owner| super::validate_owner_in_txn(self, txn, owner))
                .transpose()?;
            let cadence = load_cadence(self, &*txn)?;
            let presentation = load_presentation(self, &*txn)?;
            let mut state = load_state(self, &*txn)?;
            let next = state
                .last_regular
                .map(|last| last.saturating_add(cadence.period_secs));
            let due = next.is_none_or(|next| now >= next);
            // Judge and eval label asks spend one human's funded minutes, so
            // each recipient keeps its own mark on the shared vault cadence:
            // one person's digest never consumes another's.
            let asks_due = match &recipient {
                Some(actor) => load_ask_mark(self, &*txn, actor)?
                    .is_none_or(|last| now >= last.saturating_add(cadence.period_secs)),
                None => false,
            };
            let breakthrough =
                if let (Some(wake), Some(next), Some(owner)) = (urgent, next, recipient) {
                    if cadence.urgent_breakthrough
                        && wake.waiting_harms_intent
                        && wake.needed_before < next
                    {
                        self.get_claim_in_txn(&*txn, &wake.intent_ref)?
                            .is_some_and(|body| {
                                body.predicate == "profile.intent"
                                    && body.subject == crate::ClaimSubject::Entity(owner)
                                    && body.source == Some(ClaimSource::UserStated)
                                    && body
                                        .value
                                        .as_str()
                                        .is_some_and(|text| !text.trim().is_empty())
                                    && body.approval == ClaimApprovalStatus::Approved
                                    && body.lifecycle == ClaimLifecycleStatus::Active
                                    && !body.stale
                            })
                    } else {
                        false
                    }
                } else {
                    false
                };
            if !due && !breakthrough && !asks_due {
                return Ok(None);
            }
            let mut groups: BTreeMap<String, Vec<DigestProposal>> = BTreeMap::new();
            for (group, proposal) in pending_proposals(self, txn, authority, &state, &cadence)? {
                if !due && (!breakthrough || !presentation.urgent_groups.contains(&group)) {
                    continue;
                }
                let display_group = presentation
                    .group_aliases
                    .get(&group)
                    .cloned()
                    .unwrap_or(group);
                groups.entry(display_group).or_default().push(proposal);
            }
            // Judge asks are paid first; eval label asks spend what remains.
            let (judge_asks, eval_label_asks) = match recipient {
                Some(actor) if asks_due => (
                    crate::skill_optimize::take_digest_asks_in_txn(self, txn, actor, now)?,
                    crate::skill_optimize::take_digest_eval_asks_in_txn(self, txn, actor, now)?,
                ),
                _ => (Vec::new(), Vec::new()),
            };
            // Offers ride the regular cadence; an urgent wake is about its intent.
            let offers = if due {
                unseen_offers(&pending_offers, &state)
            } else {
                Vec::new()
            };
            // So does the cleanup after-notice: it is never urgent.
            let cleanup = if due {
                unseen_cleanup(self, &*txn, &state)?
            } else {
                None
            };
            // So do the health cards: each one touched in the period.
            let health_cards: Vec<_> = if due {
                let from = state.last_regular.unwrap_or(0);
                cards
                    .iter()
                    .filter(|card| {
                        card.opened_at >= from
                            || card.updated_at >= from
                            || card.outcome_at.is_some_and(|at| at >= from)
                    })
                    .map(super::agent_health::ConcernCardSummary::of)
                    .collect()
            } else {
                Vec::new()
            };
            if groups.is_empty()
                && judge_asks.is_empty()
                && eval_label_asks.is_empty()
                && offers.is_empty()
                && cleanup.is_none()
            {
                return Ok(None);
            }
            let mut rendered = String::new();
            for (group, proposals) in &mut groups {
                proposals.sort_by_key(|p| p.claim_ref);
                rendered.push_str(&presentation.group_template.replace("{group}", group));
                for proposal in proposals {
                    rendered.push_str(
                        &presentation
                            .item_template
                            .replace("{summary}", &proposal.summary)
                            .replace("{ref}", &proposal.claim_ref.to_hex()),
                    );
                    state
                        .seen
                        .insert(proposal.claim_ref.to_hex(), proposal.revision);
                }
            }
            if !offers.is_empty() {
                let group = presentation
                    .group_aliases
                    .get(TRAINING_OFFER_GROUP)
                    .map_or(TRAINING_OFFER_GROUP, String::as_str);
                rendered.push_str(&presentation.group_template.replace("{group}", group));
                for offer in &offers {
                    rendered.push_str(
                        &presentation
                            .item_template
                            .replace("{summary}", &offer.summary)
                            .replace("{ref}", &offer.offer.to_hex()),
                    );
                    state.offers_seen.insert(offer.offer.to_hex());
                }
            }
            if let Some(line) = &cleanup {
                let group = presentation
                    .group_aliases
                    .get(CLEANUP_GROUP)
                    .map_or(CLEANUP_GROUP, String::as_str);
                rendered.push_str(&presentation.group_template.replace("{group}", group));
                for summary in line.summaries() {
                    rendered.push_str(
                        &presentation
                            .item_template
                            .replace("{summary}", &summary)
                            .replace("{ref}", &line.view),
                    );
                }
                state.cleanup_seen.extend(line.decisions.iter().cloned());
                state.cleanup_seen.extend(line.proposals.iter().cloned());
            }
            if !health_cards.is_empty() {
                let facet = super::agent_health::COACH_AGENT_HEALTH_FACET;
                let group = presentation
                    .group_aliases
                    .get(facet)
                    .map_or(facet, String::as_str);
                rendered.push_str(&presentation.group_template.replace("{group}", group));
                for card in &health_cards {
                    let summary = format!(
                        "{facet}: {} {} {} on {}",
                        card.signal, card.tone, card.outcome, card.agent
                    );
                    rendered.push_str(
                        &presentation
                            .item_template
                            .replace("{summary}", &summary)
                            .replace("{ref}", &card.card),
                    );
                }
            }
            let is_urgent = !due && breakthrough && !groups.is_empty();
            let mut digest = ProactivityDigest {
                id: [0; 32],
                created_at: now,
                recipient,
                urgent: is_urgent,
                groups,
                judge_asks,
                eval_label_asks,
                offers,
                cleanup,
                health_cards,
                rendered,
                voice_style: presentation.voice_style,
            };
            // OF-067: the id hashes the digest as the side-row wall stores it, so the wall
            // reads it first, under the id of the digest as rendered.
            let rendered_id = digest_id(&digest)?;
            DIGEST.admit(self, txn, &rendered_id, &mut digest)?;
            digest.id = digest_id(&digest)?;
            DIGEST.put(&self.store, txn, &digest.id, &digest)?;
            // Delivery is the reader's inbox, in this same write: one
            // NOTIFICATION per reader, keyed by digest, whose seen and acked
            // marks are the reader's own and never this digest's `seen`. The
            // timer digest has no reader of its own, so every owner gets it.
            let id = crate::entity_id::bytes_to_hex_lower(&digest.id);
            let readers = match recipient {
                Some(actor) => vec![actor],
                None => crate::policy_model::owners_in_txn(self, &*txn)?,
            };
            for reader in readers {
                self.record_notification_in_txn(
                    txn,
                    &crate::inbox::NotificationEvent {
                        kind: crate::inbox::NotificationKind::Digest,
                        source: crate::inbox::NotificationSource {
                            producer: DIGEST_NOTIFICATION_PRODUCER.to_owned(),
                            event: format!("{id}:{}", reader.to_hex()),
                            result: Some(id.clone()),
                            ..crate::inbox::NotificationSource::default()
                        },
                        subject_refs: Vec::new(),
                        recipient: Some(reader),
                        created_at: now,
                        origin_conversation: None,
                    },
                )?;
            }
            // The vault state and board pointer follow the shared proposals;
            // an asks-only digest is the recipient's and moves only its mark.
            if !digest.groups.is_empty() || !digest.offers.is_empty() || digest.cleanup.is_some() {
                if due {
                    state.last_regular = Some(now);
                }
                state.last_digest_id = Some(digest.id);
                STATE.put(&self.store, txn, &(), &state)?;
            }
            let asked = !digest.judge_asks.is_empty() || !digest.eval_label_asks.is_empty();
            if let Some(actor) = recipient.filter(|_| asked) {
                JUDGE_ASK_MARK.put(&self.store, txn, &actor, &now)?;
            }
            Ok(Some(digest))
        })
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

    /// The latest scheduled or urgent output for the host's inbox/board read
    /// plane (`GET /v1/owner/proactivity/digest`). The ID still verifies the
    /// persisted digest on every read.
    pub fn latest_proactivity_digest(&self) -> Result<Option<ProactivityDigest>> {
        let id = {
            let txn = self.store.env.read_txn()?;
            load_state(self, &txn)?.last_digest_id
        };
        id.map(|id| self.read_proactivity_digest(id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn read_proactivity_digest(&self, id: [u8; 32]) -> Result<Option<ProactivityDigest>> {
        let txn = self.store.env.read_txn()?;
        DIGEST
            .get(&self.store, &txn, &id)?
            .map(|digest| {
                if digest.id != id || digest_id(&digest)? != id {
                    return Err(invalid());
                }
                Ok(digest)
            })
            .transpose()
    }
}

/// The id a digest is stored under: the hash of what it shows.
fn digest_id(digest: &ProactivityDigest) -> Result<[u8; 32]> {
    let identity = serde_json::to_vec(&(
        digest.created_at,
        digest.recipient,
        &digest.groups,
        &digest.judge_asks,
        &digest.eval_label_asks,
        &digest.offers,
        &digest.cleanup,
        digest.urgent,
        &digest.rendered,
        &digest.voice_style,
    ))
    .map_err(|_| invalid())?;
    Ok(*blake3::hash(&identity).as_bytes())
}
#[cfg(test)]
mod tests;

/// The pending offers no digest carried yet, as the digest shows them.
fn unseen_offers(
    pending: &[crate::skill_optimize::TrainingOffer],
    state: &DigestState,
) -> Vec<DigestOffer> {
    pending
        .iter()
        .filter(|offer| !state.offers_seen.contains(&offer.id.to_hex()))
        .map(|offer| DigestOffer {
            offer: offer.id,
            digest: offer.digest.clone(),
            summary: format!(
                "{TRAINING_OFFER_GROUP}: {}",
                serde_json::to_string(&offer.candidate).unwrap_or_default()
            ),
        })
        .collect()
}
/// The cleanup decisions and open proposals no digest carried yet, as one
/// line; `None` when there are none.
fn unseen_cleanup(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    state: &DigestState,
) -> Result<Option<DigestCleanup>> {
    let mut line = DigestCleanup {
        decisions: Vec::new(),
        archived: 0,
        skipped: 0,
        proposals: Vec::new(),
        proposed: 0,
        view: CLEANUP_VIEW.to_owned(),
    };
    for decision in crate::vault_cleanup::cleanup_digests_in_txn(vault, txn)? {
        let id = decision.id.to_hex();
        if state.cleanup_seen.contains(&id) {
            continue;
        }
        line.archived = line.archived.saturating_add(decision.archived.len() as u64);
        line.skipped = line.skipped.saturating_add(decision.skipped.len() as u64);
        line.decisions.push(id);
    }
    for proposal in crate::vault_cleanup::cleanup_proposals_in_txn(vault, txn)? {
        let id = proposal.id.to_hex();
        if state.cleanup_seen.contains(&id) {
            continue;
        }
        line.proposed = line
            .proposed
            .saturating_add(proposal.candidates.len() as u64);
        line.proposals.push(id);
    }
    Ok((!line.decisions.is_empty() || !line.proposals.is_empty()).then_some(line))
}
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
fn pending_proposals(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: EntityId,
    state: &DigestState,
    cadence: &ProactivityCadence,
) -> Result<Vec<(String, DigestProposal)>> {
    let mut pending = Vec::new();
    // Stream the producer index rather than using its capped 10k-ID query:
    // previously displayed proposals remain Proposed and still occupy index
    // slots. A full tray must not disable the scheduler's other deadlines.
    for row in crate::claim::PENDING_PRODUCER.iter_from(&vault.store, txn, authority.as_bytes())? {
        let ((_, id), _) = row?;
        let Some(bytes) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&bytes).ok_or_else(invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || bytes.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(&bytes[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.predicate == PROACTIVITY_POLICY_REQUEST_PREDICATE
            || body.approval != ClaimApprovalStatus::Proposed
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.source != Some(ClaimSource::Generated)
            || body.stale
            || crate::claim::session_claim_producer(&body) != Some(authority)
        {
            continue;
        }
        let revision = *blake3::hash(&bytes[ENTITY_METADATA_HEADER_LEN..]).as_bytes();
        if state.seen.get(&id.to_hex()) == Some(&revision) {
            continue;
        }
        let group = if cadence.group_by_facet {
            body.predicate
                .split('.')
                .take(2)
                .collect::<Vec<_>>()
                .join(".")
        } else {
            "proposals".into()
        };
        pending.push((
            group,
            DigestProposal {
                claim_ref: id,
                revision,
                summary: format!("{}: {}", body.predicate, body.value),
            },
        ));
    }
    Ok(pending)
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

fn load_policy_proposal(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
    claim_ref: EntityId,
) -> Result<ProactivityPolicyProposal> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &claim_ref)?
        .ok_or_else(invalid)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Err(invalid());
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.predicate != PROACTIVITY_POLICY_REQUEST_PREDICATE
        || body.subject != crate::ClaimSubject::Entity(owner)
        || body.source != Some(ClaimSource::Generated)
        || body.approval != ClaimApprovalStatus::Proposed
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
        || crate::claim::session_claim_producer(&body).is_none()
    {
        return Err(invalid());
    }
    let value = body.value.as_str().ok_or_else(invalid)?;
    if value.len() > 16_384 {
        return Err(invalid());
    }
    let request: ProactivityPolicyRequest = serde_json::from_str(value).map_err(|_| invalid())?;
    request.claim_value()?;
    Ok(ProactivityPolicyProposal {
        request,
        revision: *blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes(),
    })
}
