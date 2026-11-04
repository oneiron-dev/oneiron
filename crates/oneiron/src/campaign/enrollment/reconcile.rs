//! One effective `campaign.member` head per person and campaign (FIX 9663,
//! 9664, 10221).
//!
//! Every intake source (a saved query's consequence, a manual enrollment)
//! reads every admitted live head of the person in the campaign inside the
//! writer that lands its own, merges them into one value and supersedes them
//! all there. The merge keeps what the membership already holds: its state
//! where the person's own pause, suppression or exit governs, each existing
//! channel row with its consent basis and sticky sender, and the isolation
//! stamps of the head it replaces. Only a genuinely new channel appends, and
//! channels from a head stamped differently never join, so one source's
//! scope never widens another's. Source claims, their evidence and the
//! Supersedes lineage stay as history.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::campaign::claims::{
    CampaignMemberChannel, CampaignMemberDerivation, CampaignMemberState, CampaignMemberValue,
    live_campaign_member_heads_in_txn, normalize_campaign_pack_token,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, decode_claim_body};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::saved_query::MembershipTransition;
use crate::{EntityId, Error, Result, Vault};

/// The person's effective membership in one campaign, as its admitted live
/// heads give it.
pub(crate) struct EffectiveMember {
    /// Every admitted live head, in claim-id order. A replacement supersedes
    /// each of them in the writer that lands it.
    pub(crate) heads: Vec<EntityId>,
    /// The merged value: the oldest head's, its state folded across every
    /// head, the channels of every head stamped as it is appended in id
    /// order, and the newest derivation any head carries.
    pub(crate) value: CampaignMemberValue,
    /// The oldest head's body, whose isolation stamps the replacement keeps.
    pub(crate) body: ClaimBody,
    /// When the folded state began: the occurred start of the head carrying
    /// it.
    pub(crate) since: u64,
}

/// Every admitted (`auto` or `approved`) live `campaign.member` head of
/// `person` in `campaign`, merged, or `None` when there is none. A pending or
/// rejected candidate is not a membership and is neither merged nor closed.
///
/// # Errors
///
/// Storage and decode errors propagate.
pub(crate) fn effective_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
    campaign: EntityId,
) -> Result<Option<EffectiveMember>> {
    let mut admitted = Vec::new();
    for (id, value) in live_campaign_member_heads_in_txn(&vault.store, txn, person, campaign)? {
        let Some((body, since)) = head_body_in_txn(vault, txn, &id)? else {
            continue;
        };
        if matches!(
            body.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) {
            admitted.push((id, value, body, since));
        }
    }
    let mut rows = admitted.into_iter();
    let Some((first, mut value, body, mut since)) = rows.next() else {
        return Ok(None);
    };
    let mut heads = vec![first];
    for (id, other, other_body, other_since) in rows {
        heads.push(id);
        if state_rank(other.state) > state_rank(value.state) {
            value.state = other.state;
            since = other_since;
        }
        if other.derivation.is_some() {
            value.derivation = other.derivation;
        }
        if same_isolation(&body, &other_body) {
            merge_channels(&mut value.channels, &other.channels);
        }
    }
    Ok(Some(EffectiveMember {
        heads,
        value,
        body,
        since,
    }))
}

/// The effective state of `person` in `campaign`, read in one snapshot of
/// its own; `None` when no admitted live head exists.
///
/// # Errors
///
/// Storage and decode errors propagate.
pub(crate) fn effective_member_state(
    vault: &Vault,
    person: EntityId,
    campaign: EntityId,
) -> Result<Option<CampaignMemberState>> {
    let txn = vault.store.env.read_txn()?;
    Ok(effective_member_in_txn(vault, &txn, person, campaign)?.map(|member| member.value.state))
}

/// Where an intake comes from.
pub(crate) enum IntakeSource {
    /// A saved query's membership event.
    Query {
        /// The query the event was derived from.
        query_ref: EntityId,
        /// Its direction.
        transition: MembershipTransition,
        /// When the engine detected it.
        detected_at: u64,
    },
    /// A manual enrollment.
    Manual,
}

/// What a reconciliation lets the intake do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reconciled {
    /// The intake's own state lands.
    Applied,
    /// The intake's provenance and new channels land; the membership's own
    /// state holds.
    RecordedOnly,
    /// As [`Self::RecordedOnly`], for a saved pause whose wake falls due at
    /// this instant.
    DeferredUntil(u64),
}

/// One reconciled membership value.
pub(crate) struct Reconciliation {
    /// The value the replacement head carries.
    pub(crate) value: CampaignMemberValue,
    /// What landed.
    pub(crate) outcome: Reconciled,
    /// When a kept state began; `None` when the intake's own state landed and
    /// its own instant applies.
    pub(crate) kept_since: Option<u64>,
    /// A foreign query's exit that landed only as a record: its derivation,
    /// which the replacement keeps beside the state-owning one (FIX 9664).
    pub(crate) recorded_exit: Option<CampaignMemberDerivation>,
}

/// Reconciles one intake against the effective membership.
///
/// With no membership the intake lands as it is. Otherwise the membership's
/// value is the base: the intake's new channels append, a query intake's
/// derivation replaces the head's (so every spent epoch rides a replicated
/// claim), except a foreign exit's that lands only as a record: the head
/// keeps the state-owning derivation and carries that exit's as
/// [`Reconciliation::recorded_exit`]. The state follows these rules:
///
/// * a suppression holds against every intake;
/// * a manual intake keeps any state but `enrolled`;
/// * a query's exit applies only to a membership that query itself derived
///   and that is enrolled or exited: an exit from one source never ends a
///   membership another holds, nor a pause;
/// * a query's entry re-enters an exited membership (a new epoch, never a
///   resurrection) and refreshes an enrolled one; on a pause it lands only
///   once the saved wake is satisfied: its date has come, or it waits on a
///   new trigger and this event was detected after the pause. An unsatisfied
///   dated wake defers to its date; a trigger-only one waits for a real
///   later trigger.
pub(crate) fn reconcile(
    effective: Option<&EffectiveMember>,
    incoming: &CampaignMemberValue,
    source: &IntakeSource,
    now: u64,
) -> Reconciliation {
    let Some(effective) = effective else {
        return Reconciliation {
            value: incoming.clone(),
            outcome: Reconciled::Applied,
            kept_since: None,
            recorded_exit: None,
        };
    };
    let mut value = effective.value.clone();
    merge_channels(&mut value.channels, &incoming.channels);
    let held = effective.value.state;
    let outcome = match (source, held) {
        (_, CampaignMemberState::Suppressed) => Reconciled::RecordedOnly,
        (IntakeSource::Manual, CampaignMemberState::Enrolled) => Reconciled::Applied,
        (IntakeSource::Manual, _) => Reconciled::RecordedOnly,
        (
            IntakeSource::Query {
                query_ref,
                transition: MembershipTransition::Exited,
                ..
            },
            CampaignMemberState::Enrolled | CampaignMemberState::Exited,
        ) if derived_by(effective, *query_ref) => Reconciled::Applied,
        (
            IntakeSource::Query {
                transition: MembershipTransition::Exited,
                ..
            },
            _,
        ) => Reconciled::RecordedOnly,
        (
            IntakeSource::Query { detected_at, .. },
            CampaignMemberState::Paused { until, new_trigger },
        ) => {
            let due = until.is_some_and(|at| now >= at);
            let triggered = new_trigger == Some(true) && *detected_at > effective.since;
            if due || triggered {
                Reconciled::Applied
            } else if let Some(at) = until {
                Reconciled::DeferredUntil(at)
            } else {
                Reconciled::RecordedOnly
            }
        }
        (IntakeSource::Query { .. }, _) => Reconciled::Applied,
    };
    // A foreign exit that only records never takes the derivation: the
    // owning query's later exit must still close the membership, and the
    // exiting query's next exit must not.
    let mut recorded_exit = None;
    if let IntakeSource::Query {
        query_ref,
        transition,
        ..
    } = source
    {
        if *transition == MembershipTransition::Exited
            && outcome == Reconciled::RecordedOnly
            && !derived_by(effective, *query_ref)
        {
            recorded_exit.clone_from(&incoming.derivation);
        } else {
            value.derivation.clone_from(&incoming.derivation);
        }
    }
    if outcome == Reconciled::Applied {
        value.state = incoming.state;
        Reconciliation {
            value,
            outcome,
            kept_since: None,
            recorded_exit,
        }
    } else {
        Reconciliation {
            value,
            outcome,
            kept_since: Some(effective.since),
            recorded_exit,
        }
    }
}

/// Whether `query_ref` derived the state-owning head of `effective`.
fn derived_by(effective: &EffectiveMember, query_ref: EntityId) -> bool {
    effective
        .value
        .derivation
        .as_ref()
        .is_some_and(|derivation| derivation.source_query == query_ref)
}

/// Copies `from`'s isolation stamps (world, relationship, scope, facet and
/// project) onto `body`: a replacement never re-scopes who may read the
/// membership it replaces.
pub(crate) fn keep_isolation_stamps(body: &mut ClaimBody, from: &ClaimBody) {
    body.world = from.world;
    body.rel.clone_from(&from.rel);
    body.scope.clone_from(&from.scope);
    body.scope_facet = from.scope_facet;
    body.scope_project = from.scope_project;
}

/// Appends each row of `incoming` whose normalized channel `into` does not
/// already hold. A held row keeps its consent basis and sticky sender: a dead
/// sender is replaced only through the explicit restart route.
fn merge_channels(into: &mut Vec<CampaignMemberChannel>, incoming: &[CampaignMemberChannel]) {
    for row in incoming {
        let channel = normalize_campaign_pack_token(&row.channel);
        if into
            .iter()
            .any(|held| normalize_campaign_pack_token(&held.channel) == channel)
        {
            continue;
        }
        into.push(CampaignMemberChannel {
            channel,
            basis_evidence: row.basis_evidence,
            sender_ref: row.sender_ref,
        });
    }
}

/// The fold order of states across several heads: the person's own
/// suppression and pause dominate, and an exit yields to a membership another
/// source holds.
const fn state_rank(state: CampaignMemberState) -> u8 {
    match state {
        CampaignMemberState::Exited => 0,
        CampaignMemberState::Enrolled => 1,
        CampaignMemberState::Paused { .. } => 2,
        CampaignMemberState::Suppressed => 3,
    }
}

fn same_isolation(a: &ClaimBody, b: &ClaimBody) -> bool {
    a.world == b.world
        && a.rel == b.rel
        && a.scope == b.scope
        && a.scope_facet == b.scope_facet
        && a.scope_project == b.scope_project
}

/// The CLAIM body at `id` and its occurred start, or `None` when the row is
/// absent or not a CLAIM.
fn head_body_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(ClaimBody, u64)>> {
    let Some(raw) = vault
        .store
        .port_entity_record(txn, id)?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("campaign member head header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(Some((body, header.occurred_start)))
}
