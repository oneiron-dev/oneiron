//! A historical restore gives content as it stood, never authority as it stood.
//!
//! ARCH-0038 (RD-20, amended 2026-09-26): a checkpoint never resets the current
//! authority root or freshness pins and never restores a destroyed identity
//! key. Restoring over a live vault classes every canonical row by
//! [`super::restore_class`], deny by default:
//!
//! - **content** comes from the image;
//! - **live** rows replace the image's, and a row the live vault no longer
//!   holds stays absent: the root, device and slip plane, freshness pins,
//!   key custody, spent approvals, consent and policy switches and their
//!   receipts, erasure state, and the ledgers of sends and exports, so
//!   nothing spent, revoked, withdrawn or switched off comes back and no
//!   send is made twice;
//! - **refused** families hold authority entangled with content (grants,
//!   policy manifests, room roles and membership, e-sign ceremonies). A
//!   restore that would change one is refused before anything is created,
//!   rather than half-applied.
//!
//! Membership is checked on the result: a restore may not make anyone an
//! owner or member who is not one now, whether by reviving a deleted or
//! merged PERSON or a removed shared member (`refuse_new_members`).
use super::CanonicalRows;
use super::restore_class::{Class, Classes, Projection, Scope};
use crate::agent_def::{
    AgentCeiling, AgentScope, AgentWakeCadence, DreamingMode, McpRef, MemoryProfile,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::campaign::compliance::{
    JurisdictionObservation, rank_jurisdiction_observation, select_jurisdiction,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::conversation::{ConversationBody, RoomRole};
use crate::counterparty_contact::{
    CounterpartyContactStatus, CounterpartyFirstTouch, CounterpartyOptOut,
};
use crate::llm::ModelTierRef;
use crate::note::NoteKind;
use crate::outbound_grant::StandingOutboundGrant;
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_PERSON};
use crate::skill::{SkillDependency, SkillGovernanceTier, SkillLifecycle};
use crate::skill_hub::ScanRiskLevel;
use crate::task_authority::{TaskAuthorityFact, TaskAuthorityFactKind};
use crate::workspace_roster::{ProjectAuthority, ProjectBudgetShare, ProjectRecord, ProjectRole};
use crate::{EntityId, Error, Result, Vault};
use heed::types::Bytes;
use std::collections::{BTreeMap, BTreeSet};

/// The `vault_meta` row holding a store's random id (`vault::identity`).
const VAULT_STORE_ID: &[u8] = b"vault_identity:local:v1";

/// Rewrites `databases` so every live row is `current`'s, or refuses when a
/// refused family moved since the checkpoint.
pub(super) fn carry_current_authority(
    databases: &mut BTreeMap<String, CanonicalRows>,
    current: &Vault,
) -> Result<()> {
    let classes = Classes::new(current);
    let live = current_rows(current, &classes)?;
    // A store's random id, minted at its first open, names the vault even
    // before it has an authority log. Every image carries one; a missing or
    // different id is another vault.
    let store_id = |rows: &CanonicalRows| {
        rows.iter()
            .find(|(key, _)| key.as_slice() == VAULT_STORE_ID)
            .map(|(_, value)| value.clone())
    };
    let image_id = store_id(&databases["vault_meta"]);
    if image_id.is_none() || image_id != store_id(&live.rows["vault_meta"]) {
        return Err(Error::InvalidConfig(
            "this checkpoint belongs to another vault".into(),
        ));
    }
    // The log only grows. An image entry the live vault never saw means the
    // image is another vault's, or this one's history was rewritten.
    let log = |rows: &CanonicalRows| -> BTreeSet<Vec<u8>> {
        rows.iter()
            .filter(|(_, value)| {
                EntityMetadataHeader::parse(value)
                    .is_some_and(|header| header.entity_type == ENTITY_TYPE_AUTHORITY_LOG)
            })
            .map(|(key, _)| key.clone())
            .collect()
    };
    if !log(&databases["entities"]).is_subset(&log(&live.rows["entities"])) {
        return Err(Error::InvalidConfig(
            "this checkpoint's authority log is not a prefix of this vault's; it belongs to another vault"
                .into(),
        ));
    }
    let image_entities: BTreeSet<&[u8]> = databases["entities"]
        .iter()
        .map(|(key, _)| key.as_slice())
        .collect();
    let mut moved = authority_moved(
        &classes,
        &databases["entities"],
        &image_entities,
        &live,
        databases.get("edges_in").map_or(&[][..], Vec::as_slice),
    );
    for (database, live_rows) in &live.rows {
        let scoped = |rows| refused(&classes, database, rows, &image_entities);
        let image = scoped(&databases[*database]);
        let current = scoped(live_rows);
        for what in image.keys().chain(current.keys()) {
            if image.get(what) != current.get(what) {
                moved.insert(*what);
            }
        }
    }
    if !moved.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "restoring this checkpoint would roll back {} changed since it was taken; restore it beside the vault instead",
            moved.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    for (database, live_rows) in &live.rows {
        let is_live =
            |(key, value): &(Vec<u8>, Vec<u8>)| classes.row(database, key, value).0 == Class::Live;
        let rows = databases
            .get_mut(*database)
            .ok_or_else(super::codec_error)?;
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = std::mem::take(rows)
            .into_iter()
            .filter(|row| !is_live(row))
            .collect();
        merged.extend(live_rows.iter().filter(|row| is_live(row)).cloned());
        *rows = merged.into_iter().collect();
    }
    Ok(())
}

/// The live vault's rows that are not content.
struct LiveRows {
    /// Live rows and the rows of refused families, by database.
    rows: BTreeMap<&'static str, CanonicalRows>,
    /// The authority each live entity of a projected kind carries, by id. An
    /// entity the live vault deleted is absent, except an outbound grant.
    authority: Projected,
    /// The `edges_in` keys of the `claim_of` edges through which the campaign
    /// gate finds a subject's jurisdiction and membership claims.
    claim_of: Vec<Vec<u8>>,
}

/// Entity ids with the authority their bodies carry and the class's name.
type Projected = BTreeMap<Vec<u8>, (&'static str, Projection, Compared)>;

fn current_rows(current: &Vault, classes: &Classes) -> Result<LiveRows> {
    let txn = current.store.env.read_txn()?;
    let mut live = LiveRows {
        rows: BTreeMap::new(),
        authority: BTreeMap::new(),
        claim_of: Vec::new(),
    };
    for entry in crate::store::DB_MANIFEST {
        if !Classes::has_authority(entry.name) {
            continue;
        }
        let db = current
            .store
            .env
            .open_database::<Bytes, Bytes>(&txn, Some(entry.name))?
            .ok_or_else(super::codec_error)?;
        let mut rows = Vec::new();
        for row in db.iter(&txn)? {
            let (key, value) = row?;
            if super::storage_tier(entry.name, key) != super::StorageTier::Canonical {
                continue;
            }
            match classes.row(entry.name, key, value).0 {
                Class::Content => {}
                Class::Refuse {
                    what,
                    scope: Scope::Authority(projection),
                } => {
                    let deleted = || -> Result<bool> {
                        let id = EntityId::from_bytes(
                            key.try_into().map_err(|_| super::codec_error())?,
                        )?;
                        Ok(crate::ports::TombstoneStoreRead::port_deletion_state(
                            &current.store,
                            &txn,
                            &id,
                        )?
                        .deleted)
                    };
                    if let Some(authority) = project(projection, value)
                        && (projection == Projection::OutboundGrant || !deleted()?)
                    {
                        live.authority
                            .insert(key.to_vec(), (what, projection, authority));
                    }
                }
                _ => rows.push((key.to_vec(), value.to_vec())),
            }
        }
        live.rows.insert(entry.name, rows);
    }
    let wanted: BTreeSet<&[u8]> = live
        .authority
        .iter()
        .filter(|(_, (_, _, current))| current.campaign_reads())
        .map(|(key, _)| key.as_slice())
        .collect();
    if !wanted.is_empty() {
        let edges = current
            .store
            .env
            .open_database::<Bytes, Bytes>(&txn, Some("edges_in"))?
            .ok_or_else(super::codec_error)?;
        for row in edges.iter(&txn)? {
            let (key, _) = row?;
            if claim_of_edge(key).is_some_and(|(_, claim)| wanted.contains(claim)) {
                live.claim_of.push(key.to_vec());
            }
        }
    }
    Ok(live)
}

/// The subject and claim of an `edges_in` key of a `claim_of` edge
/// (`subject(16) | kind(1) | claim(16)`).
fn claim_of_edge(key: &[u8]) -> Option<(&[u8], &[u8])> {
    (key.len() == 33 && key[16] == crate::edge::EdgeKind::ClaimOf as u8)
        .then(|| (&key[..16], &key[17..]))
}

/// The names of the projected classes whose authority the image would roll
/// back: an entity both vaults hold whose authority differs; one the image
/// holds and the live vault deleted, or one only the live vault holds, when
/// that presence is itself authority (an outbound grant, a claim of an
/// authority family). An entity only one side holds is otherwise content.
fn authority_moved(
    classes: &Classes,
    image: &CanonicalRows,
    image_entities: &BTreeSet<&[u8]>,
    current: &LiveRows,
    image_claim_of: &[(Vec<u8>, Vec<u8>)],
) -> BTreeSet<&'static str> {
    let live = &current.authority;
    let mut moved = BTreeSet::new();
    let mut held = BTreeSet::new();
    let mut image_verdicts = Vec::new();
    let mut image_bytes = BTreeSet::new();
    let mut image_members: BTreeSet<&[u8]> = BTreeSet::new();
    let mut image_observations: BTreeMap<&[u8], Observation> = BTreeMap::new();
    for (key, value) in image {
        let (
            Class::Refuse {
                what,
                scope: Scope::Authority(projection),
            },
            _,
        ) = classes.row("entities", key, value)
        else {
            continue;
        };
        let Some(authority) = project(projection, value) else {
            continue;
        };
        if projection == Projection::Skill {
            image_bytes.extend(skill_bytes(value));
        }
        if authority.enrolls() {
            image_members.insert(key.as_slice());
        }
        // A claim compared in aggregate still has its read scope compared as
        // any claim's is, whatever the live body under its id became.
        let scope_moved = |access| {
            live.get(key)
                .is_some_and(|(_, _, current)| current.access() != Some(access))
        };
        match authority {
            Compared::ScanVerdict { access, verdict } => {
                image_verdicts.push(verdict);
                if scope_moved(access) {
                    moved.insert(what);
                }
                continue;
            }
            Compared::Jurisdiction {
                access,
                observation,
            } => {
                image_observations.insert(key.as_slice(), observation);
                if scope_moved(access) {
                    moved.insert(what);
                }
                continue;
            }
            _ => {}
        }
        held.insert(key.as_slice());
        match live.get(key) {
            Some((_, _, current)) if *current == authority => {}
            // An ordinary claim rewritten under its id into one compared in
            // aggregate: its read scope is compared here, and the aggregate
            // weighs what it now says.
            Some((_, _, current))
                if authority.family().is_none()
                    && matches!(
                        current,
                        Compared::ScanVerdict { .. } | Compared::Jurisdiction { .. }
                    )
                    && current.access() == authority.access() => {}
            Some((_, _, current)) => {
                moved.insert(authority.family().or(current.family()).unwrap_or(what));
            }
            None if presence_is_authority(projection, &authority, image_entities, false) => {
                moved.insert(authority.family().unwrap_or(what));
            }
            None => {}
        }
    }
    for (key, (what, projection, current)) in live {
        if !held.contains(key.as_slice())
            && presence_is_authority(*projection, current, image_entities, true)
        {
            moved.insert(current.family().unwrap_or(*what));
        }
    }
    let live_verdicts = live.values().filter_map(|(_, _, current)| match current {
        Compared::ScanVerdict { verdict, .. } => Some(verdict.clone()),
        _ => None,
    });
    if scan_postures(image_verdicts, &image_bytes) != scan_postures(live_verdicts, &image_bytes) {
        moved.insert("skill scan verdicts");
    }
    let live_members: BTreeSet<&[u8]> = live
        .iter()
        .filter(|(_, (_, _, current))| current.enrolls())
        .map(|(key, _)| key.as_slice())
        .collect();
    let live_observations: BTreeMap<&[u8], Observation> = live
        .iter()
        .filter_map(|(key, (_, _, current))| match current {
            Compared::Jurisdiction { observation, .. } => {
                Some((key.as_slice(), observation.clone()))
            }
            _ => None,
        })
        .collect();
    let image_view = CampaignView::new(
        image_claim_of.iter().map(|(key, _)| key.as_slice()),
        &image_members,
        &image_observations,
    );
    let live_view = CampaignView::new(
        current.claim_of.iter().map(Vec::as_slice),
        &live_members,
        &live_observations,
    );
    // The gate reads the jurisdiction of the PERSON a recipient's address
    // resolves to, and of nothing else; an entity's kind never changes.
    let image_persons: BTreeSet<&[u8]> = image
        .iter()
        .filter(|(_, value)| {
            EntityMetadataHeader::parse(value)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_PERSON)
        })
        .map(|(key, _)| key.as_slice())
        .collect();
    if image_view
        .enrolled
        .union(&live_view.enrolled)
        .filter(|subject| image_persons.contains(**subject))
        .any(|subject| image_view.selection(subject) != live_view.selection(subject))
    {
        moved.insert("recipient jurisdictions");
    }
    moved
}

/// What one `comm.jurisdiction` claim tells the campaign gate.
#[derive(Clone, PartialEq)]
enum Observation {
    /// An inactive claim, which the gate skips.
    Inactive,
    /// An active claim as the gate ranks it; `None` when its value does not
    /// decode, which fails the gate closed.
    Active(Option<JurisdictionObservation>),
}

/// The jurisdiction and confidence the campaign gate selects for a subject,
/// or `Err` when it fails closed.
type Selection = std::result::Result<Option<(String, Option<u16>)>, ()>;

/// What the campaign gate reads in one vault, finding a subject's claims as
/// it does, through their `claim_of` edges, whatever subject a body names:
/// the subjects an active membership enrolls, and each subject's
/// jurisdiction observations. The selection they give a PERSON the image
/// holds and either vault enrolls picks which compliance rules bind a
/// campaign send, so a newer observation that moves it is authority, and a
/// refreshed one with the same result changes nothing. The gate reads no
/// jurisdiction of a subject outside every campaign, so its observations are
/// content; enrolment itself is compared as the campaign enrolment family.
#[derive(Default)]
struct CampaignView<'a> {
    enrolled: BTreeSet<&'a [u8]>,
    observations: BTreeMap<&'a [u8], Vec<&'a Observation>>,
}

impl<'a> CampaignView<'a> {
    fn new(
        claim_of: impl IntoIterator<Item = &'a [u8]>,
        members: &BTreeSet<&[u8]>,
        observations: &'a BTreeMap<&'a [u8], Observation>,
    ) -> Self {
        let mut view = Self::default();
        for key in claim_of {
            let Some((subject, claim)) = claim_of_edge(key) else {
                continue;
            };
            if members.contains(claim) {
                view.enrolled.insert(subject);
            }
            if let Some(observation) = observations.get(claim) {
                view.observations
                    .entry(subject)
                    .or_default()
                    .push(observation);
            }
        }
        view
    }

    /// The jurisdiction and confidence the gate selects for `subject`; `Err`
    /// when an active observation does not decode, which fails it closed.
    fn selection(&self, subject: &[u8]) -> Selection {
        let mut ranked = Vec::new();
        for observation in self.observations.get(subject).into_iter().flatten() {
            match observation {
                Observation::Inactive => {}
                Observation::Active(Some(observation)) => ranked.push(observation.clone()),
                Observation::Active(None) => return Err(()),
            }
        }
        Ok(select_jurisdiction(ranked))
    }
}

/// One active skill scan verdict: the bytes it is about, the risk it found,
/// and whether its dependency scan was partial.
#[derive(Clone, PartialEq)]
struct ScanVerdictFacts {
    content_hash: Option<String>,
    risk: ScanRiskLevel,
    partial: bool,
}

/// The bytes a SKILL row activates, by the content hash its scan verdicts
/// name.
fn skill_bytes(raw: &[u8]) -> Option<String> {
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..)?;
    let skill = crate::skill::decode_skill_record(body).ok()?;
    Some(skill.content_hash?.to_hex())
}

/// The activation posture the bytes of each skill the image holds (`held`)
/// take from their active scan verdicts, as the activation gate folds them:
/// the worst risk, and whether a dependency scan was partial. Bytes with no
/// verdict, or only clean complete ones, are absent, so a refreshed scan with
/// the same result changes nothing; and bytes no skill of the image activates
/// leave with the content they came with.
fn scan_postures(
    verdicts: impl IntoIterator<Item = ScanVerdictFacts>,
    held: &BTreeSet<String>,
) -> BTreeMap<String, (ScanRiskLevel, bool)> {
    let mut postures: BTreeMap<_, (ScanRiskLevel, bool)> = BTreeMap::new();
    for verdict in verdicts {
        let Some(bytes) = verdict.content_hash.filter(|bytes| held.contains(bytes)) else {
            continue;
        };
        let posture = postures
            .entry(bytes)
            .or_insert((ScanRiskLevel::None, false));
        posture.0 = posture.0.max(verdict.risk);
        posture.1 |= verdict.partial;
    }
    postures.retain(|_, posture| *posture != (ScanRiskLevel::None, false));
    postures
}

/// Whether an entity only one vault holds (only the live one when
/// `live_only`) still counts as changed: an outbound grant; a claim of an
/// authority family; a contact that is revoked, opted out or first met in
/// public (which holds a send for the owner), whose absence would let a send
/// through; and an owner, cancellation or human assignment
/// fact added since the image to a task the image holds. An acknowledgement
/// only takes a failed task off the board.
fn presence_is_authority(
    projection: Projection,
    authority: &Compared,
    image_entities: &BTreeSet<&[u8]>,
    live_only: bool,
) -> bool {
    match authority {
        Compared::Contact {
            status,
            opt_out,
            first_touch,
            ..
        } => {
            opt_out.is_some()
                || *status != CounterpartyContactStatus::Active
                || *first_touch == CounterpartyFirstTouch::Public
        }
        Compared::TaskFact(fact) => {
            live_only
                && fact.kind != TaskAuthorityFactKind::Acked
                && image_entities.contains(fact.task_ref.as_bytes().as_slice())
        }
        _ => projection == Projection::OutboundGrant || authority.family().is_some(),
    }
}

/// What one refused row or projected entity is compared by.
#[derive(PartialEq)]
enum Compared {
    /// Its stored bytes: a body that does not decode compares whole.
    Row(Vec<u8>),
    /// Who a room admits, in what role, and from when.
    Room {
        members: BTreeSet<EntityId>,
        roles: BTreeMap<String, RoomRole>,
        shares_history: bool,
    },
    /// Who a relationship's participants are.
    Relationship { participants: BTreeSet<EntityId> },
    /// Whether a skill loads and what automation may do with it.
    Skill {
        approval: ClaimApprovalStatus,
        quarantined: bool,
        governance: Option<SkillGovernanceTier>,
    },
    /// What bounds an agent.
    Agent(Box<AgentBounds>),
    /// Which party on which identity a counterparty contact binds, how it was
    /// first met (a public first touch holds a send for the owner), whether it
    /// is live, and the party's consents.
    Contact {
        identity: EntityId,
        party: String,
        first_touch: CounterpartyFirstTouch,
        status: CounterpartyContactStatus,
        opt_out: Option<CounterpartyOptOut>,
        promo_consent: bool,
    },
    /// A note's kind and author.
    Note { kind: NoteKind, author: EntityId },
    /// A claim's read scope, and, for a claim of an authority family, the
    /// family's name and the claim's whole body.
    Claim {
        space: Option<EntityId>,
        private: bool,
        authority: Option<(&'static str, Vec<u8>)>,
    },
    /// What a project may do and spend, and who is in it.
    Project {
        authority: Box<ProjectAuthority>,
        roster: Vec<String>,
        role: ProjectRole,
        budget: Option<String>,
        budget_share: Option<ProjectBudgetShare>,
    },
    /// A grant as it authorizes, without its last use.
    OutboundGrant(Box<StandingOutboundGrant>),
    /// An authority fact about a task.
    TaskFact(TaskAuthorityFact),
    /// Who owns a task, whom it is assigned to, and its ask class.
    TaskBinding(crate::task_verb::TaskBinding),
    /// Any other TASK body: it binds no ask, so one replacing a task the
    /// image holds differs from it.
    TaskUnbound,
    /// A skill scan verdict claim: its read scope, and the verdict, compared
    /// as a posture.
    ScanVerdict {
        access: (Option<EntityId>, bool),
        verdict: ScanVerdictFacts,
    },
    /// A `comm.jurisdiction` claim: its read scope, and its observation,
    /// compared as part of the selection the campaign gate makes for each
    /// subject it reaches.
    Jurisdiction {
        access: (Option<EntityId>, bool),
        observation: Observation,
    },
}

impl Compared {
    /// The read scope of a claim of any kind.
    fn access(&self) -> Option<(Option<EntityId>, bool)> {
        match self {
            Self::Claim { space, private, .. } => Some((*space, *private)),
            Self::ScanVerdict { access, .. } | Self::Jurisdiction { access, .. } => Some(*access),
            _ => None,
        }
    }

    /// Whether this is an active `campaign.member` claim, which enrolls each
    /// subject the campaign gate reaches it from.
    fn enrolls(&self) -> bool {
        let Self::Claim {
            authority: Some((_, body)),
            ..
        } = self
        else {
            return false;
        };
        crate::claim::decode_claim_body(body, true).is_ok_and(|claim| {
            claim.predicate == crate::campaign::claims::PREDICATE_CAMPAIGN_MEMBER
                && claim.lifecycle == ClaimLifecycleStatus::Active
        })
    }

    /// Whether the campaign gate reads this claim: a jurisdiction observation
    /// or an active membership.
    fn campaign_reads(&self) -> bool {
        matches!(self, Self::Jurisdiction { .. }) || self.enrolls()
    }

    /// The authority family a claim belongs to, which names it in a refusal.
    fn family(&self) -> Option<&'static str> {
        match self {
            Self::Claim {
                authority: Some((family, _)),
                ..
            } => Some(*family),
            _ => None,
        }
    }
}

/// Every field of an agent definition that bounds what the agent may do.
#[derive(PartialEq)]
struct AgentBounds {
    approval: ClaimApprovalStatus,
    lifecycle: ClaimLifecycleStatus,
    enabled: bool,
    ceiling: AgentCeiling,
    scope: AgentScope,
    connectors: Vec<String>,
    tools: Vec<McpRef>,
    skills: Vec<SkillDependency>,
    model: Option<ModelTierRef>,
    memory: Option<MemoryProfile>,
    dreaming: Option<DreamingMode>,
    dreaming_model: Option<ModelTierRef>,
    wake: Option<AgentWakeCadence>,
}

/// The authority `projection` reads in one entity row, or `None` for a row
/// too short to hold a body or a note body that does not decode.
fn project(projection: Projection, raw: &[u8]) -> Option<Compared> {
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..)?;
    let whole = || Compared::Row(raw.to_vec());
    Some(match projection {
        Projection::Room => ConversationBody::from_bytes(body).map_or_else(
            |_| whole(),
            |room| Compared::Room {
                shares_history: room.shares_history(),
                members: room.member_ids.into_iter().collect(),
                roles: room.roles,
            },
        ),
        Projection::Relationship => {
            // As the audience check reads it: a body that does not decode
            // lists no participants.
            let participants = rmp_serde::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|value| value.get("participant_ids").cloned())
                .map_or(Ok(Vec::new()), serde_json::from_value::<Vec<EntityId>>);
            participants.map_or_else(
                |_| whole(),
                |participants| Compared::Relationship {
                    participants: participants.into_iter().collect(),
                },
            )
        }
        Projection::Project => rmp_serde::from_slice::<ProjectRecord>(body).map_or_else(
            |_| whole(),
            |project| Compared::Project {
                authority: Box::new(project.authority()),
                roster: project.roster,
                role: project.role,
                budget: project.budget,
                budget_share: project.budget_share,
            },
        ),
        Projection::Skill => crate::skill::decode_skill_record(body).map_or_else(
            |_| whole(),
            |skill| Compared::Skill {
                approval: skill.approval_status,
                quarantined: skill.lifecycle_status == SkillLifecycle::Quarantined,
                governance: skill.governance_tier,
            },
        ),
        Projection::Agent => crate::agent_def::decode_agent_definition(body).map_or_else(
            |_| whole(),
            |agent| {
                Compared::Agent(Box::new(AgentBounds {
                    approval: agent.approval_status,
                    lifecycle: agent.lifecycle_status,
                    enabled: agent.enabled,
                    ceiling: agent.ceiling,
                    scope: agent.scope,
                    connectors: agent.connectors,
                    tools: agent.code_mode_mcps,
                    skills: agent.skills,
                    model: agent.model_tier,
                    memory: agent.memory_profile,
                    dreaming: agent.dreaming,
                    dreaming_model: agent.dreaming_model,
                    wake: agent.wake_cadence,
                }))
            },
        ),
        Projection::Contact => crate::counterparty_contact::decode_counterparty_contact_body(body)
            .map_or_else(
                |_| whole(),
                |contact| Compared::Contact {
                    identity: contact.identity_ref,
                    party: contact.counterparty,
                    first_touch: contact.first_touch,
                    status: contact.status,
                    opt_out: contact.opt_out,
                    promo_consent: contact.promo_consent,
                },
            ),
        Projection::Note => {
            let note = crate::note::decode_note_body_using(body, NoteKind::wire).ok()?;
            Compared::Note {
                kind: note.kind,
                author: note.author_ref,
            }
        }
        Projection::Claim => crate::claim::decode_claim_body(body, true).map_or_else(
            |_| whole(),
            |claim| {
                let (space, private) = crate::claim::claim_access_axes(&claim);
                if claim.predicate == crate::skill_hub::PREDICATE_SKILL_SCAN_VERDICT {
                    return Compared::ScanVerdict {
                        access: (space, private),
                        verdict: scan_verdict(&claim),
                    };
                }
                if claim.predicate == crate::campaign::claims::PREDICATE_COMM_JURISDICTION {
                    return Compared::Jurisdiction {
                        access: (space, private),
                        observation: jurisdiction(&claim),
                    };
                }
                let authority = super::restore_class::authority_claim(&claim)
                    .map(|family| (family, body.to_vec()));
                Compared::Claim {
                    space,
                    private,
                    authority,
                }
            },
        ),
        Projection::Task => match crate::task_authority::decode_task_authority_fact_body(body) {
            Ok(fact) => Compared::TaskFact(fact),
            Err(_) => crate::task_verb::task_binding(body)
                .map_or(Compared::TaskUnbound, Compared::TaskBinding),
        },
        Projection::OutboundGrant => {
            crate::outbound_grant::decode_standing_outbound_grant_body(body).map_or_else(
                |_| whole(),
                |grant| {
                    Compared::OutboundGrant(Box::new(StandingOutboundGrant {
                        last_used_at: None,
                        ..grant
                    }))
                },
            )
        }
    })
}

/// What an active skill scan verdict tells the activation gate; an inactive
/// one tells it nothing. A risk that does not decode counts as the worst.
fn scan_verdict(claim: &crate::claim::ClaimBody) -> ScanVerdictFacts {
    let field = |name: &str| match &claim.value {
        rmpv::Value::Map(fields) => fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .and_then(|(_, value)| value.as_str()),
        _ => None,
    };
    let active = claim.lifecycle == ClaimLifecycleStatus::Active;
    ScanVerdictFacts {
        content_hash: field("contentHash").map(str::to_owned),
        risk: if active {
            crate::skill_hub::scan_verdict_row_risk(claim).unwrap_or(ScanRiskLevel::Critical)
        } else {
            ScanRiskLevel::None
        },
        partial: active
            && field("provider") == Some(crate::skill_hub::osv::OSV_SCAN_PROVIDER)
            && field("completeness") == Some("partial"),
    }
}

/// What a `comm.jurisdiction` claim tells the campaign gate, which reads
/// only active ones.
fn jurisdiction(claim: &crate::claim::ClaimBody) -> Observation {
    if claim.lifecycle == ClaimLifecycleStatus::Active {
        Observation::Active(rank_jurisdiction_observation(claim).ok())
    } else {
        Observation::Inactive
    }
}

/// One refused family's compared rows, in key order.
type Family<'a> = Vec<(&'a [u8], &'a [u8])>;

/// The rows of each refused family that its scope compares, by name. The
/// projected entity kinds are compared by [`authority_moved`].
fn refused<'a>(
    classes: &Classes,
    database: &str,
    rows: &'a CanonicalRows,
    image_entities: &BTreeSet<&[u8]>,
) -> BTreeMap<&'static str, Family<'a>> {
    let mut families: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (key, value) in rows {
        let (Class::Refuse { what, scope }, prefix) = classes.row(database, key, value) else {
            continue;
        };
        match scope {
            Scope::Family => {}
            Scope::ImageEntities => {
                let id = key.get(prefix..prefix + 16);
                if !id.is_some_and(|id| image_entities.contains(id)) {
                    continue;
                }
            }
            Scope::Authority(_) => continue,
        }
        families
            .entry(what)
            .or_default()
            .push((key.as_slice(), value.as_slice()));
    }
    families
}

/// Refuses a restored vault in which someone is a member who is not a member
/// of `current` now (the owner of a personal vault; any role of a shared one).
/// Membership rides content (PERSON rows, lifecycle, shared grants), so it is
/// checked on the result rather than by row: a person deleted or merged away
/// since the checkpoint does not regain the authority their unchanged grants
/// would confer.
pub(super) fn refuse_new_members(current: &Vault, restored: &Vault) -> Result<()> {
    if restored
        .live_member_ids()?
        .is_subset(&current.live_member_ids()?)
    {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "restoring this checkpoint would make someone a vault owner or member who is not one now; restore it beside the vault instead"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests;
