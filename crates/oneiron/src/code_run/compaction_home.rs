//! The agent's home as its own compaction wears it (FIX 4465; the home is
//! the self-model, voice, diary and lessons). A read projection, never a
//! store: each part is read through its existing door, under the agent's own
//! Grant at the place its caller sits, never under the owner's reach and
//! never as a system actor. A part the agent has none of, or may not read,
//! is named absent: it is never filled from the owner's memory or another
//! agent's diary. Home words go to the writing call only; they are not the
//! summary's evidence, which stays the span's retained turns.
//!
//! FIX 4570: the self-model is the SUMMARY the agent's binding names, read
//! through its own scoped SUMMARY read ([`self_model`]). FIX 4817: every row
//! a part was read from keeps the live revision its words were read at, in
//! the same snapshot, so what wore it lands, serves and keeps its words only
//! while each row still reads at it ([`crate::compaction::CompactionHomeRef`]).
//!
//! FIX 4571: the voice wears the persona scenario its host selected on the
//! binding ([`CompactionHostBinding::with_placement_scenario`]), else the
//! PERSON baseline. The scenario FACET is a persona input row like any other,
//! so an edit to it withdraws the worn home too.

mod self_model;

pub(crate) use self_model::{bound_self_model_in, erase_self_model_binding_actor_in_txn};

use crate::authority::VerifiedSlip;
use crate::claim::{
    CallerLocality, ClaimApprovalStatus, ClaimLifecycleStatus, ClaimReadStatus, ClaimSubject,
    PointRead, ReadRow, decode_claim_body,
};
use crate::compaction::{
    CompactionHomeRef, HOME_PART_SELF_MODEL, HOME_PART_WORN, SelfCompactionUnavailable,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{DiaryReadOutcome, Memory};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::subject_model::SubjectKind;
use crate::tokenizer::count_context_pack_tokens;
use crate::vault::RevisionRef;
use crate::{Vault, WriteActor};

/// The reason a home read gives the diary door's log.
const HOME_READ_REASON: &str = "writing my own compaction";

/// What one run that compacts is, as its host authenticated it: the actor it
/// writes as, where its caller sits, and the credential it proved, when it
/// proved one. A host builds it from its own connection or lease, never from
/// a model's or a guest's words.
#[derive(Clone)]
pub struct CompactionHostBinding {
    actor: WriteActor,
    locality: CallerLocality,
    read_proof: Option<VerifiedSlip>,
    /// The persona scenario FACET the home's voice wears (FIX 4571): only
    /// [`Self::with_placement_scenario`] sets it, from the host's own
    /// authenticated placement. `None` wears the PERSON baseline.
    scenario: Option<EntityId>,
    /// The dispatch's frozen provenance, never a home-read ceiling.
    caller_origin: crate::agent_dispatch::CallerOrigin,
}

impl CompactionHostBinding {
    /// The run's write actor: the byline its summaries carry.
    #[must_use]
    pub const fn actor(&self) -> WriteActor {
        self.actor
    }

    /// Records the frozen origin of the actual dispatch this flight runs.
    /// This changes no read binding and is never used by an admission check.
    #[must_use]
    pub const fn with_caller_origin(mut self, origin: crate::agent_dispatch::CallerOrigin) -> Self {
        self.caller_origin = origin;
        self
    }

    /// The provenance this flight's producer supplied, not its read locality.
    #[must_use]
    pub const fn caller_origin(&self) -> crate::agent_dispatch::CallerOrigin {
        self.caller_origin
    }

    /// Where the run's caller sits, as its host found it.
    #[must_use]
    pub const fn locality(&self) -> CallerLocality {
        self.locality
    }

    /// The binding with the persona scenario its home's voice wears (FIX
    /// 4571): `facet`, the FACET its host authenticated the run's placement
    /// in, kept only when it is an explicit persona scenario of the run's own
    /// PERSON, as the persona compile recognizes one under the run's own
    /// Grant at its caller's place. Any other facet, one that read cannot
    /// prove, or none keeps the PERSON baseline. A host passes its own
    /// placement only: never a tool's or a model's words, a label or a
    /// searched scenario.
    #[must_use]
    pub fn with_placement_scenario(mut self, vault: &Vault, facet: Option<EntityId>) -> Self {
        let scenario = facet.filter(|facet| owns_scenario(vault, &self, *facet));
        self.scenario = scenario;
        self
    }
}

/// Whether `facet` is an explicit persona scenario of `host`'s own PERSON,
/// read as its home's voice is: under its own Grant at its caller's place
/// (FIX 4571). An actor with no readable identity owns none.
fn owns_scenario(vault: &Vault, host: &CompactionHostBinding, facet: EntityId) -> bool {
    let Ok(identity) = resolve_compaction_identity(vault, host) else {
        return false;
    };
    home_memory(vault, host, identity.agent)
        .read_lane(ClaimReadStatus::Surfaceable)
        .is_ok_and(|read| read.owns_persona_scenario(&identity.person, facet))
}

/// The agent's own memory a home is read through: its Grant, at the place
/// its caller sits, under the credential it proved, when it proved one.
fn home_memory<'v>(vault: &'v Vault, host: &CompactionHostBinding, agent: EntityId) -> Memory<'v> {
    let memory = vault.memory(agent, EdgeActorClass::Agent).at(host.locality);
    match &host.read_proof {
        Some(proof) => memory.with_read_proof(proof),
        None => memory,
    }
}

/// The binding a host hands its compaction seat (FIX 4465). The caller's
/// place is the home read's ceiling, as on every read the run makes (a
/// caller off this device reads no device-local world); it is never an
/// eligibility test. A run compacts as itself wherever it runs, within its
/// Grant and the serving route's own admission.
#[must_use]
pub fn bind_compaction_caller(
    actor: WriteActor,
    locality: CallerLocality,
    read_proof: Option<VerifiedSlip>,
) -> CompactionHostBinding {
    CompactionHostBinding {
        actor,
        locality,
        read_proof,
        scenario: None,
        caller_origin: crate::agent_dispatch::CallerOrigin::Unknown,
    }
}

/// Whose home a run's compaction wears: the agent, and the PERSON it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionIdentity {
    pub agent: EntityId,
    pub person: EntityId,
}

/// The host-authenticated map from a run's actor to its home (FIX 4465): an
/// agent definition's PERSON is the one its stored subject anchor names, a
/// person-backed agent is its own PERSON. An AGENT_DEF id is never taken for
/// a PERSON id. An actor with no such PERSON has no home.
pub fn resolve_compaction_identity(
    vault: &Vault,
    host: &CompactionHostBinding,
) -> Result<CompactionIdentity, SelfCompactionUnavailable> {
    if host.actor.actor_class() != EdgeActorClass::Agent {
        return Err(SelfCompactionUnavailable::NoIdentity);
    }
    let agent = host.actor.entity_ref();
    let unreadable = |_| SelfCompactionUnavailable::IdentityUnreadable;
    let person = {
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(|_| SelfCompactionUnavailable::IdentityUnreadable)?;
        match vault
            .get_entity_type_in_txn(&txn, &agent)
            .map_err(unreadable)?
        {
            Some(ENTITY_TYPE_PERSON) => Some(agent),
            Some(ENTITY_TYPE_AGENT_DEF) => None,
            _ => return Err(SelfCompactionUnavailable::NoIdentity),
        }
    };
    let person = match person {
        Some(person) => person,
        None => vault
            .actor_subject_anchor(&agent, unix_now())
            .map_err(unreadable)?
            .filter(|anchor| anchor.subject_kind == SubjectKind::Person)
            .map(|anchor| anchor.subject_ref)
            .ok_or(SelfCompactionUnavailable::NoIdentity)?,
    };
    Ok(CompactionIdentity { agent, person })
}

/// One part of a home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HomePart {
    Voice,
    SelfModel,
    Diary,
    Lessons,
}

impl HomePart {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Voice => "voice",
            Self::SelfModel => HOME_PART_SELF_MODEL,
            Self::Diary => "diary",
            Self::Lessons => "lessons",
        }
    }
}

/// One home part and every row its text was read from, each with the live
/// revision it was read at (FIX 4817).
#[derive(Debug, Clone, PartialEq, Eq)]
struct HomeItem {
    part: HomePart,
    rows: Vec<(EntityId, Option<RevisionRef>)>,
    text: String,
}

/// A home, read once per flight (FIX 4465): its parts in the order a call
/// wears them (voice, self-model, lessons, then the diary newest first), and
/// each part it has none of, with why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionHome {
    identity: CompactionIdentity,
    items: Vec<HomeItem>,
    absent: Vec<(HomePart, &'static str)>,
}

/// A home as one call wears it: its text, and every part by ref with its
/// state, so a receipt shows what was worn, cut or absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedHome {
    pub text: String,
    pub refs: Vec<CompactionHomeRef>,
}

/// The tokens one call's home may take (FIX 4465): what the admitted
/// model's context leaves once the span's input, its pins and the reply's
/// reserve, and the home's frame, are counted. The span is never cut for the
/// home; a home that does not fit is cut, visibly. No constant of its own.
#[must_use]
pub const fn compaction_home_budget(
    context_tokens: u64,
    input_tokens: u64,
    output_reserve: u64,
    frame_tokens: u64,
) -> u64 {
    context_tokens
        .saturating_sub(input_tokens)
        .saturating_sub(output_reserve)
        .saturating_sub(frame_tokens)
}

/// Reads `host`'s home through the existing doors under its own Grant
/// (FIX 4465): its voice through the persona compile, wearing the scenario
/// its host selected or the PERSON baseline (FIX 4571), its self-model as the
/// SUMMARY its binding names through its own scoped SUMMARY read (FIX 4570),
/// its lessons as the admitted active `actor.lesson` and
/// `actor.failure_mode` claims about it, its diary through the diary door as
/// its own reader. Each row keeps the revision its words were read at, read
/// in that door's own snapshot (FIX 4817). An actor with no readable
/// identity holds the flight; any other part it cannot read is absent.
pub fn load_compaction_home(
    vault: &Vault,
    host: &CompactionHostBinding,
) -> Result<CompactionHome, SelfCompactionUnavailable> {
    let identity = resolve_compaction_identity(vault, host)?;
    let memory = home_memory(vault, host, identity.agent);
    let read = memory
        .read_lane(ClaimReadStatus::Surfaceable)
        .map_err(|_| SelfCompactionUnavailable::IdentityUnreadable)?;
    let mut home = CompactionHome {
        identity,
        items: Vec::new(),
        absent: Vec::new(),
    };
    // A selected scenario that no longer reads or belongs to this PERSON
    // leaves the voice absent, never another mask (FIX 4571).
    match read.compile_persona(&identity.person, host.scenario) {
        Ok(persona) => home.items.push(HomeItem {
            part: HomePart::Voice,
            rows: persona
                .made_by
                .inputs
                .into_iter()
                .zip(persona.input_revisions)
                .collect(),
            text: persona.value.to_string(),
        }),
        Err(_) => home.absent.push((HomePart::Voice, "no_readable_persona")),
    }
    match self_model::read_self_model_part(vault, &memory, identity.agent) {
        self_model::SelfModelPart::Worn {
            summary,
            revision,
            text,
        } => home.items.push(HomeItem {
            part: HomePart::SelfModel,
            rows: vec![(summary, revision)],
            text,
        }),
        self_model::SelfModelPart::Absent(why) => home.absent.push((HomePart::SelfModel, why)),
    }
    let lessons = vault
        .claims_for_subject(&identity.agent)
        .and_then(|ids| {
            let reads: Vec<_> = ids.into_iter().map(PointRead::id).collect();
            read.read_revisions(&reads)
        })
        .map(|rows| lessons_of(identity.agent, rows.value.into_iter().flatten()));
    match lessons {
        Ok(lessons) if !lessons.is_empty() => home.items.extend(lessons),
        Ok(_) => home.absent.push((HomePart::Lessons, "none")),
        Err(_) => home.absent.push((HomePart::Lessons, "unreadable")),
    }
    drop(read);
    match memory.read_agent_diary_pinned(None, identity.agent, HOME_READ_REASON) {
        Ok((DiaryReadOutcome::Granted { entries, .. }, pins)) if !entries.is_empty() => {
            let mut entries = entries;
            entries.sort_by(|a, b| b.learned_at.cmp(&a.learned_at).then(b.id.cmp(&a.id)));
            home.items.extend(entries.into_iter().map(|entry| {
                let revision = pins
                    .iter()
                    .find(|(id, _)| *id == entry.id)
                    .and_then(|(_, revision)| *revision);
                HomeItem {
                    part: HomePart::Diary,
                    rows: vec![(entry.id, revision)],
                    text: entry.markdown,
                }
            }));
        }
        Ok((DiaryReadOutcome::Granted { .. }, _)) => home.absent.push((HomePart::Diary, "none")),
        Ok(_) => home.absent.push((HomePart::Diary, "not_granted")),
        Err(_) => home.absent.push((HomePart::Diary, "unreadable")),
    }
    Ok(home)
}

/// The admitted, active craft notes about `agent`: its lessons and failure
/// modes, never a proposed candidate, each with the revision it was read at.
fn lessons_of(
    agent: EntityId,
    rows: impl Iterator<Item = (ReadRow, Option<RevisionRef>)>,
) -> Vec<HomeItem> {
    let mut lessons = Vec::new();
    for (row, revision) in rows {
        let ReadRow {
            id,
            body: Some(data),
            ..
        } = row
        else {
            continue;
        };
        let Ok(body) = decode_claim_body(&data, true) else {
            continue;
        };
        let craft = body.predicate == crate::actor_claims::PREDICATE_ACTOR_LESSON
            || body.predicate == crate::actor_claims::PREDICATE_ACTOR_FAILURE_MODE;
        if !craft
            || body.subject != ClaimSubject::Entity(agent)
            || body.approval == ClaimApprovalStatus::Proposed
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
        {
            continue;
        }
        let Some(text) = body.value.as_str() else {
            continue;
        };
        lessons.push(HomeItem {
            part: HomePart::Lessons,
            rows: vec![(id, revision)],
            text: format!("{}: {text}", body.predicate),
        });
    }
    lessons
}

impl CompactionHome {
    /// Whose home this is.
    #[must_use]
    pub const fn identity(&self) -> CompactionIdentity {
        self.identity
    }

    /// The home as one call wears it, inside `budget` tokens: each row in
    /// order while it fits, the rest of its part marked cut, and every
    /// absent part named.
    #[must_use]
    pub fn render(&self, budget: u64) -> RenderedHome {
        let mut text = String::new();
        let mut used = 0_u64;
        let mut refs = Vec::new();
        let mut cut = false;
        let mut heading = None;
        for item in &self.items {
            let section =
                (heading != Some(item.part)).then(|| format!("## {}\n", item.part.as_str()));
            let line = format!("{}{}\n", section.as_deref().unwrap_or_default(), item.text);
            let tokens = count_context_pack_tokens(&line) as u64;
            let fits = !cut && used.saturating_add(tokens) <= budget;
            if fits {
                text.push_str(&line);
                used = used.saturating_add(tokens);
                heading = Some(item.part);
            } else {
                cut = true;
            }
            let state = if fits { HOME_PART_WORN } else { "truncated" }.to_owned();
            refs.extend(item.rows.iter().map(|(row, revision)| CompactionHomeRef {
                part: item.part.as_str().to_owned(),
                row: Some(*row),
                state: state.clone(),
                revision: *revision,
            }));
        }
        for (part, why) in &self.absent {
            refs.push(CompactionHomeRef {
                part: part.as_str().to_owned(),
                row: None,
                state: format!("absent:{why}"),
                revision: None,
            });
        }
        RenderedHome { text, refs }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
