//! A pumped run's own `describe(self)` (FIX 2086): the self brief of the
//! run's agent, rendered by the self-brief renderer the authenticated path
//! uses ([`super::describe_self_for_auth`]).
//!
//! A pumped run's resident host installs the run's brief in the server's
//! self-brief custody, keyed by the agent and the run's own board
//! connection `run:<run id>`, and keeps it for the run's live run (FIX 17594
//! D3). Once that brief's prefix was delivered, describe(self) is its tail:
//! the state the run resolves now is installed again at the brief's epoch
//! and rendered through that custody, the cached prefix untouched. Before
//! then, and with no installation, the brief is resolved from the run itself
//! and rendered whole: the agent, the person its subject anchor names, the
//! owner's agent Grants that stand for the agent, the run, credential and
//! parent ceilings and the communication limits its host holds the facts
//! for ([`BriefHostFacts`]), the policy's class ceilings, the scratchpad of
//! the session its host binds, the pins its host's board admits now, the
//! result names the run its host binds has bound, the line the run's entry
//! spends on, the clock and the skills the run's own session loaded. Every
//! field no host resolves is left out of the brief and named on one
//! unavailable line ([`oneiron::context_board::SelfBrief::render`]), never
//! stated as a value.

use oneiron::authority::CommReach;
use oneiron::context_board::{
    BriefCredentialCeiling, BriefRunCeiling, BriefWorkingHandle, BriefWorkingSet,
    CommunicationLimits, SelfBriefState, SessionReadSet, StreamConnectionId,
};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::DescribeRequest;

use crate::server::SyncServer;

/// What the host that resolves a brief holds for it (FIX 17594, Engine
/// ruling 21:47), each `None` where it holds none: the run ceiling of the
/// dispatch attempt its run's entry in flight serves, the run whose replay
/// record it bound, the credential ceiling and signed comm reach of the
/// verified slip it admitted, the scratchpad of the session it binds, and
/// the pins its board admits for the reader now. A credential's call is
/// bound to no attempt and no run, so it holds no run ceiling and no replay
/// run; a code-mode durable run is no leased dispatch attempt, so it holds
/// a replay run and no run ceiling (FIX 17594 D5); an ordinary pumped run
/// holds no verified slip, so it holds neither credential value, and binds
/// no scratchpad session.
#[derive(Debug, Default)]
pub(crate) struct BriefHostFacts {
    pub(crate) run_ceiling: Option<BriefRunCeiling>,
    /// The trusted run whose replay record the host bound: the result names
    /// the brief's working set reads. A pumped run's is the run its run
    /// ceiling names; a code-mode run's is its durable run id.
    pub(crate) replay_run: Option<oneiron::EntityId>,
    pub(crate) credential_ceiling: Option<BriefCredentialCeiling>,
    /// The verified slip's comm reach, every caveat met
    /// ([`oneiron::authority::VerifiedSlip::comm`]).
    pub(crate) communication_credential_ceiling: Option<CommReach>,
    /// The working set's scratchpad family as the host read it for the
    /// session it binds ([`scratchpad_family`]).
    pub(crate) scratchpad: Option<Vec<BriefWorkingHandle>>,
    /// The working set's pins family as the host's board projection read it
    /// at describe time ([`brief_pins_family`]).
    pub(crate) pins: Option<Vec<BriefWorkingHandle>>,
}

/// The working set's pins family (FIX 17594, WORKING SET A) from the
/// pins-only MEMORIES a board's own pin projection just read for its reader
/// (`None` when it admitted no row): each pin it admitted and disclosed,
/// with the revision its read served
/// ([`oneiron::MemoriesSection::brief_pin_handles`]), and an empty family
/// when it admitted none. The projection admits and discloses afresh, so no
/// pin a reader can no longer see is shown, and nothing is recorded: the
/// disclosure receipt and the hook deliveries stay with a board that goes
/// out. A row that names no entity logs and leaves the family `None`
/// (unavailable).
pub(crate) fn brief_pins_family(
    section: Option<&oneiron::MemoriesSection>,
) -> Option<Vec<BriefWorkingHandle>> {
    section
        .map_or(Ok(Vec::new()), oneiron::MemoriesSection::brief_pin_handles)
        .inspect_err(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "the self brief's pins did not read; the brief names them unavailable"
            );
        })
        .ok()
}

/// The pins family (FIX 17594, WORKING SET A) of a credential's
/// describe(self) for `session`: the pins the caller's own board for that
/// session carries when its request names no pin list, no room and no
/// branch, read as that board reads them
/// ([`super::board_pins_projection`]): the policy manifest's pins and the
/// rows of the hook blocks that reach the session, under the caller's own
/// read and the disclosure clamp of the caller alone. A read that fails
/// logs and leaves the family `None` (unavailable).
pub(super) fn credential_pins_family(
    server: &SyncServer,
    auth: &crate::auth::CoreAuth,
    session: &str,
) -> Option<Vec<BriefWorkingHandle>> {
    let projected = server
        .vault
        .board_hook_pins(session, None)
        .map_err(|error| crate::api::core_engine_error("board hook blocks failed", error))
        .and_then(|hooks| {
            let read = crate::api::scoped_read_for_core_auth(&server.vault, auth)?;
            let pins = super::BoardPinSources {
                refs: &[],
                manifest: true,
                hooks: &hooks,
            };
            super::board_pins_projection(&server.vault, auth, read, None, &pins)
        });
    match projected {
        Ok(pins) => brief_pins_family(pins.as_ref().map(|pins| &pins.section)),
        Err(error) => {
            tracing::warn!(
                code = ?error.code(),
                "the self brief's pins did not read; the brief names them unavailable"
            );
            None
        }
    }
}

/// The working set's scratchpad family (FIX 17594, WORKING SET A) for
/// `session`, read through `memory`, the host's own surface for the agent:
/// the session's live pad NOTE when the agent's own read admits it, as its
/// board's SCRATCHPAD does, and an empty family when the session has no
/// live pad. A read that fails logs and leaves the family `None`
/// (unavailable). It opens, appends to and seals no pad.
pub(super) fn scratchpad_family(
    memory: &oneiron::memory::Memory<'_>,
    session: &str,
) -> Option<Vec<BriefWorkingHandle>> {
    memory
        .scratchpad_ref(session)
        .inspect_err(|error| {
            tracing::warn!(
                code = %error.code,
                "the self brief's scratchpad did not read; the brief names it unavailable"
            );
        })
        .ok()
        .map(|pad| {
            pad.map(|note| BriefWorkingHandle::ScratchpadNote { note })
                .into_iter()
                .collect()
        })
}

/// Answers a pumped run's `describe(self)` for its agent `actor`, over the
/// run's own board `connection`, its entry spending on `line`: the run's
/// brief with the agent's loaded skills from the run's own session reads,
/// the PEOPLE its own lane reads and the ceilings its door holds the facts
/// for (`host`), and beside it the rows the brief is derived from
/// ([`oneiron::context_board::SelfBrief::sources`]). The wire value is the
/// credential path's `TaskDescription::SelfCard`.
pub(crate) async fn describe_self_for_run(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    connection: &StreamConnectionId,
    line: Option<&RunAdmission>,
    host: &BriefHostFacts,
    request: &DescribeRequest,
) -> MemoryResult<(serde_json::Value, Vec<oneiron::EntityId>)> {
    // describe(self) names the run's own brief and nothing else (FIX 3256).
    request.validate()?;
    if !request.self_target {
        return Err(MemoryError::bad_request(
            "describe(self) names the run's own brief",
        ));
    }
    let people = run_people(server, actor)?;
    let reads = crate::api::run_session_reads(server, actor, connection).await;
    let state = resolved_state(server, actor, line, &reads, host)?;
    let key = (actor.entity_ref(), connection.0.clone());
    let mut briefs = server.self_brief_sessions.lock().await;
    let (tail, sources) = if briefs.acknowledged(&key).is_some() {
        // FIX 17594 D3: the run's delivered brief answers with its tail, from
        // the state the run resolves now, installed again at the brief's
        // epoch; the prefix the run's requests carry stays as it was.
        briefs.restate(&key, state)?;
        let (card, sources) = briefs
            .tail_listing(&key, &server.vault, &reads, Some(&people))
            .transpose()?
            .ok_or_else(|| internal("self brief tail is missing"))?;
        let tail = card
            .tail
            .ok_or_else(|| internal("self brief tail is missing"))?;
        (tail, sources)
    } else {
        drop(briefs);
        let brief = state.describe(&server.vault, &reads, Some(&people))?;
        let sources = brief.sources(&server.vault, Some(&people))?;
        (brief.render(), sources)
    };
    let value = serde_json::to_value(oneiron::task_verb::TaskDescription::SelfCard { tail })
        .map_err(|_| internal("self brief encoding failed"))?;
    Ok((value, sources))
}

/// The run's brief state as the run itself resolves it for its agent
/// `actor`, with the ceilings its host holds the facts for (`host`). Each
/// field no host produces for a run (FIX-LIST: the self-brief producers) is
/// `None`; so is the principal when no subject anchor names the person
/// behind the agent, so are the grants, the parent ceiling, the comm reach
/// and the class ceilings when their read fails, so are the run and parent
/// ceilings and the comm reach when the host bound no dispatch attempt, so
/// are the replay bindings when the host bound no replay run, the run holds
/// no replay record or its read fails, so are the credential ceiling and the
/// credential's comm reach when it verified no slip, so is the scratchpad
/// when it binds no session, so are the pins when its board's pin read
/// fails, and so are the budget lease and budget when no line binds the
/// run's entry.
/// [`oneiron::context_board::SelfBrief::render`] leaves each `None` field
/// out and names it unavailable. A credentialed agent's describe(self) with
/// no installed snapshot resolves its brief here too, over its own
/// session's reads and with no line (FIX 11461).
pub(super) fn resolved_state(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    line: Option<&RunAdmission>,
    reads: &SessionReadSet,
    host: &BriefHostFacts,
) -> MemoryResult<SelfBriefState> {
    let self_ref = actor.entity_ref();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let clock_ms = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
    // Subject anchors are dated in milliseconds, as PEOPLE reads them.
    let principal =
        oneiron::subject_model::actor_subject_anchor(&server.vault, &self_ref, clock_ms)?;
    // The skills the run's own session loaded, each one whose record
    // stands: a brief describes a skill from its record.
    let mut skill_index = Vec::new();
    for (id, _) in reads.loaded_skills() {
        let Ok(id) = oneiron::EntityId::from_hex(id) else {
            continue;
        };
        if !skill_index.contains(&id) && server.vault.get_skill_record(&id)?.is_some() {
            skill_index.push(id);
        }
    }
    // GRANT (FIX 17594): the owner's agent Grants that stand for the agent,
    // read in one snapshot. A failed read leaves them unavailable; it never
    // fails the describe.
    let grants = server
        .vault
        .self_brief_grants(actor)
        .inspect_err(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "the self brief's grants did not read; the brief names them unavailable"
            );
        })
        .ok();
    // PARENT (FIX 17594): each delegation ancestor of the attempt the host
    // bound the run to, read in one snapshot. A host bound to no attempt has
    // no chain to read; a failed read leaves it unavailable.
    let parent_ceiling = host.run_ceiling.as_ref().and_then(|run| {
        server
            .vault
            .self_brief_parent_ceiling(actor, run.attempt)
            .inspect_err(|error| {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the self brief's parent ceiling did not read; the brief names it unavailable"
                );
            })
            .ok()
            .flatten()
    });
    // COMM (FIX 17594): the reach the run the host bound addresses with
    // now, read in one snapshot of its exact attempt. A host bound to no
    // attempt has no run reach; a failed read leaves it unavailable.
    let reach = host.run_ceiling.as_ref().and_then(|run| {
        server
            .vault
            .self_brief_comm_reach(actor, run.attempt)
            .inspect_err(|error| {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the self brief's comm reach did not read; the brief names it unavailable"
                );
            })
            .ok()
            .flatten()
    });
    // CLASSES (FIX 17594): the concrete class ceilings the resolved policy
    // holds for the agent and its live definition ceiling, dated, read in
    // one snapshot. Class verdicts stay unavailable. A failed read leaves
    // the ceilings unavailable.
    let ceilings = server
        .vault
        .self_brief_ceilings(actor)
        .inspect_err(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "the self brief's class ceilings did not read; the brief names them unavailable"
            );
        })
        .ok();
    // WORKING SET (FIX 17594): the result names the run the host bound has
    // bound, read from that run's replay record. Only a host-bound run is a
    // trusted run identity: a session label proves no replay ownership. The
    // executor writes the record before the run's first step, so a run with
    // no record is unavailable, never known empty.
    let replay = host.replay_run.and_then(|run_id| {
        let bindings = server
            .vault
            .code_run_result_bindings(&run_id)
            .inspect_err(|error| {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the self brief's replay bindings did not read; it names them unavailable"
                );
            })
            .ok()
            .flatten()?;
        Some(
            bindings
                .into_iter()
                .map(|binding| BriefWorkingHandle::ReplayResult {
                    run_id,
                    name: binding.name,
                    handle: binding.handle,
                    path: binding.path,
                })
                .collect::<Vec<_>>(),
        )
    });
    Ok(SelfBriefState {
        self_ref,
        principal,
        grants,
        run_ceiling: host.run_ceiling.clone(),
        credential_ceiling: host.credential_ceiling.clone(),
        parent_ceiling,
        communication: CommunicationLimits {
            reach,
            credential_ceiling: host.communication_credential_ceiling,
        },
        ceilings,
        budget_lease_id: line.map(|line| line.run().to_owned()),
        budget: line.map(RunAdmission::read),
        clock_ms,
        skill_index,
        working_set: BriefWorkingSet {
            scratchpad: host.scratchpad.clone(),
            pins: host.pins.clone(),
            replay,
        },
    })
}

/// [`resolved_state`] for a host outside the context board: a pumped run's
/// brief state as the run resolves it now, for its agent `actor`, its entry
/// spending on `line`, over the run's own session `reads`, with the facts
/// its door holds (`host`). A resident run's port installs it (FIX 17594
/// D3).
///
/// # Errors
///
/// As [`resolved_state`].
pub(crate) fn run_brief_state(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    line: Option<&RunAdmission>,
    reads: &SessionReadSet,
    host: &BriefHostFacts,
) -> MemoryResult<SelfBriefState> {
    resolved_state(server, actor, line, reads, host)
}

/// [`run_people`] for a host outside the context board: the PEOPLE a pumped
/// run's self brief lays its roster out from, as its describe(self) reads
/// them (FIX 17594 D3).
///
/// # Errors
///
/// As [`run_people`].
pub(crate) fn run_brief_people(
    server: &SyncServer,
    actor: oneiron::WriteActor,
) -> MemoryResult<oneiron::context_board::People> {
    run_people(server, actor)
}

/// The vault's people as the agent's own lane on this device reads them
/// ([`read_people`]).
fn run_people(
    server: &SyncServer,
    actor: oneiron::WriteActor,
) -> MemoryResult<oneiron::context_board::People> {
    let key = oneiron::claim::ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or_else(|| internal("run actor key invalid"))?;
    let read = server
        .vault
        .scoped_read(key.at(oneiron::claim::CallerLocality::OnDevice));
    read_people(server, &read)
}

/// The vault's people as `read` reads them, each `about` the stored line of
/// the highest band that read reads, and the names it may be told
/// disclosed.
pub(super) fn read_people(
    server: &SyncServer,
    read: &oneiron::claim::ScopedRead<'_>,
) -> MemoryResult<oneiron::context_board::People> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    let mut people = oneiron::context_board::People::load(&server.vault, now, &mut |person| {
        read.is_entity_readable(&person)
    })?;
    let applied = read.read_receipt(None, 0)?.applied;
    let ceiling = (!applied.deny_all).then_some(applied.max_sensitivity_band);
    people.set_about(&mut |person| server.vault.person_about_sourced(person, ceiling))?;
    people.disclose_names(&server.vault, read.actor_key())?;
    Ok(people)
}

fn internal(message: &str) -> MemoryError {
    MemoryError::new(
        oneiron::memory::MEMORY_CODE_INTERNAL,
        message,
        &["Report this host-door failure."],
    )
}
