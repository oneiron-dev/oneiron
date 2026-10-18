//! A plain call's resume target (ARCH-0080 §3 Ask): a call no credential
//! came in on, which settlement runs again as its caller made it.
//!
//! The ask saves what the caller's handle carried that the drain rebuilds:
//! its sitting, its room turn's room, its read placement, whether a
//! transport reached it and its origin conversation. In the ask's own write
//! it saves the authority the call is asked under: the vault's owner by the
//! one owner resolver, with the guard of the host action it came through,
//! or any other actor by every live Grant naming it, at its revision, and the
//! ceiling the gate projects for it. Before it calls, the drain proves that
//! authority again: the owner still a live owner and the guard still
//! standing, or the same Grants at the same revisions under the same
//! ceiling. Anything else ends the call refused, never run narrower or
//! wider, and nothing waits for revoked authority to come back.
//!
//! Where the caller sits admits and refuses nothing here. It is kept only
//! so the resumed call reads what the call itself would have read
//! (DEC-0005). A handle the drain cannot rebuild saves no target, wherever
//! it runs: its caller's retry resumes it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::claim::CallerLocality;
use crate::error::ClaimError;
use crate::memory::{
    MEMORY_CODE_HOST_ACTION_REFUSED, MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError, MemoryResult,
};
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_FEDERATION_GRANT};
use crate::session_lifecycle::SessionKey;
use crate::{EdgeActorClass, EntityId, Error, Result, Vault};

use super::state::DrainScope;
use super::{InvocationId, VerbAskRefusal, VerbCall, VerbResume};

/// Context of one Grant row's revision digest.
const PLAIN_GRANT_REVISION: &str = "oneiron verb hook plain grant revision v1";
/// Context of the ceiling digest a delegated call is asked under.
const PLAIN_CEILING: &str = "oneiron verb hook plain ceiling v1";

/// How settlement runs a plain call again ([`VerbResume::Row`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlainRowResume {
    caller: PlainCaller,
    /// The host action the call came through, if any.
    host_action: Option<PlainHostAction>,
    /// The authority the ask's write read for the call; `None` until an ask
    /// saves it.
    authority: Option<PlainAuthority>,
}

/// What the caller's handle carried, as the drain rebuilds it. A retry of
/// the call presents the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PlainCaller {
    session: Option<SessionKey>,
    room: Option<EntityId>,
    placement: ReadPlacement,
    /// A transport's caller with no credential: rebuilt as one, so the
    /// drain never runs it as the host's own.
    transport: bool,
    origin_conversation: Option<EntityId>,
}

/// Where the caller read from (DEC-0005), kept so the resumed call reads
/// what the call would have read. It admits and refuses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReadPlacement {
    OnDevice,
    OffDevice,
}

impl From<CallerLocality> for ReadPlacement {
    fn from(locality: CallerLocality) -> Self {
        match locality {
            CallerLocality::OnDevice => Self::OnDevice,
            CallerLocality::OffDevice => Self::OffDevice,
        }
    }
}

impl From<ReadPlacement> for CallerLocality {
    fn from(placement: ReadPlacement) -> Self {
        match placement {
            ReadPlacement::OnDevice => Self::OnDevice,
            ReadPlacement::OffDevice => Self::OffDevice,
        }
    }
}

/// The guard of the host action (FIX 2222) an owner's call came through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlainHostAction {
    /// The explicit local dev mode.
    Dev,
    /// A self-hosted host root, by its slip's id.
    Root { slip: [u8; 32] },
}

/// The authority a plain call was asked under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlainAuthority {
    /// The vault's owner, a person acting as themself.
    Owner { person: EntityId },
    /// Any other actor: each live Grant naming it, by id and revision, and
    /// the ceiling the gate projects for it.
    Delegated {
        grants: Vec<PlainGrant>,
        ceiling: [u8; 32],
    },
}

/// One live Grant row naming the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PlainGrant {
    id: EntityId,
    revision: [u8; 32],
}

/// Why the drain ended a plain call before it ran. Each ends the call: an
/// authority given again starts a new invocation.
#[derive(Debug, Clone, Copy)]
enum PlainRefusal {
    /// The person the call was asked as is no longer a live owner.
    OwnerNotLive,
    /// The vault is no longer self-hosted: no host action acts as its owner.
    HostActionHosted,
    /// The host action the call came through no longer acts as the owner.
    HostActionLapsed,
    /// A Grant the call was asked under is revoked, past its lifetime or gone.
    GrantLapsed,
    /// The caller's Grants or ceiling are not what they were at the ask.
    AuthorityChanged,
    /// The saved authority does not name this call's caller.
    ContextUnavailable,
}

impl PlainRefusal {
    /// The error the call ends with, under an existing stable code. It is
    /// never the engine's internal one, so the drain saves it and the call
    /// ends.
    fn error(self) -> MemoryError {
        let (code, reason) = match self {
            Self::OwnerNotLive => (
                MEMORY_CODE_OWNER_BINDING_REQUIRED,
                "the person it was asked as is no longer a live owner of this vault",
            ),
            Self::HostActionHosted => (
                MEMORY_CODE_HOST_ACTION_REFUSED,
                "the vault is no longer self-hosted, so the host action it came through acts as no one",
            ),
            Self::HostActionLapsed => (
                MEMORY_CODE_OWNER_BINDING_REQUIRED,
                "the host action it came through no longer acts as the owner",
            ),
            Self::GrantLapsed => (
                VerbAskRefusal::ScopeRefused.code(),
                "a grant it was asked under was revoked, ran out or is gone",
            ),
            Self::AuthorityChanged => (
                VerbAskRefusal::ScopeRefused.code(),
                "its caller's grants or ceiling changed since it was asked",
            ),
            Self::ContextUnavailable => (
                VerbAskRefusal::ContextUnavailable.code(),
                "the authority saved with it does not name its caller",
            ),
        };
        MemoryError::new(
            code,
            format!("settlement did not run this call: {reason}"),
            &["Call again with a new invocation, under the authority that stands now."],
        )
    }
}

impl PlainRowResume {
    /// The target of a plain call on a handle the drain can rebuild
    /// (`Memory::plain_resume`): its sitting, its room turn's room, where it
    /// reads from, whether a transport reached it, its origin conversation
    /// and the host action it came through. Its authority is read when an
    /// ask saves it.
    pub(crate) fn of(
        session: Option<SessionKey>,
        room: Option<EntityId>,
        locality: CallerLocality,
        transport: bool,
        origin_conversation: Option<EntityId>,
        host_action: Option<&crate::authority::HostActionAuthority>,
    ) -> Self {
        Self {
            caller: PlainCaller {
                session,
                room,
                placement: locality.into(),
                transport,
                origin_conversation,
            },
            host_action: host_action.map(|action| match action.guard().root_slip_id() {
                Some(slip) => PlainHostAction::Root { slip },
                None => PlainHostAction::Dev,
            }),
            authority: None,
        }
    }

    /// Whether a call presenting `call` is the call this target was saved
    /// for: the same handle, whatever authority the ask read for it.
    pub(super) fn same_caller(&self, call: &Self) -> bool {
        self.caller == call.caller
    }
}

/// The target an ask saves for `resume`, in the ask's own write `txn`: a
/// plain call's carries the authority it is asked under, read there. A plain
/// call whose authority does not read saves none and resumes on its caller's
/// retry. Any other target passes as it is.
pub(super) fn retain_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    call: &VerbCall,
    resume: Option<VerbResume>,
) -> Option<VerbResume> {
    let mut plain = match resume {
        Some(VerbResume::Row(plain)) => plain,
        other => return other,
    };
    let class = super::super::filter::edge_class(call.class);
    match authority_in_txn(vault, txn, call.actor, class, plain.host_action.is_some()) {
        Ok(authority) => {
            plain.authority = authority;
            plain.authority.is_some().then_some(VerbResume::Row(plain))
        }
        Err(error) => {
            tracing::warn!(%error, "a plain call's authority did not read: it resumes on its caller's retry");
            None
        }
    }
}

/// Runs a ready plain call again as its caller (`Vault::drain_verb_asks`).
/// The authority its ask saved is proved again first. Then the native
/// handle is rebuilt with the call's invocation, sitting, read placement,
/// transport mark and origin conversation, and the generated dispatcher runs
/// the row, in its room's turn when it had one, whose current terms admit it
/// again or refuse it. A saved authority that no longer stands ends the call
/// refused before anything runs.
///
/// # Errors
///
/// Storage errors reading that authority: the call waits for the next pass.
pub(super) fn run(
    vault: &Vault,
    invocation: InvocationId,
    verb: &str,
    actor: EntityId,
    class: EdgeActorClass,
    args: Value,
    plain: PlainRowResume,
) -> Result<MemoryResult<Value>> {
    let refusal = {
        let txn = vault.store.env.read_txn()?;
        match &plain.authority {
            Some(authority) => {
                authority.refusal_in_txn(vault, &txn, actor, class, plain.host_action)?
            }
            None => Some(PlainRefusal::ContextUnavailable),
        }
    };
    if let Some(refusal) = refusal {
        return Ok(Err(refusal.error()));
    }
    let PlainCaller {
        session,
        room,
        placement,
        transport,
        origin_conversation,
    } = plain.caller;
    let mut memory = vault
        .memory(actor, class)
        .with_invocation(invocation)
        .at(placement.into());
    if let Some(session) = session {
        memory = memory.with_session(session);
    }
    if transport {
        memory = memory.with_transport_invocation();
    }
    if let Some(conversation) = origin_conversation {
        memory = memory.with_origin_conversation(conversation);
    }
    let _draining = DrainScope::enter(invocation);
    Ok(match room {
        Some(room) => memory
            .for_room_turn(room)
            .and_then(|turn| turn.invoke(verb, args)),
        None => crate::task_verb::sdk::invoke(&memory, verb, args),
    })
}

/// The authority a call by `actor` is asked under, read in `txn`: the owner
/// when the one owner resolver names this person, else every live Grant
/// naming the actor and the ceiling the gate projects for it. `None` for a
/// call through a host action whose actor is no live owner: a host action
/// acts only as the owner.
fn authority_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    host_action: bool,
) -> Result<Option<PlainAuthority>> {
    if class == EdgeActorClass::Human
        && crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)?
    {
        return Ok(Some(PlainAuthority::Owner { person: actor }));
    }
    if host_action {
        return Ok(None);
    }
    Ok(Some(PlainAuthority::Delegated {
        grants: grants_in_txn(vault, txn, actor)?,
        ceiling: ceiling_in_txn(vault, txn, actor, class)?,
    }))
}

impl PlainAuthority {
    /// Why this saved authority no longer stands for `actor` in `txn`, or
    /// `None` when it does.
    fn refusal_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        host_action: Option<PlainHostAction>,
    ) -> Result<Option<PlainRefusal>> {
        match self {
            Self::Owner { person } => {
                if *person != actor || class != EdgeActorClass::Human {
                    return Ok(Some(PlainRefusal::ContextUnavailable));
                }
                if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, person)? {
                    return Ok(Some(PlainRefusal::OwnerNotLive));
                }
                match host_action {
                    Some(action) => action.refusal_in_txn(vault, txn, *person),
                    None => Ok(None),
                }
            }
            Self::Delegated { grants, ceiling } => {
                let held = grants_in_txn(vault, txn, actor)?;
                if grants
                    .iter()
                    .any(|saved| held.iter().all(|grant| grant.id != saved.id))
                {
                    return Ok(Some(PlainRefusal::GrantLapsed));
                }
                let changed =
                    held != *grants || ceiling_in_txn(vault, txn, actor, class)? != *ceiling;
                Ok(changed.then_some(PlainRefusal::AuthorityChanged))
            }
        }
    }
}

impl PlainHostAction {
    /// Why this guard no longer stands for `person` in `txn`, or `None`
    /// when it does: the one host-action owner rule (a self-hosted vault,
    /// the owner-verb rule, a live PERSON) still names them, and a host
    /// root's slip is still live (revocation, lifetime and its signers,
    /// checked by its id as a session's later frames are).
    fn refusal_in_txn(
        self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<Option<PlainRefusal>> {
        let owner = match vault.host_action_owner_in_txn(txn, None) {
            Ok(owner) => owner,
            Err(Error::HostActionRequiresSupportGrant) => {
                return Ok(Some(PlainRefusal::HostActionHosted));
            }
            Err(Error::Claim(ClaimError::ScopedReadOwnerNotLive(_))) => {
                return Ok(Some(PlainRefusal::HostActionLapsed));
            }
            Err(error) => return Err(error),
        };
        let root_live = match self {
            Self::Dev => true,
            Self::Root { slip } => vault.capability_slip_id_is_live_in_txn(txn, &slip)?,
        };
        Ok((owner != person || !root_live).then_some(PlainRefusal::HostActionLapsed))
    }
}

/// Every live Grant naming `actor` in `txn`, at its revision, in id order:
/// the federation grants that confer on it now under their pact, and the
/// access grants active for it now.
fn grants_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, actor: EntityId) -> Result<Vec<PlainGrant>> {
    let now = vault.store.clock.now_recorded_at();
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    let mut grants = Vec::new();
    for kind in [ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ACCESS_GRANT] {
        for entry in
            crate::ports::EntityStoreRead::port_entity_ids_by_type(&vault.store, txn, kind, None)?
        {
            let id = entry?;
            let crate::vault::LiveEntityRow::Live { entity_type, body } =
                crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?
            else {
                continue;
            };
            if entity_type != kind {
                continue;
            }
            let names = if kind == ENTITY_TYPE_FEDERATION_GRANT {
                crate::federation::decode_federation_grant_body(&body).is_ok_and(|grant| {
                    grant.member_ref == actor
                        && grant.confers_at(now)
                        && crate::federation::pact_admits_grant(&fold, &id, &grant)
                })
            } else {
                crate::access_grant::decode_access_grant_body(&body).is_ok_and(|grant| {
                    grant.principal_ref == actor
                        && grant.effective_status_at(now)
                            == crate::access_grant::AccessGrantStatus::Active
                })
            };
            if names {
                grants.push(PlainGrant {
                    id,
                    revision: revision(kind, &id, &body),
                });
            }
        }
    }
    grants.sort_unstable_by_key(|grant| grant.id);
    Ok(grants)
}

/// One Grant row's revision: a digest of its type, id and stored body.
fn revision(kind: u8, id: &EntityId, body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PLAIN_GRANT_REVISION);
    hasher.update(&[kind]);
    hasher.update(id.as_bytes());
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

/// The ceiling the gate projects for `actor` in `txn`, as a digest: its
/// approval ceiling (the owner's actor-ceiling rows for it, met with its
/// own definition's bound, as a task actor's ceiling is) and the authority
/// bindings it holds.
fn ceiling_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    class: EdgeActorClass,
) -> Result<[u8; 32]> {
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let projected = policy.actor_ceiling(class.gate_actor_class(), Some(actor.to_hex().as_str()));
    let ceiling = crate::gate::agent_definition_ceiling_for_actor(
        &vault.store,
        txn,
        crate::WriteActor::new(actor, class),
    )
    .map_or(projected, |definition| {
        crate::gate::dispatched_agent_effective_ceiling(definition, projected)
    });
    let mut hasher = blake3::Hasher::new_derive_key(PLAIN_CEILING);
    hasher.update(actor.as_bytes());
    hasher.update(class.gate_actor_class().as_bytes());
    hasher.update(&[u8::from(
        ceiling == crate::gate::PolicyApprovalCeiling::Auto,
    )]);
    if let Some(generation) = vault.actor_binding_generation_in_txn(txn, actor)? {
        for binding in generation.bindings() {
            hasher.update(binding);
        }
    }
    Ok(*hasher.finalize().as_bytes())
}
