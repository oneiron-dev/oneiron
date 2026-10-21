//! Scoped children (FIX 7507 PR2): a separate code-mode agent a host queues
//! on the reader-job machinery, holding only what its parent lends it.
//!
//! A scoped child is a reader child with a loan: the exact result
//! occurrences and ranges of its parent it reads (`src`, its primary input,
//! and every other input by its name), the [`Scope`] its model calls carry,
//! and an exact set of registered ports, each an SDK verb by its canonical
//! name. Nothing else is lent: no ambient read, no write but a lent port's,
//! no child of its own. The ordinary read child and the summary keep their
//! own rules; a scoped child is a new binding, not a relaxed read child.
//!
//! The loan is host-made ([`ScopedChildLoan::from_parent`]): no guest call
//! constructs one, and it carries no credential. Its authority is its parent
//! actor's own standing (a live person, or a live agent one live Grant of
//! the owner's stands for), re-resolved at every port call and every read of
//! what it was lent ([`scoped_child_authority`]), never where anyone runs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::dispatcher::ReaderChildBinding;
use crate::code_run::{
    AgentVerbAnswer, AgentVerbRefusal, DelegatedSource, HostSelfDispatcher, ReaderJob, ReaderRoute,
    SelfAgentVerbCall, valid_reader_key, vault_ref,
};
use crate::llm::Scope;
use crate::memory::HostWriteOrigin;
use crate::runtime_hooks::InvocationId;
use crate::task_verb::sdk::AgentVerb;
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// The name a reader child, read or scoped, reads its primary input by.
pub(crate) const READER_SOURCE_NAME: &str = "src";

/// The refusal a scoped child's verb call gets when its loan did not lend
/// that verb by name (`scoped_child_call_allowed`).
pub const SCOPED_CHILD_PORT_NOT_LENT: &str = "scoped_child_port_not_lent";

/// The refusal a scoped child's lent verb gets when no adapter its host
/// registered serves it (`scoped_child_service_admission`): the job reports
/// it and never runs as a read child in its place.
pub const SCOPED_CHILD_SERVICE_UNBOUND: &str = "scoped_child_service_unbound";

/// The refusal every call of a scoped child gets once its parent actor no
/// longer stands (`scoped_child_authority`).
pub const SCOPED_CHILD_AUTHORITY_LAPSED: &str = "scoped_child_authority_lapsed";

/// A loan whose resource scope is wider than the bound its parent holds.
const SCOPED_CHILD_SCOPE_WIDENS: &str = "scoped_child_scope_widens";

/// A loan input that is not one of its parent's own committed, clean result
/// occurrences inside its body, or a loan with no `src`.
const SCOPED_CHILD_INPUT_UNKNOWN: &str = "scoped_child_input_unknown";

/// The verb a scoped child's authority stands under: it reads what its
/// parent lent it. A lent port's own verb is its adapter's to rule on.
const SCOPED_CHILD_AUTHORITY_VERB: &str = "read";

/// What a scoped child is lent, as its job row keeps it: its named inputs,
/// each one of its parent's result occurrences and the range of it the child
/// may read, in its parent's offsets (`src`, its primary input, among them);
/// the resource scope its model calls carry; and the exact SDK verbs it may
/// call, each by its canonical name. Metadata only: no input's bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedChildSpec {
    pub inputs: BTreeMap<String, DelegatedSource>,
    pub scope: Scope,
    pub ports: BTreeSet<String>,
}

impl ScopedChildSpec {
    /// Its primary input, `src`.
    pub(crate) fn source(&self) -> Option<&DelegatedSource> {
        self.inputs.get(READER_SOURCE_NAME)
    }

    /// The first lent port none of `ports` serves, if any: a job that lends
    /// it reports `scoped_child_service_unbound` before any call.
    #[must_use]
    pub fn unbound_port(&self, ports: Option<&dyn ScopedChildPorts>) -> Option<&str> {
        self.ports.iter().map(String::as_str).find(|name| {
            AgentVerb::from_name(name)
                .is_none_or(|verb| scoped_child_service_admission(ports, verb).is_err())
        })
    }
}

/// A host's loan to one scoped child: the parent run and actor it is lent
/// from, the route the parent runs on, and the spec it validated. Only
/// [`Self::from_parent`] makes one; it is never serialized and carries no
/// credential.
#[derive(Debug, Clone)]
pub struct ScopedChildLoan {
    pub(super) parent_run: EntityId,
    pub(super) actor: WriteActor,
    pub(super) route: ReaderRoute,
    pub(super) spec: ScopedChildSpec,
}

impl ScopedChildLoan {
    /// The loan `parent`, the dispatcher its host bound to run `parent_run`,
    /// makes of `requested`, under the resource `bound` and the ports
    /// `allowed` its host holds for it. The actor and route are the
    /// dispatcher's own, never an argument's. It holds only while:
    /// - the parent actor stands (`scoped_child_authority`);
    /// - every requested port is an SDK verb named in `allowed`;
    /// - the requested scope narrows `bound` ([`Scope::attenuate`]);
    /// - `src` is among the inputs, and every input is one of `parent_run`'s
    ///   own committed results, clean now, its range inside its body.
    ///
    /// The answer's `Err` names the first that does not.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when `vault` is not the vault `parent`'s
    /// route is on; the route's own read errors.
    pub fn from_parent(
        vault: &Vault,
        parent: &HostSelfDispatcher<'_>,
        parent_run: EntityId,
        bound: &Scope,
        allowed: &BTreeSet<String>,
        requested: ScopedChildSpec,
    ) -> Result<std::result::Result<Self, &'static str>> {
        if vault.vault_id() != parent.vault_id() {
            return Err(Error::InvalidConfig(
                "a scoped loan's vault is not its parent's".to_owned(),
            ));
        }
        let actor = parent.actor();
        if !principal_stands(vault, actor)? {
            return Ok(Err(SCOPED_CHILD_AUTHORITY_LAPSED));
        }
        let lent = requested
            .ports
            .iter()
            .all(|name| AgentVerb::from_name(name).is_some() && allowed.contains(name));
        if !lent {
            return Ok(Err(SCOPED_CHILD_PORT_NOT_LENT));
        }
        if bound.attenuate(requested.scope.clone()).is_err() {
            return Ok(Err(SCOPED_CHILD_SCOPE_WIDENS));
        }
        if requested.source().is_none() {
            return Ok(Err(SCOPED_CHILD_INPUT_UNKNOWN));
        }
        let record = parent.storage.get_code_run_replay_record(&parent_run)?;
        for (name, input) in &requested.inputs {
            let Some(output) = record.as_ref().and_then(|record| {
                record
                    .outputs
                    .iter()
                    .find(|output| output.path == input.path && output.handle == input.handle)
            }) else {
                return Ok(Err(SCOPED_CHILD_INPUT_UNKNOWN));
            };
            let (start, end) = input.range;
            if !valid_reader_key(name)
                || input.owner != parent_run
                || start > end
                || end > output.raw_len
            {
                return Ok(Err(SCOPED_CHILD_INPUT_UNKNOWN));
            }
            if parent
                .storage
                .code_run_result_taint(Some(parent_run), output)?
                .0
                .is_tainted()
            {
                return Ok(Err(SCOPED_CHILD_INPUT_UNKNOWN));
            }
        }
        Ok(Ok(Self {
            parent_run,
            actor,
            route: ReaderRoute {
                vault: vault_ref(parent.vault_id()),
                session_ref: parent.session_ref().map(str::to_owned),
                participant: parent.participant(),
            },
            spec: requested,
        }))
    }
}

/// The ports a host registers for scoped children: an exact dispatch of SDK
/// verbs, each run by an adapter of the host's, never an unrestricted vault
/// or a generic proxy. A verb it does not name is unbound; there is no
/// wildcard.
pub trait ScopedChildPorts: Send + Sync {
    /// Whether this host serves `verb`.
    fn serves(&self, verb: AgentVerb) -> bool;

    /// Runs one lent port call, `call`, for the scoped child `ctx` holds,
    /// under the run's own write origin and the call's step invocation. The
    /// dispatcher checked the lent verb, this host's registration, the
    /// child's authority and its job first, and keeps a write's receipt on
    /// the child's route. Every input the adapter reads goes through `ctx`,
    /// so a ref nested in the call's input reaches only what was lent.
    ///
    /// # Errors
    ///
    /// As [`crate::code_run::AgentVerbDoor::call`]'s: a verb hook's stop, or
    /// a model call no provider answered; every refusal is the inner one.
    fn call(
        &self,
        ctx: &ScopedChildCallContext<'_, '_>,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>>;
}

/// What a port adapter is handed for one call of a scoped child: the
/// child's job, read on its own route. It reads the child's named inputs
/// with every check a read of them takes, and nothing else: no vault, no
/// storage and no other result.
pub struct ScopedChildCallContext<'c, 'a> {
    dispatcher: &'c HostSelfDispatcher<'a>,
    child: &'c ReaderChildBinding,
    spec: &'c ScopedChildSpec,
}

/// One lent input as a port read it: its name, its handle, the range read,
/// the rows its parent's read of it was checked against (`None` when one
/// answer kept no set), and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedInputRead {
    pub name: String,
    pub handle: String,
    pub range: (u64, u64),
    pub rows: Option<Vec<EntityId>>,
    pub text: String,
}

impl<'c, 'a> ScopedChildCallContext<'c, 'a> {
    pub(crate) const fn new(
        dispatcher: &'c HostSelfDispatcher<'a>,
        child: &'c ReaderChildBinding,
        spec: &'c ScopedChildSpec,
    ) -> Self {
        Self {
            dispatcher,
            child,
            spec,
        }
    }
}

impl ScopedChildCallContext<'_, '_> {
    /// The child's task.
    #[must_use]
    pub const fn task(&self) -> EntityId {
        self.child.task
    }

    /// The generation its runner claimed it at.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.child.generation
    }

    /// The actor its parent runs as, which its writes are stamped with.
    #[must_use]
    pub const fn actor(&self) -> WriteActor {
        self.dispatcher.actor()
    }

    /// The resource scope its loan lent it.
    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.spec.scope
    }

    /// The lent input `reference` names, by its name or its handle, read as
    /// a read of it is while the job is live: in its owner's committed
    /// record, clean now, inside its range, released by the child's door.
    /// Any other reference names nothing (`scoped_child_input`). The
    /// answer's `Err` is the read's refusal code.
    ///
    /// # Errors
    ///
    /// The route's own read errors.
    pub fn read_input(
        &self,
        reference: &str,
    ) -> Result<std::result::Result<ScopedInputRead, &'static str>> {
        let Some((name, source)) = scoped_child_input(self.spec, true, reference)
            .or_else(|| scoped_child_input(self.spec, false, reference))
        else {
            return Ok(Err("unknown_handle"));
        };
        if !self.dispatcher.reader_job_live()? {
            return Ok(Err("reader_task_settled"));
        }
        let storage = &self.dispatcher.storage;
        let Some(output) = storage
            .get_code_run_replay_record(&source.owner)?
            .and_then(|record| {
                record
                    .outputs
                    .into_iter()
                    .find(|output| output.path == source.path && output.handle == source.handle)
            })
        else {
            return Ok(Err("input_gone"));
        };
        let (start, end) = source.range;
        if start > end || end > output.raw_len {
            return Ok(Err("outside_delegated_range"));
        }
        if storage
            .code_run_result_taint(Some(source.owner), &output)?
            .0
            .is_tainted()
        {
            return Ok(Err("tainted"));
        }
        if !matches!(
            self.dispatcher.withholds_retained(source.rows.as_deref()),
            Ok(false)
        ) {
            return Ok(Err("result_withheld"));
        }
        let len = usize::try_from(end - start)
            .map_err(|_| Error::ArithmeticOverflow("scoped input length"))?;
        let bytes = storage
            .read_code_run_raw_output_range(&output, start, len)?
            .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
        // A body stored before its scan read every rule may hold a secret no
        // mark names (OF-067); no port is shown any of it.
        if crate::batch::secret_scan::write_payload_hit(&bytes).is_some() {
            return Ok(Err("tainted"));
        }
        Ok(Ok(ScopedInputRead {
            name: name.to_owned(),
            handle: source.handle.clone(),
            range: source.range,
            rows: source.rows.clone(),
            text: String::from_utf8_lossy(&bytes).into_owned(),
        }))
    }
}

/// `scoped_child_call_allowed` (CALLS, open): a scoped child may call
/// `verb` exactly when its loan lent it by its canonical name. An empty set
/// lends none: no default tagger, decision, write, search or spawn.
pub(crate) fn scoped_child_call_allowed(spec: &ScopedChildSpec, verb: AgentVerb) -> bool {
    spec.ports.contains(verb.as_str())
}

/// `scoped_child_service_admission` (CALLS, open): the adapter a lent
/// `verb` runs on, when the host's `ports` serve it; otherwise the typed
/// `scoped_child_service_unbound`, never a fallback to the host's own door.
pub(crate) fn scoped_child_service_admission(
    ports: Option<&dyn ScopedChildPorts>,
    verb: AgentVerb,
) -> std::result::Result<&dyn ScopedChildPorts, AgentVerbRefusal> {
    ports
        .filter(|ports| ports.serves(verb))
        .ok_or_else(|| AgentVerbRefusal {
            code: SCOPED_CHILD_SERVICE_UNBOUND.to_owned(),
        })
}

/// `scoped_child_input` (CALLS, open): the lent input `reference` names, by
/// its name (`by_name`) or by its handle, with the name it is read by. Only
/// the job's named inputs resolve; no other handle of the parent's does.
pub(crate) fn scoped_child_input<'s>(
    spec: &'s ScopedChildSpec,
    by_name: bool,
    reference: &str,
) -> Option<(&'s str, &'s DelegatedSource)> {
    if by_name {
        return spec
            .inputs
            .get_key_value(reference)
            .map(|(name, source)| (name.as_str(), source));
    }
    spec.inputs
        .iter()
        .find(|(_, source)| source.handle == reference)
        .map(|(name, source)| (name.as_str(), source))
}

/// `scoped_child_authority` (CALLS, open): whether scoped job `job`'s
/// authority stands now in `vault`: its parent actor, re-resolved in this
/// snapshot as a live person, or a live agent one live Grant of the owner's
/// stands for under `read` (`authority::principal_standing_in_txn`). A job
/// in another vault, one that is not scoped, and an actor that is missing,
/// retired or revoked never stand: the answer's `Err` is
/// [`SCOPED_CHILD_AUTHORITY_LAPSED`], never an open default. Where the
/// actor or the vault runs is never asked.
///
/// # Errors
///
/// A store, fold or clock failure of the standing check.
pub fn scoped_child_authority(
    vault: &Vault,
    job: &ReaderJob,
) -> Result<std::result::Result<(), &'static str>> {
    if job.scoped_spec().is_none() || job.binding.route.vault != vault_ref(vault.vault_id()) {
        return Ok(Err(SCOPED_CHILD_AUTHORITY_LAPSED));
    }
    let actor = job.binding.actor.write_actor()?;
    Ok(if principal_stands(vault, actor)? {
        Ok(())
    } else {
        Err(SCOPED_CHILD_AUTHORITY_LAPSED)
    })
}

/// Whether `actor` stands in `vault` now for a scoped child's reads.
fn principal_stands(vault: &Vault, actor: WriteActor) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::authority::principal_standing_in_txn(
        vault,
        &txn,
        actor.entity_ref(),
        actor.actor_class(),
        SCOPED_CHILD_AUTHORITY_VERB,
    )?
    .is_some())
}
