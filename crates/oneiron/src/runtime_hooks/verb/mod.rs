//! Verb hooks (ARCH-0080 §3, §5), slice 2: hooks that run inside a call,
//! before and after one logical verb.
//!
//! Two attach points carry every verb hook: the boundary per logical row on
//! each executable dispatch path, and the code-run effect dispatcher for every
//! SelfCall but AgentVerb. Host verbs (`host.turn.generate`,
//! `host.session.open`, `host.session.close`) name runtime points with no row
//! behind them and take the same chain. A hook runs once per logical verb:
//! one [`InvocationId`] crosses transport wrappers and internal dispatch.

mod ask;
mod chain;
mod credential;
mod record;
mod redact;
mod resume;
mod served;
mod state;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::claim::ScopedReadActorKey;
pub use crate::error::VerbHookStop;
use crate::memory::MemoryResult;
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{EdgeActorClass, EntityId, Result, Vault};

pub use credential::{
    VerbAskCredential, VerbAskCredentialCheck, VerbAskCredentialRef, VerbAskCredentialSource,
    VerbAskDoor, VerbAskDrainPermit, VerbAskDrainScope, VerbAskInstrument, VerbAskRefusal,
    VerbAskResumed, VerbAskSavedCall,
};
pub(super) use record::{HookVerbRunRecord, VERB_RUNS};
pub(crate) use resume::{VerbResume, verb_ask_settled_in_txn};
pub(crate) use state::{HookDepth, VerbHookState};
pub use state::{InvocationClaim, InvocationEntry, InvocationOutcome, InvocationWait};

/// One logical verb's id, minted once where the call enters and passed
/// across transport wrappers and internal dispatch (review fix M7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InvocationId(pub [u8; 16]);

impl InvocationId {
    /// A fresh id for a call that carried none.
    #[must_use]
    pub fn mint() -> Self {
        Self(*uuid::Uuid::now_v7().as_bytes())
    }

    /// The id of one code-mode step: the same across replays of the run, so
    /// a retried step finds its saved Ask continuation.
    #[must_use]
    pub fn of_run_step(run_id: &[u8], seq: u64) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron runtime hook invocation v1");
        hasher.update(run_id);
        hasher.update(&seq.to_le_bytes());
        let mut id = [0; 16];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Self(id)
    }

    /// 32 lowercase hex digits.
    #[must_use]
    pub fn to_hex(self) -> String {
        uuid::Uuid::from_bytes(self.0).simple().to_string()
    }

    /// Parses [`Self::to_hex`]; `None` for anything else.
    #[must_use]
    pub fn parse_hex(text: &str) -> Option<Self> {
        if text.len() != 32 {
            return None;
        }
        uuid::Uuid::try_parse(text)
            .ok()
            .map(|id| Self(id.into_bytes()))
    }
}

/// What a blocking hook's failure does to the verb (DEC-0006 invariant 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerbDomain {
    /// A failed blocking pre-hook hides the result.
    Read,
    /// A failed blocking pre-hook sends the verb to an ask.
    Write,
}

/// The call a verb hook fires on: what the hook reads besides the args, the
/// board and the receipt tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerbCall {
    /// A row name, a SelfEffect label or a `host.*` verb.
    pub verb: String,
    pub invocation: InvocationId,
    pub actor: EntityId,
    pub class: HookActorClass,
    /// The world, facet, room or project the call runs in, when the host
    /// knows one; a hook's own scope only narrows.
    pub scope: Option<String>,
    pub board_epoch: Option<u64>,
    pub domain: VerbDomain,
    /// The caller's scoped-read key: its proof, room turn and locality. A
    /// hook reads through it, capped by its grant. `None` for a host's own
    /// call, which reads as its actor.
    pub reader: Option<ScopedReadActorKey>,
}

impl VerbCall {
    /// The call of `verb` on `memory`: its actor and class, the invocation
    /// its host bound or a fresh one, and the handle's read key when a hook
    /// may run on `verb`.
    ///
    /// # Errors
    ///
    /// When a hook may run and the handle's read key does not build.
    pub fn for_memory(
        memory: &crate::Memory<'_>,
        verb: &str,
        domain: VerbDomain,
    ) -> MemoryResult<Self> {
        Ok(Self {
            verb: verb.to_owned(),
            invocation: memory.invocation().unwrap_or_else(InvocationId::mint),
            actor: memory.actor(),
            class: hook_class(memory.actor_class()),
            scope: None,
            board_epoch: None,
            domain,
            reader: Self::reader_of(memory, verb)?,
        })
    }

    /// Whether a verb hook may run on `verb`. A door builds what only a hook
    /// reads (the caller's key, a rewrite's re-admission) only when one may,
    /// so a call no binding takes pays nothing.
    #[must_use]
    pub fn may_run(vault: &Vault, verb: &str) -> bool {
        vault.verb_hooks_may_run(verb)
    }

    /// The key a call of `verb` on `memory` carries: the handle's read key
    /// when a hook may run on `verb`, else none.
    ///
    /// # Errors
    ///
    /// When a hook may run and the handle's read key does not build.
    pub fn reader_of(
        memory: &crate::Memory<'_>,
        verb: &str,
    ) -> MemoryResult<Option<ScopedReadActorKey>> {
        if Self::may_run(memory.vault(), verb) {
            memory.read_key().map(Some)
        } else {
            Ok(None)
        }
    }
}

/// The selector's class for a stored actor class.
#[must_use]
pub fn hook_class(class: EdgeActorClass) -> HookActorClass {
    match class {
        EdgeActorClass::Human => HookActorClass::Human,
        EdgeActorClass::Agent => HookActorClass::Agent,
        EdgeActorClass::System => HookActorClass::System,
    }
}

/// What the pre chain left: the args the verb runs with, and the state the
/// post chain picks up. Hand it to [`Vault::post_verb_hooks`] once the verb
/// ran.
#[derive(Debug)]
pub struct VerbHookPre {
    call: VerbCall,
    /// The args after every Rewrite, each re-validated.
    pub args: Value,
    /// Set when hooks are live for this call: the post chain runs on it.
    carry: Option<state::Carry>,
}

impl VerbHookPre {
    #[must_use]
    pub fn call(&self) -> &VerbCall {
        &self.call
    }
}

/// Re-validates rewritten args as if the caller sent them.
pub type VerbArgsCheck<'a> = &'a dyn Fn(&Value) -> std::result::Result<(), String>;

impl Vault {
    /// A cheap check before a host builds a call's hook args: false when no
    /// verb hook can run on `verb` (hooks off or suppressed, hook depth 1,
    /// no binding's verb glob takes it). True when the bindings do not read.
    pub(crate) fn verb_hooks_may_run(&self, verb: &str) -> bool {
        chain::may_run(self, verb)
    }

    /// Runs the pre chain of `call` over `args`: the matching pre-hooks in
    /// priority order, each outcome validated. `Err(stop)` when a hook
    /// skipped or asked, or a blocking one failed safe. At hook depth 1 or
    /// with hooks off, it passes `args` through untouched.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur; a hook's own failure is never one.
    pub fn pre_verb_hooks(
        &self,
        call: VerbCall,
        args: Value,
        check: VerbArgsCheck<'_>,
    ) -> Result<std::result::Result<VerbHookPre, VerbHookStop>> {
        chain::pre(self, call, args, check, None)
    }

    /// [`Self::pre_verb_hooks`] for a call settlement can run again without
    /// its caller: an ask saves `resume`, and once the drain ran the call a
    /// retry presenting the same target gets [`VerbHookStop::Completed`] or
    /// [`VerbHookStop::CompletedWithError`]. `None` is a call only its
    /// caller's retry resumes.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur; a hook's own failure is never one.
    pub(crate) fn pre_verb_hooks_resumable(
        &self,
        call: VerbCall,
        args: Value,
        check: VerbArgsCheck<'_>,
        resume: Option<VerbResume>,
    ) -> Result<std::result::Result<VerbHookPre, VerbHookStop>> {
        chain::pre(self, call, args, check, resume.as_ref())
    }

    /// [`Self::pre_verb_hooks`] for a credential caller's call its host can
    /// run again through the door it came in by: an ask saves `credential`'s
    /// reference and pins its witness in the ask's own write, so settlement
    /// resumes the call through the host's check, and a retry presenting the
    /// same reference reads what it returned. With no check installed, or
    /// `None`, only the caller's retry resumes it.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur; a hook's own failure is never one.
    pub fn pre_verb_hooks_for_credential(
        &self,
        call: VerbCall,
        args: Value,
        check: VerbArgsCheck<'_>,
        credential: Option<VerbAskCredential>,
    ) -> Result<std::result::Result<VerbHookPre, VerbHookStop>> {
        let credential = credential.filter(|_| self.verb_hook_state.credential_check().is_some());
        let resume = credential.as_ref().map(|credential| VerbResume::Credential {
            reference: credential.reference().clone(),
        });
        let _witness =
            credential::WitnessScope::enter(credential.map(VerbAskCredential::into_witness));
        self.pre_verb_hooks_resumable(call, args, check, resume)
    }

    /// Runs the post chain over the verb's `result`: the caller's view after
    /// every Redact, with notes, blocks and post outcomes committed. A write
    /// that committed stays reported as committed whatever a post-hook does.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur; a hook's own failure is never one.
    pub fn post_verb_hooks(
        &self,
        pre: VerbHookPre,
        result: Value,
    ) -> Result<std::result::Result<Value, VerbHookStop>> {
        chain::post(self, pre, result)
    }

    /// The pre chain, the verb and the post chain for one call. `run` gets
    /// the args after every Rewrite; an error from it skips the post chain.
    /// A call its settled ask already ran answers what it returned.
    ///
    /// # Errors
    ///
    /// What `run` returns, and storage errors as they occur.
    pub fn verb_hooks<E: From<crate::Error>>(
        &self,
        call: VerbCall,
        args: Value,
        check: VerbArgsCheck<'_>,
        run: impl FnOnce(Value) -> std::result::Result<Value, E>,
    ) -> std::result::Result<std::result::Result<Value, VerbHookStop>, E> {
        let pre = match self.pre_verb_hooks(call, args, check)? {
            Ok(pre) => pre,
            Err(VerbHookStop::Completed { result, .. }) => return Ok(Ok(result)),
            Err(stop) => return Ok(Err(stop)),
        };
        let result = run(pre.args.clone())?;
        Ok(self.post_verb_hooks(pre, result)?)
    }
}
