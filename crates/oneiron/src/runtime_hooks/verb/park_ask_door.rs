//! Door for `oneiron-server`'s `tests/workflow_park_save_retry.rs`
//! ([WORKFLOW-PARK-FAIL-RETRYABLE]): a verb pre-hook's ask saved under a
//! call's invocation through the hook's own `ask::open`, the owner's proceed
//! answer, and what a later try of that invocation reads through
//! `ask::retry`, the read `chain::pre` makes before any hook runs. Compiled
//! only under `--cfg oneiron_test_support`; never API.

use serde_json::json;

use super::ask::{self, Retry};
use super::{InvocationId, VerbCall, VerbDomain, VerbHookStop, hook_class};
use crate::skill_hub::pack_catalog::{
    HookAuthor, HookOutcomeKind, HookPhase, HookRenderClass, HookSelector, PackHookBinding,
};
use crate::task_verb::{TaskAskHandle, TaskAskOptionId, TaskAskWord};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault, WriteActor};

/// The pack and hook the door's binding names.
const PACK: &str = "park-retry-pack";
const HOOK: &str = "ask-before-use";

/// What a call finds under its invocation before its chain runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavedAsk {
    /// No ask is saved under the invocation: the chain runs from its start.
    Fresh,
    /// The call parks on `ask`, still open.
    Pending { ask: EntityId },
    /// `ask` was answered proceed: the chain resumes and the call runs.
    Resume { ask: EntityId },
    /// Any other stop, with its words.
    Stopped(String),
}

/// An owner's pre-hook on `verb`, which asks before a call of it runs.
pub struct HookAsk {
    owner: EntityId,
    binding_id: EntityId,
    binding: PackHookBinding,
    verb: String,
}

impl HookAsk {
    /// The owner's asking pre-hook on `verb` (a binding row the door holds;
    /// the ask's own write names it, as a pack install's would).
    #[must_use]
    pub fn on_verb(owner: EntityId, verb: &str) -> Self {
        let binding = PackHookBinding {
            // HOOK_BINDING_VERSION; `ask::open` reads only the pack, the
            // hook and the author.
            version: 2,
            code: EntityId::now(),
            owner,
            source: EntityId::now(),
            pack: PACK.to_owned(),
            hook: HOOK.to_owned(),
            hook_version: "1".to_owned(),
            body_hash: blake3::hash(b"ask-before-use").to_hex().to_string(),
            selector: HookSelector {
                verbs: vec![verb.to_owned()],
                actors: Vec::new(),
                scope: None,
                phase: HookPhase::Pre,
                priority: 0,
                budget_ms: 50,
                blocking: false,
                outcomes: vec![HookOutcomeKind::Ask],
                served: Vec::new(),
                render_class: HookRenderClass::default(),
            },
            enabled: true,
            author: HookAuthor::Owner,
        };
        Self {
            owner,
            binding_id: EntityId::now(),
            binding,
            verb: verb.to_owned(),
        }
    }

    /// The call of this hook's verb by `actor` under `invocation`, as a
    /// step's `self.use` presents it at the hook boundary.
    fn call(&self, actor: &WriteActor, invocation: InvocationId) -> VerbCall {
        VerbCall {
            verb: self.verb.clone(),
            invocation,
            actor: actor.entity_ref(),
            class: hook_class(actor.actor_class()),
            scope: None,
            board_epoch: None,
            turn: None,
            domain: VerbDomain::Write,
            reader: None,
        }
    }

    /// The hook asks before `actor`'s call under `invocation` runs: the ask
    /// opens and its row is saved under the invocation, as `chain::pre`
    /// saves it. Answers the ask's group.
    ///
    /// # Errors
    ///
    /// Storage, or the ask door's refusal in words.
    pub fn ask(
        &self,
        vault: &Vault,
        actor: &WriteActor,
        invocation: InvocationId,
    ) -> Result<EntityId> {
        let call = self.call(actor, invocation);
        let opened = ask::open(
            vault,
            &call,
            (self.binding_id, &self.binding),
            0,
            &json!({"operation": "use"}),
            "Run this use?",
            None,
            None,
            &|_txn: &mut heed::RwTxn<'_>| Ok(()),
        )?;
        match opened {
            Ok(stop) => pending_ask(&stop).ok_or_else(|| {
                Error::InvalidConfig(format!("the hook's ask did not park: {stop:?}"))
            }),
            Err(refusal) => Err(Error::InvalidConfig(format!(
                "the ask door refused: {refusal}"
            ))),
        }
    }

    /// The owner answers `ask` proceed.
    ///
    /// # Errors
    ///
    /// The answer door's refusal.
    pub fn answer_proceed(&self, vault: &Vault, ask: EntityId) -> Result<()> {
        let mut word = TaskAskWord::new(ask);
        word.option = Some(
            TaskAskOptionId::new("proceed")
                .map_err(|_| Error::InvariantViolation("proceed option"))?,
        );
        vault
            .memory(self.owner, EdgeActorClass::Human)
            .tasks_answer(&TaskAskHandle { group_ref: ask }, &word)
            .map_err(|error| {
                Error::InvalidConfig(format!("the owner's answer: {}", error.message))
            })?;
        Ok(())
    }

    /// What `actor`'s call under `invocation` finds before its chain runs
    /// (`ask::retry`, with no resume target and no task-work turn, as a
    /// workflow step presents them).
    ///
    /// # Errors
    ///
    /// Storage.
    pub fn retry(
        &self,
        vault: &Vault,
        actor: &WriteActor,
        invocation: InvocationId,
    ) -> Result<SavedAsk> {
        let call = self.call(actor, invocation);
        Ok(match ask::retry(vault, &call, None, None)? {
            Retry::Fresh => SavedAsk::Fresh,
            Retry::Resume { token, .. } => SavedAsk::Resume { ask: token.ask() },
            Retry::Stop(stop) => match pending_ask(&stop) {
                Some(ask) => SavedAsk::Pending { ask },
                None => SavedAsk::Stopped(format!("{stop:?}")),
            },
        })
    }
}

/// The ask a Pending stop parks on.
fn pending_ask(stop: &VerbHookStop) -> Option<EntityId> {
    match stop {
        VerbHookStop::Pending { ask, .. } => EntityId::from_hex(ask).ok(),
        _ => None,
    }
}
