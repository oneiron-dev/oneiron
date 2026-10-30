//! A held call's pre state, kept beside its consent wait (FIX 11497): the
//! part of a [`VerbHookPre`] that survives being written down, so the
//! answered pass can run the post chain the first pass never reached.
//!
//! Only rows this boundary holds carry one: a browser or desktop press
//! parked on the owner's answer. The pre chain never re-runs for the
//! answered act; its result is rebuilt here and handed to the post chain.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::EntityId;
use crate::runtime_hooks::block::HookTurnTarget;
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::task_verb::revoke_lands::Landing;

use super::state::Carry;
use super::storage::SessionCarry;
use super::{InvocationId, VerbCall, VerbDomain, VerbHookPre};

/// What of a [`VerbHookPre`] a consent wait keeps: the call but for its
/// reader, the rewritten args, when the pre chain ran, and the landing
/// and session carries, each reduced to what serializes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbHookPreSnapshot {
    verb: String,
    invocation: InvocationId,
    actor: EntityId,
    class: HookActorClass,
    scope: Option<String>,
    board_epoch: Option<u64>,
    turn: Option<HookTurnTarget>,
    domain: VerbDomain,
    args: Value,
    carry_now: Option<u64>,
    landing: Option<LandingSnapshot>,
    session: Option<SessionCarry>,
}

/// A landing's kept parts: its verb (its row is found by it again), the
/// caller's own args, and the owner's notice lines. Its pins and check
/// are the row's fn pointers and never persist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LandingSnapshot {
    verb: String,
    original: Value,
    notes: Vec<String>,
}

impl VerbHookPreSnapshot {
    /// The snapshot of `pre` at hold time: `None` for a through-path pre
    /// (no carry, no landing, no session carry), whose post passes the
    /// result through and whose notice is silent, so nothing is kept.
    #[must_use]
    pub fn from_pre(pre: &VerbHookPre) -> Option<Self> {
        if pre.carry.is_none() && pre.landing.is_none() && pre.session.is_none() {
            return None;
        }
        let call = pre.call();
        Some(Self {
            verb: call.verb.clone(),
            invocation: call.invocation,
            actor: call.actor,
            class: call.class,
            scope: call.scope.clone(),
            board_epoch: call.board_epoch,
            turn: call.turn.clone(),
            domain: call.domain,
            args: pre.args.clone(),
            carry_now: pre.carry.as_ref().map(|carry| carry.now),
            landing: pre.landing.as_ref().map(|landing| {
                let (verb, original, notes) = landing.snapshot_parts();
                LandingSnapshot {
                    verb: verb.to_owned(),
                    original: original.clone(),
                    notes: notes.to_vec(),
                }
            }),
            session: pre.session.clone(),
        })
    }

    /// The post-only [`VerbHookPre`] this snapshot rebuilds on the
    /// answered pass. Two parts of the live pre never persisted, and the
    /// rebuild is the narrower for both: the caller's read key (a live
    /// proof, never written down), so the post hooks read on the actor's
    /// own key and room- and world-scope hooks match by the room ceiling
    /// alone; and the in-flight mark (a process-local guard), rebuilt as
    /// none. A landing whose verb names no restrictive row any more
    /// rebuilds as none: its notice is silent, as a call with no landing.
    #[must_use]
    pub fn into_post_pre(self) -> VerbHookPre {
        VerbHookPre {
            call: VerbCall {
                verb: self.verb,
                invocation: self.invocation,
                actor: self.actor,
                class: self.class,
                scope: self.scope,
                board_epoch: self.board_epoch,
                turn: self.turn,
                domain: self.domain,
                reader: None,
            },
            args: self.args,
            carry: self.carry_now.map(|now| Carry { mark: None, now }),
            landing: self.landing.and_then(|landing| {
                Landing::from_snapshot(&landing.verb, landing.original, landing.notes)
            }),
            session: self.session,
        }
    }
}
