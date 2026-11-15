//! The DOOR-141 vocabulary: the pinned program, its arming, the wake a
//! landed turn owes it, and what admitting that wake decided.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::{EntityId, bytes_to_hex_lower};

use super::authority::TurnProgramAuthority;

#[doc(hidden)]
pub(super) use oneiron_verb_wire::dreamer_runner::program::types::OccurrenceKind;
#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_runner::program::types::{
    ArmTurnProgram, DisarmTurnProgram, ProgramRecipePin, ProgramTrigger, TurnProgramRegistration,
};

const ADMISSION_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-admission:v1";
const CODE_RUN_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-code-run:v1";
/// The committed turn that woke a program: the TURN, its conversation, and
/// when it landed on the vault's recording clock, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandedTurnRef {
    pub turn: EntityId,
    pub conversation: EntityId,
    pub landed_at: u64,
}

/// What admitting one wake decided.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TurnProgramAdmissionOutcome {
    /// Queued as one Dreamer program attempt, the root of its run tree,
    /// under the waking actor's own stamp, for the program runtime to run.
    /// `run_id` is its code run's id: the run its callable entry is called
    /// in. Nothing has run and nothing is complete.
    Queued { attempt: AttemptId, run_id: String },
    /// Refused in the admission writer; nothing was queued.
    Refused { reason: String },
}

/// One admission's answer: the wake, who it runs as, the Gate receipt, and
/// the attempt it queued or why it was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnProgramAdmissionReceipt {
    /// The admission's identity: actor, registration, definition revision
    /// and turn. One turn wakes one program once.
    pub admission: [u8; 32],
    pub registration: EntityId,
    /// The waking actor the program runs as.
    pub actor: EntityId,
    pub wake: LandedTurnRef,
    /// The pinned executable the attempt is bound to, immutable once
    /// admitted; `None` for a refusal.
    pub definition: Option<ProgramRecipePin>,
    /// Digest of the effective credential scope the waking turn was admitted
    /// under, when a credential admitted it.
    pub sealed_scope: Option<[u8; 32]>,
    /// The Gate decision that recorded the admission.
    pub gate_receipt: [u8; 16],
    pub outcome: TurnProgramAdmissionOutcome,
    pub decided_at: u64,
    /// `false` when an identical wake was already admitted: this call
    /// decided nothing new.
    pub first: bool,
}

/// One drain of owed wakes: how many were admitted (or found already
/// admitted), refused, and held owed on a lapsed slip (FIX 12058), and
/// whether more wait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TurnProgramDrain {
    pub admitted: usize,
    pub refused: usize,
    pub held: usize,
    pub more: bool,
}

/// One armed program's row: the actor whose future turns wake it, the
/// conversation it listens to, and the pinned definition with its revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TurnProgramArming {
    pub(super) registration: EntityId,
    pub(super) actor: EntityId,
    pub(super) actor_class: u8,
    pub(super) conversation: Option<EntityId>,
    pub(super) definition: ProgramRecipePin,
    pub(super) revision: [u8; 32],
    pub(super) armed_at: u64,
    /// What wakes it; a turn for every arming written before slice 6.8c.
    #[serde(default, skip_serializing_if = "ProgramTrigger::is_turn")]
    pub(super) trigger: ProgramTrigger,
    /// The arming actor's authority, sealed at arm for a trigger that is not a turn (B-3): each
    /// occurrence's wake carries it, and each admission judges it again. A turn's wake seals
    /// its own turn's authority instead, so a turn arming keeps none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) sealed: Option<TurnProgramAuthority>,
    /// A timer's next due time, the key of its row in the due index; `None` once a timer that
    /// wakes once has woken, and for every other trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) next_due: Option<u64>,
}

impl TurnProgramArming {
    /// Whether a turn `authority`'s actor landed wakes this program: a turn
    /// trigger, its own actor at its own class, in its conversation, at or
    /// after arming.
    pub(super) fn wakes_on(&self, authority: &TurnProgramAuthority, turn: &LandedTurnRef) -> bool {
        self.trigger.is_turn()
            && self.actor == authority.actor()
            && self.actor_class == authority.class_byte()
            && self
                .conversation
                .is_none_or(|conversation| conversation == turn.conversation)
            && turn.landed_at >= self.armed_at
    }

    pub(super) fn view(&self, newly_armed: bool) -> TurnProgramRegistration {
        TurnProgramRegistration {
            registration: self.registration,
            actor: self.actor,
            conversation: self.conversation,
            definition: self.definition.clone(),
            revision: self.revision,
            armed_at: self.armed_at,
            newly_armed,
        }
    }
}

/// A disarm this machine knows (FIX 5266): when it was made, on the
/// disarming writer's recording clock, so an arming of the same registration
/// carried by any window never arms it here again. Arming the definition
/// again mints another registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TurnProgramDisarm {
    pub(super) at: u64,
}

/// The wake a landed turn owes one armed program, sealed in that turn's own
/// commit: the registration and definition revision it woke, the authority
/// the turn was admitted under, and the turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TurnProgramWake {
    pub(super) registration: EntityId,
    pub(super) revision: [u8; 32],
    pub(super) authority: TurnProgramAuthority,
    /// The landed turn that woke it; for an occurrence (`occurrence` set), the occurrence's id
    /// in both `turn` and `conversation` and its time in `landed_at`, so the wake's key, its
    /// admission's identity and the turn index name the occurrence as they name a turn.
    pub(super) turn: LandedTurnRef,
    /// The kind of occurrence that woke a program whose trigger is not a turn; none for a
    /// turn's wake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) occurrence: Option<OccurrenceKind>,
    /// The owed row's status once an admission found its sealed slip
    /// lapsed and kept it owed (FIX 12058); none until then. It is never
    /// part of the wake an admission records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) held: Option<OwedWakeHold>,
}

/// Why an owed wake waits (FIX 12058): an admission found its sealed slip
/// lapsed and kept it owed for a rebind instead of refusing it. The drain
/// passes it by until `expires_at`, the wake's own expiry; an admission
/// after that judges it finally, as any wake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwedWakeHold {
    /// The refusal the lapse would have been.
    pub(super) reason: String,
    /// When the first admission found the lapse.
    pub(super) held_at: u64,
    /// The wake's own expiry: a fixed time after its turn landed.
    pub(super) expires_at: u64,
}

impl TurnProgramWake {
    /// The row key: the turn, then the registration it woke.
    pub(super) fn key(&self) -> (EntityId, EntityId) {
        (self.turn.turn, self.registration)
    }

    /// The dedupe identity: actor, registration, definition revision and
    /// turn, never a time or a session.
    pub(super) fn admission_id(&self) -> [u8; 32] {
        *blake3::Hasher::new()
            .update(ADMISSION_DOMAIN)
            .update(self.authority.actor().as_bytes())
            .update(self.registration.as_bytes())
            .update(&self.revision)
            .update(self.turn.turn.as_bytes())
            .finalize()
            .as_bytes()
    }
}

/// One admission as the writer decided it: the sealed wake, the executable
/// it binds (a copy of the pin, so disarming never unbinds an admitted
/// attempt), its Gate receipt, and the attempt it queued or why it was
/// refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TurnProgramAdmissionRecord {
    pub(super) admission: [u8; 32],
    pub(super) wake: TurnProgramWake,
    pub(super) definition: Option<ProgramRecipePin>,
    pub(super) receipt_id: [u8; 16],
    pub(super) attempt: Option<AttemptId>,
    pub(super) refused: Option<String>,
    pub(super) decided_at: u64,
}

impl TurnProgramAdmissionRecord {
    pub(super) fn receipt(&self, first: bool) -> TurnProgramAdmissionReceipt {
        TurnProgramAdmissionReceipt {
            admission: self.admission,
            registration: self.wake.registration,
            actor: self.wake.authority.actor(),
            wake: self.wake.turn,
            definition: self.definition.clone(),
            sealed_scope: self.wake.authority.scope_digest(),
            gate_receipt: self.receipt_id,
            outcome: match self.attempt {
                Some(attempt) => TurnProgramAdmissionOutcome::Queued {
                    attempt,
                    run_id: run_id(&self.admission),
                },
                None => TurnProgramAdmissionOutcome::Refused {
                    reason: self.refused.clone().unwrap_or_default(),
                },
            },
            decided_at: self.decided_at,
            first,
        }
    }
}

/// The waking actor one program attempt runs as, bound at its enqueue to the
/// admission that sealed that actor's authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TurnProgramAttemptStamp {
    pub(super) attempt_id: [u8; 16],
    pub(super) admission: [u8; 32],
    pub(super) actor: EntityId,
    pub(super) actor_class: u8,
    pub(super) receipt_id: [u8; 16],
}

/// The queue run id one admission's attempt carries: its code run's id, as
/// the callable it calls checks it against the caller's leased run.
pub(super) fn run_id(admission: &[u8; 32]) -> String {
    bytes_to_hex_lower(&code_run_bytes(admission))
}

/// The code run one admission's program runs as (DOOR-141 PR2), fixed by
/// the admission so every try of it names the same run.
pub(super) fn code_run_bytes(admission: &[u8; 32]) -> [u8; 16] {
    let digest = blake3::Hasher::new()
        .update(CODE_RUN_DOMAIN)
        .update(admission)
        .finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes
}
