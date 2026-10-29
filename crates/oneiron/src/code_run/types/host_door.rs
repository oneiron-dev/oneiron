//! The host door and its admission vocabulary for run calls.
//! Entry trait: `AgentVerbDoor`.
//! Definitions live here; `code_run::types` forwards the old names.

use super::*;

/// Dispatcher for host-side `self.*` calls emitted by a first-party runtime.
pub trait SelfDispatcher {
    /// Routes one typed call through the host-owned dispatcher.
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome>;
}

/// A verb call's answer, as the host door gives it and the run records it:
/// the verb's JSON output, exactly as its other doors return it, and the rows
/// the door listed as served in producing it (DEC-0005), ids only. The record
/// keeps the rows beside the output, so a re-entered run's replayed answers
/// are released by the rows that produced them. A door always lists them;
/// `None` is only an answer recorded with no set, which no caller off this
/// device is released.
///
/// Beside them come the observations the door delivered with the answer
/// (FIX 2135): frames queued on the run's own board connection, drained once
/// the answer succeeded. They are no part of the verb's output, and each
/// keeps the rows it was derived from, never mixed into the answer's own.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentVerbAnswer {
    pub output: serde_json::Value,
    pub rows: Option<Vec<EntityId>>,
    pub observations: Vec<RunObservation>,
}

impl AgentVerbAnswer {
    /// An answer of `output`, served from `rows`, with no observation
    /// beside it.
    #[must_use]
    pub fn new(output: serde_json::Value, rows: Option<Vec<EntityId>>) -> Self {
        Self {
            output,
            rows,
            observations: Vec::new(),
        }
    }

    /// The rows a run that read this answer is released by: the answer's
    /// own and every observation's (DEC-0005). `None` when the answer was
    /// recorded with no row set.
    #[must_use]
    pub fn released_rows(&self) -> Option<Vec<EntityId>> {
        let mut rows = self.rows.clone()?;
        rows.extend(
            self.observations
                .iter()
                .flat_map(|observation| observation.rows.iter().copied()),
        );
        Some(rows)
    }
}

/// One frame a run's host door delivered beside a verb's answer (FIX 2135):
/// queued on the run's own board STREAM connection and drained, never
/// waited for, once the answer succeeded. The connection and the frame's
/// epoch and kind name it; `rows` are the rows it was derived from.
#[derive(Debug, Clone, PartialEq)]
pub struct RunObservation {
    /// The run's board connection the frame was queued on.
    pub connection: String,
    /// The frame, as the connection's STREAM carries it.
    pub frame: crate::context_board::BoardStreamFrame,
    /// The rows the frame was derived from.
    pub rows: Vec<EntityId>,
}

/// A verb call the bound door refused or could not run, as the guest sees it:
/// a stable code, never prose. Agent-facing words are configuration, so the
/// host or prompt layer supplies any wording for a code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentVerbRefusal {
    pub code: String,
}

/// A verb-table row's refusal as its own route worded it (OF-181): the code,
/// the message and the suggestions a host caller of its action is answered
/// with. The guest still sees only the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentVerbRefusalWords {
    pub code: String,
    pub message: String,
    pub suggestions: Vec<String>,
}

/// The refusal a verb call gets from a run whose host binds no verb door.
pub const AGENT_VERB_DOOR_UNBOUND: &str = "agent_verb_door_unbound";

/// The refusal a verb call gets from a run bound to an off-record session:
/// the host's door runs on the canonical vault, where the session's route
/// and saver are not checked. The reads the room serves itself
/// (`dispatcher::session_verbs`) answer through the room's view instead.
pub const AGENT_VERB_SESSION_BOUND: &str = "agent_verb_session_bound";

/// The host's door onto the SDK verb table.
///
/// The engine runs no verb here. The host that binds this door runs each call
/// with its own actor ceiling and gate, exactly as its other doors do, so code
/// mode holds no authority a direct call lacks. Unbound, a verb call is refused.
///
/// The door binds `origin` onto the memory surface the verb runs on, so the
/// verb's claims carry the run's `Generated` source, lineage and provenance,
/// never a source the guest's input names. Its answer lists the rows the
/// verb served, as its other doors list them for release.
///
/// The door binds `invocation`, the call's step's id, as the logical verb
/// the row's verb hooks fire once for (ARCH-0080 §3). The outer `Err` is
/// a hook's stop (`Error::VerbHook`) or a model call no provider answered
/// (`Error::ProviderUnavailable`, FIX 3194), which the run parks on; every
/// refusal is the inner one.
pub trait AgentVerbDoor: Send + Sync {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &crate::memory::HostWriteOrigin,
        invocation: crate::runtime_hooks::InvocationId,
    ) -> crate::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>>;

    /// Admits one call the run serves itself, before it runs. The host's
    /// ceiling and credential bind these as they bind [`Self::call`], so a run
    /// keeps no authority its door has lost or never had. A search admitted
    /// with a key reads only what that key's lane admits, and a facet stamp
    /// admitted with one places only a row that lane reads. A refusal spelled as
    /// a gate's outcome word (`pending`, `deny`) is taken as that gate's: the
    /// run's bridge halts after it, as after any gate's refusal.
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> std::result::Result<Option<crate::claim::ScopedReadActorKey>, AgentVerbRefusal>;

    /// Whether the run's own `vault.search`, admitted with a key, keeps only
    /// surfaceable claims, as the memory surface's own BM25 channel serves
    /// them. A door that answers `false` has its search filtered by the
    /// key's authorization alone: every row that key may read stays, claims
    /// of every status among them, as its unkeyed search served them before
    /// the door keyed it (FIX 5976).
    fn keyed_search_surfaceable_only(&self) -> bool {
        true
    }

    /// Admits one read a run bound to an off-record session serves through
    /// the room's view (WILL L11-01): `vault.get`, `vault.hydrate`,
    /// `vault.refs.resolve` or `vault.search.bm25`. The answer is the key
    /// the read reads under: this door's caller, as its credential and
    /// ceiling bind them now, never a wider key. A door that admits no such
    /// read refuses it as a session-bound run's verbs were refused before.
    fn admit_session_read(
        &self,
        _verb: crate::task_verb::sdk::AgentVerb,
    ) -> std::result::Result<crate::claim::ScopedReadActorKey, AgentVerbRefusal> {
        Err(AgentVerbRefusal {
            code: AGENT_VERB_SESSION_BOUND.to_owned(),
        })
    }

    /// Admits one of the two writes a run bound to an off-record session
    /// stages in its room (WILL L11-01, S01-2a): `vault.notes.create` or
    /// `vault.claims.upsert`. The answer is what the write lands under: this
    /// door's caller, as its credential and ceiling bind them now, and the
    /// ceiling the write's own transaction checks again. A read's key
    /// ([`Self::admit_session_read`]) is no write permit. A door that admits
    /// no such write refuses it as a session-bound run's verbs were refused
    /// before.
    fn admit_session_write(
        &self,
        _verb: crate::task_verb::sdk::AgentVerb,
    ) -> std::result::Result<SessionWriteAdmission, AgentVerbRefusal> {
        Err(AgentVerbRefusal {
            code: AGENT_VERB_SESSION_BOUND.to_owned(),
        })
    }

    /// Whether a result the run retained stays on this device for the door's
    /// caller now (DEC-0005), re-checked at each read of it: `rows` are the
    /// rows the run was served producing it, `None` when one of its answers
    /// was recorded with no row set. A door whose caller sits on this device
    /// withholds nothing.
    fn withholds_retained(
        &self,
        _rows: Option<&[EntityId]>,
    ) -> std::result::Result<bool, AgentVerbRefusal> {
        Ok(false)
    }

    /// The words the door's route refused its newest call with, when it
    /// worded one. An action keeps them on its replay record, so a retry
    /// under the same key answers as the first try did. A door that words
    /// no refusal keeps none.
    fn refusal_words(&self) -> Option<AgentVerbRefusalWords> {
        None
    }

    /// What the row this door last ran stated of its call receipt, as its
    /// reply spells it (`call:<32hex>`, or `none; no-record` for an
    /// anonymous off-record session's call): `None` when it stated nothing.
    /// An action keeps it on its replay record, so a retry under the same
    /// key states the first dispatch's receipt again (FIX 8159). A door that
    /// states no receipt keeps none.
    fn row_receipt(&self) -> Option<String> {
        None
    }

    /// The receipt the first dispatch of a replayed action stated
    /// ([`Self::row_receipt`]), handed back to this door, whose caller
    /// states it again: the replay runs no row and writes no receipt of its
    /// own. A door that states no receipt ignores it.
    fn replay_row_receipt(&self, _receipt: &str) {}

    /// Sends the run's answer to the questions one of its connector calls
    /// waits on (`connector.answer`, ONE-2510), for the run's own caller:
    /// the door checks it under the original call's grant and principal, and
    /// its answer is `connector.call`'s reply. The run's admission and verb
    /// hooks already ran around it. A door that sends no connector calls
    /// refuses it as unbound.
    fn connector_answer(
        &self,
        _request: &crate::task_verb::sdk::ConnectorAnswerRequest,
        _invocation: crate::runtime_hooks::InvocationId,
    ) -> crate::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(AgentVerbRefusal {
            code: AGENT_VERB_DOOR_UNBOUND.to_owned(),
        }))
    }
}

/// One call a run serves itself, as its host door is asked about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCall {
    /// A call over the bridge: a run row such as `vault.search` or
    /// `vault.claims.put`, or a `self.*` import. The run's trailing
    /// implicit speech is a `self.speak` too.
    Bridge(SelfEffect),
    /// A read of the run's own recorded output: by its context reference, or
    /// a resumed write's kept answer, read back from its receipt.
    RecordedOutput,
}
