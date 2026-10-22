//! The read-only door a reader child run calls its agent verbs through.
//! `ReaderChildDoor` (its `AgentVerbDoor` impl) is its call surface.
//! The code_mode_verbs root defines `ReaderChildDoor`; `oneiron::code_run` owns the verb records.

use super::*;

impl ReaderChildDoor {
    pub(crate) fn new(
        vault: Arc<oneiron::Vault>,
        caller: impl Into<oneiron::settings::ReadDestination>,
    ) -> Self {
        Self {
            vault,
            caller: caller.into(),
        }
    }
}

pub(super) fn read_only() -> AgentVerbRefusal {
    AgentVerbRefusal {
        code: crate::server::READER_CHILD_READ_ONLY.to_owned(),
    }
}

impl AgentVerbDoor for ReaderChildDoor {
    fn call(
        &self,
        _: &SelfAgentVerbCall,
        _: &HostWriteOrigin,
        _: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(read_only()))
    }

    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        match call {
            RunCall::RecordedOutput
            | RunCall::Bridge(SelfEffect::ReaderReport | SelfEffect::Context | SelfEffect::Think) => {
                Ok(None)
            }
            _ => Err(read_only()),
        }
    }

    /// The parent caller's rule: on this device nothing is withheld; off
    /// it, a result leaves again only while every row it was served from
    /// may, and one with no row set stays.
    fn withholds_retained(
        &self,
        rows: Option<&[oneiron::EntityId]>,
    ) -> Result<bool, AgentVerbRefusal> {
        if !self.caller.is_off_device() {
            return Ok(false);
        }
        let Some(rows) = rows else {
            return Ok(true);
        };
        crate::device_local::withholds_retained(&self.vault, &self.caller, rows, &[]).map_err(
            |_| AgentVerbRefusal {
                code: "engine_error".to_owned(),
            },
        )
    }
}
