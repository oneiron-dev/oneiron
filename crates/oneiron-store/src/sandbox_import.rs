//! Guest-linked host import names and effect classes.

/// Class of a host import linked into a guest program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxImportClass {
    /// Reads only: the guest gains no write. Host bookkeeping the owner opted
    /// into (retrieval telemetry, an access grant's clock) is not a write
    /// import.
    ReadOnly,
    CredentialHandle,
    Determinism,
    /// The step's own streamed result: console lines, the finish answer and
    /// `/mnt/outputs` files, written as they are produced. It is the result
    /// the host records for the step, as it recorded the returned one, never
    /// a vault write.
    Output,
    /// A foreign guest's proposed file, streamed to the host in frames. It
    /// is inert proposal data for review, never a host write; first-party
    /// guests do not link it.
    Proposal,
    DurableWait,
    /// The blocked-report receipt. The memory writes it once stood beside
    /// (claim, supersede, edge) are verb-table rows the run answers itself.
    WriteTrap,
    /// Agent-definition authoring is an audited, lease-bound configuration
    /// write, not a memory write.
    AgentAuthoring,
    /// The `self.speak` family (ONE-1686): an explicit host effect that emits
    /// one durable MESSAGE bubble through the run's bound witness route.
    ///
    /// Deliberately NOT `WriteTrap`. Write traps are gated memory verbs or
    /// the blocked-report receipt; OF-060 P3 pins that set closed. Speech
    /// writes a transcript row instead of memory and is gated on the witness
    /// path, so the two ceilings stay distinct.
    Speech,
    /// The SDK verb table (ARCH-0028): the served names and one call of any
    /// row. A row may write, so the class is a write. A host row's call is
    /// gated by the host's bound verb door, as every other door gates it; a
    /// run row (`RunVerb`) is the run's own typed memory call and gate. OF-060
    /// P3 pins the run rows' write effects with the write traps.
    VerbTable,
}

impl SandboxImportClass {
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Self::WriteTrap | Self::AgentAuthoring | Self::VerbTable
        )
    }
}
