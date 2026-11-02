//! The engine scans whose tables grow with use (rule 5); their list,
//! codes, thresholds and tags are in `engine_scan_table`. Split from its
//! parent, which re-exports them.

/// Each engine scan whose table grows with use, and so each that once
/// refused past a row count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineScan {
    /// One repository's receive-pack intents: its pending pushes, and any
    /// settled one the scan prunes on its way.
    ReceivePackIntents,
    /// The vault's publication journal, every repository's history.
    PublicationRows,
    /// One repository's visible-ref slots: one per ref name it publishes.
    VisibleRefRows,
    /// One repository's keep-ref owners, every kind.
    KeepOwnerRows,
    /// One repository's full Git tree walk, trees and files (once refused past 100,000).
    OriginTreeEntries,
    /// One annotated-tag chain document ingress peels (once refused past 64).
    OriginTagPeelSteps,
    /// One GitWire plan's written and existing objects (once refused past 256).
    GitWirePlanObjects,
    /// One GitWire ref transaction's publications (once refused past 64).
    GitWirePublications,
    /// One origin publication's required Git and LFS objects (once refused past 4096).
    OriginPublicationObligations,
    /// One entity type's rows in the type index.
    TypeIndexRows,
    /// One learned-at window's rows in the temporal index.
    LearnedRangeRows,
    /// One record's edges of one kind, one way.
    EdgePeerRows,
    /// The local receipt-record index a canonical window capture walks.
    ReceiptRecordRows,
    /// The records of one anchor's supersession chain.
    TimelineRecords,
    /// The gate-decision ledger a gate receipt query walks.
    GateDecisionRows,
    /// One record's edges a scoped reader's admission walks, one way.
    ScopedEdgeRows,
    /// The owner's MACHINE rows a mesh address bind walks for its endpoint.
    MachineRows,
    /// Every repository's proposals a snapshot lookup walks (once refused past 100,000).
    RepoProposalSnapshotRows,
    /// The files and symlinks one checkout snapshot captures (once refused past 100,000).
    RepoSnapshotFiles,
    /// The own-catalog votes one repository proposal keeps (once refused past 64).
    RepoProposalCritiques,
    /// The paths one repository conflict records (once refused past 1,024).
    RepoConflictPaths,
    /// The access grants a companion persona list walks.
    AccessGrantRows,
    /// One seed's inbound mentions a specificity weight counts.
    MentionRows,
    /// The PPR cache's dependency rows a replaced or dead entry's walk reads.
    PprCacheDepRows,
    /// The sync rematerialization markers and quarantine rows a pack's
    /// exclusion index reads.
    PackQuarantineRows,
    /// The legacy lexical-hint claims a target's hint lookup walks.
    LexicalHintRows,
    /// The graduation answer log a gate receipt query projects.
    AnswerReceiptRows,
    /// The proposal artifacts a substitution-mining pass indexes.
    MinerArtifactRows,
    /// The synced edge map's entries an unseated child's parent arbitration
    /// walks.
    ChildOfMapEntries,
    /// The long-interval index a temporal window's spanner scan reads.
    TemporalSpannerRows,
    /// The timeline rows an occurred-range query reads, both halves.
    OccurredRangeRows,
    /// The retrieval run ledger a blend-weight tuning pass walks.
    BlendTuningRuns,
    /// One conversation's peers a Dreamer selection retry reads.
    DreamerRetryPeers,
    /// The pending gate-consent tray a consent list walks.
    PendingGateConsentRows,
    /// The tasks an omitted ask target or task context is resolved from, for
    /// one asking actor.
    TaskCensusRows,
    /// One ask's words.
    AskWordRows,
    /// The room members' tasks a thread census reads, for one reader.
    RoomThreadTasks,
    /// The rows one session's read set holds.
    ReadSetRows,
    /// One code symbol manifest's chunks or symbols, the more (once refused past 100,000).
    SymbolManifestRows,
    /// The longest producing-operation chain one symbol manifest carries (once refused past 1,024).
    SymbolOperationChain,
    /// One codebase snapshot's file manifest (once refused past 100,000).
    CodebaseFileRows,
    /// One room's history rows a message page passes over.
    RoomPageRows,
    /// One room's history rows a liveness snapshot reads.
    RoomHistoryRows,
    /// The TASK rows one board assembly reads.
    TaskBoardRows,
    /// One room's thread-children index rows a hang check walks, for one
    /// room or parent turn.
    RoomThreadChildRows,
    /// The message-to-project origin index rows a hang check walks, for one
    /// message.
    MessageOriginRows,
    /// A thread's bound and moved tasks, counted at bind and conversion.
    ThreadTaskCensus,
    /// The task and ask lists one PROJECT body's normalization reads.
    ProjectTaskRows,
    /// The vault's inbound STOPs this replica has not projected yet, which
    /// each external send reads. A STOP the projector keeps refusing stays.
    PendingCommStops,
    /// The contact claims naming a party, which an external send reads when
    /// a party-wide opt-out stands for its party and no contact row held it.
    PartyContactClaims,
    /// One code-memory slot's live values after a write (once refused past 256).
    CodeMemorySlotValues,
    /// One code symbol's always-on contract keys (once refused past 8).
    CodeMemoryAlwaysOnContracts,
    /// The seed symbols one code-memory pull names (once refused past 256).
    CodeMemoryPullSeeds,
    /// The note limit one code-memory pull asks for (once refused past 256).
    CodeMemoryPullNotes,
    /// The symbols one code-memory pull expands (once cut short past 256).
    CodeMemoryPullSymbols,
    /// One repo diff side's visible text files (once refused past 1024).
    RepoDiffFiles,
    /// The soft-confirm notice deliveries one retry sweep's page reads,
    /// settled ones included.
    AskSoftConfirmDeliveryRows,
    /// One predicate's claims in the claim projection index, which a weave
    /// report reads whole.
    PredicateClaimRows,
    /// Every edge in the vault, which a vault-wide walk (the owner weave
    /// report's links) reads.
    VaultEdgeRows,
    /// The Dreamer prefilter's skip and round receipt rows a receipt query
    /// walks.
    PrefilterReceiptRows,
    /// One MACHINE claim's handoff chain, packet by packet, which each read
    /// of its whole history walks.
    MachineHandoffChain,
    /// One MACHINE claim's target index: the ids of its birth, transitions
    /// and handoffs.
    MachineHistoryTargetRows,
    /// One claim's incident edges of every kind, one way, which a claim-VAD
    /// consolidation or clear reads.
    ClaimVadIncidentEdges,
    /// The retrieval run ledger a newest-runs read walks, provisional rows
    /// included.
    RetrievalRunRows,
    /// The call receipt ledger a served MCP-refusal detector pass walks
    /// before its time and kind filters.
    CallReceiptRows,
    /// One durable run's blocked-report lineage rows.
    BlockedRunReports,
    /// The Sieve's audit rows an audit read walks before its sampled filter,
    /// rows that fail to decode included.
    SieveAuditRows,
    /// One room's roster, which each write of its body validates whole; its
    /// roles are members.
    RoomRosterMembers,
    /// The records and edges one conversation DAG walk reads: an ancestor
    /// chain, a scope's forks, a thread chain, an adoption pass.
    DagWalkRecords,
    /// One TASK's inbound `ScopedTo` edges its authority fold reads, facts
    /// or not.
    TaskAuthorityFactEdges,
    /// Every TASK row one person's open-ask read walks, for one person.
    OpenAskTaskRows,
    /// One record's edges of one kind, one way, which an audience, ancestry
    /// or enumeration read outside a DAG walk reads whole.
    AudienceEdgeRows,
    /// The records a room lookup walks up from one record.
    RoomAncestryRecords,
    /// The records one private-thread walk reaches from one record: its
    /// places and the sources of its words.
    PrivateThreadAncestryRecords,
    /// One trusted policy manifest's room-policy rows, each fold.
    RoomPolicyRows,
    /// One trusted policy manifest's room-thread holder rows, each fold.
    RoomThreadHolderRows,
    /// The signed creation-default edits a creation-default fold reads.
    ProjectDepthDefaultRows,
    /// One project's stored depth-policy contributions a depth fold reads.
    ProjectDepthPolicyRows,
    /// The default-edit ancestry one pinned birth source's walk reads.
    ProjectDepthSourceAncestors,
    /// One depth-policy edit's predecessors, at its put.
    ProjectDepthPredecessors,
    /// One depth-policy contribution's bytes, at its put.
    ProjectDepthContributionBytes,
    /// The attempt records one dispatch ancestor walk reads, wrappers
    /// included.
    DispatchAncestorRows,
    /// One TASK's Linear mirror event index rows a provenance page reads,
    /// its lookahead row included.
    LinearProvenanceRows,
    /// One NOTE document's body bytes, as a store-aware entrance loads or a
    /// room's birth projects it (once refused past 1 MiB).
    NoteDocumentBytes,
    /// One loaded NOTE document's pins (once refused past 256).
    NoteDocumentPinRows,
    /// One loaded NOTE document's authorship entries (once refused past
    /// 4096).
    NoteDocumentAuthorshipRows,
    /// One agent definition's entries in one composition list (skills,
    /// connectors, MCPs, models, verbatim pins or optional-memory
    /// families), at its put (once refused past 64).
    AgentDefinitionListEntries,
    /// The SKILL rows one agent birth's source scan reads (once refused past
    /// 100,000).
    AgentBirthSkillRows,
    /// The ClaimOf edges one agent birth's source scan reads (once refused
    /// past 100,000).
    AgentBirthClaimOfRows,
    /// The spend scopes one ancestry walk reads (once refused past 256).
    SpendAncestorScopes,
    /// The attempt rows one spend retry lookup reads (once refused past
    /// 1,024).
    SpendRetryAttempts,
    /// The attempt rows one kind listing reads, counted before its kind
    /// filter (once refused past 100,000).
    AttemptKindRows,
    /// The longest actor one attempt row's events and cancel receipts carry,
    /// in bytes (once refused past 128).
    AttemptEventActorBytes,
    /// The longest note one attempt row's events carry, in bytes (once
    /// refused past 2048).
    AttemptEventNoteBytes,
    /// The live identity candidates one attendee's first entry offers its
    /// "who is this?" ask (once refused past 32).
    AttendeeIdentityCandidates,
    /// The fact refs one guest ask discloses, against the resolved class or
    /// holder limit (once refused past it; shipped 16).
    GuestDisclosureRefs,
    /// The disclosed refs one guest grant carries (once refused past 64).
    GuestGrantDisclosedRefs,
    /// The symbols one symbol lease declaration names (once refused past
    /// 4096).
    DeclaredSymbols,
    /// The longest session or speaker key one attendee's first entry
    /// carries, in bytes (once refused past 128).
    AttendeeIdentityKeyBytes,
    /// The longest symbol one symbol lease declaration names, in bytes (once
    /// refused past 1024).
    DeclaredSymbolBytes,
    /// The ancestor attempts one comm widen reach walk reads (once refused
    /// past 256).
    CommWidenAncestorRows,
    /// The axes one confirmed project goal intake names, against its
    /// resolved goal limit (once refused past it; shipped 32).
    ProjectGoalAxes,
    /// The preferences one confirmed project goal intake names, against its
    /// resolved goal limit (once refused past it; shipped 64).
    ProjectGoalPreferences,
    /// One goal intake's goal or why, in bytes, against its resolved goal
    /// limit (once refused past it; shipped 4096).
    ProjectGoalTextBytes,
    /// One goal intake's axis name, in bytes, against its resolved goal
    /// limit (once refused past it; shipped 128).
    ProjectGoalAxisNameBytes,
    /// One goal intake's axis measure or bound, or preference field, in
    /// bytes, against its resolved goal limit (once refused past it;
    /// shipped 1024).
    ProjectGoalDetailBytes,
    /// One project body's board, roster, session or branch list (once
    /// refused past 4096).
    ProjectSideListEntries,
    /// One project body's goal record axes (once refused past 128).
    ProjectBodyGoalAxes,
    /// The projects one project ancestry walk reads, or one body's direct
    /// parents (once refused past 256).
    ProjectAncestryRows,
    /// The unanswered project cards one conversation or thread shows once a
    /// new card is kept (once refused past 1).
    ProjectOutstandingCards,
    /// One project card's goal axes, board humans or starting skills (once
    /// refused past 128).
    ProjectProposalEntries,
    /// The distinct views one parent-cycle member's worlds fold to, against
    /// the resolved `cycle_worlds_max` (once withheld past it; shipped 64).
    ProjectCycleWorlds,
    /// The assignments one parent-cycle member's open states enumerate,
    /// against the resolved `cycle_worlds_max` times its open states plus
    /// one (once withheld past it; shipped factor 64).
    ProjectCycleAssignments,
    /// The work one parent-cycle decision spends, against the resolved
    /// `cycle_worlds_max` times 64 times its members and held rows (once
    /// withheld past it; shipped factor 64 × 64).
    ProjectJointWork,
    /// One project card's text, list entry, joined list or fallback text,
    /// in bytes (once refused past 16 KiB).
    ProjectProposalTextBytes,
    /// One page of a thread's quote reply strips, as its caller asked for
    /// it (once refused past 256; a larger ask is served 256 a page).
    ReplyStripRequestedRows,
    /// One page of a room's history, thread history, find, participants or
    /// offers, as its caller asked for it (once refused past 256; a larger
    /// ask is served 256 a page).
    RoomRequestedPageRows,
    /// The rows one room thread list was asked to render (once refused past
    /// 64; a larger ask renders 64 with its find/get continuation).
    RoomThreadListRows,
    /// The links one room reply-chain walk reads (once refused past
    /// 100,000).
    RoomLinkWalkRows,
    /// The messages one Retry lineage walk, or the turns one inherited
    /// offer walk, reads (once refused or cut short past 10,000).
    RoomRetryLineageRows,
    /// The room mentions one witnessed room turn names (once refused past
    /// 256).
    RoomMentions,
    /// The rows per list one room thread policy names (once refused past
    /// 100,000).
    RoomThreadPolicyRows,
    /// The tokens per list one room thread policy names (once refused past
    /// 1,000,000).
    RoomThreadTokens,
    /// The waits per thread one room thread policy names (once refused past
    /// 100,000).
    RoomThreadWaitRows,
    /// One resident binding's goal axes (once refused past 32).
    ResidentGoalAxes,
    /// One agent definition's agentId, logicalId or displayName, in bytes
    /// (once refused past 256).
    AgentDefinitionIdentityBytes,
    /// One agent definition's desc or a model entry's `when`, in bytes (once
    /// refused past 4096).
    AgentDefinitionDescriptionBytes,
    /// One agent definition's version or a skill or MCP minVersion, in bytes
    /// (once refused past 128).
    AgentDefinitionVersionBytes,
    /// One agent definition's instructions, in bytes (once refused past
    /// 16,384).
    AgentDefinitionInstructionBytes,
    /// One agent definition's model, backend, skill, connector, MCP or
    /// optional-memory family reference, in bytes (once refused past 256).
    AgentDefinitionReferenceBytes,
    /// One agent definition's verbatim pin, in bytes (once refused past
    /// 1024).
    AgentDefinitionVerbatimPinBytes,
    /// One agent birth source's encoded bytes (once refused past 32 MiB).
    AgentBirthSourceBytes,
    /// One TASK post's caller intent key, in bytes (once refused past 256).
    TaskPostIntentKeyBytes,
    /// The deepest cover one audience read walks under its row (once denied
    /// past 64).
    AudienceCoverDepth,
    /// One project authority chain's anchors (once quarantined past 64).
    ProjectAnchorDepth,
    /// One project fold's deepest lineage walk (once quarantined past 256).
    ProjectFoldDepth,
    /// One receipt-family source ledger a receipt query reads, named by its
    /// scope (once cut short or refused past 100,000; FIX 3582).
    ReceiptSourceRows,
}
