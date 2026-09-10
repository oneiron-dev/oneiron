"""Variant -> domain assignment for the error-enum split (DESIGN option B).

The table below is the ONLY hand-authored input to the split. Everything else
(`manifest.json`, the rewrite, the invariance check) is derived from it plus
`crates/oneiron/src/error.rs`.

Assignment rule, in order:

1. `ROOT` is the cross-cutting bag the design pins: variants constructed from
   tens of unrelated modules, where nesting would rewrite call sites for no
   readability gain. The design names 21 and this table keeps exactly those 21.
2. Every other variant goes to the domain that owns its *semantics*, read from
   the variant's own doc comment and confirmed against the modules that
   actually construct it. Name prefix is the tie-break, not the rule: e.g.
   `InvalidPredicate` is claim-owned ("Claim predicate violates the pinned D17
   grammar") even though the name reads registry-ish, and
   `MaintenanceKindNotWritable` is registry-owned (it is a type-byte-zone
   refusal, not a maintenance op).
3. A variant constructed from 3+ unrelated domains is a promotion candidate for
   `root`. None is promoted automatically: `PROMOTION_CANDIDATES` records them
   with their module spread so the call is explicit and reversible.
"""

# Domain id -> (enum name, file under crates/oneiron/src/, root wrapper variant).
DOMAINS = {
    "store": ("StoreError", "error/store.rs", "Store"),
    "registry": ("RegistryError", "error/registry.rs", "Registry"),
    "claim": ("ClaimError", "error/claim.rs", "Claim"),
    "gate": ("GateError", "error/gate.rs", "Gate"),
    "record": ("RecordError", "error/record.rs", "Record"),
    "artifact": ("ArtifactError", "error/artifact.rs", "Artifact"),
    "code": ("CodeError", "error/code.rs", "Code"),
    "sync": ("SyncError", "error/sync.rs", "Sync"),
    "offrecord": ("OffRecordError", "error/off_record.rs", "OffRecord"),
    "secret": ("SecretError", "error/secret.rs", "Secret"),
    "relay": ("RelayError", "error/relay.rs", "Relay"),
    "maintenance": ("MaintenanceError", "error/maintenance.rs", "Maintenance"),
}

ROOT_FILE = "error.rs"

# The 21-variant cross-cutting bag. Stays flat on `Error`; zero call sites move.
ROOT = [
    "Storage",
    "Io",
    "MapFull",
    "CorruptedIndex",
    "ConcurrentWrite",
    "InvalidKey",
    "UpstreamToolFailure",
    "InvalidConfig",
    "DimensionMismatch",
    "InvalidVector",
    "InvalidEdgeWeight",
    "InvalidVad",
    "InvalidTemporalExpression",
    "InvalidTimeRange",
    "ArithmeticOverflow",
    "IndexOverflow",
    "InvariantViolation",
    "EntityNotFound",
    "EdgeNotFound",
    "InvalidEntityType",
    "InvalidClaimBody",
]

ASSIGNMENT = {
    # --- store: vault open gates, manifests, analyzer/text index -------------
    "store": [
        "EmbeddingModelChanged",
        "HnswConfigChanged",
        "StorageAbiVersionChanged",
        "StorageSchemaVersionChanged",
        "DbManifestMismatch",
        "VaultRootPreflight",
        "MissingPostingEntry",
        "IncompatibleAnalyzer",
        "Bm25FieldSchemaChanged",
        "InvalidRankProfile",
        "AnalyzerAssetMissing",
        "AnalyzerError",
        "VaultRead",
    ],
    # --- registry: entity kinds, type bytes, edge kinds, the ChildOf tree ----
    "registry": [
        "InvalidFacet",
        "InvalidRelationship",
        "InvalidFacetOfEdge",
        "MaintenanceKindNotWritable",
        "StructuralKindZoneViolation",
        "StructuralKindTypeByteCollision",
        "StructuralKindPrefixCollision",
        "InvalidStructuralKindRegistration",
        "SurfaceEventCorrelationKindCollision",
        "EntityTypeImmutable",
        "ReservedEdgeKind",
        "CycleDetected",
        "ChildOfCardinality",
        "ChildOfParentMissing",
        "TaskChildOfParentNotTask",
        "TaskChildOfNesting",
    ],
    # --- claim: claim + provenance lifecycle, predicates, emit receipts ------
    "claim": [
        "InvalidPredicate",
        "ReservedPredicate",
        "ActorLacksClaimAuthority",
        "ProvenanceOnStructuralEdge",
        "ActorClassMismatch",
        "InvalidProvenanceBody",
        "InvalidModelSubstrate",
        "EmitAdjacentReceiptRequired",
        "ClaimAlreadyClosed",
        "WriteVerbTargetStale",
        "ClaimSelfSupersession",
        "ProvenanceClaimLifecycle",
        "NotAProvenanceClaim",
        "ProvenanceClaimAlreadyClosed",
        "ProvenanceClaimIdInUse",
        "ProvenanceSubjectMismatch",
        "ProvenanceSelfSupersession",
        "ProvenancePrecedenceViolation",
        "EdgeIsProvenanced",
    ],
    # --- gate: gate decisions, consent, disclosure ---------------------------
    "gate": [
        "InvalidDisclosureScope",
        "DisclosureClampViolation",
        "InvalidConsentBound",
        "InvalidConsentGrantRow",
        "InvalidConsentEffectFacts",
        "ConsentOwnerNotAuthenticated",
        "ConsentUnauthenticatedActor",
        "ConsentCatastropheNotRememberable",
        "ConsentGrantNotFound",
        "ConsentGrantRevoked",
        "ConsentApproveOnceSpent",
        "GateWriteRejected",
        "GateConsentStale",
        "FamilyRequiresAutoGrant",
        "SourceNotTrustedForAuto",
        "PersonaSnapshotConsentStale",
    ],
    # --- record: typed record bodies, *AlreadyExists, charter, authority log -
    "record": [
        "AccessGrantAlreadyExists",
        "OutboundGrantAlreadyExists",
        "ConnectorKeyAlreadyExists",
        "ChannelIdentityAlreadyExists",
        "CounterpartyContactAlreadyExists",
        "CompanionRecordAlreadyExists",
        "InvalidFederationGrantBody",
        "InvalidAuthorityLogBody",
        "AuthorityLogAppendOnlyViolation",
        "AuthorityLogStoreKeyMismatch",
        "ContextPackValidation",
        "InvalidCompanionRecordBody",
        "InvalidPsychProfileBody",
        "InvalidPersonaSnapshot",
        "InvalidNoteBody",
        "InvalidWitnessMessageBody",
        "InvalidAccessGrantBody",
        "InvalidOutboundGrantBody",
        "InvalidConnectorKeyBody",
        "ConnectorCharterCompile",
        "ConnectorCharterApprovalMismatch",
        "ConnectorCharterMissing",
        "InvalidChannelIdentityBody",
        "WorkspaceMailboxAutonomyNotReady",
        "InvalidCounterpartyContactBody",
        "InvalidCommRecordBody",
        "InvalidDiagnosticBody",
        "InvalidTaskBody",
    ],
    # --- artifact: artifacts, edits, skills, agents, attempt queue, recovery -
    "artifact": [
        "InvalidCodeArtifactBody",
        "InvalidBlobArtifactBody",
        "InvalidLfsObject",
        "InvalidAnchor",
        "AnnotationThreadNotFound",
        "InvalidEditManifest",
        "EditRoundtripFailed",
        "EditProposalAlreadySettled",
        "EditProposalStale",
        "SettleNotAuthorized",
        "DeltaCaptureUnavailable",
        "InvalidSkillBody",
        "SkillEditGateRetry",
        "SkillContentAnchorTypeMismatch",
        "InvalidAgentDefBody",
        "AgentDefinitionNotFound",
        "AgentDefinitionDisabled",
        "SeededAgentDefinitionConflict",
        "AgentNotDispatchable",
        "InvalidAgentDispatchInput",
        "InvalidAttemptQueueRecord",
        "InvalidAttemptQueueTransition",
        "InvalidRecoveryArtifact",
        "RecoveryArtifactQuarantineExhausted",
    ],
    # --- code: codebase, code_run, code memory, repo mutation, git http, VM --
    "code": [
        "InvalidCodebaseSnapshotBody",
        "HostedMediaHashMatchKnownMatch",
        "InvalidCodeSymbolManifestBody",
        "InvalidRepoMutationRecord",
        "RepoMutationFailed",
        "RepoMutationRecoveryDiverged",
        "MicroVmBackendUnavailable",
        "MicroVmBackendError",
        "MicroVmOverlayError",
        "MicroVmCredentialDestinationDenied",
        "CodeEmissionMissingDreamerRunId",
        "CodeReviewContextRequired",
        "CodeReviewUnsupportedOperation",
        "CodeReviewMissingReviewerRunId",
        "CodeReviewRunIdNotDistinct",
        "CodeReviewMissingArtifactRefs",
        "CodeReviewAuthoringRunIdMismatch",
        "CodeBlastRadiusMissingTouchedSymbols",
        "CodeBlastRadiusUnknownSymbol",
        "CodeMemoryInvalidAnchor",
        "CodeMemoryInvalidAnchorTransfer",
        "CodeMemoryBlocksCycle",
        "CodeMemoryBlocksActorDenied",
        "CodeMemoryBlocksSourceUntrusted",
        "CodeMemoryAlwaysOnInvalid",
        "CodeMemoryLimitExceeded",
        "GitHttpInvalidRepoName",
        "GitHttpRepoNotFound",
        "GitHttpServeFailed",
        "ReceivePackDoorRejected",
        "ReceivePackLandingRefused",
    ],
    # --- sync: the 11 cfg(sync) variants + receipts + identity topology ------
    "sync": [
        "CrdtDecodeError",
        "WindowNotFound",
        "WindowBusy",
        "SyncProtocolError",
        "SyncEngineError",
        "MaintenanceIngestQuotaExceeded",
        "RedactionReceiptDivergence",
        "ReceiptAttestationInvalid",
        "ReceiptLeaseUnknown",
        "ReceiptLeaseRevoked",
        "IdentityTopologyEventDivergence",
        "InvalidRedactionReceiptBody",
        "IdentityTopologyRejected",
        "InvalidIdentityTopologyEventBody",
        "IdentityTopologyUnarmed",
        "IdentityProposalAmendmentOutOfScope",
    ],
    # --- offrecord: off-record sessions and their overlays -------------------
    "offrecord": [
        "KillSwitchDisabled",
        "OffRecordSessionAlreadyExists",
        "OffRecordSessionNotFound",
        "OffRecordSessionClosing",
        "OffRecordOverlayFull",
        "OffRecordOverlayLeaseClosed",
        "OffRecordPromoteUnauthenticated",
        "OffRecordTaintedBaseWrite",
        "OffRecordWitnessDoorRejected",
        "OffRecordGuestTurnRefRejected",
        "OffRecordTalkOnly",
        "OffRecordTurnNotInJournal",
    ],
    # --- secret: custody, leases, taint --------------------------------------
    "secret": [
        "InvalidSecretCustodyBody",
        "SecretNameInUse",
        "SecretCustodyNotActive",
        "SecretBindingDenied",
        "ManifestWidensFloor",
        "SecretTierDenied",
        "SecretRefNotFound",
        "SecretLeaseNotFound",
        "SecretLeaseNotActive",
        "SecretLeasePathNotDeclared",
        "SecretLeasePathConflict",
        "SecretLeasePathRefused",
        "SecretLeaseReceiptWriteFailed",
        "InvalidSecretLeaseBody",
        "InvalidSecretRotationBody",
        "TaintedArtifactStale",
    ],
    # --- relay: relay attestation, hosted legal policy -----------------------
    "relay": [
        "RelayAttestationInvalidServiceIdentity",
        "RelayVaultReceiptUntrusted",
        "PolicyVerdictNotInForce",
        "RelayAttestationClassMismatch",
        "RelayAttestationEdgeServiceConflict",
        "RelayHostedLegalPolicyInvalid",
        "PolicyManifestInvalid",
    ],
    # --- maintenance: compaction packets, vault cleanup ----------------------
    "maintenance": [
        "CompactionPacketRejected",
        "VaultCleanupRestoreNotArchived",
        "VaultCleanupArchiveMarkerUndecodable",
        "VaultCleanupProposalNotFound",
        "VaultCleanupWakeTriggerRejected",
    ],
}

# Judgment calls worth a second reader. `name -> (domain, why)`.
NOTES = {
    "InvalidPredicate": ("claim", "doc: 'Claim predicate violates the pinned D17 grammar'; constructed in claim/"),
    "ReservedPredicate": ("claim", "doc: 'Claim predicate lives in the reserved edge.* namespace'"),
    "MaintenanceKindNotWritable": ("registry", "a type-byte-zone refusal, sibling of InvalidEntityType; not a maintenance op"),
    "SourceNotTrustedForAuto": ("gate", "source-trust ceiling refusing an auto-approved write; constructed under gate/"),
    "FamilyRequiresAutoGrant": ("gate", "doc: 'asked the gate for Auto, did not get it'; sibling of GateWriteRejected"),
    "PersonaSnapshotConsentStale": ("gate", "consent staleness against a compile stamp; record-named but gate-semantic"),
    "EmitAdjacentReceiptRequired": ("claim", "emit-receipt surface (OF-369/RS9); not a cfg(sync) receipt"),
    "DeltaCaptureUnavailable": ("artifact", "ARCH-0056 amendment-delta telemetry; constructed in edit_distance/"),
    "KillSwitchDisabled": ("offrecord", "doc: 'Off-record entry is disabled by the vault-level kill-switch'"),
    "HostedMediaHashMatchKnownMatch": ("code", "constructed in codebase/; hosted-media provider on the code ingest path"),
    "InvalidLfsObject": ("artifact", "design pins 'code/blob/lfs artifacts' to ArtifactError even though origin/ constructs it"),
    "VaultRead": ("store", "design pins VaultReadError under StoreError; the type itself lives in code_run/vault_read/"),
    "ContextPackValidation": ("record", "cross-record assembly anomaly; constructed in context_pack/"),
    "WorkspaceMailboxAutonomyNotReady": ("record", "ONE-1829 onboarding-journal state on a record surface"),
    "InvalidClaimBody": ("root", "claim-named but in the 21-variant bag: 854 lines across 72 modules"),
}

# Variants that never move but whose payload types or helpers do.
# `(item, kind, from_file, to_domain, note)`
MOVING_ITEMS = [
    ("GateDenialOutcome", "enum", "error.rs", "gate", "GateDenial taxonomy, error.rs:16-48"),
    ("GateDenialReason", "enum", "error.rs", "gate", "error.rs:50-169"),
    ("GateDenial", "struct", "error.rs", "gate", "error.rs:171-202"),
    ("Error::gate_denial", "method", "error.rs", "gate", "reads GateWriteRejected; becomes GateError::gate_denial, root delegates"),
    ("CompactionPacketError", "enum", "error.rs", "maintenance", "error.rs:204-281 incl. Display"),
    ("From<CompactionPacketError>", "impl", "error.rs", "maintenance", "targets CompactionPacketRejected; becomes From<..> for MaintenanceError"),
    ("SyncConfigField", "enum", "error.rs", "sync", "error.rs:520-547"),
    ("SyncSelectorValidation", "enum", "error.rs", "sync", "error.rs:549-646"),
    ("SyncProtocolPruneScope", "enum", "error.rs", "sync", "error.rs:648-655"),
    ("SyncProtocolValidation", "enum", "error.rs", "sync", "error.rs:657-711"),
    ("SyncEngineContext", "enum", "error.rs", "sync", "error.rs:713-755"),
    ("SyncRollbackError", "struct", "error.rs", "sync", "error.rs:757-805 incl. StdError impl"),
    ("Error::sync_protocol", "method", "error.rs", "sync", "cfg(sync) constructor; becomes SyncError::sync_protocol"),
    ("Error::sync_engine", "method", "error.rs", "sync", "cfg(sync) constructor"),
    ("Error::sync_engine_rollback", "method", "error.rs", "sync", "cfg(sync) constructor"),
    ("VaultRootEntry", "enum", "error.rs", "store", "error.rs:807-828"),
    ("VaultRootProblem", "enum", "error.rs", "store", "error.rs:830-901"),
    ("VaultReadError", "enum", "code_run/vault_read/error.rs", "store", "NOT in error.rs; only the VaultRead wrapper variant relocates"),
]

# Manual `From<X> for Error` impls and where they land.
FROM_IMPLS = [
    {
        "impl": "From<heed::Error> for Error",
        "file": "crates/oneiron/src/error.rs",
        "targets": ["MapFull", "Storage"],
        "goes_to": "root",
        "note": "both targets are bag variants; impl is unchanged",
    },
    {
        "impl": "From<std::io::Error> for Error",
        "file": "crates/oneiron/src/error.rs",
        "targets": ["Io"],
        "goes_to": "root",
        "note": "bag variant; impl is unchanged",
    },
    {
        "impl": "From<CompactionPacketError> for Error",
        "file": "crates/oneiron/src/error.rs",
        "targets": ["CompactionPacketRejected"],
        "goes_to": "maintenance",
        "note": "becomes From<CompactionPacketError> for MaintenanceError; the root #[from] wrapper "
                "then supplies From<CompactionPacketError> for Error only via two hops, so KEEP a "
                "root-level From<CompactionPacketError> for Error delegating to MaintenanceError",
    },
    {
        "impl": "From<ScheduleError> for crate::Error",
        "file": "crates/oneiron/src/commitment_schedule.rs",
        "targets": ["InvariantViolation", "ArithmeticOverflow", "<passthrough Engine(inner)>"],
        "goes_to": "stays put",
        "note": "all targets are bag variants; file is untouched by the rewrite",
    },
    {
        "impl": "From<ConnectorCharterCompileIssue> for Error",
        "file": "crates/oneiron/src/connector_key/charter.rs",
        "targets": ["ConnectorCharterCompile"],
        "goes_to": "stays put, body rewritten",
        "note": "target moves to RecordError; the impl stays in charter.rs and its body becomes "
                "Error::Record(RecordError::ConnectorCharterCompile { .. })",
    },
]

# Root inherent methods that must keep working after the split.
ROOT_METHODS = [
    {"name": "kind", "note": "21 bag arms + 12 delegations to <Domain>Error::kind(); stays exhaustive, no wildcard"},
    {"name": "is_retryable", "note": "ConcurrentWrite/UpstreamToolFailure/Io stay; SkillEditGateRetry delegates to ArtifactError, "
                                     "cfg(sync) WindowBusy delegates to SyncError; trailing wildcard arm stays"},
    {"name": "gate_denial", "note": "moves to GateError; root keeps a delegating wrapper so the 3 external path uses hold"},
    {"name": "invalid_vector_component", "note": "pub(crate); target InvalidVector is a bag variant; unchanged"},
]


# The design's side finding: two variants with zero references anywhere.
# Verdict per variant, with the evidence that produced it. `action` here
# overrides the manifest's default for that variant.
DEAD_VERDICTS = {
    "AnalyzerAssetMissing": {
        "verdict": "keep",
        "action": "move",
        "references": 0,
        "evidence": [
            "zero occurrences anywhere in the repo outside error.rs: the only three "
            "lines are its ErrorKind twin (error.rs:416), its own declaration "
            "(error.rs:1742) and its kind() arm (error.rs:2605) — grepped across "
            "crates/, docs/, scripts/, apps/, packages/ and every .json/.jsonl/.snap",
            "its ErrorKind name is NOT in remote_rejection_reason's allowlist in "
            "sync/quarantine/keys_classifier.rs, so it can never become a persisted "
            "quarantine reason code; and reason_code_for only ever sees a CONSTRUCTED "
            "error, which this never is",
            "the door it documents is unbuilt: no dict-asset existence check exists. "
            "analyzer/manifest.rs fails the open-time handshake with IncompatibleAnalyzer, "
            "and config.rs:330 documents IncompatibleAnalyzer as the escape hatch",
        ],
        "why_keep": "deleting it edits ErrorKind, and `ErrorKind byte-identical` is the "
                    "single invariant that makes this refactor mechanically verifiable "
                    "(check c). It costs nothing to carry: it moves with StoreError like "
                    "any other variant, with zero call sites to rewrite. Delete it in its "
                    "own one-line PR, before or after, never inside this one.",
    },
    "OffRecordPromoteUnauthenticated": {
        "verdict": "keep",
        "action": "move",
        "references": 0,
        "evidence": [
            "zero occurrences anywhere in the repo outside error.rs: declaration "
            "(error.rs:1864), ErrorKind twin (error.rs:438), kind() arm (error.rs:2629)",
            "its ErrorKind name is NOT in remote_rejection_reason's allowlist, so it "
            "cannot be persisted as a quarantine reason code",
            "the door it documents is unbuilt, and provably so: "
            "OffRecordSession::promote_turn (off_record/lifecycle/session.rs:686) is "
            "`fn promote_turn(&self, turn: &EntityId)` — it takes no actor argument, so "
            "there is nothing to authenticate. The OF-326 / ONE-1645 authentication it "
            "describes has not been wired",
        ],
        "why_keep": "same reason as AnalyzerAssetMissing, plus this one is a forward "
                    "declaration of a fail-closed consent door. Deleting it drops the "
                    "recorded intent that promote MUST authenticate the owner principal, "
                    "and nothing else in the tree records that.",
    },
}

# Zero direct `Error::X` references but reachable another way — not a dead variant.
REACHABLE_WITHOUT_NAMING = {
    "VaultRead": "constructed only through `#[from] VaultReadError` (thiserror generates "
                 "the From impl); `?` on a VaultReadError is the only caller",
}
