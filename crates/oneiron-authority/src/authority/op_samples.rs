//! Populated wire-shape samples for the authority overlay census.
//!
//! These exercise `op_value`, not admission: optional payloads deliberately
//! coexist even when validation would reject that combination. Collections
//! have two members, except intrinsic wire shapes noted at their construction.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use super::*;
use crate::entity_id::EntityId;
use crate::federation::{
    FederationDirectionScope, FederationGrantKind, FederationPactScope, GitPushBounds, GitPushRepo,
    RepoAccessBounds, Scope, ScopeAxis, ScopeId, SelectorRange, Sensitivity, SensitivityCeiling,
    WalletRef, WorkingViewEditBounds,
};
use crate::share_travel::{BornWithField, TravelChoice};

pub(super) const OP_KIND_NAMES: [&str; 42] = [
    "SlipMint",
    "SlipRevoke",
    "SlipConsume",
    "SlipGrantRevoke",
    "RemovalArchiveConsume",
    "Genesis",
    "EnrollDevice",
    "RevokeDevice",
    "RotateKey",
    "ReRoot",
    "FederationConfirm",
    "CriticalWriteConfirm",
    "FederationLifecycle",
    "BindActor",
    "RebindActor",
    "RevokeActor",
    "MachineProfile",
    "OwnerRoot",
    "WorldPrivacy",
    "WorldKeyWraps",
    "OwnerHandover",
    "ResidenceDirective",
    "ResidenceResult",
    "GrantTravelSet",
    "OwnerWorkRequest",
    "OwnerWorkResult",
    "OwnerWorkCancel",
    "ExportSupplementImported",
    "CustodyPermitPiece",
    "CheckpointPolicySet",
    "HomeNodePick",
    "ConversationTrainingSet",
    "ConversationTrainingVaultSet",
    "HomeCandidacy",
    "AgentGrantAct",
    "PolicySettingSet",
    "ExportAct",
    "OwnerKeyEnroll",
    "FrontierJoin",
    "OriginCut",
    "DeviceSuccession",
    "MembershipExecution",
];

pub(super) fn op_kind_name(op: &AuthorityOp) -> &'static str {
    match op {
        AuthorityOp::SlipMint(_) => "SlipMint",
        AuthorityOp::SlipRevoke { .. } => "SlipRevoke",
        AuthorityOp::SlipConsume { .. } => "SlipConsume",
        AuthorityOp::SlipGrantRevoke { .. } => "SlipGrantRevoke",
        AuthorityOp::RemovalArchiveConsume { .. } => "RemovalArchiveConsume",
        AuthorityOp::Genesis { .. } => "Genesis",
        AuthorityOp::EnrollDevice { .. } => "EnrollDevice",
        AuthorityOp::RevokeDevice { .. } => "RevokeDevice",
        AuthorityOp::RotateKey { .. } => "RotateKey",
        AuthorityOp::ReRoot { .. } => "ReRoot",
        AuthorityOp::FederationConfirm(_) => "FederationConfirm",
        AuthorityOp::CriticalWriteConfirm(_) => "CriticalWriteConfirm",
        AuthorityOp::FederationLifecycle(_) => "FederationLifecycle",
        AuthorityOp::BindActor { .. } => "BindActor",
        AuthorityOp::RebindActor { .. } => "RebindActor",
        AuthorityOp::RevokeActor { .. } => "RevokeActor",
        AuthorityOp::MachineProfile(_) => "MachineProfile",
        AuthorityOp::OwnerRoot(_) => "OwnerRoot",
        AuthorityOp::WorldPrivacy(_) => "WorldPrivacy",
        AuthorityOp::WorldKeyWraps(_) => "WorldKeyWraps",
        AuthorityOp::OwnerHandover(_) => "OwnerHandover",
        AuthorityOp::ResidenceDirective(_) => "ResidenceDirective",
        AuthorityOp::ResidenceResult(_) => "ResidenceResult",
        AuthorityOp::GrantTravelSet(_) => "GrantTravelSet",
        AuthorityOp::OwnerWorkRequest(_) => "OwnerWorkRequest",
        AuthorityOp::OwnerWorkResult(_) => "OwnerWorkResult",
        AuthorityOp::OwnerWorkCancel(_) => "OwnerWorkCancel",
        AuthorityOp::ExportSupplementImported(_) => "ExportSupplementImported",
        AuthorityOp::CustodyPermitPiece(_) => "CustodyPermitPiece",
        AuthorityOp::CheckpointPolicySet(_) => "CheckpointPolicySet",
        AuthorityOp::HomeNodePick(_) => "HomeNodePick",
        AuthorityOp::ConversationTrainingSet(_) => "ConversationTrainingSet",
        AuthorityOp::ConversationTrainingVaultSet(_) => "ConversationTrainingVaultSet",
        AuthorityOp::HomeCandidacy(_) => "HomeCandidacy",
        AuthorityOp::AgentGrantAct(_) => "AgentGrantAct",
        AuthorityOp::PolicySettingSet(_) => "PolicySettingSet",
        AuthorityOp::ExportAct(_) => "ExportAct",
        AuthorityOp::OwnerKeyEnroll(_) => "OwnerKeyEnroll",
        AuthorityOp::FrontierJoin(_) => "FrontierJoin",
        AuthorityOp::OriginCut(_) => "OriginCut",
        AuthorityOp::DeviceSuccession(_) => "DeviceSuccession",
        AuthorityOp::MembershipExecution(_) => "MembershipExecution",
    }
}

fn entity_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("sample id is outside the reserved sentinel range")
}

fn strings(first: &str, second: &str) -> BTreeSet<String> {
    BTreeSet::from([first.to_owned(), second.to_owned()])
}

fn device() -> DeviceAuthority {
    DeviceAuthority {
        key: AuthorityKey::Ed25519([1; 32]),
        transport_key_binding: [2; 32],
        attestation: AuthorityAttestation {
            kind: "software".to_owned(),
            evidence: vec![3, 4],
        },
        tier: AuthorityTier::Software,
        roles: ROLE_OWNER,
    }
}

fn encryption_key() -> MachineEncryptionKey {
    MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![5, 6],
    }
}

fn owner_act(kind: OwnerActKind) -> OwnerAct {
    OwnerAct {
        owner: entity_id(1),
        by: ActBy::Agent {
            agent: entity_id(2),
            grant: entity_id(3),
        },
        surface: ActSurface::LinkedDevice {
            machine: entity_id(4),
        },
        act: kind,
        target: entity_id(5),
        seen: [7; 32],
        answer: Some(entity_id(6)),
    }
}

fn scope() -> Scope {
    Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([
            ScopeId(entity_id(7)),
            ScopeId(entity_id(8)),
        ])),
        facets: ScopeAxis::Some(BTreeSet::from([
            ScopeId(entity_id(9)),
            ScopeId(entity_id(10)),
        ])),
        bands: ScopeAxis::Some(BTreeSet::from([1, 2])),
        audience: ScopeAxis::Some(BTreeSet::from([
            ScopeId(entity_id(11)),
            ScopeId(entity_id(12)),
        ])),
        verbs: ScopeAxis::Some(strings("read", "write")),
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Private),
    }
}

fn slip_mint(scope: Scope) -> AuthorityOp {
    AuthorityOp::SlipMint(SlipMintAction {
        claims: SlipClaims {
            slip_id: [8; 32],
            vault_id: [9; 32],
            parent_id: Some([10; 32]),
            holder_ref: entity_id(13).to_hex(),
            binding_key: [11; 32],
            scope,
            issued_at: 100,
            expires_at: 200,
            ttl_secs: 100,
            single_use: true,
            records: strings("repo:payroll-ledger", "repo:release-notes"),
            channels: strings("slack:#ops", "slack:#releases"),
            actor_class: Some("agent".to_owned()),
            org_ref: Some(entity_id(14).to_hex()),
            grant_ref: Some(entity_id(15).to_hex()),
            invitation_ref: Some(entity_id(16).to_hex()),
            share_ref: Some(entity_id(17).to_hex()),
            delegation: Some(SupportDelegation {
                purpose: "repair expired leases".to_owned(),
                ticket_ref: Some("support:42".to_owned()),
                owner_ref: entity_id(18).to_hex(),
                approved_at: 100,
                wall_expires_at: 200,
                repairs: BTreeSet::from([
                    SupportRepair::CriticalConfirmExpiry,
                    SupportRepair::SymbolLeaseExpiry,
                ]),
            }),
            comm: Some(CommReach::Project),
            trusted_contact: Some(TrustedContactSlipBinding {
                person: entity_id(19),
                version: 2,
            }),
            seat_claim: Some(SeatClaimSlipBinding {
                attempt: [12; 16],
                lease_owner: "worker:payroll".to_owned(),
                attempt_count: 2,
            }),
        },
        renews: Some([13; 32]),
        minting_member: Some(entity_id(20)),
    })
}

fn slip_samples() -> Vec<AuthorityOp> {
    vec![
        slip_mint(scope()),
        slip_mint(Scope::top()),
        slip_mint(Scope::default()),
        AuthorityOp::SlipRevoke { slip_id: [14; 32] },
        AuthorityOp::SlipConsume { slip_id: [15; 32] },
        AuthorityOp::SlipGrantRevoke {
            grant_ref: entity_id(21),
            membership_receipt: Some(entity_id(22).to_hex()),
        },
        AuthorityOp::RemovalArchiveConsume {
            slip_id: [16; 32],
            member: entity_id(23),
        },
    ]
}

fn roster_samples() -> Vec<AuthorityOp> {
    vec![
        AuthorityOp::Genesis {
            device: device(),
            genesis_nonce: [17; 32],
            recovery: GenesisRecoveryStep::Saved([18; 32]),
        },
        AuthorityOp::EnrollDevice { device: device() },
        AuthorityOp::RevokeDevice {
            revoked_key: AuthorityKey::Ed25519([19; 32]),
        },
        AuthorityOp::RotateKey {
            old_key: AuthorityKey::Ed25519([20; 32]),
            new_device: device(),
        },
        AuthorityOp::ReRoot {
            new_device: device(),
        },
        AuthorityOp::BindActor {
            authority_key: AuthorityKey::Ed25519([21; 32]),
            actor_ref: entity_id(24),
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        AuthorityOp::RebindActor {
            authority_key: AuthorityKey::Ed25519([22; 32]),
            actor_ref: entity_id(25),
            actor_class: "agent".to_owned(),
            epoch: 2,
        },
        AuthorityOp::RevokeActor {
            authority_key: AuthorityKey::Ed25519([23; 32]),
            epoch: 3,
        },
        AuthorityOp::FederationConfirm(AuthorityConfirmAction {
            kind: AuthorityConfirmKind::Accept,
            confirm_id: [24; 32],
            peer_vault_id: [25; 32],
            epoch: 1,
            nonce: [26; 16],
        }),
        AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
            schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
            confirm_id: [27; 32],
            gate_decision_id: [28; 16],
            claim_id: entity_id(26),
            effect_digest: [29; 32],
            read_frontier_hash: [30; 32],
            nonce: [31; 16],
            expires_at: 200,
            disposition: CriticalWriteConfirmDisposition::Clear,
            method: CriticalWriteConfirmMethod::TokenReauth,
        }),
    ]
}
fn direction_scope() -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: ScopeAxis::Some(BTreeSet::from([
            ScopeId(entity_id(27)),
            ScopeId(entity_id(28)),
        ])),
        facets: ScopeAxis::Some(BTreeSet::from([
            ScopeId(entity_id(29)),
            ScopeId(entity_id(30)),
        ])),
        bands: ScopeAxis::Some(BTreeSet::from([
            SelectorRange::Semantic,
            SelectorRange::Core,
        ])),
    }
}

fn direction_scope_samples() -> Vec<FederationDirectionScope> {
    vec![
        direction_scope(),
        FederationDirectionScope {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::All,
            bands: ScopeAxis::All,
        },
        FederationDirectionScope {
            worlds: ScopeAxis::Bottom,
            facets: ScopeAxis::Bottom,
            bands: ScopeAxis::Bottom,
        },
        FederationDirectionScope {
            // The special `base` spelling requires exactly one world.
            worlds: crate::federation::pact_scope::base_world_axis(),
            facets: direction_scope().facets,
            bands: direction_scope().bands,
        },
    ]
}

fn lifecycle_sample(
    kind: FederationLifecycleKind,
    direction: FederationDirectionScope,
) -> AuthorityOp {
    AuthorityOp::FederationLifecycle(FederationLifecycleAction {
        kind,
        pact_id: [32; 32],
        grant_ref: entity_id(31),
        peer_vault_id: [33; 32],
        pact_epoch: 1,
        pact_scope: Some(FederationPactScope {
            lo_to_hi: direction.clone(),
            hi_to_lo: direction.clone(),
        }),
        effective_scope: Some(direction),
        scope_digest: Some([34; 32]),
        gesture: Some(FederationPactGesture {
            signer: AuthorityKey::Ed25519([35; 32]),
            signature: vec![36, 37],
        }),
        successor_vault_id: Some([38; 32]),
        pact_nonce: [39; 16],
    })
}

fn lifecycle_samples() -> Vec<AuthorityOp> {
    [
        FederationLifecycleKind::Connect,
        FederationLifecycleKind::Rescope,
        FederationLifecycleKind::Disconnect,
        FederationLifecycleKind::Promote,
        FederationLifecycleKind::Dissolve,
    ]
    .into_iter()
    .flat_map(|kind| {
        direction_scope_samples()
            .into_iter()
            .map(move |direction| lifecycle_sample(kind, direction))
    })
    .collect()
}

fn machine_profile() -> MachineProfile {
    MachineProfile {
        machine: entity_id(32),
        owner: entity_id(1),
        machine_key: [40; 32],
        device_class: MachineDeviceClass::Computer,
        encryption_key: encryption_key(),
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 2,
        machine_proof: [41; 64],
        seen_world_edits: BTreeSet::from([[42; 32], [43; 32]]),
        carrier: Some(entity_id(4)),
        act: Some(owner_act(OwnerActKind::MachineAnswer)),
    }
}

fn world_key_wraps() -> WorldKeyWrapsRecord {
    let machine = WrapRecipient::Machine(entity_id(33));
    let root = WrapRecipient::RecoveryRoot(RecoveryRootId([44; 32]));
    WorldKeyWrapsRecord {
        key: WorldKeyId {
            world: entity_id(34),
            generation: 2,
            mint: [45; 16],
        },
        commitment: [46; 32],
        owner: entity_id(1),
        policy: PolicyRevision([47; 32]),
        machine: entity_id(4),
        wraps: vec![(machine, vec![48, 49]), (root, vec![50, 51])],
        request: Some([52; 32]),
        permitted: vec![machine, root],
    }
}

fn owner_handover() -> OwnerHandover {
    OwnerHandover {
        shared_vault: 42,
        cause: OwnerHandoverCause::Transfer,
        from: entity_id(35),
        to: Some(entity_id(36)),
        from_keeps: Some("admin".to_owned()),
        act: Some(entity_id(37).to_hex()),
        proof: Some("35".repeat(32)),
        authorizer: Some(entity_id(38)),
        receipt: entity_id(39).to_hex(),
        affected_grants: vec![entity_id(40), entity_id(41)],
        retired_own_device_grants: vec![entity_id(42), entity_id(43)],
    }
}

fn privacy_samples() -> Vec<AuthorityOp> {
    let mut samples = vec![
        AuthorityOp::MachineProfile(machine_profile()),
        AuthorityOp::OwnerRoot(OwnerRootRecord {
            owner: entity_id(1),
            root: RecoveryRootId([54; 32]),
            recovery_key: encryption_key(),
            anchor_key: [55; 32],
        }),
        AuthorityOp::WorldKeyWraps(world_key_wraps()),
        AuthorityOp::OwnerHandover(owner_handover()),
    ];
    for by in [
        ActBy::Owner,
        ActBy::Agent {
            agent: entity_id(2),
            grant: entity_id(3),
        },
    ] {
        for surface in [
            ActSurface::ThisInstall,
            ActSurface::LinkedDevice {
                machine: entity_id(4),
            },
            ActSurface::HostedConsole,
        ] {
            samples.push(AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world: entity_id(34),
                act: OwnerAct {
                    by,
                    surface,
                    ..owner_act(OwnerActKind::WorldPrivacy)
                },
                machine: entity_id(4),
                settings: WorldPrivacy {
                    read: ReadLocation::OneMachine(entity_id(33)),
                    sealed: SealedCopies::CloudAndMyMachines,
                    models: ModelOrder::Ordered(vec![
                        "local:fast".to_owned(),
                        "remote:careful".to_owned(),
                    ]),
                },
            }));
        }
    }
    samples
}

fn residence_samples() -> Vec<AuthorityOp> {
    let mut samples: Vec<_> = [
        ResidenceAct::SyncAll,
        ResidenceAct::SyncOpened,
        ResidenceAct::Follow {
            worlds: BTreeSet::from([entity_id(44), entity_id(45)]),
        },
        ResidenceAct::Open {
            window: "repo:payroll-ledger".to_owned(),
            item: entity_id(46),
        },
        ResidenceAct::Index,
        ResidenceAct::Prune { before: 100 },
    ]
    .into_iter()
    .map(|act| {
        AuthorityOp::ResidenceDirective(ResidenceDirective {
            id: entity_id(47),
            machine: entity_id(4),
            owner: entity_id(1),
            issued_at: 150,
            act,
        })
    })
    .collect();
    samples.push(AuthorityOp::ResidenceResult(ResidenceResult {
        directive: entity_id(47),
        machine: entity_id(4),
        directive_entry: [56; 32],
        finished_at: 200,
        status: ResidenceResultStatus::Refused,
        count: 2,
        reason: Some("window not granted".to_owned()),
    }));
    samples
}
fn root_basis() -> RootRevisionBasis {
    RootRevisionBasis {
        roots: BTreeSet::from([RecoveryRootId([57; 32]), RecoveryRootId([58; 32])]),
        roster: Some([59; 32]),
        roster_trusted: Some([60; 32]),
        anchored: BTreeMap::from([([61; 32], [62; 32]), ([63; 32], [64; 32])]),
        bound: Some([65; 32]),
        parents: BTreeMap::from([
            ([62; 32], BTreeSet::from([[66; 32], [67; 32]])),
            ([64; 32], BTreeSet::from([[68; 32], [69; 32]])),
        ]),
    }
}

fn permit(machine: u8, profile: u8, encryption_key: u8) -> CustodyRecipientPermit {
    CustodyRecipientPermit {
        machine: entity_id(machine),
        profile: [profile; 32],
        encryption_key: [encryption_key; 32],
    }
}

fn permits() -> Vec<CustodyRecipientPermit> {
    vec![permit(48, 70, 71), permit(49, 72, 73)]
}

fn permit_pieces() -> CustodyPermitPieces {
    CustodyPermitPieces {
        set: [74; 32],
        count: 2,
        pieces: 2,
    }
}

fn custody_work(pieces: Option<CustodyPermitPieces>) -> OwnerWorkBody {
    OwnerWorkBody::Custody {
        change: CustodyChange::Register,
        generation: 2,
        input: Some([75; 32]),
        holder: Some(entity_id(50)),
        recipients: CustodyPermitSet::from(permits()),
        pieces,
        authority: CustodyRequestAuthority::PinnedKit {
            root: RecoveryRootId([76; 32]),
        },
    }
}

fn export_secret_work() -> ExportSecretWork {
    ExportSecretWork {
        secret: entity_id(51),
        generation: 2,
        export: entity_id(52),
        digest: Some([77; 32]),
        export_act: Some([78; 32]),
        recipient: permit(48, 70, 71),
    }
}

fn work_request(work: OwnerWorkBody) -> AuthorityOp {
    let kind = work.kind().act();
    AuthorityOp::OwnerWorkRequest(OwnerWorkRequest {
        carrier: entity_id(4),
        act: owner_act(kind),
        executor: entity_id(50),
        work,
        privacy_basis: Some(WorldPrivacyWorkBasis {
            edit: [79; 32],
            after: [80; 32],
            key_owner: entity_id(1),
        }),
    })
}

fn work_request_samples() -> Vec<AuthorityOp> {
    let mut samples = vec![
        work_request(OwnerWorkBody::WorldKey {
            mode: WorldKeyMode::Ensure,
        }),
        work_request(OwnerWorkBody::PublishBundle {
            home: entity_id(53),
        }),
        work_request(custody_work(Some(permit_pieces()))),
        // Inline permit maps are hidden when `pieces` is Some.
        work_request(custody_work(None)),
        work_request(OwnerWorkBody::ExportSecret(export_secret_work())),
    ];
    for change in [
        RootChange::Pin {
            root: RecoveryRootId([81; 32]),
        },
        RootChange::Activate,
        RootChange::Restore {
            root: RecoveryRootId([82; 32]),
        },
        RootChange::Anchor {
            root: RecoveryRootId([83; 32]),
            machine: entity_id(54),
        },
    ] {
        samples.push(work_request(OwnerWorkBody::Root {
            change,
            basis: root_basis(),
        }));
    }
    samples
}

fn work_result_samples() -> Vec<AuthorityOp> {
    [
        OwnerWorkOutcome::Enacted {
            detail: Some(CustodyRegisterCheck::Checked {
                // The encoder derives a singleton refs array from this scalar.
                manifest_ref: "repo:payroll-manifest".to_owned(),
            }),
        },
        OwnerWorkOutcome::Enacted {
            detail: Some(CustodyRegisterCheck::Unchecked {
                reason: CustodyUncheckedReason::OtherManifest,
                refs: vec![
                    "repo:payroll-manifest".to_owned(),
                    "repo:release-manifest".to_owned(),
                ],
            }),
        },
        OwnerWorkOutcome::Refused {
            reason: OwnerWorkRefusal::StaleRevision,
        },
        OwnerWorkOutcome::Sealed {
            output: SealedWorkOutput {
                digest: [84; 32],
                bytes: 128,
                envelopes: 2,
            },
        },
    ]
    .into_iter()
    .map(|outcome| {
        AuthorityOp::OwnerWorkResult(OwnerWorkResult {
            request: [85; 32],
            executor: entity_id(50),
            outcome,
        })
    })
    .collect()
}

fn work_metadata_samples() -> Vec<AuthorityOp> {
    vec![
        AuthorityOp::OwnerWorkCancel(OwnerWorkCancel {
            carrier: entity_id(4),
            act: owner_act(OwnerActKind::RootRequest),
            request: [86; 32],
        }),
        AuthorityOp::ExportSupplementImported(ExportSupplementImported {
            carrier: entity_id(4),
            act: owner_act(OwnerActKind::Export),
            request: [87; 32],
        }),
        AuthorityOp::CustodyPermitPiece(CustodyPermitPiece {
            carrier: Some(entity_id(4)),
            commitment: permit_pieces(),
            index: 0,
            first: 0,
            permits: CustodyRecipientPermits::from(permits()),
        }),
    ]
}

fn policy_samples() -> Vec<AuthorityOp> {
    vec![
        AuthorityOp::GrantTravelSet(GrantTravelSet {
            grant: entity_id(55),
            act: owner_act(OwnerActKind::GrantTravel),
            machine: entity_id(4),
            choice: Some(TravelChoice {
                born_with: BTreeSet::from([BornWithField::Prompt, BornWithField::Keep]),
            }),
        }),
        AuthorityOp::CheckpointPolicySet(CheckpointPolicySet {
            act: owner_act(OwnerActKind::CheckpointPolicy),
            machine: entity_id(4),
            choice: Some(CheckpointRootChoice {
                roots: vec![
                    AuthorityKey::Ed25519([88; 32]),
                    AuthorityKey::Ed25519([89; 32]),
                ],
                quorum: 2,
                hardware: true,
            }),
        }),
        AuthorityOp::HomeNodePick(HomeNodePick {
            act: owner_act(OwnerActKind::HomeNodePick),
            machine: entity_id(4),
            node_id: Some(42),
        }),
        AuthorityOp::ConversationTrainingSet(ConversationTrainingSet {
            act: owner_act(OwnerActKind::ConversationTraining),
            machine: entity_id(4),
            leave_out: true,
        }),
        AuthorityOp::ConversationTrainingVaultSet(ConversationTrainingVaultSet {
            act: owner_act(OwnerActKind::ConversationTraining),
            machine: entity_id(4),
            on: true,
            allow_opt_out: true,
        }),
        AuthorityOp::HomeCandidacy(HomeCandidacy {
            machine: entity_id(4),
            node_id: 42,
            always_on: true,
            primary: true,
            macro_ready: true,
            cloud: false,
        }),
        AuthorityOp::PolicySettingSet(PolicySettingSet {
            act: owner_act(OwnerActKind::PolicySetting),
            machine: entity_id(4),
            setting: PolicySetting::DreamerWakePolicy,
            prior: [90; 32],
            value: Some([91; 32]),
        }),
        AuthorityOp::ExportAct(ExportActRecord {
            act: owner_act(OwnerActKind::Export),
            machine: entity_id(4),
            export: entity_id(52),
            format: "archive".to_owned(),
            bytes: Some(128),
            digest: Some([92; 32]),
        }),
    ]
}
fn repo_bounds() -> RepoAccessBounds {
    RepoAccessBounds {
        repo: entity_id(56),
        project: entity_id(57),
        refs: strings("refs/heads/main", "refs/heads/run/*"),
        readable: strings("src/**/*.rs", "docs/**/*.md"),
        editable: strings("src/authority/*.rs", "docs/authority/*.md"),
    }
}

fn git_push_bounds() -> GitPushBounds {
    GitPushBounds {
        repos: BTreeSet::from([
            GitPushRepo {
                repo: entity_id(56),
                project: entity_id(57),
            },
            GitPushRepo {
                repo: entity_id(58),
                project: entity_id(59),
            },
        ]),
    }
}

fn grant_mint(grant_kind: FederationGrantKind) -> AuthorityOp {
    AuthorityOp::AgentGrantAct(AgentGrantActRecord {
        act: owner_act(OwnerActKind::GrantMint),
        machine: entity_id(4),
        grant: entity_id(60),
        change: AgentGrantChange::Mint {
            member: entity_id(2),
            scope: scope(),
            expires_at: Some(200),
            repo_bounds: Some(repo_bounds()),
            grant_kind,
            git_push_bounds: Some(git_push_bounds()),
            verb_classes: strings("read", "write"),
            wallet_ref: Some(WalletRef {
                issuer: "host:primary".to_owned(),
                id: "wallet:payroll".to_owned(),
            }),
            steward: true,
            working_view_bounds: Some(WorkingViewEditBounds {
                view: entity_id(61),
                account: entity_id(1),
            }),
        },
    })
}

fn grant_samples() -> Vec<AuthorityOp> {
    vec![
        grant_mint(FederationGrantKind::Access),
        grant_mint(FederationGrantKind::GitPush),
        AuthorityOp::AgentGrantAct(AgentGrantActRecord {
            act: owner_act(OwnerActKind::GrantRevoke),
            machine: entity_id(4),
            grant: entity_id(60),
            change: AgentGrantChange::Revoke {
                acknowledged_topology: BTreeSet::from([[93; 32], [94; 32]]),
            },
        }),
    ]
}

fn frontier_samples() -> Vec<AuthorityOp> {
    [
        FrontierJoinFamily::Install(entity_id(4)),
        FrontierJoinFamily::Host,
        FrontierJoinFamily::Anchor,
    ]
    .into_iter()
    .flat_map(|family| {
        [
            FrontierJoinScope::Main,
            FrontierJoinScope::AnchorSide,
            FrontierJoinScope::World(entity_id(34)),
        ]
        .into_iter()
        .map(move |scope| AuthorityOp::FrontierJoin(FrontierJoin { family, scope }))
    })
    .collect()
}

fn membership_execution() -> MembershipExecution {
    MembershipExecution {
        machine: entity_id(4),
        shared_vault: 42,
        cause: MembershipExecutionCause::TransferOwnership,
        person: entity_id(1),
        member: entity_id(62),
        act: Some(entity_id(63).to_hex()),
        receipt: entity_id(64).to_hex(),
        executed_at: 200,
        withdrawn_grants: vec![entity_id(65), entity_id(66)],
        handover: Some(MembershipHandover {
            to: Some(entity_id(67)),
            from_keeps: Some("admin".to_owned()),
            affected_grants: vec![entity_id(68), entity_id(69)],
            retired_own_device_grants: vec![entity_id(70), entity_id(71)],
        }),
    }
}

fn topology_samples() -> Vec<AuthorityOp> {
    vec![
        AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll {
            act: owner_act(OwnerActKind::OwnerKeyEnrollment),
            machine: entity_id(32),
            carrier: entity_id(4),
            device: device(),
        }),
        AuthorityOp::OriginCut(OriginCut {
            act: owner_act(OwnerActKind::OriginCut),
            machine: entity_id(4),
            repo: [95; 32],
            epoch: 2,
            writer: entity_id(32),
        }),
        AuthorityOp::DeviceSuccession(DeviceSuccession {
            act: owner_act(OwnerActKind::DeviceSuccession),
            machine: entity_id(4),
            client: 42,
            device_key: [96; 32],
            successor: entity_id(32),
        }),
        AuthorityOp::MembershipExecution(membership_execution()),
    ]
}

pub(super) fn every_op_sample() -> Vec<AuthorityOp> {
    let mut samples = slip_samples();
    samples.extend(roster_samples());
    samples.extend(lifecycle_samples());
    samples.extend(privacy_samples());
    samples.extend(residence_samples());
    samples.extend(work_request_samples());
    samples.extend(work_result_samples());
    samples.extend(work_metadata_samples());
    samples.extend(policy_samples());
    samples.extend(grant_samples());
    samples.extend(frontier_samples());
    samples.extend(topology_samples());
    samples
}

#[test]
fn every_variant_has_a_sample() {
    let expected: BTreeSet<_> = OP_KIND_NAMES.into_iter().collect();
    let actual: BTreeSet<_> = every_op_sample().iter().map(op_kind_name).collect();
    assert_eq!(actual, expected);
}

#[test]
fn every_sample_encodes_to_a_kind_map() {
    for sample in every_op_sample() {
        let Value::Map(entries) = op_value(&sample) else {
            panic!("{} did not encode to a map", op_kind_name(&sample));
        };
        assert!(
            entries
                .iter()
                .any(|(key, _)| key.as_str() == Some(OP_KEY_KIND)),
            "{} encoded without {OP_KEY_KIND}",
            op_kind_name(&sample),
        );
    }
}
