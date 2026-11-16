//! Measures what the authority fold holds and how long it takes on long logs
//! ([ROSTER-KEY-LOG-FLOOD] PLAN v2, step one; root FIX-LIST 25305). A counting
//! global allocator weighs each phase: the rows by hash, the ancestor index,
//! every row's state, the deepest row's state, the merge and the whole vault
//! fold. Each run prints one `FOLD-MEASURE` line; nothing here asserts a
//! number. Re-run for PR 4 (the floor, from a re-measurement on the stack
//! top) at PR 3's head: the PR body's gates read the ids, runs and merge
//! gain the line ends with.
//!
//! Op families (each measured row grows the family's own field; a two-row
//! family pairs a setup row with the measured row): `confirm` (federation
//! confirms), `critical` (critical write confirms), `enroll` (roster),
//! `residence` (residence directives), `agents` (enrol, then bind; chain
//! only), `slip-mint` (slip mints), `slip-revoke` (mint, then revoke),
//! `world-edit` (one world's edits), `machine-revision` (one machine's
//! revisions), `owner-work` (request, then result; chain only), `rescope`
//! (one pact's narrowings), `refused-world-edit`, `refused-grant-travel` and
//! `refused-export` (valid rows without effect), `actor-revoke` (bind, then
//! revoke), `enroll-p256` (P-256 roster keys) and `enroll-p256-owner` (the
//! same under a P-256 owner). Shapes: `chain` (each row on the one before),
//! `star` (each row on the root), `grid` (rows in a square of side
//! ceil(sqrt n), each on its left and lower neighbours), `braid` (two chains
//! with a join row over each pair), `join32` (32 chains with a 32-parent join
//! row after each round) and `frontier` (128 chains with a `FrontierJoin`
//! row after each round). The plan runs three tiers: every family on the
//! first three shapes at 500 and 2000 rows, the wide shapes at 500 and 2000
//! for four families, then long chains and wide stars and grids.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test fold_memory_measure -- --nocapture`. Times are of
//! the test profile (the oneiron crate at opt-level 0). `ONEIRON_FOLD_MEASURE`
//! narrows the runs: `family:shape:rows[,rows...]` items separated by `;`.
//! A run past `RUN_BUDGET_SECS` (900 s) stops its family and shape's larger
//! sizes; past `ONEIRON_FOLD_MEASURE_BUDGET_SECS` (4800 s) later runs print
//! `FOLD-RUN-SKIP` instead of running.

// The test door is compiled only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::EntityId;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityAttestation, AuthorityConfirmAction,
    AuthorityConfirmKind, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityTier, AuthorityVaultId, CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
    CriticalWriteConfirmAction, CriticalWriteConfirmDisposition, CriticalWriteConfirmMethod,
    DeviceAuthority, FederationLifecycleAction, FederationLifecycleKind, GenesisRecoveryStep,
    GrantTravelSet, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineOwnership, MachineProfile, MachineRole,
    ModelOrder, OwnerAct, OwnerActKind, OwnerWorkBody, OwnerWorkOutcome, OwnerWorkRequest,
    OwnerWorkResult, ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER, ReadLocation, ResidenceAct,
    ResidenceDirective, SealedCopies, SlipClaims, SlipMintAction, WorldPrivacy, WorldPrivacyEdit,
    authority_entry_hash, authority_transcript, federation_scope_digest, genesis_vault_id,
    machine_profile_proof_transcript, sign_federation_pact_gesture,
};
use oneiron::test_doors::authority_fold_memory as door;
use oneiron_authority::authority::{
    EXPORT_ACT_TARGET_NAME, ExportActRecord, FrontierJoin, FrontierJoinFamily, FrontierJoinScope,
    owner_act_target,
};
use oneiron_authority::federation::{
    FederationDirectionScope, FederationPactScope, Scope, ScopeAxis, ScopeId,
    encode_federation_pact_scope,
};
use oneiron_authority::share_travel::{BornWithField, TravelChoice};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use rand::SeedableRng;
use rand::rngs::StdRng;

/// The bytes the process holds now, and the most it held since the last
/// reset.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

impl CountingAllocator {
    fn grew(by: usize) {
        let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }

    fn shrank(by: usize) {
        LIVE.fetch_sub(by, Ordering::Relaxed);
    }
}

// SAFETY: every call goes to the system allocator with the caller's own
// arguments; the counters only add and subtract the sizes it was handed.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is the system's.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            Self::grew(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc_zeroed` is the system's.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            Self::grew(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator, so from the system's.
        unsafe { System.dealloc(ptr, layout) };
        Self::shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `ptr` came from this allocator, so from the system's.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                Self::grew(new_size - layout.size());
            } else {
                Self::shrank(layout.size() - new_size);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// What one phase held when it returned, the most it held while it ran, both
/// over the bytes held before it, and its time.
struct Weight {
    held: usize,
    peak: usize,
    secs: f64,
}

fn weigh<T>(phase: impl FnOnce() -> T) -> (T, Weight) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let started = Instant::now();
    let value = phase();
    let secs = started.elapsed().as_secs_f64();
    let weight = Weight {
        held: LIVE.load(Ordering::Relaxed).saturating_sub(before),
        peak: PEAK.load(Ordering::Relaxed).saturating_sub(before),
        secs,
    };
    (value, weight)
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// The `n`th key of the family `tag`.
fn numbered_key(tag: u8, n: usize) -> SigningKey {
    let mut seed = [tag; 32];
    seed[..8].copy_from_slice(&(n as u64).to_be_bytes());
    SigningKey::from_bytes(&seed)
}

/// `n` in the last eight bytes of `WIDTH` bytes of `tag`.
fn numbered<const WIDTH: usize>(tag: u8, n: usize) -> [u8; WIDTH] {
    let mut bytes = [tag; WIDTH];
    bytes[WIDTH - 8..].copy_from_slice(&(n as u64).to_be_bytes());
    bytes
}

fn numbered_id(tag: u8, n: usize) -> EntityId {
    EntityId::from_bytes(numbered(tag, n)).expect("entity id")
}

fn device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

/// `signer`'s row `op` at `seq` on `parents`, cosigned by `cosigner`.
fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
    cosigner: Option<&SigningKey>,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parents,
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    if let Some(cosigner) = cosigner {
        let key = key_of(cosigner);
        entry.cosigns.push(AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        });
    }
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    if let Some(cosigner) = cosigner {
        entry.cosigns[0].signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    entry
}

/// The `n`th P-256 key of the family `tag`.
fn p256_key(tag: u8, n: usize) -> P256SigningKey {
    let mut rng = StdRng::from_seed(numbered(tag, n));
    P256SigningKey::random(&mut rng)
}

fn p256_key_of(signing: &P256SigningKey) -> AuthorityKey {
    AuthorityKey::P256(
        signing
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    )
}

/// `signer`'s P-256 row `op` at `seq` on `parents`, in the low-S form the
/// signature check takes.
fn signed_p256(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &P256SigningKey,
) -> AuthorityLogEntry {
    let key = p256_key_of(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parents,
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    let mut signature: P256Signature = signer.sign(&transcript);
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
    }
    entry.signer.signature = signature.to_bytes().to_vec();
    entry
}

/// Which key signs a shaped row: the owner, the setup machine's install
/// key, or the P-256 owner.
#[derive(Clone, Copy)]
enum RowSigner {
    Owner,
    Install,
    P256Owner,
}

/// The owner's own act of `kind` on `target`, decided on no revision shown.
fn owner_act_for(owner: EntityId, kind: OwnerActKind, target: EntityId) -> OwnerAct {
    OwnerAct::by_owner(owner, kind, target, ActSurface::ThisInstall, [0; 32])
}

/// A roster-signed revision of `machine`'s standing: `role` at `revision`,
/// proved by `key`'s signature over the profile.
fn machine_profile_for(
    vault_id: &AuthorityVaultId,
    machine: EntityId,
    owner: EntityId,
    key: &SigningKey,
    role: MachineRole,
    revision: u64,
) -> MachineProfile {
    let machine_key = key.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = key
        .sign(&machine_profile_proof_transcript(
            vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    MachineProfile {
        machine,
        owner,
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        role,
        revision,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    }
}

fn machine_id() -> EntityId {
    numbered_id(0x6A, 1)
}

fn owner_id() -> EntityId {
    numbered_id(0x6B, 1)
}

fn world_id() -> EntityId {
    numbered_id(0x6C, 1)
}

fn home_id() -> EntityId {
    numbered_id(0x6D, 1)
}

fn grant_id() -> EntityId {
    numbered_id(0x6E, 1)
}

fn pact_id() -> [u8; 32] {
    numbered(0x50, 1)
}

fn pact_nonce() -> [u8; 16] {
    numbered(0x50, 2)
}

fn peer_vault_id() -> AuthorityVaultId {
    numbered(0x50, 3)
}

/// The `rescope` ceiling: open in both directions.
fn pact_scope() -> FederationPactScope {
    let all = FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    };
    FederationPactScope {
        lo_to_hi: all.clone(),
        hi_to_lo: all,
    }
}

/// The `rescope` narrowing: the ceiling with one facet.
fn narrowed_scope() -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::from_iter([ScopeId(numbered_id(0x6F, 1))]),
        bands: ScopeAxis::All,
    }
}

/// Fresh parentless slip claims of `vault_id` under `slip_id`, bound to
/// `key`'s verifying key.
fn slip_mint_for(
    vault_id: &AuthorityVaultId,
    slip_id: [u8; 32],
    key: &SigningKey,
    holder: usize,
) -> AuthorityOp {
    AuthorityOp::SlipMint(SlipMintAction {
        claims: SlipClaims {
            slip_id,
            vault_id: *vault_id,
            parent_id: None,
            holder_ref: format!("holder-{holder:06}"),
            binding_key: key.verifying_key().to_bytes(),
            scope: Scope::top(),
            issued_at: 1,
            expires_at: 3601,
            ttl_secs: 3600,
            single_use: false,
            records: BTreeSet::new(),
            channels: BTreeSet::new(),
            actor_class: None,
            org_ref: None,
            grant_ref: None,
            invitation_ref: None,
            share_ref: None,
            delegation: None,
            comm: None,
            trusted_contact: None,
            seat_claim: None,
        },
        renews: None,
        minting_member: None,
    })
}

fn p256_enroll(n: usize) -> AuthorityOp {
    AuthorityOp::EnrollDevice {
        device: device(p256_key_of(&p256_key(0xB0, n)), ROLE_AGENT),
    }
}

/// The `rescope` setup row: a connect over the open scope, gestured by a
/// peer key no roster names.
fn connect_op(vault_id: &AuthorityVaultId) -> AuthorityOp {
    let scope = pact_scope();
    let digest = federation_scope_digest(
        &[0x68; 32],
        &pact_nonce(),
        &encode_federation_pact_scope(&scope).expect("scope encodes"),
    );
    let peer = numbered_key(0x94, 0);
    let gesture = sign_federation_pact_gesture(
        FederationLifecycleKind::Connect,
        &pact_id(),
        vault_id,
        &peer_vault_id(),
        1,
        &digest,
        None,
        &pact_nonce(),
        key_of(&peer),
        |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
    )
    .expect("gesture");
    AuthorityOp::FederationLifecycle(FederationLifecycleAction {
        kind: FederationLifecycleKind::Connect,
        pact_id: pact_id(),
        grant_ref: grant_id(),
        peer_vault_id: peer_vault_id(),
        pact_epoch: 1,
        pact_scope: Some(scope),
        effective_scope: None,
        scope_digest: Some(digest),
        gesture: Some(gesture),
        successor_vault_id: None,
        pact_nonce: pact_nonce(),
    })
}

/// Row `n`'s op of `family` (the `n`th family row), which key signs it,
/// and the key that cosigns it. `pair` is the two-row cycle's setup row hash
/// for a measured row.
fn family_op(
    family: &str,
    n: usize,
    vault_id: &AuthorityVaultId,
    pair: Option<AuthorityEntryHash>,
) -> (AuthorityOp, RowSigner, Option<SigningKey>) {
    match family {
        "confirm" => (
            AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: AuthorityConfirmKind::Accept,
                confirm_id: numbered(0xC0, n),
                peer_vault_id: [77; 32],
                epoch: 1,
                nonce: numbered(0xC1, n),
            }),
            RowSigner::Owner,
            None,
        ),
        "critical" => (
            AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
                schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
                confirm_id: numbered(0xC2, n),
                gate_decision_id: numbered(0xC3, n),
                claim_id: numbered_id(0x72, n),
                effect_digest: [0xE1; 32],
                read_frontier_hash: [0xF1; 32],
                nonce: numbered(0xC4, n),
                expires_at: 4_000_000_000,
                disposition: CriticalWriteConfirmDisposition::Clear,
                method: CriticalWriteConfirmMethod::TokenReauth,
            }),
            RowSigner::Owner,
            None,
        ),
        "enroll" => (
            AuthorityOp::EnrollDevice {
                device: device(key_of(&numbered_key(0xA7, n)), ROLE_AGENT),
            },
            RowSigner::Owner,
            None,
        ),
        "residence" => (
            AuthorityOp::ResidenceDirective(ResidenceDirective {
                id: numbered_id(0x73, n),
                machine: numbered_id(0x74, 1),
                owner: numbered_id(0x75, 1),
                issued_at: 1,
                act: ResidenceAct::SyncAll,
            }),
            RowSigner::Owner,
            None,
        ),
        "agents" if n % 2 == 0 => (
            AuthorityOp::EnrollDevice {
                device: device(key_of(&numbered_key(0xA6, n / 2)), ROLE_AGENT),
            },
            RowSigner::Owner,
            None,
        ),
        "agents" => {
            let agent = numbered_key(0xA6, n / 2);
            (
                AuthorityOp::BindActor {
                    authority_key: key_of(&agent),
                    actor_ref: numbered_id(0x71, n),
                    actor_class: "system".to_owned(),
                    epoch: 1,
                },
                RowSigner::Owner,
                Some(agent),
            )
        }
        "slip-mint" => (
            slip_mint_for(vault_id, numbered(0x51, n), &numbered_key(0x53, n), n),
            RowSigner::Owner,
            None,
        ),
        "slip-revoke" if n % 2 == 0 => (
            slip_mint_for(
                vault_id,
                numbered(0x52, n / 2),
                &numbered_key(0x54, n / 2),
                n / 2,
            ),
            RowSigner::Owner,
            None,
        ),
        "slip-revoke" => (
            AuthorityOp::SlipRevoke {
                slip_id: numbered(0x52, n / 2),
            },
            RowSigner::Owner,
            None,
        ),
        "world-edit" | "refused-world-edit" => (
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world: world_id(),
                act: owner_act_for(owner_id(), OwnerActKind::WorldPrivacy, world_id()),
                machine: machine_id(),
                settings: WorldPrivacy {
                    read: ReadLocation::MyMachines,
                    sealed: SealedCopies::CloudAndMyMachines,
                    models: ModelOrder::Inherit,
                },
            }),
            RowSigner::Install,
            None,
        ),
        "machine-revision" => (
            AuthorityOp::MachineProfile(machine_profile_for(
                vault_id,
                machine_id(),
                owner_id(),
                &numbered_key(0x92, 0),
                MachineRole::Owned(MachineOwnership::Yours),
                n as u64 + 1,
            )),
            RowSigner::Owner,
            None,
        ),
        "owner-work" if n % 2 == 0 => (
            AuthorityOp::OwnerWorkRequest(OwnerWorkRequest {
                carrier: machine_id(),
                act: owner_act_for(owner_id(), OwnerActKind::WorldKeyRequest, home_id()),
                executor: machine_id(),
                work: OwnerWorkBody::PublishBundle { home: home_id() },
                privacy_basis: None,
            }),
            RowSigner::Install,
            None,
        ),
        "owner-work" => (
            AuthorityOp::OwnerWorkResult(OwnerWorkResult {
                request: pair.expect("an owner-work result needs its request"),
                executor: machine_id(),
                outcome: OwnerWorkOutcome::enacted(),
            }),
            RowSigner::Install,
            None,
        ),
        "rescope" => (
            AuthorityOp::FederationLifecycle(FederationLifecycleAction {
                kind: FederationLifecycleKind::Rescope,
                pact_id: pact_id(),
                grant_ref: grant_id(),
                peer_vault_id: peer_vault_id(),
                pact_epoch: 1,
                pact_scope: None,
                effective_scope: Some(narrowed_scope()),
                scope_digest: None,
                gesture: None,
                successor_vault_id: None,
                pact_nonce: pact_nonce(),
            }),
            RowSigner::Owner,
            None,
        ),
        "refused-grant-travel" => (
            AuthorityOp::GrantTravelSet(GrantTravelSet {
                grant: grant_id(),
                act: owner_act_for(owner_id(), OwnerActKind::GrantTravel, grant_id()),
                machine: machine_id(),
                choice: Some(TravelChoice {
                    born_with: BTreeSet::from([BornWithField::Prompt]),
                }),
            }),
            RowSigner::Install,
            None,
        ),
        "refused-export" => (
            AuthorityOp::ExportAct(ExportActRecord {
                act: owner_act_for(
                    owner_id(),
                    OwnerActKind::Export,
                    owner_act_target(EXPORT_ACT_TARGET_NAME).expect("export target"),
                ),
                machine: machine_id(),
                export: numbered_id(0x67, n),
                format: "archive".to_owned(),
                bytes: None,
                digest: None,
            }),
            RowSigner::Install,
            None,
        ),
        "actor-revoke" if n % 2 == 0 => {
            let agent = numbered_key(0xA8, n / 2);
            (
                AuthorityOp::BindActor {
                    authority_key: key_of(&agent),
                    actor_ref: numbered_id(0x76, n / 2),
                    actor_class: "system".to_owned(),
                    epoch: 1,
                },
                RowSigner::Owner,
                Some(agent),
            )
        }
        "actor-revoke" => (
            AuthorityOp::RevokeActor {
                authority_key: key_of(&numbered_key(0xA8, n / 2)),
                epoch: 1,
            },
            RowSigner::Owner,
            None,
        ),
        "enroll-p256" => (p256_enroll(n), RowSigner::Owner, None),
        "enroll-p256-owner" => (p256_enroll(n), RowSigner::P256Owner, None),
        other => panic!("unknown family {other}"),
    }
}

/// The setup rows of `family`'s log: a short chain after genesis whose last
/// row is the shapes' root.
fn setup_ops(
    family: &str,
    rows: usize,
    vault_id: &AuthorityVaultId,
    install: &SigningKey,
) -> Vec<AuthorityOp> {
    let live_machine = || {
        machine_profile_for(
            vault_id,
            machine_id(),
            owner_id(),
            install,
            MachineRole::Owned(MachineOwnership::Yours),
            1,
        )
    };
    match family {
        "world-edit" | "owner-work" => vec![AuthorityOp::MachineProfile(live_machine())],
        "rescope" => vec![connect_op(vault_id)],
        "refused-world-edit" | "refused-grant-travel" | "refused-export" => vec![
            AuthorityOp::MachineProfile(live_machine()),
            AuthorityOp::MachineProfile(machine_profile_for(
                vault_id,
                machine_id(),
                owner_id(),
                install,
                MachineRole::Removed,
                2,
            )),
        ],
        "actor-revoke" => (0..rows.div_ceil(2))
            .map(|k| AuthorityOp::EnrollDevice {
                device: device(key_of(&numbered_key(0xA8, k)), ROLE_AGENT),
            })
            .collect(),
        "confirm" | "critical" | "enroll" | "residence" | "agents" | "slip-mint"
        | "slip-revoke" | "machine-revision" | "enroll-p256" | "enroll-p256-owner" => Vec::new(),
        other => panic!("unknown family {other}"),
    }
}

/// Shaped row `n`'s parents, and whether it is a frontier join row: `hashes`
/// holds the shaped rows' hashes so far, `root` the setup's last row.
fn shape_parents(
    shape: &str,
    n: usize,
    root: AuthorityEntryHash,
    hashes: &[AuthorityEntryHash],
    side: usize,
) -> (Vec<AuthorityEntryHash>, bool) {
    match shape {
        "chain" => (vec![hashes.last().copied().unwrap_or(root)], false),
        "star" => (vec![root], false),
        "grid" => {
            let mut parents = Vec::new();
            if n % side > 0 {
                parents.push(hashes[n - 1]);
            }
            if n >= side {
                parents.push(hashes[n - side]);
            }
            if parents.is_empty() {
                parents.push(root);
            }
            (parents, false)
        }
        // Triples: A_k on A_{k-1}, B_k on B_{k-1}, C_k on A_k and B_k.
        "braid" => match n % 3 {
            0 if n == 0 => (vec![root], false),
            1 if n == 1 => (vec![root], false),
            0 | 1 => (vec![hashes[n - 3]], false),
            _ => (vec![hashes[n - 2], hashes[n - 1]], false),
        },
        // Rounds of 32 chain rows and one join row over the 32 tips.
        "join32" => {
            if n % 33 < 32 {
                (
                    vec![hashes.get(n.wrapping_sub(33)).copied().unwrap_or(root)],
                    false,
                )
            } else {
                (hashes[n - 32..n].to_vec(), false)
            }
        }
        // Rounds of 128 chain rows and one frontier join over the 128 tips.
        "frontier" => {
            if n % 129 < 128 {
                (
                    vec![hashes.get(n.wrapping_sub(129)).copied().unwrap_or(root)],
                    false,
                )
            } else {
                (hashes[n - 128..n].to_vec(), true)
            }
        }
        other => panic!("unknown shape {other}"),
    }
}

/// Genesis, the setup chain, then `rows` shaped rows of `family` that the
/// family's keys sign, in `shape`.
fn measured_log(family: &str, shape: &str, rows: usize) -> Vec<AuthorityLogEntry> {
    let owner = numbered_key(0x91, 0);
    let install = numbered_key(0x92, 0);
    let p256_owner = (family == "enroll-p256-owner").then(|| p256_key(0xB1, 0));
    let genesis = if family == "enroll-p256-owner" {
        signed_p256(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: device(
                    p256_key_of(p256_owner.as_ref().expect("p256 owner")),
                    ROLE_OWNER | ROLE_ADMIN,
                ),
                genesis_nonce: [0x91; 32],
                recovery: GenesisRecoveryStep::Saved([1; 32]),
            },
            p256_owner.as_ref().expect("p256 owner"),
        )
    } else {
        signed(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: device(key_of(&owner), ROLE_OWNER | ROLE_ADMIN),
                genesis_nonce: [0x91; 32],
                recovery: GenesisRecoveryStep::Saved([1; 32]),
            },
            &owner,
            None,
        )
    };
    let vault_id = genesis_vault_id(&genesis).expect("vault id");
    let mut entries = vec![genesis];
    let mut owner_seq = 0;
    let mut install_seq = 0;
    let mut p256_seq = 0;
    let mut root = authority_entry_hash(&entries[0]).expect("genesis hash");
    for op in setup_ops(family, rows, &vault_id, &install) {
        owner_seq += 1;
        let entry = signed(Some(vault_id), owner_seq, vec![root], op, &owner, None);
        root = authority_entry_hash(&entry).expect("setup hash");
        entries.push(entry);
    }
    let side = (1..).find(|side| side * side >= rows).unwrap_or(1);
    let mut hashes: Vec<AuthorityEntryHash> = Vec::with_capacity(rows);
    let mut family_hashes: Vec<AuthorityEntryHash> = Vec::new();
    let mut family_n = 0;
    for n in 0..rows {
        let (parents, frontier_join) = shape_parents(shape, n, root, &hashes, side);
        let (op, signer, cosigner) = if frontier_join {
            (
                AuthorityOp::FrontierJoin(FrontierJoin {
                    family: FrontierJoinFamily::Host,
                    scope: FrontierJoinScope::Main,
                }),
                RowSigner::Owner,
                None,
            )
        } else {
            let pair =
                (family == "owner-work" && family_n % 2 == 1).then(|| family_hashes[family_n - 1]);
            let (op, signer, cosigner) = family_op(family, family_n, &vault_id, pair);
            family_n += 1;
            (op, signer, cosigner)
        };
        let seq = match signer {
            RowSigner::Owner => {
                owner_seq += 1;
                owner_seq
            }
            RowSigner::Install => {
                install_seq += 1;
                install_seq
            }
            RowSigner::P256Owner => {
                p256_seq += 1;
                p256_seq
            }
        };
        let entry = match signer {
            RowSigner::Owner => signed(Some(vault_id), seq, parents, op, &owner, cosigner.as_ref()),
            RowSigner::Install => signed(
                Some(vault_id),
                seq,
                parents,
                op,
                &install,
                cosigner.as_ref(),
            ),
            RowSigner::P256Owner => signed_p256(
                Some(vault_id),
                seq,
                parents,
                op,
                p256_owner.as_ref().expect("p256 owner"),
            ),
        };
        let hash = authority_entry_hash(&entry).expect("row hash");
        hashes.push(hash);
        if !frontier_join {
            family_hashes.push(hash);
        }
        entries.push(entry);
    }
    entries
}

/// A (family, shape) whose run took longer than this runs no larger log.
const RUN_BUDGET_SECS: f64 = 900.0;

fn plan() -> Vec<(String, String, Vec<usize>)> {
    if let Ok(spec) = std::env::var("ONEIRON_FOLD_MEASURE") {
        return spec
            .split(';')
            .filter(|item| !item.trim().is_empty())
            .map(|item| {
                let mut parts = item.trim().split(':');
                let family = parts.next().expect("family").to_owned();
                let shape = parts.next().expect("shape").to_owned();
                let sizes = parts
                    .next()
                    .expect("rows")
                    .split(',')
                    .map(|rows| rows.parse().expect("row count"))
                    .collect();
                (family, shape, sizes)
            })
            .collect();
    }
    let mut plan = Vec::new();
    // Tier 1: every family on the first three shapes at 500 and 2000 rows.
    // The two-row families whose measured row needs its setup row in its
    // ancestry run chain only, as `agents` always has.
    let sizes = vec![500, 2000];
    for family in ["confirm", "critical", "enroll", "residence"] {
        for shape in ["chain", "star", "grid"] {
            plan.push((family.to_owned(), shape.to_owned(), sizes.clone()));
        }
    }
    plan.push(("agents".to_owned(), "chain".to_owned(), sizes.clone()));
    for family in [
        "slip-mint",
        "slip-revoke",
        "world-edit",
        "machine-revision",
        "rescope",
        "refused-world-edit",
        "refused-grant-travel",
        "refused-export",
        "actor-revoke",
        "enroll-p256",
        "enroll-p256-owner",
    ] {
        for shape in ["chain", "star", "grid"] {
            plan.push((family.to_owned(), shape.to_owned(), sizes.clone()));
        }
    }
    plan.push(("owner-work".to_owned(), "chain".to_owned(), sizes));
    // Tier 2: the wide shapes at 500 and 2000 rows for four families.
    for family in ["critical", "enroll", "world-edit", "slip-mint"] {
        for shape in ["braid", "join32", "frontier"] {
            plan.push((family.to_owned(), shape.to_owned(), vec![500, 2000]));
        }
    }
    // Tier 3: long chains, then wide stars and grids.
    for family in [
        "critical",
        "enroll",
        "slip-mint",
        "world-edit",
        "machine-revision",
    ] {
        plan.push((family.to_owned(), "chain".to_owned(), vec![10000, 40000]));
    }
    for family in ["critical", "enroll"] {
        for shape in ["star", "grid"] {
            plan.push((family.to_owned(), shape.to_owned(), vec![4000]));
        }
    }
    plan
}

fn ratio(bytes: usize, per: u64) -> u64 {
    (bytes as u64).checked_div(per).unwrap_or(0)
}

/// One run: every phase's weight on `family`'s log of `rows` rows in `shape`.
/// Answers the run's time.
fn measure(family: &str, shape: &str, rows: usize) -> f64 {
    let started = Instant::now();
    let entries = measured_log(family, shape, rows);
    let (by_hash, rows_weight) = weigh(|| door::rows(&entries));
    let (index, index_weight) = weigh(|| door::index(&by_hash));
    let (states, states_weight) = weigh(|| door::states(&by_hash, &index));
    let (deepest, deepest_weight) = weigh(|| states.deepest(&index));
    let deepest_entries = deepest.grown_entries();
    let deepest_family = door::family_entries(&deepest, family);
    drop(deepest);
    let (merged, merge_weight) = weigh(|| states.merged());
    let merged_entries = merged.grown_entries();
    let merged_family = door::family_entries(&merged, family);
    drop(merged);
    let folded_rows = states.len();
    let grown = states.grown_entries();
    let states_family = states.family_entries(family);
    drop(states);
    let (folded, fold_weight) = weigh(|| door::fold(&entries));
    let pairs = index.pairs();
    let ids = index.ids();
    let runs = index.runs();
    let gain = door::merge_gain(&by_hash, &index);
    let projected = door::projected_bytes(entries.len(), pairs);
    println!(
        "FOLD-MEASURE family={family} shape={shape} rows={} pairs={pairs} counted_pairs={} \
         fold_counted_pairs={} folded_rows={folded_rows} valid={} grown_entries={grown} \
         deepest_grown={deepest_entries} merged_grown={merged_entries} \
         rows_held={} index_held={} index_peak={} index_secs={:.3} \
         states_held={} states_peak={} states_secs={:.3} deepest_state_bytes={} \
         merge_peak={} merge_secs={:.3} fold_peak={} fold_secs={:.3} projected={projected} \
         index_bytes_per_pair={} states_bytes_per_grown_entry={} states_bytes_per_row={} \
         fold_peak_bytes_per_pair={} ids={ids} runs={runs} merge_gain={gain} \
         deepest_family={deepest_family} merged_family={merged_family} \
         states_family={states_family} index_bytes_per_run={}",
        entries.len(),
        index.counted_pairs(),
        folded.counted_pairs,
        folded.valid,
        rows_weight.held,
        index_weight.held,
        index_weight.peak,
        index_weight.secs,
        states_weight.held,
        states_weight.peak,
        states_weight.secs,
        deepest_weight.held,
        merge_weight.peak,
        merge_weight.secs,
        fold_weight.peak,
        fold_weight.secs,
        ratio(index_weight.held, pairs),
        ratio(states_weight.held, grown as u64),
        ratio(states_weight.held, folded_rows as u64),
        ratio(fold_weight.peak, pairs),
        ratio(index_weight.held, runs),
    );
    started.elapsed().as_secs_f64()
}

/// Every run of the plan, smallest log first. One test, so no other test's
/// allocations land in a weight.
#[test]
fn fold_memory_by_phase() {
    let budget = std::env::var("ONEIRON_FOLD_MEASURE_BUDGET_SECS")
        .ok()
        .and_then(|secs| secs.parse::<f64>().ok())
        .unwrap_or(4800.0);
    let started = Instant::now();
    for (family, shape, sizes) in plan() {
        for rows in sizes {
            if started.elapsed().as_secs_f64() > budget {
                println!("FOLD-RUN-SKIP family={family} shape={shape} rows={rows}");
                continue;
            }
            let secs = measure(&family, &shape, rows);
            println!("FOLD-RUN family={family} shape={shape} rows={rows} secs={secs:.3}");
            if secs > RUN_BUDGET_SECS {
                println!("FOLD-RUN-STOP family={family} shape={shape} after rows={rows}");
                break;
            }
        }
    }
}
