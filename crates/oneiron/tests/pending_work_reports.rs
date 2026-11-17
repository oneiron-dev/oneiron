//! FIX 5558: tests for the pending-work reports (#3254). A root request
//! whose target moved past the act's `seen` is refused as a revision
//! mismatch, with advice for the owner; a target still syncing what the
//! owner saw waits instead. The executor's diagnostics are its own
//! observation: unavailable anywhere else. A publication names its home's
//! warning and what this install's relay last saw there.
//!
//! A test-gap row: there is no red on main. Every test below passes on
//! main as written, and fails if the report it pins regresses.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test pending_work_reports`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActSurface, AuthorityEntryHash, HostSlipIssuer, MachineDeviceClass, MachineOwnership,
    MachineRole, OwnerWorkKind, OwnerWorkRefusal, RecoveryRootId, RootChange,
};
#[cfg(feature = "sync")]
use oneiron::authority::{ReadLocation, WorldPrivacy};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_support::bind_host_owner;
#[cfg(feature = "sync")]
use oneiron::world_keys::PublishObserved;
use oneiron::world_keys::{
    BundleHomeWarning, CapsuleRead, EnsureDiagnostics, ExecutorObservation, LatestRead,
    OwnerWorkCancelState, OwnerWorkDrain, OwnerWorkReceipt, OwnerWorkStatus, OwnerWorkUnassigned,
    PublicationDiagnostics, PublishReach, ReassertDiagnostics, ReassertKeyState, ReassertUnread,
    RelayObservation,
};
use oneiron::{EntityId, Vault, VaultConfig};

/// What a refused-for-mismatch status advises: the words of
/// `OwnerWorkStatus::advice` for `RootRevisionMismatch`.
const MISMATCH_ADVICE: &str = "the target holds owner roots or a standing of its own other than \
    the ones you saw (a target still syncing what you saw waits instead). Review where it stands \
    and ask again";

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// The vault's host: a hosted node, rooted, whose install carries the
/// owner's acts, as every live machine profile of the vault does.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    _issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    vault_id: [u8; 32],
}

fn host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("the hosted node's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let owner = proof(&vault, person);
    let vault_id = vault
        .authority_fold()
        .expect("the host's fold")
        .vault_id
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        _issuer: issuer,
        owner,
        vault_id,
    }
}

impl Host {
    /// This install's machine id.
    fn machine(&self) -> EntityId {
        self.vault
            .local_machine()
            .expect("this install")
            .expect("the host has a machine id")
            .id
    }

    /// A recovery root the host mints with a seed of its own, on its own
    /// install: its record, its anchor's mark of the host's machine, and the
    /// host's own pin.
    fn mint_own_root(&self) -> RecoveryRootId {
        let prepared = self
            .vault
            .prepare_owner_root(&self.owner)
            .expect("the host prepares a root");
        self.vault
            .activate_owner_root(&self.owner, prepared, &BTreeSet::new())
            .expect("the host activates its root")
            .root
    }

    /// Records a pin of `root` on `target`, carried by the host's install
    /// as the hosted console's act.
    fn request_pin(&self, target: EntityId, root: RecoveryRootId) {
        let receipt = self
            .vault
            .request_root_change(
                &self.owner,
                ActSurface::HostedConsole,
                target,
                RootChange::Pin { root },
            )
            .expect("the host records the pin request");
        assert!(
            receipt.request.is_some(),
            "the pin request is recorded for its target: {receipt:?}"
        );
    }

    /// Imports the device's history, as sync does. Rows the host holds
    /// already land again harmlessly.
    fn take(&self, device: &Device) {
        let history = device
            .vault
            .export_signed_authority_history()
            .expect("the device's history");
        self.vault
            .import_signed_authority_history(&history)
            .expect("the host takes the rows");
    }
}

/// The owner's second install, enrolled as his. It takes the vault's
/// authority history from the host, as sync does.
struct Device {
    _dir: tempfile::TempDir,
    vault: Vault,
    machine: EntityId,
    held: BTreeSet<Vec<u8>>,
}

fn device(host: &Host) -> Device {
    device_with_class(host, MachineDeviceClass::Computer)
}

fn device_with_class(host: &Host, class: MachineDeviceClass) -> Device {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.machine_device_class = class;
    let vault = Vault::open(dir.path(), config).expect("the device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(host.vault_id)
        .expect("the device's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, key)
        .expect("the device's enrolment request");
    host.vault
        .enroll_machine(
            &host.owner,
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the device as his");
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the device");
    let mut device = Device {
        _dir: dir,
        vault,
        machine: request.machine,
        held: BTreeSet::new(),
    };
    device.take(host);
    device
}

impl Device {
    /// Imports the rows of the host's history this device does not hold yet.
    fn take(&mut self, host: &Host) {
        let new: Vec<Vec<u8>> = host
            .vault
            .export_signed_authority_history()
            .expect("the host's history")
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new)
            .expect("the device takes the rows");
        self.held.extend(new);
    }

    fn owner(&self) -> AuthenticatedOwner {
        let person = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("the owner on the device");
        proof(&self.vault, person)
    }

    /// Records a pin of `root` on `target`, carried by this install as the
    /// hosted console's act.
    fn request_pin(&self, target: EntityId, root: RecoveryRootId) {
        let receipt = self
            .vault
            .request_root_change(
                &self.owner(),
                ActSurface::HostedConsole,
                target,
                RootChange::Pin { root },
            )
            .expect("the device records the pin request");
        assert!(
            receipt.request.is_some(),
            "the pin request is recorded for its target: {receipt:?}"
        );
    }

    /// Two syncs and pickups: the first may only commit the wait for a root
    /// whose record the device does not store yet, which lets the next sync
    /// store it.
    fn sync_and_pick_up(&mut self, host: &Host) -> Vec<OwnerWorkDrain> {
        let mut drains = Vec::new();
        for _ in 0..2 {
            self.take(host);
            drains.push(
                self.vault
                    .run_pending_owner_work(|| true)
                    .expect("the device's pickup"),
            );
        }
        self.take(host);
        drains
    }
}

/// The device's one pending pin request: its entry, change and receipt.
fn pending_pin(device: &Device) -> (AuthorityEntryHash, RootChange, OwnerWorkReceipt) {
    let pending = device
        .vault
        .pending_root_requests(&device.owner())
        .expect("the device's pending root requests");
    assert_eq!(
        pending.len(),
        1,
        "the device counts one pin request naming it"
    );
    pending.into_iter().next().expect("one request")
}

/// The entry hash a receipt's `request` hex names.
fn entry_hash(hex: &str) -> AuthorityEntryHash {
    assert_eq!(hex.len(), 64, "a request entry is 32 bytes as hex");
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex");
    }
    out
}

/// Only three statuses advise: a mismatch names the target's move, a
/// cancel says what stands, a supersede names the newer request. Every
/// other status, and every other refusal reason, advises nothing.
#[test]
fn refusal_advice_names_only_the_next_step_each_status_has() {
    assert_eq!(
        OwnerWorkStatus::Refused {
            reason: OwnerWorkRefusal::RootRevisionMismatch,
        }
        .advice(),
        Some(MISMATCH_ADVICE),
        "a mismatch advises a review and another ask"
    );
    assert_eq!(
        OwnerWorkStatus::Cancelled.advice(),
        Some(
            "the target never runs it once it has synced the cancel; a result it signed before \
             then stands, and nothing is undone"
        ),
        "a cancel says what stands"
    );
    assert_eq!(
        OwnerWorkStatus::Superseded.advice(),
        Some("a newer request on the same target replaced it, and the target never runs this one"),
        "a supersede names the newer request"
    );
    assert_eq!(
        OwnerWorkStatus::RecordedAwaitingHolder.advice(),
        None,
        "a pending request advises nothing"
    );
    assert_eq!(
        OwnerWorkStatus::Enacted.advice(),
        None,
        "an enacted request advises nothing"
    );
    for reason in [
        OwnerWorkRefusal::StaleRevision,
        OwnerWorkRefusal::OwnerNotLive,
        OwnerWorkRefusal::WorldNotLive,
        OwnerWorkRefusal::ExecutorNotReader,
        OwnerWorkRefusal::HomeNotLinked,
        OwnerWorkRefusal::SecretNotPortable,
        OwnerWorkRefusal::SecretNotActive,
        OwnerWorkRefusal::RecipientChanged,
        OwnerWorkRefusal::InvalidInput,
        OwnerWorkRefusal::CustodyConflict,
        OwnerWorkRefusal::WiderThanFloor,
    ] {
        assert_eq!(
            OwnerWorkStatus::Refused { reason }.advice(),
            None,
            "no other refusal advises: {reason:?}"
        );
    }
}

/// Every refusal's wire tag, and the tag that names it back: the mismatch
/// travels as `root_revision_mismatch`. Unknown text names nothing.
#[test]
fn refusal_wire_tags_round_trip() {
    for (reason, tag) in [
        (OwnerWorkRefusal::StaleRevision, "stale_revision"),
        (OwnerWorkRefusal::OwnerNotLive, "owner_not_live"),
        (OwnerWorkRefusal::WorldNotLive, "world_not_live"),
        (OwnerWorkRefusal::ExecutorNotReader, "executor_not_reader"),
        (OwnerWorkRefusal::HomeNotLinked, "home_not_linked"),
        (OwnerWorkRefusal::SecretNotPortable, "secret_not_portable"),
        (OwnerWorkRefusal::SecretNotActive, "secret_not_active"),
        (OwnerWorkRefusal::RecipientChanged, "recipient_changed"),
        (OwnerWorkRefusal::InvalidInput, "invalid_input"),
        (OwnerWorkRefusal::CustodyConflict, "custody_conflict"),
        (OwnerWorkRefusal::WiderThanFloor, "wider_than_floor"),
        (
            OwnerWorkRefusal::RootRevisionMismatch,
            "root_revision_mismatch",
        ),
    ] {
        assert_eq!(reason.as_str(), tag);
        assert_eq!(
            OwnerWorkRefusal::from_name(tag),
            Some(reason),
            "the tag names its reason back"
        );
    }
    assert_eq!(OwnerWorkRefusal::from_name("root_mismatch"), None);
    assert_eq!(OwnerWorkRefusal::from_name(""), None);
}

/// Each status says where its request stands.
#[test]
fn status_text_says_where_the_request_stands() {
    assert_eq!(
        OwnerWorkStatus::RecordedAwaitingHolder.text(),
        "recorded, awaiting a holder"
    );
    assert_eq!(OwnerWorkStatus::Enacted.text(), "enacted by its holder");
    assert_eq!(
        OwnerWorkStatus::Refused {
            reason: OwnerWorkRefusal::RootRevisionMismatch,
        }
        .text(),
        "refused by its holder"
    );
    assert_eq!(OwnerWorkStatus::Cancelled.text(), "cancelled by the owner");
    assert_eq!(
        OwnerWorkStatus::Superseded.text(),
        "superseded by a newer request on its target"
    );
}

/// Why no install was named, and where a cancel stands, in words.
#[test]
fn unassigned_and_cancel_state_texts() {
    assert_eq!(
        OwnerWorkUnassigned::NoEligibleReader.text(),
        "no other install may read the world"
    );
    assert_eq!(
        OwnerWorkUnassigned::TargetIsRecorder.text(),
        "this install is the target; make the change here"
    );
    assert_eq!(
        OwnerWorkUnassigned::TargetNotLinked.text(),
        "the target is not a linked install"
    );
    assert_eq!(
        OwnerWorkUnassigned::NoBundleHolder.text(),
        "no install holds every world's key"
    );
    assert_eq!(
        OwnerWorkUnassigned::NoCustodyHolder.text(),
        "no linked install was named to hold the secret"
    );
    assert_eq!(OwnerWorkCancelState::Cancelled.text(), "cancelled");
    assert_eq!(
        OwnerWorkCancelState::AlreadyEnacted.text(),
        "already enacted: the result stands"
    );
    assert_eq!(
        OwnerWorkCancelState::AlreadyRefused.text(),
        "already refused: that answer stands"
    );
}

/// Each home warning says why the home may keep no sealed copy.
#[test]
fn home_warning_text_says_why_the_home_may_keep_no_copy() {
    assert_eq!(
        BundleHomeWarning::HomeDoesNotKeepSealedBundles.text(),
        "the home is a phone, which keeps no sealed copy; the request stays pending until you \
         ask for a home that keeps one"
    );
    assert_eq!(
        BundleHomeWarning::HomeProfileUnknown.text(),
        "no profile of the home is known here, so whether it keeps sealed copies is unknown"
    );
    let world = EntityId::from_bytes([0x41; 16]).expect("a world id");
    assert_eq!(
        BundleHomeWarning::AwaitingReader {
            worlds: vec![world],
        }
        .text(),
        "the home's newest copy keeps these worlds' keys sealed for an earlier recovery kit or \
         none; the current kit restores each once a machine that reads it publishes again"
    );
}

/// Each executor observation says what was observed.
#[test]
fn executor_observation_text_says_what_was_observed() {
    assert_eq!(
        ExecutorObservation::Unavailable.text(),
        "executor observation unavailable on this install"
    );
    assert_eq!(
        ExecutorObservation::Answered.text(),
        "answered by its executor"
    );
    let world = EntityId::from_bytes([0x41; 16]).expect("a world id");
    assert_eq!(
        ExecutorObservation::Reassert(ReassertDiagnostics {
            world,
            unread: None,
            reads_everywhere: false,
            question_raised: false,
            keys: Vec::new(),
            next_offset: None,
            ensure: None,
        })
        .text(),
        "the executor's own records name these keys; keys of unknown history are listed as such"
    );
    assert_eq!(
        ExecutorObservation::Ensure(EnsureDiagnostics {
            world,
            unread: None,
            reads_everywhere: false,
            question_raised: false,
            ensure: None,
        })
        .text(),
        "the world's current key on the executor, or the first key it would mint, and what \
         blocks wrapping it to every reader"
    );
    assert_eq!(
        ExecutorObservation::BundlePublication(PublicationDiagnostics {
            home: world,
            home_warning: None,
            relay: RelayObservation::Unknown,
            device_sync_start: None,
            attempt: None,
        })
        .text(),
        "what the executor's relay last saw here; unknown until a pass observes it"
    );
    assert_eq!(
        ExecutorObservation::NotReported.text(),
        "no executor diagnostics are kept for this work"
    );
}

/// The diagnostic states are closed sets: every key state, reach, unread
/// reason, capsule read, latest read and relay observation is one of
/// these. Each match below has no wildcard, so a new state breaks the
/// build until the reports name it.
#[test]
fn diagnostic_state_enums_list_every_state() {
    fn key_state(state: ReassertKeyState) -> &'static str {
        match state {
            ReassertKeyState::Wrapped => "wrapped",
            ReassertKeyState::WrapsPending { .. } => "wraps_pending",
            ReassertKeyState::MissingPad => "missing_pad",
            ReassertKeyState::NoOpeningRecordOrWrap => "no_opening_record_or_wrap",
            ReassertKeyState::FrontierNeedsSplit => "frontier_needs_split",
            ReassertKeyState::Conflicted => "conflicted",
            ReassertKeyState::UnknownHistory => "unknown_history",
        }
    }
    for state in [
        ReassertKeyState::Wrapped,
        ReassertKeyState::WrapsPending { missing: 2 },
        ReassertKeyState::MissingPad,
        ReassertKeyState::NoOpeningRecordOrWrap,
        ReassertKeyState::FrontierNeedsSplit,
        ReassertKeyState::Conflicted,
        ReassertKeyState::UnknownHistory,
    ] {
        assert!(!key_state(state).is_empty());
    }
    fn reach(reach: PublishReach) -> &'static str {
        match reach {
            PublishReach::Reached => "reached",
            PublishReach::OtherHome => "other_home",
            PublishReach::HomeUnproven => "home_unproven",
            PublishReach::Offline => "offline",
            PublishReach::Refused => "refused",
        }
    }
    for got in [
        PublishReach::Reached,
        PublishReach::OtherHome,
        PublishReach::HomeUnproven,
        PublishReach::Offline,
        PublishReach::Refused,
    ] {
        assert!(!reach(got).is_empty());
    }
    fn unread(unread: ReassertUnread) -> &'static str {
        match unread {
            ReassertUnread::NoMachineSecret => "no_machine_secret",
            ReassertUnread::NotMineReader => "not_mine_reader",
        }
    }
    for got in [
        ReassertUnread::NoMachineSecret,
        ReassertUnread::NotMineReader,
    ] {
        assert!(!unread(got).is_empty());
    }
    fn capsule(read: CapsuleRead) -> &'static str {
        match read {
            CapsuleRead::Opens => "opens",
            CapsuleRead::NoCapsuleHere => "no_capsule_here",
            CapsuleRead::PublicationGrant => "publication_grant",
            CapsuleRead::Refused => "refused",
        }
    }
    for read in [
        CapsuleRead::Opens,
        CapsuleRead::NoCapsuleHere,
        CapsuleRead::PublicationGrant,
        CapsuleRead::Refused,
    ] {
        assert!(!capsule(read).is_empty());
    }
    fn latest(read: &LatestRead) -> &'static str {
        match read {
            LatestRead::NotRead => "not_read",
            LatestRead::NoneKept => "none_kept",
            LatestRead::Read { .. } => "read",
        }
    }
    for read in [
        LatestRead::NotRead,
        LatestRead::NoneKept,
        LatestRead::Read {
            bundle: CapsuleRead::Opens,
            pads: CapsuleRead::Opens,
            awaiting_reader: Vec::new(),
        },
    ] {
        assert!(!latest(&read).is_empty());
    }
    fn relay(relay: &RelayObservation) -> &'static str {
        match relay {
            RelayObservation::Unknown => "unknown",
            RelayObservation::Observed { .. } => "observed",
        }
    }
    for got in [
        RelayObservation::Unknown,
        RelayObservation::Observed { passes: Vec::new() },
    ] {
        assert!(!relay(&got).is_empty());
    }
}

/// A target still syncing what the owner saw waits: the request stays
/// pending with no result, never refused.
#[test]
fn a_lagging_target_waits_instead_of_refusing() {
    let host = host();
    let mut device = device(&host);
    let root = host.mint_own_root();
    host.request_pin(device.machine, root);
    device.take(&host);
    let (hash, _, _) = pending_pin(&device);
    let drains = device.sync_and_pick_up(&host);
    assert_eq!(drains.len(), 2, "two syncs and pickups ran");
    for drain in &drains {
        assert_eq!(
            drain.refused, 0,
            "a syncing target signs no refusal: {drain:?}"
        );
        assert_eq!(
            drain.enacted, 0,
            "a carried pin enacts nothing here: {drain:?}"
        );
    }
    let (_, _, pending) = pending_pin(&device);
    assert_eq!(
        pending.status,
        OwnerWorkStatus::RecordedAwaitingHolder,
        "the request stays pending"
    );
    let read = device
        .vault
        .owner_work_receipt(&device.owner(), hash)
        .expect("the receipt reads")
        .expect("the request folds");
    assert_eq!(
        read.status,
        OwnerWorkStatus::RecordedAwaitingHolder,
        "the receipt says awaiting a holder, not refused"
    );
}

/// Roots that moved since the owner decided refuse the request as a
/// revision mismatch: the target's receipt says refused, with advice, and
/// its diagnostics say answered.
#[test]
fn moved_roots_refuse_the_request_as_a_revision_mismatch() {
    let host = host();
    let device = device(&host);
    let root = host.mint_own_root();
    device.request_pin(host.machine(), root);
    // The revision moves after the owner decided: another root the
    // request's witness never saw.
    let moved = host.mint_own_root();
    assert!(
        moved != root,
        "the second mint is the move the witness never saw"
    );
    host.take(&device);
    let before = host
        .vault
        .pending_root_requests(&host.owner)
        .expect("the host's pending root requests");
    assert_eq!(
        before.len(),
        1,
        "the host counts the device's request naming it"
    );
    let (hash, change, _) = before.into_iter().next().expect("one request");
    assert!(
        matches!(change, RootChange::Pin { root: bound } if bound == root),
        "the pending request is the device's pin"
    );
    let drain = host
        .vault
        .run_pending_owner_work(|| true)
        .expect("the host's pickup");
    assert_eq!(
        drain.refused, 1,
        "the moved revision refuses the request: {drain:?}"
    );
    assert_eq!(drain.enacted, 0, "nothing is enacted: {drain:?}");
    let receipt = host
        .vault
        .owner_work_receipt(&host.owner, hash)
        .expect("the receipt reads")
        .expect("the request folds");
    assert_eq!(
        receipt.status,
        OwnerWorkStatus::Refused {
            reason: OwnerWorkRefusal::RootRevisionMismatch,
        },
        "the receipt names the mismatch"
    );
    assert_eq!(receipt.status.text(), "refused by its holder");
    assert_eq!(receipt.status.advice(), Some(MISMATCH_ADVICE));
    let after = host
        .vault
        .pending_root_requests(&host.owner)
        .expect("the host's pending root requests");
    assert!(after.is_empty(), "a refused request is no longer pending");
    let diagnostics = host
        .vault
        .owner_work_diagnostics(&host.owner, hash, 0)
        .expect("the diagnostics read")
        .expect("the request folds");
    assert_eq!(diagnostics.executor, Some(host.machine()));
    assert!(
        matches!(diagnostics.observation, ExecutorObservation::Answered),
        "an answered request reports nothing to observe: {:?}",
        diagnostics.observation
    );
}

/// Only the executor observes its own work: any other install answers
/// that the observation is unavailable here.
#[test]
fn diagnostics_are_unavailable_on_a_non_executor() {
    let host = host();
    let mut device = device(&host);
    let root = host.mint_own_root();
    host.request_pin(device.machine, root);
    device.take(&host);
    let (hash, _, asked) = pending_pin(&device);
    let diagnostics = host
        .vault
        .owner_work_diagnostics(&host.owner, hash, 0)
        .expect("the diagnostics read")
        .expect("the request folds");
    assert_eq!(diagnostics.kind, OwnerWorkKind::Root);
    assert_eq!(diagnostics.executor, Some(device.machine));
    assert!(
        matches!(diagnostics.observation, ExecutorObservation::Unavailable),
        "a non-executor reports its observation unavailable: {:?}",
        diagnostics.observation
    );
    assert_eq!(
        diagnostics.request,
        asked.request.expect("the receipt names its entry"),
        "the diagnostics name the request they observe"
    );
}

/// An entry no request was signed as has no diagnostics.
#[test]
fn diagnostics_name_nothing_for_an_unknown_request() {
    let host = host();
    let device = device(&host);
    let root = host.mint_own_root();
    host.request_pin(device.machine, root);
    let missing = host
        .vault
        .owner_work_diagnostics(&host.owner, [0xA5; 32], 0)
        .expect("the diagnostics read");
    assert!(missing.is_none(), "no request, no diagnostics");
}

/// Root work keeps no executor diagnostics: on its executor a pending
/// root request says so.
#[test]
fn root_work_reports_no_executor_diagnostics_on_its_executor() {
    let host = host();
    let mut device = device(&host);
    let root = host.mint_own_root();
    host.request_pin(device.machine, root);
    device.take(&host);
    let (hash, _, _) = pending_pin(&device);
    let diagnostics = device
        .vault
        .owner_work_diagnostics(&device.owner(), hash, 0)
        .expect("the diagnostics read")
        .expect("the request folds");
    assert_eq!(diagnostics.kind, OwnerWorkKind::Root);
    assert_eq!(diagnostics.executor, Some(device.machine));
    assert!(
        matches!(diagnostics.observation, ExecutorObservation::NotReported),
        "root work reports no executor diagnostics: {:?}",
        diagnostics.observation
    );
    assert!(
        diagnostics.unmerged_upload.is_none(),
        "only a publication names an unmerged upload"
    );
}

/// A publication to a home that keeps sealed copies carries no warning:
/// on its executor the report names the home, an unknown relay, no
/// attempt and no unmerged upload.
#[test]
fn a_computer_home_carries_no_warning() {
    let host = host();
    let device = device(&host);
    let receipt = host
        .vault
        .request_bundle_publication(&host.owner, ActSurface::HostedConsole, device.machine)
        .expect("the publication is asked");
    let entry = receipt.request.clone().expect("a holder is named");
    assert_eq!(receipt.kind, OwnerWorkKind::PublishBundle);
    assert_eq!(receipt.executor, Some(host.machine()));
    assert_eq!(
        receipt.home_warning, None,
        "a computer home carries no warning"
    );
    let hash = entry_hash(&entry);
    let diagnostics = host
        .vault
        .owner_work_diagnostics(&host.owner, hash, 0)
        .expect("the diagnostics read")
        .expect("the request folds");
    assert_eq!(diagnostics.request, entry);
    assert_eq!(diagnostics.executor, Some(host.machine()));
    assert!(
        diagnostics.unmerged_upload.is_none(),
        "no upload was assembled here"
    );
    match &diagnostics.observation {
        ExecutorObservation::BundlePublication(report) => {
            assert_eq!(report.home, device.machine);
            assert_eq!(report.home_warning, None);
            assert!(
                matches!(report.relay, RelayObservation::Unknown),
                "no relay pass observed it: {:?}",
                report.relay
            );
            assert!(report.device_sync_start.is_none());
            assert!(report.attempt.is_none());
        }
        other => panic!("the executor reports its publication: {other:?}"),
    }
}

/// A publication to a phone warns that it keeps no sealed copy, on the
/// receipt and on the executor's report alike.
#[cfg(feature = "sync")]
#[test]
fn a_phone_home_warns_it_keeps_no_sealed_copy() {
    let host = host();
    let phone = device_with_class(&host, MachineDeviceClass::Phone);
    let receipt = host
        .vault
        .request_bundle_publication(&host.owner, ActSurface::HostedConsole, phone.machine)
        .expect("the publication is asked");
    assert_eq!(receipt.kind, OwnerWorkKind::PublishBundle);
    assert_eq!(receipt.executor, Some(host.machine()));
    assert_eq!(
        receipt.home_warning,
        Some(BundleHomeWarning::HomeDoesNotKeepSealedBundles),
        "a phone home warns it keeps no sealed copy"
    );
    let hash = entry_hash(&receipt.request.clone().expect("a holder is named"));
    let diagnostics = host
        .vault
        .owner_work_diagnostics(&host.owner, hash, 0)
        .expect("the diagnostics read")
        .expect("the request folds");
    match &diagnostics.observation {
        ExecutorObservation::BundlePublication(report) => {
            assert_eq!(report.home, phone.machine);
            assert_eq!(
                report.home_warning,
                Some(BundleHomeWarning::HomeDoesNotKeepSealedBundles),
                "the executor's report carries the same warning"
            );
            assert!(
                matches!(report.relay, RelayObservation::Unknown),
                "no relay pass observed it: {:?}",
                report.relay
            );
        }
        other => panic!("the executor reports its publication: {other:?}"),
    }
}

/// What one relay pass saw for a publication is what the executor
/// reports: the pass itself, and the worlds its generation leaves to a
/// reader.
#[cfg(feature = "sync")]
#[test]
fn a_relay_pass_observation_is_what_the_executor_reports() {
    use oneiron::test_doors::pending_work_reports::observe_bundle_publication;

    let host = host();
    let device = device(&host);
    let receipt = host
        .vault
        .request_bundle_publication(&host.owner, ActSurface::HostedConsole, device.machine)
        .expect("the publication is asked");
    let hash = entry_hash(&receipt.request.clone().expect("a holder is named"));
    let world = EntityId::from_bytes([0x41; 16]).expect("a world id");
    let observed = PublishObserved {
        at: 9,
        home: Some(device.machine),
        reach: PublishReach::Reached,
        latest: LatestRead::Read {
            bundle: CapsuleRead::Opens,
            pads: CapsuleRead::Opens,
            awaiting_reader: vec![world],
        },
        incomplete_authority: Vec::new(),
    };
    observe_bundle_publication(&host.vault, hash, observed.clone());
    let diagnostics = host
        .vault
        .owner_work_diagnostics(&host.owner, hash, 0)
        .expect("the diagnostics read")
        .expect("the request folds");
    match &diagnostics.observation {
        ExecutorObservation::BundlePublication(report) => {
            assert_eq!(
                report.relay,
                RelayObservation::Observed {
                    passes: vec![observed],
                },
                "the executor reports the pass it saw"
            );
            assert_eq!(
                report.home_warning,
                Some(BundleHomeWarning::AwaitingReader {
                    worlds: vec![world],
                }),
                "the generation's worlds await a reader"
            );
            assert!(report.attempt.is_none());
        }
        other => panic!("the executor reports its publication: {other:?}"),
    }
}

/// A re-assertion with more keys than one page lists pages by offset: the
/// first page lists 256 keys and names the rest, and the second page lists
/// the remainder, ordered after the first page's last, and names no more.
/// The one minted key reads wrapped; the extra records name no stored pad.
#[cfg(feature = "sync")]
#[test]
fn reassert_keys_page_by_offset() {
    use oneiron::test_doors::pending_work_reports::{
        append_reassert_paging_keys, record_reassert_request,
    };

    let host = host();
    let mut device = device(&host);
    let world = device
        .vault
        .create_world(
            &device.owner(),
            "paged re-assertion",
            device.vault.now_recorded_at(),
        )
        .expect("the device's world");
    device
        .vault
        .set_world_privacy_as(
            &device.owner(),
            ActSurface::HostedConsole,
            world,
            WorldPrivacy {
                read: ReadLocation::OneMachine(device.machine),
                ..WorldPrivacy::default()
            },
            None,
        )
        .expect("the world reads on the device alone");
    host.take(&device);
    let receipt = record_reassert_request(&host.vault, &host.owner, world)
        .expect("the host records the re-assertion");
    assert_eq!(
        receipt.executor,
        Some(device.machine),
        "the device holds the world's key, so it does the work"
    );
    let entry = receipt.request.clone().expect("a holder is named");
    device.take(&host);
    let person = device
        .vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the device");
    append_reassert_paging_keys(&device.vault, person, device.machine, world, 256)
        .expect("256 extra key records");
    let hash = entry_hash(&entry);
    let first = device
        .vault
        .owner_work_diagnostics(&device.owner(), hash, 0)
        .expect("the diagnostics read")
        .expect("the request folds");
    assert_eq!(first.kind, OwnerWorkKind::WorldKey);
    assert_eq!(first.request, entry);
    assert_eq!(first.executor, Some(device.machine));
    match &first.observation {
        ExecutorObservation::Reassert(paged) => {
            assert_eq!(paged.world, world);
            assert_eq!(paged.keys.len(), 256, "one page lists 256 keys");
            let next = paged.next_offset.expect("a second page follows");
            assert_eq!(next, 256, "the next page starts after the first");
            assert!(paged.ensure.is_some(), "the ensure step follows the keys");
            let second = device
                .vault
                .owner_work_diagnostics(&device.owner(), hash, next)
                .expect("the diagnostics read")
                .expect("the request folds");
            match &second.observation {
                ExecutorObservation::Reassert(rest) => {
                    assert_eq!(rest.world, world);
                    assert_eq!(rest.keys.len(), 1, "the second page lists the remainder");
                    assert!(rest.next_offset.is_none(), "no third page follows");
                    assert!(
                        rest.keys[0].key > paged.keys[255].key,
                        "the second page follows the first page's last"
                    );
                    let wrapped = paged
                        .keys
                        .iter()
                        .chain(rest.keys.iter())
                        .filter(|key| key.state == ReassertKeyState::Wrapped)
                        .count();
                    assert_eq!(wrapped, 1, "the minted key reads wrapped");
                    let missing = paged
                        .keys
                        .iter()
                        .chain(rest.keys.iter())
                        .filter(|key| key.state == ReassertKeyState::MissingPad)
                        .count();
                    assert_eq!(missing, 256, "the extra records name no stored pad");
                }
                other => panic!("the second page reports the re-assertion: {other:?}"),
            }
        }
        other => panic!("the executor reports its re-assertion: {other:?}"),
    }
}
