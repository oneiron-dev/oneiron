//! World privacy P6b acceptance for the world-key doors (contract §8): a
//! world's key opens only on the machines its world reads on and for the
//! owner's kit, never reaches the store unwrapped, and a record that names
//! another key, or a kit that was never activated, changes nothing; and a
//! kit restore reports every key its root holds.
use std::sync::Arc;

use oneiron_crypto::{HybridSecretKey, Purpose, SealKey, SealParams, SuiteId};
use oneiron_keystore::MemoryKeystore;

use super::machine_identity::{Host, host, own_encryption_key};
use super::support::{authority_key_from_ed, ed_key, sign_ed, unsigned_entry};
use super::world_privacy::{edit_by, land, settings, stored_entries, world_row};
use super::*;
use crate::recovery::checkpoint::RestoreReason;
use crate::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit,
    restore_kit,
};
use crate::store::GateDecisionId;
use crate::world_keys::{
    KitConfirmation, RecoveryRootSeed, Withheld, WorldKeyBinding, WorldKeyStatus,
    WorldRecoveryState, machine_secret, open_world_key,
};
use crate::{Vault, VaultConfig};

/// A machine of the owner's whose install key and encryption secret the
/// test generates and holds.
pub(super) struct Keyed {
    pub(super) machine: EntityId,
    pub(super) signing: SigningKey,
    pub(super) secret: HybridSecretKey,
}

pub(super) fn keyed_machine(host: &Host, seed: u8) -> Keyed {
    let machine = EntityId::now();
    let secret =
        machine_secret(&MemoryKeystore::new(), host.vault_id, *machine.as_bytes()).unwrap();
    let signing = ed_key(seed);
    let machine_key = signing.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: secret.public_key().to_bytes(),
    };
    let machine_proof = signing
        .sign(&machine_profile_proof_transcript(
            &host.vault_id,
            machine,
            &machine_key,
            &encryption_key,
        ))
        .to_bytes();
    let request = MachineEnrolmentRequest {
        vault_id: host.vault_id,
        machine,
        machine_key,
        encryption_key,
        machine_proof,
    };
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    Keyed {
        machine,
        signing,
        secret,
    }
}

/// This install, enrolled as one of the owner's machines with its own keys.
pub(super) fn enrol_own(host: &Host) -> EntityId {
    let key = own_encryption_key(&host.vault, host.vault_id);
    let request = host
        .vault
        .machine_enrolment_request(host.vault_id, key)
        .unwrap();
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    request.machine
}

pub(super) fn set(host: &Host, world: EntityId, read: ReadLocation) {
    host.vault
        .set_world_privacy_as(
            &host.owner,
            ActSurface::ThisInstall,
            world,
            settings(read),
            None,
        )
        .unwrap();
}

/// A new install of the host's vault, restored from its checkpoint: a new
/// machine id, no pin, and an empty keystore of its own.
pub(super) struct Fresh {
    pub(super) _backups: tempfile::TempDir,
    pub(super) vault: Vault,
    pub(super) owner: crate::consent::AuthenticatedOwner,
    keys: Arc<MemoryKeystore>,
    config: VaultConfig,
}

pub(super) fn fresh_install(host: &Host) -> Fresh {
    fresh_install_with(host, VaultConfig::default())
}

/// [`fresh_install`] opened under `config`.
pub(super) fn fresh_install_with(host: &Host, config: VaultConfig) -> Fresh {
    let backups = crate::test_support::restore_tempdir();
    let image = backups.path().join("image");
    host.vault.snapshot_checkpoint(&image, 100).unwrap();
    let (vault, _) = Vault::restore_checkpoint(
        &image,
        &backups.path().join("fresh"),
        config.clone(),
        RestoreReason::Restore,
        200,
    )
    .unwrap();
    Fresh::on(backups, vault, Arc::new(MemoryKeystore::new()), config)
}

impl Fresh {
    fn on(
        backups: tempfile::TempDir,
        vault: Vault,
        keys: Arc<MemoryKeystore>,
        config: VaultConfig,
    ) -> Self {
        vault.install_device_keystore(Arc::clone(&keys) as Arc<dyn oneiron_keystore::DeviceKeystore>);
        let person = crate::vault::embedded_owner_actor_id().unwrap();
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .unwrap();
        Self {
            _backups: backups,
            vault,
            owner,
            keys,
            config,
        }
    }

    /// The same install closed and opened again: its keystore stays, and its
    /// session ring starts empty.
    pub(super) fn reopen(self) -> Self {
        let Self {
            _backups,
            vault,
            keys,
            config,
            ..
        } = self;
        drop(vault);
        let vault = Vault::open(_backups.path().join("fresh"), config.clone()).unwrap();
        Self::on(_backups, vault, keys, config)
    }

    pub(super) fn machine(&self) -> EntityId {
        self.vault.local_machine().unwrap().unwrap().id
    }
}

/// This install's own enrolment request.
pub(super) fn own_request(vault: &Vault) -> MachineEnrolmentRequest {
    let vault_id = vault.authority_fold().unwrap().vault_id.unwrap();
    let key = vault.machine_encryption_key(vault_id).unwrap();
    vault.machine_enrolment_request(vault_id, key).unwrap()
}

/// Every stored key record of `world`.
pub(super) fn key_records(vault: &Vault, world: EntityId) -> Vec<WorldKeyWrapsRecord> {
    stored_entries(vault)
        .into_iter()
        .filter_map(|entry| match entry.op {
            AuthorityOp::WorldKeyWraps(record) if record.key.world == world => Some(record),
            _ => None,
        })
        .collect()
}

/// The commitments of key `id` that `secret`, opening as `opener`, gets out
/// of the stored wraps: every envelope of every record is tried, whoever it
/// names.
pub(super) fn opened_by(
    vault: &Vault,
    vault_id: [u8; 32],
    id: WorldKeyId,
    opener: WrapRecipient,
    secret: &HybridSecretKey,
) -> BTreeSet<[u8; 32]> {
    key_records(vault, id.world)
        .into_iter()
        .filter(|record| record.key == id)
        .flat_map(|record| {
            let binding = WorldKeyBinding {
                vault_id,
                key: record.key,
                owner: record.owner,
                policy: record.policy,
                commitment: record.commitment,
            };
            record
                .wraps
                .into_iter()
                .filter_map(move |(_, bytes)| {
                    let envelope = oneiron_crypto::Envelope::parse(&bytes).ok()?;
                    open_world_key(&binding, opener, secret, &envelope).ok()
                })
                .map(|key| key.commitment())
        })
        .collect()
}

/// `record`, signed by `by` as its own, on the host's main-log heads and the
/// world's live edits.
fn record_by(host: &Host, by: &Keyed, record: WorldKeyWrapsRecord) -> AuthorityLogEntry {
    let fold = host.vault.authority_fold().unwrap();
    let signer = authority_key_from_ed(&by.signing);
    let seq = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
    let mut parents = fold.append_heads.clone();
    if let Some(folded) = fold.worlds.get(&record.key.world) {
        parents.extend(folded.live.keys().copied());
    }
    sign_ed(
        unsigned_entry(
            fold.vault_id,
            seq,
            parents.into_iter().collect(),
            AuthorityOp::WorldKeyWraps(WorldKeyWrapsRecord {
                machine: by.machine,
                ..record
            }),
            signer,
            2,
        ),
        &by.signing,
    )
}

/// An envelope with a world key's header for `to`, under `suite` and `kem`,
/// around a payload of the right length that no key went into.
fn sealed_blank(
    vault_id: [u8; 32],
    id: WorldKeyId,
    to: WrapRecipient,
    public: &oneiron_crypto::HybridPublicKey,
    suite: SuiteId,
    kem: SuiteId,
) -> Option<Vec<u8>> {
    oneiron_crypto::seal(
        &SealParams {
            suite,
            purpose: Purpose::WorldDek,
            epoch: WORLD_KEY_EPOCH,
            key_id: &id.envelope_key_id(),
            recipient: &to.envelope_recipient(),
            vault_id: &vault_id,
        },
        SealKey::Hybrid {
            recipient: public,
            kem_suite: kem,
        },
        &[0; WORLD_KEY_PAYLOAD_LEN],
        &mut getrandom::SysRng,
    )
    .ok()
    .map(|envelope| envelope.to_bytes())
}

fn holds(path: &std::path::Path, secret: &[u8; 32]) -> bool {
    if path.is_dir() {
        return std::fs::read_dir(path)
            .unwrap()
            .any(|entry| holds(&entry.unwrap().path(), secret));
    }
    std::fs::read(path)
        .unwrap()
        .windows(secret.len())
        .any(|window| window == secret)
}

/// Check 1, with checks 5 and 10: a world key opens only on the machines its
/// world reads on and for the owner's kit. A wrap made for A refuses B's
/// secret even when B names A, the kit opens its root's wrap, and once the
/// world reads on every machine of the owner's, the same key opens on B and
/// C. The warning shows until the kit covers the key, and neither the key
/// nor the kit's seed reaches the store or a checkpoint.
#[test]
fn a_world_key_opens_only_where_its_world_reads_and_for_the_kit() {
    let host = host();
    let a = enrol_own(&host);
    let b = keyed_machine(&host, 41);
    let c = keyed_machine(&host, 42);
    let world = world_row(&host);
    let open = world_row(&host);
    set(&host, world, ReadLocation::OneMachine(a));
    assert_eq!(
        host.vault.world_recovery_state(world).unwrap(),
        WorldRecoveryState::NoKit
    );
    assert_eq!(
        host.vault.world_recovery_state(open).unwrap(),
        WorldRecoveryState::NotPrivate
    );
    let key = host.vault.world_key(world).unwrap();
    let id = *key.id();

    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let root = prepared.seed().public(&host.vault_id).unwrap();
    let kit = prepared.seed().recovery_secret().unwrap();
    let kit_bytes = prepared.seed().kit_bytes();
    let activated = host
        .vault
        .activate_owner_root(
            &host.owner,
            EditOrigin::ThisMachine,
            prepared,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(activated.root, root.id);
    assert_eq!(activated.keys.rewrapped, vec![id]);
    assert_eq!(
        host.vault.ensure_world_key(&host.owner, world).unwrap(),
        WorldKeyStatus::UpToDate(id)
    );
    assert_eq!(
        host.vault.world_recovery_state(world).unwrap(),
        WorldRecoveryState::Covered
    );

    let mine = |opener: WrapRecipient, secret: &HybridSecretKey| {
        opened_by(&host.vault, host.vault_id, id, opener, secret)
    };
    let only_this_key = BTreeSet::from([key.commitment()]);
    assert_eq!(
        mine(WrapRecipient::RecoveryRoot(root.id), &kit),
        only_this_key
    );
    for other in [&b, &c] {
        assert!(mine(WrapRecipient::Machine(a), &other.secret).is_empty());
        assert!(mine(WrapRecipient::Machine(other.machine), &other.secret).is_empty());
    }

    set(&host, world, ReadLocation::MyMachines);
    assert_eq!(
        host.vault.ensure_world_key(&host.owner, world).unwrap(),
        WorldKeyStatus::UpToDate(id)
    );
    for other in [&b, &c] {
        assert_eq!(
            mine(WrapRecipient::Machine(other.machine), &other.secret),
            only_this_key
        );
    }
    assert_eq!(host.vault.world_key(world).unwrap().id(), &id);

    let backups = tempfile::tempdir().unwrap();
    let image = backups.path().join("image");
    host.vault.snapshot_checkpoint(&image, 100).unwrap();
    for place in [host.vault.store.env.path(), image.as_path()] {
        assert!(!holds(place, key.expose()), "a world key reached the store");
        assert!(
            !holds(place, &kit_bytes),
            "the kit's seed reached the store"
        );
    }
}

/// Check 3: a record whose envelope names another world's key, a generation
/// its envelope does not, or a suite other than the one world keys use, is
/// refused at the write door and at signed-history ingest, and no row is
/// written. The same record with an envelope for its own key lands.
#[test]
fn a_record_naming_another_key_or_suite_is_refused_before_any_write() {
    let host = host();
    enrol_own(&host);
    let b = keyed_machine(&host, 43);
    let (first, second) = (world_row(&host), world_row(&host));
    set(&host, first, ReadLocation::MyMachines);
    set(&host, second, ReadLocation::MyMachines);
    let to_b = WrapRecipient::Machine(b.machine);
    let wrap_to_b = |world| {
        key_records(&host.vault, world)
            .into_iter()
            .find_map(|record| {
                let (_, bytes) = record.wraps.iter().find(|(to, _)| *to == to_b)?.clone();
                Some((record, bytes))
            })
            .unwrap()
    };
    let (_, from_first) = wrap_to_b(first);
    let (genuine, own) = wrap_to_b(second);
    let with = |key: WorldKeyId, bytes: Vec<u8>| WorldKeyWrapsRecord {
        key,
        wraps: vec![(to_b, bytes)],
        ..genuine.clone()
    };
    let blank = |suite, kem| {
        sealed_blank(
            host.vault_id,
            genuine.key,
            to_b,
            b.secret.public_key(),
            suite,
            kem,
        )
    };
    let next_generation = WorldKeyId {
        generation: genuine.key.generation + 1,
        ..genuine.key
    };
    let mut refused = vec![
        with(genuine.key, from_first),
        with(next_generation, own.clone()),
    ];
    refused.extend(
        [
            (SuiteId::AES256GCM_V1, SuiteId::KEM_X25519_MLKEM1024_V1),
            (
                SuiteId::XCHACHA20POLY1305_V1,
                SuiteId::KEM_X25519_MLKEM768_V1,
            ),
        ]
        .into_iter()
        .filter_map(|(suite, kem)| blank(suite, kem))
        .map(|bytes| with(genuine.key, bytes)),
    );
    assert!(refused.len() >= 3);

    let at = TimeRange { start: 2, end: 2 };
    let stored = stored_entries(&host.vault).len();
    for record in refused {
        let entry = record_by(&host, &b, record);
        assert!(host.vault.put_authority_log_entry(&entry, at, 2).is_err());
        let bytes = encode_value(&entry_value(&entry, true)).unwrap();
        assert!(decode_authority_log_entry_body(&bytes).is_err());
        assert!(
            host.vault
                .import_signed_authority_history(&[bytes])
                .is_err()
        );
        assert_eq!(stored_entries(&host.vault).len(), stored);
    }
    let control = record_by(&host, &b, with(genuine.key, own));
    host.vault.put_authority_log_entry(&control, at, 2).unwrap();
    assert_eq!(stored_entries(&host.vault).len(), stored + 1);
}

/// Check 4: one key id names one key. A record of another machine of the
/// owner's that names the world's key id with other bytes leaves the key
/// conflicted, and the next `ensure_world_key` mints a fresh one. Corrupt
/// wraps beside a good one never stop the good one opening.
#[test]
fn a_second_key_under_one_id_conflicts_and_the_next_door_mints_afresh() {
    let host = host();
    let vault_id = host.vault_id;
    let a = enrol_own(&host);
    let b = keyed_machine(&host, 44);
    let world = world_row(&host);
    set(&host, world, ReadLocation::MyMachines);
    let first = *host.vault.world_key(world).unwrap().id();
    let genuine = key_records(&host.vault, world).remove(0);
    let at = TimeRange { start: 2, end: 2 };

    let to_b = WrapRecipient::Machine(b.machine);
    let other_bytes = WorldKeyWrapsRecord {
        commitment: [0x5c; 32],
        wraps: vec![(
            to_b,
            sealed_blank(
                vault_id,
                first,
                to_b,
                b.secret.public_key(),
                SuiteId::XCHACHA20POLY1305_V1,
                SuiteId::KEM_X25519_MLKEM1024_V1,
            )
            .unwrap(),
        )],
        ..genuine
    };
    host.vault
        .put_authority_log_entry(&record_by(&host, &b, other_bytes), at, 2)
        .unwrap();
    let fold = host.vault.authority_fold().unwrap();
    assert!(fold.world_key(&first).is_some_and(|key| key.conflicted));
    assert!(fold.current_world_key(world).is_none());
    assert!(host.vault.world_key(world).is_err());
    let WorldKeyStatus::Minted(fresh) = host.vault.ensure_world_key(&host.owner, world).unwrap()
    else {
        panic!("a conflicted key is replaced");
    };
    assert_ne!(fresh, first);
    assert_eq!(fresh.world, world);

    // B copies A's wrap of the fresh key three times with its tag broken.
    let to_a = WrapRecipient::Machine(a);
    let latest = key_records(&host.vault, world)
        .into_iter()
        .find(|record| record.key == fresh)
        .unwrap();
    let (_, good) = latest.wraps.iter().find(|(to, _)| *to == to_a).unwrap();
    for flip in 1..=3u8 {
        let mut broken = good.clone();
        let last = broken.len() - 1;
        broken[last] ^= flip;
        let record = WorldKeyWrapsRecord {
            wraps: vec![(to_a, broken)],
            ..latest.clone()
        };
        host.vault
            .put_authority_log_entry(&record_by(&host, &b, record), at, 2)
            .unwrap();
    }
    let fold = host.vault.authority_fold().unwrap();
    let held = fold.world_key(&fresh).unwrap();
    assert!(!held.conflicted);
    assert_eq!(held.wraps[&to_a].len(), 4);
    // A fresh handle has an empty session ring: the key opens from its wraps.
    let Host {
        _dir: dir, vault, ..
    } = host;
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    own_encryption_key(&vault, vault_id);
    assert_eq!(vault.world_key(world).unwrap().id(), &fresh);
}

/// Check 8: a kit issue that never activates publishes nothing. With no
/// root the private world warns, and the prepared seed restores nothing and
/// anchors nothing, whatever the owner confirms, before any write. Its
/// fingerprint pins nothing: the root is only awaited (r23).
#[test]
fn a_kit_issue_that_never_activates_publishes_nothing() {
    let host = host();
    let a = enrol_own(&host);
    let world = world_row(&host);
    set(&host, world, ReadLocation::OneMachine(a));
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let root = prepared.seed().public(&host.vault_id).unwrap();
    let stored = stored_entries(&host.vault).len();
    let own = host
        .vault
        .machine_enrolment_request(
            host.vault_id,
            own_encryption_key(&host.vault, host.vault_id),
        )
        .unwrap();
    for confirm in [
        None,
        Some(KitConfirmation::Owner),
        Some(KitConfirmation::Fingerprint(root.id)),
    ] {
        assert!(
            host.vault
                .restore_world_keys(
                    &host.owner,
                    EditOrigin::ThisMachine,
                    prepared.seed(),
                    confirm
                )
                .is_err()
        );
        assert!(
            host.vault
                .anchor_machine(
                    &host.owner,
                    EditOrigin::ThisMachine,
                    prepared.seed(),
                    &own,
                    None,
                    confirm
                )
                .is_err()
        );
    }
    let report = host
        .vault
        .pin_owner_root(&host.owner, EditOrigin::ThisMachine, root.id)
        .unwrap();
    assert_eq!(report.awaiting, Some(root.id));
    assert_eq!(stored_entries(&host.vault).len(), stored);
    let view = host.vault.owner_root_view(None, 0).unwrap();
    assert_eq!(view.pinned, None);
    let awaiting = AwaitedRoot {
        root: root.id,
        arrived: false,
    };
    assert_eq!(view.awaiting, Some(awaiting));
    assert_eq!(
        host.vault.world_recovery_state(world).unwrap(),
        WorldRecoveryState::NoKit
    );
}

/// The owner's kit for `drawn`, rebuilt from two of its stored pieces: the
/// authenticated seed a restore on a new machine reads.
pub(super) fn kit_seed(vault_id: [u8; 32], drawn: &RecoveryRootSeed) -> RecoveryRootSeed {
    let issue = KitIssue {
        vault_id,
        homes: [
            PieceHome::ThisMachine,
            PieceHome::OtherMachine(EntityId::now()),
            PieceHome::RecoveryCode(CodeKeeping::Paper),
        ],
        passphrase: None,
        cost: PassphraseCost::FLOOR,
        only_machine: false,
    };
    let pieces = issue_recovery_root_kit(&issue, &drawn.kit_bytes())
        .unwrap()
        .into_pieces();
    let restored = restore_kit(
        vault_id,
        KitSecretKind::RecoveryRoot,
        &[&pieces[0], &pieces[1]],
        None,
    )
    .unwrap();
    RecoveryRootSeed::from_restored_kit(restored).unwrap()
}

/// Check 9, with check 6's restore on a fresh install: the kit alone, on a
/// new machine of the vault with an empty keystore, anchors that machine's
/// own request, opens the key of a world every machine of the owner's reads
/// and wraps it to the new machine. A world kept on one other machine needs
/// a re-home and gets no wrap here, an erased world's key is never opened,
/// a conflicted world's key is withheld, and every key wrapped to the root
/// appears in exactly one list.
#[test]
fn a_kit_restore_honours_erasure_and_one_machine_and_reports_every_key() {
    let host = host();
    let a = enrol_own(&host);
    let c = keyed_machine(&host, 45);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let seed = kit_seed(host.vault_id, prepared.seed());
    host.vault
        .activate_owner_root(
            &host.owner,
            EditOrigin::ThisMachine,
            prepared,
            &BTreeSet::new(),
        )
        .unwrap();
    let shared = world_row(&host);
    set(&host, shared, ReadLocation::MyMachines);
    let kept = world_row(&host);
    set(&host, kept, ReadLocation::OneMachine(a));
    let erased = world_row(&host);
    set(&host, erased, ReadLocation::MyMachines);
    let contested = world_row(&host);
    let pick = edit_by(
        &host,
        c.machine,
        &c.signing,
        contested,
        settings(ReadLocation::OneMachine(c.machine)),
    );
    set(&host, contested, ReadLocation::OneMachine(a));
    land(&host, &[pick]);
    assert!(matches!(
        host.vault.world_privacy(contested).unwrap().read,
        EffectiveRead::Conflicted { .. }
    ));
    let fold = host.vault.authority_fold().unwrap();
    let [shared_key, kept_key, erased_key, contested_key] =
        [shared, kept, erased, contested].map(|world| fold.current_world_key(world).unwrap().id);
    assert!(host.vault.delete_entity(&erased).unwrap());

    let Fresh {
        _backups,
        vault: fresh,
        owner,
        ..
    } = fresh_install(&host);
    let restore = fresh
        .restore_world_keys(&owner, EditOrigin::ThisMachine, &seed, None)
        .unwrap();
    assert_eq!(restore.usable, vec![shared_key]);
    assert_eq!(restore.needs_rehome, vec![kept_key]);
    let withheld: BTreeMap<_, _> = restore.withheld.iter().copied().collect();
    assert_eq!(
        withheld,
        BTreeMap::from([
            (erased_key, Withheld::NotLive),
            (contested_key, Withheld::NotReadable),
        ])
    );
    assert_eq!(restore.withheld.len(), 2);

    let here = fresh.local_machine().unwrap().unwrap();
    assert!(here.mine);
    let to_here = WrapRecipient::Machine(here.id);
    assert_eq!(fresh.world_key(shared).unwrap().id(), &shared_key);
    assert!(fresh.world_key(kept).is_err());
    for world in [kept, erased, contested] {
        assert!(
            key_records(&fresh, world)
                .iter()
                .all(|record| record.wraps.iter().all(|(to, _)| *to != to_here))
        );
    }
}
