//! World privacy P6b acceptance in the authority fold: an owner root's anchor
//! marks machines in a chain of its own, the pin decides which anchor counts,
//! and nothing a host signs under its own root or its roster takes the
//! owner's mark away (contract §4, checks 7 and 7d).
use super::machine_identity::request_for;
use super::support::{authority_key_from_ed, device, ed_key, sign_ed, unsigned_entry};
use super::*;
use crate::world_keys::{RecoveryRoot, RecoveryRootSeed};

/// A hosted vault's genesis under the host's cloud root.
fn hosted_genesis(cloud: &SigningKey) -> AuthorityLogEntry {
    let key = authority_key_from_ed(cloud);
    sign_ed(
        unsigned_entry(
            None,
            0,
            vec![],
            AuthorityOp::Genesis {
                device: device(
                    key.clone(),
                    ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
                    AuthorityTier::CloudCustodial,
                ),
                genesis_nonce: [131; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
                recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            },
            key,
            1,
        ),
        cloud,
    )
}

fn signed(
    id: AuthorityVaultId,
    parents: &[&AuthorityLogEntry],
    signer: &SigningKey,
    seq: u64,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(id),
            seq,
            parents
                .iter()
                .map(|parent| authority_entry_hash(parent).unwrap())
                .collect(),
            op,
            authority_key_from_ed(signer),
            2,
        ),
        signer,
    )
}

fn root_record(root: &RecoveryRoot) -> OwnerRootRecord {
    OwnerRootRecord {
        owner: EntityId::now(),
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    }
}

/// A root published by its own anchor on `parent`.
fn publish(
    id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
) -> (RecoveryRoot, SigningKey, AuthorityLogEntry) {
    let seed = RecoveryRootSeed::generate().unwrap();
    let root = seed.public(&id).unwrap();
    let anchor = seed.anchor();
    let entry = signed(
        id,
        &[parent],
        &anchor,
        1,
        AuthorityOp::OwnerRoot(root_record(&root)),
    );
    (root, anchor, entry)
}

fn profile(request: &MachineEnrolmentRequest, role: MachineRole, revision: u64) -> AuthorityOp {
    AuthorityOp::MachineProfile(MachineProfile {
        machine: request.machine,
        owner: EntityId::now(),
        machine_key: request.machine_key,
        encryption_key: request.encryption_key.clone(),
        role,
        revision,
        machine_proof: request.machine_proof,
    })
}

fn pin(root: &RecoveryRoot) -> PinnedRoot {
    PinnedRoot {
        id: root.id,
        anchor_key: root.anchor_key,
    }
}

fn hosted_fold(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    fold_authority_log_for_posture(
        entries,
        &BTreeMap::new(),
        10,
        &BTreeMap::new(),
        crate::HostingPrivacyPosture::Hosted,
    )
}

const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);

/// The owner's anchor marks machine M. The host then signs sibling revisions
/// of M, each valid on its own: under a root of its own, a verbatim copy at
/// revision `u64::MAX` and a removal; under its roster key, a removal and a
/// conflicting equal revision. On an install pinned to the owner's root M
/// stays mine with its own keys, whether the host's revisions saw the owner's
/// mark or not, and a later owner revision still lands. An unpinned install
/// counts no anchor admission.
#[test]
fn neither_a_foreign_anchor_nor_a_host_roster_strips_the_owners_mark() {
    let cloud = ed_key(130);
    let genesis = hosted_genesis(&cloud);
    let id = genesis_vault_id(&genesis).unwrap();
    let (owner_root, owner_anchor, owner_published) = publish(id, &genesis);
    let (host_root, host_anchor, host_published) = publish(id, &genesis);
    let machine_key = ed_key(132);
    let request = request_for(id, EntityId::now(), &machine_key);
    let mark = signed(
        id,
        &[&owner_published],
        &owner_anchor,
        2,
        profile(&request, YOURS, 1),
    );
    for host_saw_the_mark in [false, true] {
        let root_parent = if host_saw_the_mark {
            &mark
        } else {
            &host_published
        };
        let host_parents = [&host_published, root_parent];
        let roster_parent = if host_saw_the_mark { &mark } else { &genesis };
        let host_revisions = [
            signed(
                id,
                &host_parents,
                &host_anchor,
                2,
                profile(&request, YOURS, u64::MAX),
            ),
            signed(
                id,
                &host_parents,
                &host_anchor,
                3,
                profile(&request, MachineRole::Removed, 1),
            ),
            signed(
                id,
                &[roster_parent],
                &cloud,
                1,
                profile(&request, MachineRole::Removed, 1),
            ),
            signed(
                id,
                &[roster_parent],
                &cloud,
                2,
                profile(&request, MachineRole::HostedNode, 1),
            ),
        ];
        let mut entries = vec![
            genesis.clone(),
            owner_published.clone(),
            host_published.clone(),
            mark.clone(),
        ];
        entries.extend(host_revisions.iter().cloned());
        let fold = hosted_fold(&entries);
        for revision in &host_revisions {
            assert!(
                fold.valid_entries
                    .contains(&authority_entry_hash(revision).unwrap()),
                "{host_saw_the_mark}"
            );
        }
        assert_eq!(
            fold.root_anchors(),
            &BTreeMap::from([
                (owner_root.anchor_key, BTreeSet::from([owner_root.id])),
                (host_root.anchor_key, BTreeSet::from([host_root.id])),
            ])
        );
        let folded = fold.machine(request.machine).unwrap();
        let trusted = folded.trusted(Some(&pin(&owner_root))).unwrap();
        assert_eq!(
            trusted.chain,
            MachineAdmitter::Anchor(owner_root.anchor_key)
        );
        assert_eq!(trusted.profile.machine_key, request.machine_key);
        assert!(!folded.is_mine(None), "{host_saw_the_mark}");
        assert!(!folded.is_mine(Some(&pin(&host_root))));
        assert!(!folded.admits(&MachineAdmitter::Roster));

        let heads: Vec<&AuthorityLogEntry> = host_revisions.iter().chain([&mark]).collect();
        let later = signed(id, &heads, &owner_anchor, 3, profile(&request, YOURS, 2));
        entries.push(later.clone());
        let fold = hosted_fold(&entries);
        let folded = fold.machine(request.machine).unwrap();
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&later).unwrap())
        );
        assert_eq!(folded.anchored[&owner_root.anchor_key].profile.revision, 2);
        assert!(folded.is_mine(Some(&pin(&owner_root))));
    }
}

/// A foreign anchor marks the owner's machine id with keys of its own and a
/// valid proof for them. That chain admits the id under its own anchor, and
/// it never lends the machine its keys: on an install pinned to the owner's
/// root the machine stands, and proves itself, only on the owner's keys. A
/// second machine the owner's anchor marks with the first one's key poisons
/// the first one's trusted chain (Sol R1b-F3, Wonder R1n-F1).
#[test]
fn a_foreign_chain_never_lends_the_owners_machine_its_keys() {
    let cloud = ed_key(133);
    let genesis = hosted_genesis(&cloud);
    let id = genesis_vault_id(&genesis).unwrap();
    let (owner_root, owner_anchor, owner_published) = publish(id, &genesis);
    let (host_root, host_anchor, host_published) = publish(id, &genesis);
    let machine = EntityId::now();
    let owners = request_for(id, machine, &ed_key(134));
    let clone = request_for(id, machine, &ed_key(135));
    let mark = signed(
        id,
        &[&owner_published],
        &owner_anchor,
        2,
        profile(&owners, YOURS, 1),
    );
    let cloned = signed(
        id,
        &[&host_published],
        &host_anchor,
        2,
        profile(&clone, YOURS, 1),
    );
    let entries = vec![
        genesis.clone(),
        owner_published.clone(),
        host_published,
        mark.clone(),
        cloned,
    ];
    let mut fold = hosted_fold(&entries);
    let folded = fold.machine(machine).unwrap();
    assert!(folded.admits(&MachineAdmitter::Anchor(host_root.anchor_key)));
    assert_eq!(
        folded
            .trusted(Some(&pin(&owner_root)))
            .unwrap()
            .profile
            .machine_key,
        owners.machine_key
    );
    fold.pinned_root = Some(pin(&owner_root));
    assert_eq!(fold.machine_proof_key(machine), Some(owners.machine_key));
    fold.pinned_root = None;
    assert_eq!(fold.machine_proof_key(machine), None);

    let other = EntityId::now();
    let shared = request_for(id, other, &ed_key(134));
    let poison = signed(id, &[&mark], &owner_anchor, 3, profile(&shared, YOURS, 1));
    let fold = hosted_fold(&[entries, vec![poison]].concat());
    let folded = fold.machine(machine).unwrap();
    assert!(folded.trusted(Some(&pin(&owner_root))).is_none());
    assert!(folded.trusted(Some(&pin(&host_root))).is_some());
}

/// A root record is its id: the id binds the entry's vault and both keys, and
/// the anchor alone signs it. A record that states another vault's id, copies
/// the owner's recovery key under another anchor, is signed by any other key
/// or carries a cosign is refused by the shared validator every write door
/// runs (contract §4, R1-F1).
#[test]
fn a_root_record_binds_its_vault_and_both_keys() {
    let genesis = hosted_genesis(&ed_key(136));
    let id = genesis_vault_id(&genesis).unwrap();
    let (root, anchor, published) = publish(id, &genesis);
    assert!(published.validate_shape().is_ok());
    let refused = |record: OwnerRootRecord, signer: &SigningKey| {
        signed(id, &[&genesis], signer, 1, AuthorityOp::OwnerRoot(record))
            .validate_shape()
            .is_err()
    };
    let other_seed = RecoveryRootSeed::generate().unwrap();
    let elsewhere = OwnerRootRecord {
        root: crate::world_keys::RecoveryRootId::of(&[9; 32], &root.recovery_key, &root.anchor_key),
        ..root_record(&root)
    };
    assert!(refused(elsewhere, &anchor));
    let substitute = other_seed.anchor();
    let copied = OwnerRootRecord {
        anchor_key: substitute.verifying_key().to_bytes(),
        ..root_record(&root)
    };
    assert!(refused(copied, &substitute));
    assert!(refused(root_record(&root), &ed_key(137)));
    let mut cosigned = published.clone();
    cosigned.cosigns.push(AuthoritySignature {
        suite: AuthoritySignatureSuite::Ed25519,
        public_key: authority_key_from_ed(&ed_key(138)),
        signature: vec![0; 64],
    });
    assert!(cosigned.validate_shape().is_err());
    assert!(root.matches(&root_record(&root)));
}
