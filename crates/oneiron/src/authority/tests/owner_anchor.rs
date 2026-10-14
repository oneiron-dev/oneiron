//! World privacy P6b acceptance in the authority fold: an owner root's anchor
//! marks machines in a chain of its own, the pin decides which anchor counts,
//! and nothing a host signs under its own root or its roster takes the
//! owner's mark away (contract §4, checks 7 and 7d).
use super::history_transfer::re_root_entry;
use super::machine_identity::request_for;
use super::support::{
    EnrollSpec, RosterChain, authority_key_from_ed, cosign_ed, device, ed_key, enroll_device_entry,
    genesis_entry, sign_ed, unsigned_entry,
};
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
        let host_parents = if host_saw_the_mark {
            vec![&host_published, &mark]
        } else {
            vec![&host_published]
        };
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

/// Seen at 100 by this install, and folded at `now` under `posture`.
fn fold_seen_at(
    entries: &[AuthorityLogEntry],
    now: u64,
    posture: crate::HostingPrivacyPosture,
) -> AuthorityFold {
    let first_seen: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (authority_entry_hash(entry).unwrap(), 100))
        .collect();
    fold_authority_log_for_posture(entries, &first_seen, now, &BTreeMap::new(), posture)
}

/// The host enrols a second key of its own, agent-only as the vault door
/// still lands, on `parent`.
fn agent(
    id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    cloud: &SigningKey,
    seed: u8,
) -> AuthorityLogEntry {
    enroll_device_entry(
        id,
        parent,
        cloud,
        EnrollSpec {
            seed,
            roles: ROLE_AGENT,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    )
}

/// The host's roster enrols the anchor's public key as an agent, with its
/// second key's cosign, on `parent`.
fn enrol_anchor(
    id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    (cloud, second): (&SigningKey, &SigningKey),
    seq: u64,
    root: &RecoveryRoot,
) -> AuthorityLogEntry {
    let op = AuthorityOp::EnrollDevice {
        device: device(
            AuthorityKey::Ed25519(root.anchor_key),
            ROLE_AGENT,
            AuthorityTier::Software,
        ),
    };
    cosign_ed(signed(id, &[parent], cloud, seq, op), cloud, second)
}

/// Anyone may enrol a public key, so the host enrols the owner's anchor key
/// in its roster as an agent, then revokes it. The anchor still marks and
/// removes machines in its own chain, and the revocation never makes its mark
/// stale, past the stale-roster window too (Sol code-R1 S1-F3). Fails before:
/// a roster that named the anchor's key took its marks off the anchor's chain.
#[test]
fn a_roster_that_names_the_anchor_key_never_takes_its_chain() {
    let (cloud, second) = (ed_key(140), ed_key(145));
    let genesis = hosted_genesis(&cloud);
    let id = genesis_vault_id(&genesis).unwrap();
    let (root, anchor, published) = publish(id, &genesis);
    let host_second = agent(id, &published, &cloud, 145);
    let enrolled = enrol_anchor(id, &host_second, (&cloud, &second), 2, &root);
    let request = request_for(id, EntityId::now(), &ed_key(141));
    let mark = signed(id, &[&enrolled], &anchor, 2, profile(&request, YOURS, 1));
    let revoked = cosign_ed(
        signed(
            id,
            &[&mark],
            &cloud,
            3,
            AuthorityOp::RevokeDevice {
                revoked_key: AuthorityKey::Ed25519(root.anchor_key),
            },
        ),
        &cloud,
        &second,
    );
    let revocation = authority_entry_hash(&revoked).unwrap();
    let mut entries = vec![genesis, published, host_second, enrolled, mark, revoked];
    let hosted = crate::HostingPrivacyPosture::Hosted;
    let late = 100 + DEFAULT_STALE_ROSTER_WINDOW_SECS + 1;
    for now in [100, late] {
        let fold = fold_seen_at(&entries, now, hosted);
        assert!(fold.valid_entries.contains(&revocation), "{now}");
        let trusted = fold
            .machine(request.machine)
            .and_then(|folded| folded.trusted(Some(&pin(&root))));
        assert_eq!(
            trusted.map(|trusted| trusted.profile.machine_key),
            Some(request.machine_key),
            "{now}"
        );
    }
    let last = entries.last().unwrap().clone();
    entries.push(signed(
        id,
        &[&last],
        &anchor,
        3,
        profile(&request, MachineRole::Removed, 2),
    ));
    let fold = fold_seen_at(&entries, late, hosted);
    let folded = fold.machine(request.machine).unwrap();
    assert!(folded.anchored[&root.anchor_key].removed);
    assert!(!folded.is_mine(Some(&pin(&root))));
}

/// The owner's roster key marks M "yours", then hands the vault to another
/// key, so the mark goes stale once the window passes. A foreign anchor's
/// verbatim copy of that mark renews nothing: an unpinned install, which
/// trusts the roster alone, never counts M mine again (Sol code-R1 S1-F4).
/// Fails before: any valid entry with the same profile renewed the roster's
/// revision.
#[test]
fn a_foreign_anchors_copy_never_renews_a_stale_roster_mark() {
    let owner = ed_key(142);
    let next = ed_key(143);
    let genesis = genesis_entry(142, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let request = request_for(id, EntityId::now(), &ed_key(144));
    let op = profile(&request, YOURS, 1);
    let mark = signed(id, &[&genesis], &owner, 1, op.clone());
    let handoff = super::history_transfer::re_root_entry(id, &mark, &owner, 2, &next);
    let (_, anchor, published) = publish(id, &genesis);
    let copy = signed(id, &[&published], &anchor, 2, op);
    let entries = [genesis, mark, handoff, published, copy];
    let self_host = crate::HostingPrivacyPosture::SelfHostLocal;
    assert!(
        fold_seen_at(&entries, 100, self_host)
            .machine(request.machine)
            .is_some_and(|folded| folded.is_mine(None))
    );
    let late = fold_seen_at(
        &entries,
        100 + DEFAULT_STALE_ROSTER_WINDOW_SECS + 1,
        self_host,
    );
    let folded = late.machine(request.machine).unwrap();
    assert!(folded.roster_chain().stale);
    assert!(!folded.is_mine(None));
}

/// The host enrols the owner's anchor key on a branch without the owner's
/// root, then hands its roster to a new key there, which fences every key of
/// that roster, the anchor's too. The owner's root, its mark and a mark made
/// after the handoff all still stand, and no door refuses a new anchor row
/// for the fence (Sol code-R1 S1-F7). Fails before: the fence pruned the
/// owner's root and marks as rows of a retired signer.
#[test]
fn a_host_handoff_never_retires_the_owners_anchor() {
    let (cloud, second, next) = (ed_key(146), ed_key(147), ed_key(148));
    let genesis = hosted_genesis(&cloud);
    let id = genesis_vault_id(&genesis).unwrap();
    let (root, anchor, published) = publish(id, &genesis);
    let request = request_for(id, EntityId::now(), &ed_key(149));
    let mark = signed(id, &[&published], &anchor, 2, profile(&request, YOURS, 1));
    let host_second = agent(id, &genesis, &cloud, 147);
    let enrolled = enrol_anchor(id, &host_second, (&cloud, &second), 2, &root);
    let handoff = cosign_ed(
        re_root_entry(id, &enrolled, &cloud, 3, &next),
        &cloud,
        &second,
    );
    let after = signed(
        id,
        &[&mark, &handoff],
        &anchor,
        3,
        profile(&request, YOURS, 2),
    );
    let entries = vec![
        genesis,
        published.clone(),
        mark.clone(),
        host_second,
        enrolled,
        handoff.clone(),
        after.clone(),
    ];
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let fold = hosted_fold(&entries);
    assert!(fold.valid_entries.contains(&hash(&handoff)));
    assert!(
        fold.retired_keys
            .contains(&AuthorityKey::Ed25519(root.anchor_key))
    );
    for entry in [&published, &mark, &after] {
        assert!(fold.valid_entries.contains(&hash(entry)));
    }
    let trusted = fold
        .machine(request.machine)
        .and_then(|folded| folded.trusted(Some(&pin(&root))))
        .unwrap();
    assert_eq!(trusted.profile.revision, 2);

    let removal = signed(
        id,
        &[&after],
        &anchor,
        4,
        profile(&request, MachineRole::Removed, 3),
    );
    let by_hash: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (hash(entry), entry.clone()))
        .collect();
    let mut row = |at: &AuthorityEntryHash| Ok::<_, crate::error::Error>(by_hash.get(at).cloned());
    assert!(
        !fold
            .stands_on_retired_key(&hash(&removal), &removal, &mut row)
            .unwrap()
    );
}

/// On a hosted fold the owner's root key R marks machine M, then removes it.
/// Key A, which R enrolled as an ordinary key, marks M again after that, and
/// on a sibling branch R enrols A once more for the cloud; a handoff joins
/// the two, so custody reaches A on the merged history. A's mark leaves the
/// trusted roster chain, but R's removal stays in it: with the owner's anchor
/// marking M too, M is still not mine under the pin (Sol code-R1 S1-F5).
/// Fails before: custody reaching the head's signer dropped the whole trusted
/// chain, R's removal with it.
#[test]
fn custody_reaching_a_later_signer_keeps_an_accepted_removal() {
    let (root_key, later, next) = (ed_key(150), ed_key(151), ed_key(153));
    let genesis = genesis_entry(150, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let (root, anchor, published) = publish(id, &genesis);
    let enrol = |seq, roles, tier| {
        signed(
            id,
            &[&genesis],
            &root_key,
            seq,
            AuthorityOp::EnrollDevice {
                device: device(authority_key_from_ed(&later), roles, tier),
            },
        )
    };
    let plain = enrol(1, ROLE_OWNER | ROLE_ADMIN, AuthorityTier::Software);
    let request = request_for(id, EntityId::now(), &ed_key(152));
    let marked = signed(id, &[&plain], &root_key, 2, profile(&request, YOURS, 1));
    let removed = signed(
        id,
        &[&marked],
        &root_key,
        3,
        profile(&request, MachineRole::Removed, 2),
    );
    let remarked = signed(id, &[&removed], &later, 1, profile(&request, YOURS, 3));
    let custody = enrol(
        4,
        ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
        AuthorityTier::CloudCustodial,
    );
    // Client enrolments land only in a handoff's own ancestry.
    let handoff = cosign_ed(
        signed(
            id,
            &[&remarked, &custody],
            &root_key,
            5,
            AuthorityOp::ReRoot {
                new_device: device(
                    authority_key_from_ed(&next),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
        ),
        &root_key,
        &later,
    );
    let anchor_mark = signed(id, &[&published], &anchor, 2, profile(&request, YOURS, 1));
    let entries = [
        genesis,
        published,
        plain,
        marked,
        removed,
        remarked.clone(),
        custody,
        handoff.clone(),
        anchor_mark,
    ];
    let fold = hosted_fold(&entries);
    for entry in [&remarked, &handoff] {
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(entry).unwrap())
        );
    }
    let folded = fold.machine(request.machine).unwrap();
    assert_eq!(folded.roster_chain().signer_class, SignerClass::Custodial);
    let trusted = folded.roster_trusted.as_ref().unwrap();
    assert!(trusted.removed);
    assert_eq!(trusted.signer, authority_key_from_ed(&root_key));
    assert!(folded.admits(&MachineAdmitter::Anchor(root.anchor_key)));
    assert!(!folded.is_mine(Some(&pin(&root))));
    assert!(!folded.is_mine(None));
}
