//! A Grant's end on a branch the projection drops travels only as that branch counted it (pass
//! 28; Astra r1-r2d F2, F4). A confirmation that loses a collision drops every entry after it;
//! the restriction proof keeps each counted end on that branch, the owner's revoke of his agent
//! Grant among them, and never turns a valid act its fold carried without effect into an end.
use super::machine_identity::request_for;
use super::support::{
    EnrollSpec, authority_key_from_ed, cosign_ed, ed_key, enroll_device_entry, genesis_entry,
    sign_ed, unsigned_entry,
};
use super::*;

/// The owner's federation confirmation `id` at `seq` on `parent`, cosigned by the consent
/// device; every confirmation here shares one nonce, so two of them collide.
fn confirm_on(
    parent: AuthorityEntryHash,
    vault: AuthorityVaultId,
    (owner, consent): (&SigningKey, &SigningKey),
    seq: u64,
    id: u8,
) -> AuthorityLogEntry {
    cosign_ed(
        unsigned_entry(
            Some(vault),
            seq,
            vec![parent],
            AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: AuthorityConfirmKind::Accept,
                confirm_id: [id; 32],
                peer_vault_id: [77; 32],
                epoch: 1,
                nonce: [93; 16],
            }),
            authority_key_from_ed(owner),
            4,
        ),
        owner,
        consent,
    )
}

/// The owner's revision `revision` of `machine` in `role`, at `seq` on `parent`, signed by
/// his device alone, as a roster revision is.
fn machine_revision(
    vault: AuthorityVaultId,
    owner: &SigningKey,
    (seq, parent): (u64, AuthorityEntryHash),
    (machine, owner_person, request): (EntityId, EntityId, &MachineEnrolmentRequest),
    (role, revision): (MachineRole, u64),
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(vault),
            seq,
            vec![parent],
            AuthorityOp::MachineProfile(MachineProfile {
                machine,
                owner: owner_person,
                machine_key: request.machine_key,
                device_class: request.device_class,
                encryption_key: request.encryption_key.clone(),
                role,
                revision,
                machine_proof: request.machine_proof,
                seen_world_edits: BTreeSet::new(),
                carrier: None,
                act: None,
            }),
            authority_key_from_ed(owner),
            3,
        ),
        owner,
    )
}

/// `op`, signed by the install key `key` at `seq` on `parent`.
fn carried(
    vault: AuthorityVaultId,
    key: &SigningKey,
    (seq, parent): (u64, AuthorityEntryHash),
    op: AuthorityOp,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(vault),
            seq,
            vec![parent],
            op,
            authority_key_from_ed(key),
            5,
        ),
        key,
    )
}

/// A confirmation that loses its collision drops a branch holding two acts of one machine:
/// the owner's revoke of his agent Grant `revoked`, which counts there (its carrier is live),
/// and, after the machine's removal, a rule's end of Grant `forged`, which its fold carries
/// without effect (Astra r1-r2d F2). Once the winning sibling arrives, the revoke still ends
/// its line (F4), and the forged end ends nothing.
#[test]
fn a_dropped_branch_keeps_its_counted_ends_and_proves_no_refused_one() {
    let owner = ed_key(110);
    let consent = ed_key(111);
    let keys = (&owner, &consent);
    let genesis = genesis_entry(110, 1);
    let vault = genesis_vault_id(&genesis).unwrap();
    let enroll_consent = enroll_device_entry(
        vault,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 111,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let laptop = EntityId::now();
    let laptop_key = ed_key(112);
    let person = EntityId::now();
    let request = request_for(vault, laptop, &laptop_key);
    let enrol = machine_revision(
        vault,
        &owner,
        (2, authority_entry_hash(&enroll_consent).unwrap()),
        (laptop, person, &request),
        (MachineRole::Owned(MachineOwnership::Yours), 1),
    );
    let enrol_hash = authority_entry_hash(&enrol).unwrap();
    let first = confirm_on(enrol_hash, vault, keys, 3, 155);
    let first_hash = authority_entry_hash(&first).unwrap();
    let sibling = (1..=u8::MAX)
        .map(|id| confirm_on(enrol_hash, vault, keys, 5, id))
        .find(|entry| authority_entry_hash(entry).unwrap() < first_hash)
        .unwrap();

    let revoked = EntityId::now();
    let revoke = carried(
        vault,
        &laptop_key,
        (1, first_hash),
        AuthorityOp::AgentGrantAct(AgentGrantActRecord {
            act: OwnerAct::by_owner(
                person,
                OwnerActKind::GrantRevoke,
                revoked,
                ActSurface::ThisInstall,
                AGENT_GRANT_ACT_SEEN,
            ),
            machine: laptop,
            grant: revoked,
            change: AgentGrantChange::Revoke {
                acknowledged_topology: BTreeSet::new(),
            },
        }),
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();
    let removal = machine_revision(
        vault,
        &owner,
        (4, revoke_hash),
        (laptop, person, &request),
        (MachineRole::Removed, 2),
    );
    let forged = EntityId::now();
    let end = carried(
        vault,
        &laptop_key,
        (2, authority_entry_hash(&removal).unwrap()),
        AuthorityOp::GrantAct(GrantActRecord {
            decider: GrantDecider::Rule,
            machine: laptop,
            subject: forged,
            family: GrantFamily::SharedMember,
            change: GrantActChange::End,
        }),
    );
    let end_hash = authority_entry_hash(&end).unwrap();

    let mut entries = vec![genesis, enroll_consent, enrol, first, revoke, removal, end];
    let seen = |entries: &[AuthorityLogEntry]| -> BTreeMap<AuthorityEntryHash, u64> {
        entries
            .iter()
            .map(|entry| (authority_entry_hash(entry).unwrap(), 1))
            .collect()
    };
    let now = 10_000_000;
    let before = fold_legacy_authority_log_with_seen_times(&entries, &seen(&entries), now);
    assert!(
        before.valid_entries.contains(&revoke_hash) && before.valid_entries.contains(&end_hash),
        "the branch folds before its collision: {:?}",
        before.issues
    );
    assert!(
        before.grant_line(revoked).is_some_and(|line| line.ended),
        "the revoke counts on its branch"
    );
    assert!(
        before.grant_line(forged).is_none(),
        "the removed machine's end is carried without effect"
    );

    entries.push(sibling);
    let after = fold_legacy_authority_log_with_seen_times(&entries, &seen(&entries), now);
    assert!(
        !after.valid_entries.contains(&revoke_hash) && !after.valid_entries.contains(&end_hash),
        "the losing confirmation drops the branch: {:?}",
        after.issues
    );
    assert!(
        after.grant_line(revoked).is_some_and(|line| line.ended),
        "the owner's counted revoke is lost with its branch"
    );
    assert!(
        after.grant_line(forged).is_none_or(|line| !line.ended),
        "a refused end became an end"
    );
}
