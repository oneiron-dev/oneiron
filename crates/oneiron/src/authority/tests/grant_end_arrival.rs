//! A Grant's end lands whatever the order it arrives in (pass 28 R1; review #8845 P1-1,
//! P1-2). A replica that stored a later row of the end's signer first keeps the end as
//! restriction only, as a world narrowing does (Astra #1430), and the retired-standing door
//! stores an end signed above a main-log row a handoff's fence refuses, which the fold judges
//! again with that row crossed, as it judges a world edit (Wonder P2 round 1, W4).
use super::history_transfer::re_root_entry;
use super::machine_identity::{Host, host, request_for};
use super::support::{authority_key_from_ed, ed_key, genesis_entry, sign_ed, unsigned_entry};
use super::world_privacy::other_machine;
use super::*;
use crate::{Vault, VaultConfig};

/// The owner `owner`'s revoke of his agent Grant `grant`, carried by `machine`.
fn owner_revoke(owner: EntityId, machine: EntityId, grant: EntityId) -> AuthorityOp {
    AuthorityOp::AgentGrantAct(AgentGrantActRecord {
        act: OwnerAct::by_owner(
            owner,
            OwnerActKind::GrantRevoke,
            grant,
            ActSurface::ThisInstall,
            AGENT_GRANT_ACT_SEEN,
        ),
        machine,
        grant,
        change: AgentGrantChange::Revoke {
            acknowledged_topology: BTreeSet::new(),
        },
    })
}

/// `op`, signed by the install key `key` at `seq` on `parents` in `vault`.
fn signed_by(
    vault: [u8; 32],
    key: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(Some(vault), seq, parents, op, authority_key_from_ed(key), 2),
        key,
    )
}

/// Whether `vault` stores `row` at its door. A row no admitter signed waits at the door
/// (H72); the fold's reading of it is the subject here, so the door opens for it.
fn stored(vault: &Vault, row: &AuthorityLogEntry) -> crate::error::Result<()> {
    let put = || vault.put_authority_log_entry(row, TimeRange { start: 3, end: 3 }, 3);
    match put() {
        Err(err) if err.kind() == crate::error::ErrorKind::AuthorityLogSignerPending => {
            crate::authority::with_authority_doors_open_for_test(put)
        }
        other => other,
    }
}

/// A replica of the host's history so far.
fn replica_of(host: &Host) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    replica
        .import_signed_authority_history(&host.vault.export_signed_authority_history().unwrap())
        .unwrap();
    (dir, replica)
}

/// Review #8845 P1-1: a machine signs the owner's revoke of an agent Grant, and is then
/// removed on a branch that does not hold the revoke. Its retained key signs a later revoke
/// at a high sequence on the removal. A replica that stores the removal and that later row
/// before the revoke still stores the revoke and reads the Grant's line ended, as one that
/// stores the revoke first does.
#[test]
fn an_owner_revoke_that_arrives_after_a_later_row_of_its_signer_still_ends_the_grant() {
    let host = host();
    let owner = host.owner.actor();
    let (laptop, laptop_key) =
        other_machine(&host, 93, MachineRole::Owned(MachineOwnership::Yours));
    let grant = EntityId::now();
    let fold = host.vault.authority_fold().unwrap();
    let signer = authority_key_from_ed(&laptop_key);
    let seq = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
    let heads: Vec<AuthorityEntryHash> = fold.append_heads.iter().copied().collect();
    let revoke = signed_by(
        host.vault_id,
        &laptop_key,
        seq,
        heads.clone(),
        owner_revoke(owner, laptop, grant),
    );
    let removal = host
        .issuer
        .sign_entry(
            Some(host.vault_id),
            fold.append_sequences[&host.issuer.public_key()] + 1,
            heads,
            AuthorityOp::MachineProfile(MachineProfile {
                role: MachineRole::Removed,
                revision: 2,
                ..fold.machine(laptop).unwrap().head().profile.clone()
            }),
            2,
        )
        .unwrap();
    let later = signed_by(
        host.vault_id,
        &laptop_key,
        100,
        vec![authority_entry_hash(&removal).unwrap()],
        owner_revoke(owner, laptop, EntityId::now()),
    );
    for (order, rows) in [
        ("revoke first", [&revoke, &removal, &later]),
        ("later row first", [&removal, &later, &revoke]),
    ] {
        let (_dir, replica) = replica_of(&host);
        for row in rows {
            stored(&replica, row).unwrap_or_else(|err| panic!("{order}: a row is refused: {err}"));
        }
        let fold = replica.authority_fold().unwrap();
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&revoke).unwrap()),
            "{order}: the revoke is refused"
        );
        assert!(
            fold.grant_line(grant).is_some_and(|line| line.ended),
            "{order}: the Grant's line is not ended"
        );
    }
}

/// Review #8845 P1-2: the laptop signs the owner's revoke of an agent Grant on a head the old
/// root signed outside its own handoff, so the handoff's fence refuses that row. A replica
/// that held the fenced row before it settled the handoff still stores the revoke, which the
/// fold judges again with the fenced row crossed, and reads the Grant's line ended.
#[test]
fn a_revoke_above_a_fenced_row_is_stored_and_ends_the_grant() {
    let old = ed_key(141);
    let next = ed_key(142);
    let genesis = genesis_entry(141, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let hash = |entry: &AuthorityLogEntry| authority_entry_hash(entry).unwrap();
    let (laptop, laptop_key) = (EntityId::now(), ed_key(143));
    let (other, other_key) = (EntityId::now(), ed_key(144));
    let mark = |parent: &AuthorityLogEntry, seq, machine, key| {
        let request = request_for(id, machine, key);
        sign_ed(
            unsigned_entry(
                Some(id),
                seq,
                vec![hash(parent)],
                AuthorityOp::MachineProfile(MachineProfile {
                    machine,
                    owner: EntityId::now(),
                    machine_key: request.machine_key,
                    device_class: request.device_class,
                    encryption_key: request.encryption_key,
                    role: MachineRole::Owned(MachineOwnership::Yours),
                    revision: 1,
                    machine_proof: request.machine_proof,
                    seen_world_edits: BTreeSet::new(),
                    carrier: None,
                    act: None,
                    restored_from: None,
                }),
                authority_key_from_ed(&old),
                2,
            ),
            &old,
        )
    };
    let laptop_mark = mark(&genesis, 1, laptop, &laptop_key);
    let handoff = re_root_entry(id, &laptop_mark, &old, 2, &next);
    let fenced = mark(&laptop_mark, 3, other, &other_key);
    let grant = EntityId::now();
    let revoke = signed_by(
        id,
        &laptop_key,
        1,
        vec![hash(&fenced)],
        owner_revoke(EntityId::now(), laptop, grant),
    );
    let fold = fold_authority_log(&[
        genesis.clone(),
        laptop_mark.clone(),
        handoff.clone(),
        fenced.clone(),
        revoke.clone(),
    ]);
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::RetiredSigner(hash(&fenced)))
    );
    assert!(fold.valid_entries.contains(&hash(&revoke)));
    assert!(fold.grant_line(grant).is_some_and(|line| line.ended));

    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    for entry in [&genesis, &laptop_mark, &fenced, &handoff] {
        stored(&replica, entry).unwrap();
    }
    stored(&replica, &revoke).expect("the door refuses an end above a fenced row");
    let fold = replica.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&revoke)));
    assert!(
        fold.grant_line(grant).is_some_and(|line| line.ended),
        "the Grant's line is not ended on the replica"
    );
}
