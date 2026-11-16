//! A Grant's end still lands past a sequence floor (pass 28; Astra r1-r2d F1). A replica that
//! stored a later row of the end's signer first keeps the end as restriction only, so every
//! arrival order reads the Grant ended, as a world narrowing does (Astra #1430).
use super::machine_identity::{Host, host};
use super::support::{authority_key_from_ed, sign_ed, unsigned_entry};
use super::world_privacy::other_machine;
use super::*;
use crate::{Vault, VaultConfig};

/// A replica of the host's history so far that then stores `rows` in this order, each in a
/// write of its own, as sync delivers them.
fn replica_storing(host: &Host, rows: &[&AuthorityLogEntry]) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    replica
        .import_signed_authority_history(&host.vault.export_signed_authority_history().unwrap())
        .unwrap();
    for row in rows {
        let put = || replica.put_authority_log_entry(row, TimeRange { start: 3, end: 3 }, 3);
        match put() {
            // No door stores a row no admitter signed (H72); the fold's reading of it is the
            // subject here.
            Err(err) if err.kind() == crate::error::ErrorKind::AuthorityLogSignerPending => {
                crate::authority::with_authority_doors_open_for_test(put).unwrap();
            }
            stored => {
                stored.unwrap();
            }
        }
    }
    (dir, replica)
}

/// `op`, signed by the install key `key` at `seq` on `parents`.
fn signed_by(
    host: &Host,
    key: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(host.vault_id),
            seq,
            parents,
            op,
            authority_key_from_ed(key),
            2,
        ),
        key,
    )
}

/// A rule's end of the Grant row `grant` of `family`, carried by `machine`.
fn rule_end(machine: EntityId, grant: EntityId, family: GrantFamily) -> AuthorityOp {
    AuthorityOp::GrantAct(GrantActRecord {
        decider: GrantDecider::Rule,
        machine,
        subject: grant,
        family,
        change: GrantActChange::End,
    })
}

/// The owner's revoke of his agent Grant `grant`, carried by `machine`.
fn owner_revoke(host: &Host, machine: EntityId, grant: EntityId) -> AuthorityOp {
    AuthorityOp::AgentGrantAct(AgentGrantActRecord {
        act: OwnerAct::by_owner(
            host.owner.actor(),
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

/// Astra r1-r2d F1: a machine signs the end of a Grant, and is then removed on a branch that
/// does not hold the end. Its retained key signs a later act at a high sequence on the removal.
/// A replica that stores the removal and that act before the end still ends the Grant: in both
/// orders its line reads ended. Both the general grant act's end and the owner's revoke of his
/// agent Grant.
#[test]
fn an_end_that_arrives_after_a_later_row_of_its_signer_still_ends_the_grant() {
    let host = host();
    let (laptop, laptop_key) =
        other_machine(&host, 91, MachineRole::Owned(MachineOwnership::Yours));
    for (label, family) in [
        ("general grant act end", GrantFamily::SharedMember),
        ("owner agent revoke", GrantFamily::OwnerAgent),
    ] {
        let grant = EntityId::now();
        let fold = host.vault.authority_fold().unwrap();
        let signer = authority_key_from_ed(&laptop_key);
        let seq = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
        let heads: Vec<AuthorityEntryHash> = fold.append_heads.iter().copied().collect();
        let end_op = match family {
            GrantFamily::OwnerAgent => owner_revoke(&host, laptop, grant),
            _ => rule_end(laptop, grant, family),
        };
        let end = signed_by(&host, &laptop_key, seq, heads.clone(), end_op);
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
            &host,
            &laptop_key,
            100,
            vec![authority_entry_hash(&removal).unwrap()],
            rule_end(laptop, EntityId::now(), GrantFamily::SharedMember),
        );
        for (order, rows) in [
            ("end first", [&end, &removal, &later]),
            ("later row first", [&removal, &later, &end]),
        ] {
            let (_dir, replica) = replica_storing(&host, &rows);
            let fold = replica.authority_fold().unwrap();
            assert!(
                fold.valid_entries
                    .contains(&authority_entry_hash(&end).unwrap()),
                "{label}, {order}: the end is refused"
            );
            assert!(
                fold.grant_line(grant).is_some_and(|line| line.ended),
                "{label}, {order}: the Grant's line is not ended"
            );
        }
    }
}
