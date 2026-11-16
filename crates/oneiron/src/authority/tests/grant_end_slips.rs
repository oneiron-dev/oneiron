//! A general grant act's end withdraws the slips minted under its Grant only where the merged
//! line takes it as its end (pass 28 R2a; review #8846 P1-1). An end of another family than
//! a giving on a branch the fold cannot order ends nothing, and withdraws no slip either.
use super::machine_identity::{Host, host};
use super::support::{authority_key_from_ed, sign_ed, unsigned_entry};
use super::world_privacy::other_machine;
use super::*;

/// A person's general grant act on the Grant row `grant` of `family`, carried by `machine`.
fn grant_act(
    person: EntityId,
    machine: EntityId,
    grant: EntityId,
    family: GrantFamily,
    change: GrantActChange,
) -> AuthorityOp {
    AuthorityOp::GrantAct(GrantActRecord {
        decider: GrantDecider::Person(OwnerAct::by_owner(
            person,
            change.act_kind(),
            grant,
            ActSurface::ThisInstall,
            GRANT_ACT_SEEN,
        )),
        machine,
        subject: grant,
        family,
        change,
    })
}

/// `op`, signed by `machine`'s install key `key` on `parents`, and stored at the host's door.
fn store_signed(
    host: &Host,
    key: &SigningKey,
    parents: &[AuthorityEntryHash],
    op: AuthorityOp,
) -> AuthorityEntryHash {
    let fold = host.vault.authority_fold().unwrap();
    let signer = authority_key_from_ed(key);
    let seq = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
    let entry = sign_ed(
        unsigned_entry(Some(host.vault_id), seq, parents.to_vec(), op, signer, 2),
        key,
    );
    let put = || {
        host.vault
            .put_authority_log_entry(&entry, TimeRange { start: 3, end: 3 }, 3)
    };
    match put() {
        // No door stores a row no admitter signed (H72); the fold's reading of it is the
        // subject here.
        Err(err) if err.kind() == crate::error::ErrorKind::AuthorityLogSignerPending => {
            crate::authority::with_authority_doors_open_for_test(put).unwrap();
        }
        stored => stored.unwrap(),
    }
    authority_entry_hash(&entry).unwrap()
}

/// A slip the host mints under the Grant `grant`, on its heads now; its id.
fn slip_under(host: &Host, grant: EntityId, seed: u8) -> [u8; 32] {
    let root = host.vault.ensure_host_root_slip(&host.issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [seed; 32];
    claims.parent_id = None;
    claims.grant_ref = Some(grant.to_hex());
    host.vault
        .mint_capability_slip(&host.issuer, claims)
        .unwrap();
    [seed; 32]
}

/// Review #8846 P1-1: from one parent with no line for either Grant, one branch gives each a
/// Delegate giving and mints a slip under it; a branch the fold cannot order with it ends one
/// Grant in another family (a person's SharedMember end) and the other in its own family. The
/// merged line of the first holds two families and stands ended by neither, so its slip stays
/// live; the second reads ended, and its slip is withdrawn.
#[test]
fn an_end_of_another_family_on_an_unordered_branch_withdraws_no_slip() {
    let host = host();
    let person = host.owner.actor();
    let (laptop, laptop_key) =
        other_machine(&host, 95, MachineRole::Owned(MachineOwnership::Yours));
    let (phone, phone_key) = other_machine(&host, 96, MachineRole::Owned(MachineOwnership::Yours));
    let (crossed, own) = (EntityId::now(), EntityId::now());
    let parents: Vec<AuthorityEntryHash> = host
        .vault
        .authority_fold()
        .unwrap()
        .append_heads
        .iter()
        .copied()
        .collect();
    for grant in [crossed, own] {
        let fold = host.vault.authority_fold().unwrap();
        let heads: Vec<AuthorityEntryHash> = fold.append_heads.iter().copied().collect();
        store_signed(
            &host,
            &laptop_key,
            &heads,
            grant_act(
                person,
                laptop,
                grant,
                GrantFamily::Delegate,
                GrantActChange::Give { terms: [7; 32] },
            ),
        );
    }
    let crossed_slip = slip_under(&host, crossed, 201);
    let own_slip = slip_under(&host, own, 202);
    for (grant, family) in [
        (crossed, GrantFamily::SharedMember),
        (own, GrantFamily::Delegate),
    ] {
        store_signed(
            &host,
            &phone_key,
            &parents,
            grant_act(person, phone, grant, family, GrantActChange::End),
        );
    }

    let fold = host.vault.authority_fold().unwrap();
    assert!(
        fold.grant_line(crossed).is_some_and(|line| !line.ended),
        "an end of another family ended the line"
    );
    assert!(
        !fold.slips.revoked.contains(&crossed_slip),
        "an end of another family withdrew the slip minted under the Grant"
    );
    assert!(fold.grant_line(own).is_some_and(|line| line.ended));
    assert!(
        fold.slips.revoked.contains(&own_slip),
        "an end of the line's own family withdrew no slip"
    );
}
