//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, part 2b: the vault
//! owner's own world-privacy edit carries the owner key's proof. Past its
//! owner reserve, install B lands only the owner's work
//! (`authority/log_budget.rs` `owner_work`), and an edit install A carries
//! reaches B signed by A's install key. Since #9892 the fold takes one owner
//! key's proof beside that signature on a world-privacy edit; here the
//! settings door signs it when the holder is the vault owner in person
//! (`WorldEditAuthor::owner_authored`), and so does the install join the
//! edit names when A's frontier is wider than one entry names.
//!
//! Each test takes A's history to a second install B, floods B until its
//! door holds a row at the reserve (`owner_reserve/two_installs.rs`), then
//! the owner narrows a world on A, and B imports the edit A wrote (and its
//! join), not the key work A records after it.
//!
//! Red at the base (#9904 head e11a8402, the settings door signs no proof):
//! A's edit and its join carry no cosign, and B's import of them refuses
//! with `AuthorityLogFull`. The control, the same edit from an A that holds
//! no owner key, waits at B on both.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_world_privacy`.

use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityLogEntry, AuthorityOp, EffectiveRead, ReadLocation,
    WorldPrivacy, authority_entry_hash,
};
use oneiron::{EntityId, ErrorKind};
use oneiron_authority::authority::{FrontierJoinFamily, MAX_PARENTS};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    AT, Rooted, Second, admit_flooder, flood_row, heads_of_a, hold_owner_key, rooted,
    second_install_at_its_reserve, second_install_at_its_reserve_from, written_since,
};

/// How many concurrent heads the flooder signs on A: one more than one
/// entry names, so the owner's edit on A joins them first.
const WIDE_HEADS: u64 = MAX_PARENTS as u64 + 1;

/// A world the owner creates on A, read everywhere until an edit narrows it.
fn world_on_a(rooted: &Rooted) -> EntityId {
    rooted
        .vault
        .create_world(
            &rooted.proof,
            "Owner reserve world",
            rooted.vault.now_recorded_at(),
        )
        .expect("FIXTURE: the owner creates a world on A")
}

/// The owner narrows `world` to the owner's machines on A, at the owner's
/// own settings door.
fn owner_narrows_on_a(rooted: &Rooted, world: EntityId) {
    let receipt = rooted
        .vault
        .set_world_privacy_as(
            &rooted.proof,
            ActSurface::ThisInstall,
            world,
            WorldPrivacy {
                read: ReadLocation::MyMachines,
                ..WorldPrivacy::default()
            },
            None,
        )
        .expect("the owner narrows the world on A");
    assert_eq!(
        receipt.next.read,
        EffectiveRead::MyMachines,
        "A reads the world narrowed"
    );
}

/// A's one row since B took its history that edits `world`'s settings: its
/// stored bytes, the entry and its hash.
fn the_edit_a_wrote(
    rooted: &Rooted,
    second: &Second,
    world: EntityId,
) -> (Vec<u8>, AuthorityLogEntry, AuthorityEntryHash) {
    let mut edits = written_since(rooted, second).into_iter().filter(
        |(_, entry)| matches!(&entry.op, AuthorityOp::WorldPrivacy(edit) if edit.world == world),
    );
    let (row, entry) = edits.next().expect("A signed the edit");
    assert!(edits.next().is_none(), "A signed the edit once");
    let hash = authority_entry_hash(&entry).expect("hash");
    (row, entry, hash)
}

/// B imports `rows` and counts the edit `hash` of `world`; A signed `entry`
/// with one owner key's proof beside its install key.
fn b_lands_the_proven_edit(
    second: &Second,
    rows: &[Vec<u8>],
    (entry, hash): (&AuthorityLogEntry, AuthorityEntryHash),
    world: EntityId,
) {
    assert_eq!(
        entry.cosigns.len(),
        1,
        "A signed the edit with one owner key's proof beside its install key"
    );
    assert_ne!(
        entry.cosigns[0].public_key, entry.signer.public_key,
        "the proof is not A's install key"
    );
    second
        .vault
        .import_signed_authority_history(rows)
        .expect("B lands the edit A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the edit"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
    assert_eq!(
        second
            .vault
            .world_privacy(world)
            .expect("B's settings")
            .read,
        EffectiveRead::MyMachines,
        "B reads the world narrowed by A's edit"
    );
}

/// The owner narrows a world on A, where A holds an owner key: the edit
/// carries the proof, and B, past its owner reserve, lands it.
#[test]
fn the_owners_world_edit_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let world = world_on_a(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    owner_narrows_on_a(&rooted, world);
    let (row, entry, hash) = the_edit_a_wrote(&rooted, &second, world);
    b_lands_the_proven_edit(&second, &[row], (&entry, hash), world);
}

/// The same edit from an A that holds no owner key: A carries it unproven,
/// and it waits at B's door (`AuthorityLogFull`), as before.
#[test]
fn the_owners_world_edit_another_install_carries_unproven_waits_past_this_installs_reserve() {
    let rooted = rooted();
    let flooder = admit_flooder(&rooted);
    let world = world_on_a(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    owner_narrows_on_a(&rooted, world);
    let (row, entry, hash) = the_edit_a_wrote(&rooted, &second, world);
    assert!(
        entry.cosigns.is_empty(),
        "A holds no owner key, so it carries the edit unproven"
    );
    let import = second.vault.import_signed_authority_history(&[row]);
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven edit at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(!fold.valid_entries.contains(&hash), "B does not count it");
}

/// The flooder signs one more concurrent head on A than one entry names,
/// and B takes them, below its reserve. The owner then narrows a world on
/// A, where A holds an owner key: A joins the wide frontier first, and the
/// join carries the edit's proof, so B, past its reserve, lands the join and
/// the edit on it.
#[test]
fn the_owners_world_edit_past_a_wide_frontier_lands_with_its_join_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let world = world_on_a(&rooted);
    let mut last = flooder.admission;
    for seq in 1..=WIDE_HEADS {
        let row = flood_row(&rooted, &flooder, EntityId::now(), seq, flooder.admission);
        rooted
            .vault
            .put_authority_log_entry(&row, AT, 1)
            .expect("FIXTURE: A stores the flooder's concurrent world edit");
        last = authority_entry_hash(&row).expect("hash");
    }
    let heads = heads_of_a(&rooted).len();
    assert!(
        heads > MAX_PARENTS,
        "FIXTURE: A's frontier is wider than one entry names: {heads} heads"
    );
    let second = second_install_at_its_reserve_from(&rooted, &flooder, (last, WIDE_HEADS + 1));
    owner_narrows_on_a(&rooted, world);
    let written = written_since(&rooted, &second);
    let joins: Vec<&(Vec<u8>, AuthorityLogEntry)> = written
        .iter()
        .filter(|(_, entry)| {
            matches!(&entry.op, AuthorityOp::FrontierJoin(join)
                if matches!(join.family, FrontierJoinFamily::Install(_)))
        })
        .collect();
    let [(join_row, join)] = joins.as_slice() else {
        panic!("A joined its wide frontier once before the edit: {joins:?}");
    };
    assert!(
        join.parent_hashes.len() > MAX_PARENTS && join.cosigns.len() == 1,
        "A's join names every head and carries the owner key's proof: {} parents, {} cosigns",
        join.parent_hashes.len(),
        join.cosigns.len()
    );
    let join_hash = authority_entry_hash(join).expect("hash");
    let (row, entry, hash) = the_edit_a_wrote(&rooted, &second, world);
    assert_eq!(
        entry.parent_hashes,
        vec![join_hash],
        "the edit names the join alone"
    );
    b_lands_the_proven_edit(&second, &[join_row.clone(), row], (&entry, hash), world);
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&join_hash),
        "B's fold counts the join"
    );
}
