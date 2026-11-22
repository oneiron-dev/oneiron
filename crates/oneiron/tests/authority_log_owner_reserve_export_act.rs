//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, part 2f: the owner's own
//! whole-vault export carries the owner key's proof. Past its owner reserve,
//! install B lands only the owner's work (`authority/log_budget.rs`), and the
//! signed `ExportAct` install A writes in the export's audit write reaches B
//! signed by A's install key. Since #9892 the fold takes one owner key's
//! proof beside that signature; here the export door's proof of the owner,
//! revalidated in the audit write as his own write, makes the act, and the
//! install join it names when A's frontier is wider than one entry names,
//! carry it (`Vault::owner_act_proof_signer`).
//!
//! Each test takes A's history to a second install B, floods B until its
//! door holds a row at the reserve (`owner_reserve/two_installs.rs`), then
//! the owner exports the whole vault on A
//! (`Vault::export_with_authenticated_owner_listing`), and B imports what A
//! wrote.
//!
//! Red at the base (#9946 head 97e767f0, an export act is carried
//! unproven): A's export act, and the join before it, carry no proof, so the
//! first and third tests fail. The control, the export from an A that holds
//! no owner key, waits at B on both.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_export_act`.

use oneiron::authority::{ActSurface, AuthorityEntryHash, AuthorityLogEntry, AuthorityOp};
use oneiron::memory::ExportOptions;
use oneiron::settings::ReadDestination;
use oneiron::{EntityId, ErrorKind};
use oneiron_authority::authority::{FrontierJoinFamily, MAX_PARENTS};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    AT, Rooted, Second, admit_flooder, flood_row, heads_of_a, hold_owner_key, rooted,
    second_install_at_its_reserve, second_install_at_its_reserve_from, the_row_a_wrote,
    written_since,
};

/// How many concurrent heads the flooder signs on A: one more than one
/// entry names, so the export act on A joins them first.
const WIDE_HEADS: u64 = MAX_PARENTS as u64 + 1;

/// The owner exports the whole vault on A, by the proof the request
/// authenticated, on this device.
fn owner_exports_on_a(rooted: &Rooted) {
    let (export, _) = rooted
        .vault
        .export_with_authenticated_owner_listing(
            &ExportOptions::default(),
            &rooted.proof,
            ActSurface::ThisInstall,
            ReadDestination::on_device(),
        )
        .expect("the owner exports the whole vault on A");
    assert!(
        !export.archive.is_empty(),
        "the owner's export has its archive"
    );
}

fn is_export_act(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::ExportAct(_))
}

/// B imports `rows`, what A wrote since B took its history, and counts the
/// act `hash`; A signed `entry` with one owner key's proof beside its
/// install key.
fn b_lands_the_proven_act(
    second: &Second,
    rows: &[Vec<u8>],
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) {
    assert_eq!(
        entry.cosigns.len(),
        1,
        "A signed the export act with one owner key's proof beside its install key"
    );
    assert_ne!(
        entry.cosigns[0].public_key, entry.signer.public_key,
        "the proof is not A's install key"
    );
    second
        .vault
        .import_signed_authority_history(rows, &std::collections::BTreeMap::new())
        .expect("B lands the export act A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the export act"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
}

/// The owner exports the whole vault on A, where A holds an owner key: the
/// export act carries the proof, and B, past its owner reserve, lands it.
#[test]
fn the_owners_export_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    owner_exports_on_a(&rooted);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_export_act);
    b_lands_the_proven_act(&second, &rows, &entry, hash);
}

/// The same export from an A that holds no owner key: A carries the act
/// unproven, and it waits at B's door (`AuthorityLogFull`), as before.
#[test]
fn the_owners_export_another_install_carries_unproven_waits_past_this_installs_reserve() {
    let rooted = rooted();
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    owner_exports_on_a(&rooted);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_export_act);
    assert!(
        entry.cosigns.is_empty(),
        "A holds no owner key, so it carries the export act unproven"
    );
    let import = second
        .vault
        .import_signed_authority_history(&rows, &std::collections::BTreeMap::new());
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven export act at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(!fold.valid_entries.contains(&hash), "B does not count it");
}

/// The flooder signs one more concurrent head on A than one entry names,
/// each its own world edit on its admission, and B takes them, below its
/// reserve. The owner then exports on A, where A holds an owner key: A joins
/// the wide frontier first, and the join carries the export act's proof, so
/// B, past its reserve, lands the join and the act on it.
#[test]
fn the_owners_export_past_a_wide_frontier_lands_with_its_join_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let mut last = flooder.admission;
    for seq in 1..=WIDE_HEADS {
        let row = flood_row(&rooted, &flooder, EntityId::now(), seq, flooder.admission);
        rooted
            .vault
            .put_authority_log_entry(&row, AT, 1)
            .expect("FIXTURE: A stores the flooder's concurrent world edit");
        last = oneiron::authority::authority_entry_hash(&row).expect("hash");
    }
    let heads = heads_of_a(&rooted).len();
    assert!(
        heads > MAX_PARENTS,
        "FIXTURE: A's frontier is wider than one entry names: {heads} heads"
    );
    let second = second_install_at_its_reserve_from(&rooted, &flooder, (last, WIDE_HEADS + 1));
    owner_exports_on_a(&rooted);
    let written = written_since(&rooted, &second);
    let joins: Vec<&AuthorityLogEntry> = written
        .iter()
        .map(|(_, entry)| entry)
        .filter(|entry| {
            matches!(&entry.op, AuthorityOp::FrontierJoin(join)
                if matches!(join.family, FrontierJoinFamily::Install(_)))
        })
        .collect();
    let [join] = joins.as_slice() else {
        panic!("A joined its wide frontier once before the export act: {joins:?}");
    };
    assert!(
        join.parent_hashes.len() > MAX_PARENTS && join.cosigns.len() == 1,
        "A's join names every head and carries the owner key's proof: {} parents, {} cosigns",
        join.parent_hashes.len(),
        join.cosigns.len()
    );
    let join_hash = oneiron::authority::authority_entry_hash(join).expect("hash");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_export_act);
    assert_eq!(
        entry.parent_hashes,
        vec![join_hash],
        "the export act names the join alone"
    );
    b_lands_the_proven_act(&second, &rows, &entry, hash);
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&join_hash),
        "B's fold counts the join"
    );
}
