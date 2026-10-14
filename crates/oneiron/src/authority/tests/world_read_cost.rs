//! Contract §4's cost bound on a world's read (Sol S2-R2 S2-F4, Astra
//! A2-F3): one evaluation is linear in the world's edits, however many live
//! edits share an ancestry.
use super::super::install_fold::fold_authority_log_with_machine_standing;
use super::super::world_strength::WORLD_MEET_VISITS;
use super::machine_identity::host;
use super::support::sign_ed;
use super::world_privacy::{edit_by, land, other_machine, settings, stored_entries, world_row};
use super::*;

/// A machine this install does not count signs a chain of edits, then many
/// concurrent successors of its last one. None counts at full strength
/// here, so each successor's contribution reaches back through the whole
/// chain. Before, every successor walked the chain again: tips × chain
/// visits per read.
#[test]
fn one_world_read_walks_a_shared_ancestry_once() {
    const CHAIN: usize = 48;
    const TIPS: usize = 48;
    let host = host();
    let world = world_row(&host);
    let (writer, key) = other_machine(&host, 63, MachineRole::Owned(MachineOwnership::Yours));
    for _ in 0..CHAIN {
        let edit = edit_by(
            &host,
            writer,
            &key,
            world,
            settings(ReadLocation::MyMachines),
        );
        land(&host, &[edit]);
    }
    let tips: Vec<_> = (0..TIPS as u64)
        .map(|ts| {
            let mut entry = edit_by(
                &host,
                writer,
                &key,
                world,
                settings(ReadLocation::MyMachines),
            );
            entry.ts = ts;
            sign_ed(entry, &key)
        })
        .collect();
    land(&host, &tips);
    let entries = stored_entries(&host.vault);

    WORLD_MEET_VISITS.with(|visits| visits.set(0));
    let fold = fold_authority_log_with_machine_standing(&entries, &|machine, _| machine != writer);
    let visits = WORLD_MEET_VISITS.with(std::cell::Cell::get);
    assert_eq!(fold.worlds[&world].live.len(), TIPS);
    // Every read of the fold together stays within a small multiple of the
    // world's edits; one shared-ancestry read alone was TIPS × CHAIN.
    assert!(visits < CHAIN * TIPS, "{visits} visits");
}
