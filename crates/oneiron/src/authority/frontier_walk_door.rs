//! The authority-internal half of the frontier walk doors (Setting stage 7b-1): the walk's parts
//! on a fixed frontier, and seeded frontiers read through the walk and through the two reads it
//! replaced, which this file keeps as they stood on main 28a0ed385015 as the oracle.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron_authority::share_travel::BornWithField;

use super::grant_travel::{GrantFrontier, SignedChoice, travel_meet};
use super::world_privacy::PrivacyMeet;
use super::world_strength::{FrontierEdit, WalkPart, WorldFrontier, frontier_meet, frontier_walk};
use super::{AuthorityEntryHash, ModelOrder, ReadLocation, SealedCopies, WorldPrivacy};
use crate::entity_id::EntityId;

/// The parts of the walk over a fixed frontier, each named by its edit's label or `default`.
/// Edits (label: what it replaced, whether it counts at full strength):
/// a: nothing, no; g: nothing, no; b: a and g, yes; c: a, no; d: b and c, no;
/// e: c, no, and two copies of it disagreed; f: nothing, no. Live: d, e, f.
pub(crate) fn walk_order() -> Vec<String> {
    let edit = |replaced: &str, disputed: bool| FrontierEdit {
        settings: (),
        machine: machine(0),
        key: [7; 32],
        replaced: replaced.bytes().map(|label| [label; 32]).collect(),
        narrow_only: false,
        marks: BTreeMap::new(),
        restriction_only: false,
        disputed,
    };
    let mut frontier = WorldFrontier {
        live: BTreeMap::new(),
        superseded: BTreeMap::new(),
    };
    for (label, replaced, disputed, live) in [
        (b'a', "", false, false),
        (b'g', "", false, false),
        (b'b', "ag", false, false),
        (b'c', "a", false, false),
        (b'd', "bc", false, true),
        (b'e', "c", true, true),
        (b'f', "", false, true),
    ] {
        let into = if live {
            &mut frontier.live
        } else {
            &mut frontier.superseded
        };
        into.insert([label; 32], Arc::new(edit(replaced, disputed)));
    }
    frontier_walk(&frontier, |hash, _| hash[0] == b'b')
        .map(|part| match part {
            WalkPart::Edit(hash, _) => char::from(hash[0]).to_string(),
            WalkPart::Default => "default".to_owned(),
        })
        .collect()
}

/// Reads `cases` seeded frontiers, from `seed`, through [`frontier_meet`] and through the world
/// meet the walk replaced. Answers how many cases agreed, or the first that did not.
pub(crate) fn world_reads_match_before(seed: u64, cases: usize) -> Result<usize, String> {
    let mut rng = Rng::new(seed);
    for case in 0..cases {
        let (frontier, strong) = seeded_frontier(&mut rng, world_privacy);
        let now = frontier_meet(&frontier, |hash, _| strong.contains(hash));
        let before = frontier_meet_before(&frontier, |hash, _| strong.contains(hash));
        if now != before {
            return Err(format!(
                "case {case}: walk {now:?}, before {before:?}, frontier {frontier:?}, strong {strong:?}"
            ));
        }
    }
    Ok(cases)
}

/// Reads `cases` seeded grant frontiers, from `seed`, through [`travel_meet`] and through the
/// grant meet the walk replaced. Answers how many cases agreed, or the first that did not.
pub(crate) fn travel_reads_match_before(seed: u64, cases: usize) -> Result<usize, String> {
    let mut rng = Rng::new(seed);
    for case in 0..cases {
        let (frontier, strong) = seeded_frontier(&mut rng, travel_choice);
        let now = travel_meet(&frontier, |hash, _| strong.contains(hash));
        let before = travel_meet_before(&frontier, |hash, _| strong.contains(hash));
        if now != before {
            return Err(format!(
                "case {case}: walk {now:?}, before {before:?}, frontier {frontier:?}, strong {strong:?}"
            ));
        }
    }
    Ok(cases)
}

/// A seeded frontier of 1 to 24 edits, and the edits that count at full strength. Each edit
/// replaces up to three earlier ones, and now and then one this frontier does not hold; the live
/// edits are those no later edit replaced. About one in ten is disputed and one in three counts
/// at full strength.
fn seeded_frontier<S>(
    rng: &mut Rng,
    mut settings: impl FnMut(&mut Rng) -> S,
) -> (WorldFrontier<S>, BTreeSet<AuthorityEntryHash>) {
    let edits = 1 + rng.below(24) as usize;
    let hashes: Vec<AuthorityEntryHash> = (0..edits)
        .map(|index| {
            let mut hash = [0; 32];
            hash[..8].copy_from_slice(&rng.next().to_be_bytes());
            hash[8..16].copy_from_slice(&(index as u64).to_be_bytes());
            hash
        })
        .collect();
    let mut replaced_later = BTreeSet::new();
    let mut made = Vec::with_capacity(edits);
    for (index, hash) in hashes.iter().enumerate() {
        let mut replaced = BTreeSet::new();
        if index > 0 {
            for _ in 0..rng.below(4) {
                replaced.insert(hashes[rng.below(index as u64) as usize]);
            }
        }
        if rng.below(12) == 0 {
            replaced.insert([0xee; 32]);
        }
        replaced_later.extend(replaced.iter().copied());
        let edit = FrontierEdit {
            settings: settings(&mut *rng),
            machine: machine(rng.below(3) as u8),
            key: [7; 32],
            replaced,
            narrow_only: false,
            marks: BTreeMap::new(),
            restriction_only: false,
            disputed: rng.below(10) == 0,
        };
        made.push((*hash, Arc::new(edit)));
    }
    let mut frontier = WorldFrontier {
        live: BTreeMap::new(),
        superseded: BTreeMap::new(),
    };
    for (hash, edit) in made {
        if replaced_later.contains(&hash) {
            frontier.superseded.insert(hash, edit);
        } else {
            frontier.live.insert(hash, edit);
        }
    }
    let strong = hashes
        .iter()
        .filter(|_| rng.below(3) == 0)
        .copied()
        .collect();
    (frontier, strong)
}

fn world_privacy(rng: &mut Rng) -> WorldPrivacy {
    WorldPrivacy {
        read: match rng.below(5) {
            0 => ReadLocation::Everywhere,
            1 => ReadLocation::MyMachines,
            pick => ReadLocation::OneMachine(machine(pick as u8)),
        },
        sealed: match rng.below(3) {
            0 => SealedCopies::Off,
            1 => SealedCopies::MyMachines,
            _ => SealedCopies::CloudAndMyMachines,
        },
        models: match rng.below(3) {
            0 => ModelOrder::Inherit,
            1 => ModelOrder::Ordered(vec!["first".to_owned()]),
            _ => ModelOrder::Ordered(vec!["second".to_owned(), "first".to_owned()]),
        },
    }
}

fn travel_choice(rng: &mut Rng) -> SignedChoice {
    let fields = [
        BornWithField::Prompt,
        BornWithField::Why,
        BornWithField::Keep,
        BornWithField::IntentPrompt,
    ]
    .into_iter()
    .filter(|_| rng.below(4) != 0)
    .collect();
    SignedChoice::of_fields(fields)
}

fn machine(byte: u8) -> EntityId {
    EntityId::from_bytes([byte.wrapping_add(1); 16])
        .expect("fixture machine ids are not reserved sentinels")
}

/// A xorshift64 sequence: the same cases from the same seed on every host.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// `world_strength::frontier_meet` as it stood before the walk (main 28a0ed385015), without its
/// test-only visit count: the oracle.
fn frontier_meet_before(
    frontier: &WorldFrontier,
    mut strong: impl FnMut(&AuthorityEntryHash, &FrontierEdit) -> bool,
) -> PrivacyMeet {
    let default = || PrivacyMeet::of(&WorldPrivacy::default());
    let Some(first) = frontier.live.values().next() else {
        return default();
    };
    let mut meet = PrivacyMeet::of(&first.settings);
    let mut visited = BTreeSet::new();
    let mut pending = Vec::new();
    for (hash, edit) in &frontier.live {
        meet.meet_with(&PrivacyMeet::of(&edit.settings));
        if visited.insert(*hash) && !strong(hash, edit) {
            pending.push(edit.as_ref());
        }
    }
    while let Some(next) = pending.pop() {
        if next.replaced.is_empty() || next.disputed {
            meet.meet_with(&default());
        }
        for replaced in &next.replaced {
            if !visited.insert(*replaced) {
                continue;
            }
            let Some(prior) = frontier
                .superseded
                .get(replaced)
                .or_else(|| frontier.live.get(replaced))
            else {
                continue;
            };
            meet.meet_with(&PrivacyMeet::of(&prior.settings));
            if !strong(replaced, prior) {
                pending.push(prior.as_ref());
            }
        }
    }
    meet
}

/// `grant_travel::grant_meet` as it stood before the walk (main 28a0ed385015), with `strong` in
/// the place of its install's `counts_here`: the oracle.
fn travel_meet_before(
    frontier: &GrantFrontier,
    mut strong: impl FnMut(&AuthorityEntryHash, &FrontierEdit<SignedChoice>) -> bool,
) -> BTreeSet<BornWithField> {
    let Some(first) = frontier.live.values().next() else {
        return BTreeSet::new();
    };
    let mut meet = first.settings.fields().clone();
    let mut visited = BTreeSet::new();
    let mut pending = Vec::new();
    for (hash, choice) in &frontier.live {
        meet.retain(|field| choice.settings.fields().contains(field));
        if visited.insert(*hash) && !strong(hash, choice) {
            pending.push(choice.as_ref());
        }
    }
    while let Some(next) = pending.pop() {
        if meet.is_empty() {
            break;
        }
        if next.replaced.is_empty() || next.disputed {
            meet.clear();
            break;
        }
        for replaced in &next.replaced {
            if !visited.insert(*replaced) {
                continue;
            }
            let Some(prior) = frontier
                .superseded
                .get(replaced)
                .or_else(|| frontier.live.get(replaced))
            else {
                continue;
            };
            meet.retain(|field| prior.settings.fields().contains(field));
            if !strong(replaced, prior) {
                pending.push(prior.as_ref());
            }
        }
    }
    meet
}
