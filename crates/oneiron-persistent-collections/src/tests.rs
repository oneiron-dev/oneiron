//! Each collection against the std one it stands for: the same entries, order,
//! lookups, equality, hash and serde bytes after every operation, in every
//! form, and clones that never see each other's writes.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use proptest::prelude::*;

use crate::{Entry, PersistentMap, PersistentSet, SHRINK_LIMIT, SMALL_LIMIT};

const KEY_SPACE: u16 = 200;

fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn assert_map_matches(map: &PersistentMap<u16, u8>, reference: &BTreeMap<u16, u8>) {
    assert_eq!(map.len(), reference.len());
    assert_eq!(map.is_empty(), reference.is_empty());
    assert!(map.iter().eq(reference.iter()));
    assert!(map.iter().rev().eq(reference.iter().rev()));
    assert_eq!(map.iter().len(), reference.len());
    assert!(map.keys().eq(reference.keys()));
    assert!(map.values().rev().eq(reference.values().rev()));
    assert_eq!(map.first_key_value(), reference.first_key_value());
    assert_eq!(map.last_key_value(), reference.last_key_value());
    for key in [0, 1, 31, 63, 64, 65, 100, KEY_SPACE - 1, KEY_SPACE] {
        assert_eq!(map.get(&key), reference.get(&key));
        assert_eq!(map.contains_key(&key), reference.contains_key(&key));
        assert_eq!(map.get_key_value(&key), reference.get_key_value(&key));
    }
    assert!(map.range(40..120).eq(reference.range(40..120)));
    assert!(map.range(..=64).rev().eq(reference.range(..=64).rev()));
    assert_eq!(map.to_btree_map(), *reference);
    assert_eq!(*map, PersistentMap::from(reference.clone()));
    assert_eq!(
        hash_of(map),
        hash_of(&PersistentMap::from(reference.clone()))
    );
    assert_eq!(format!("{map:?}"), format!("{reference:?}"));
    assert_eq!(
        rmp_serde::to_vec(map).expect("map encodes"),
        rmp_serde::to_vec(reference).expect("reference encodes")
    );
}

fn assert_set_matches(set: &PersistentSet<u16>, reference: &BTreeSet<u16>) {
    assert_eq!(set.len(), reference.len());
    assert!(set.iter().eq(reference.iter()));
    assert!(set.iter().rev().eq(reference.iter().rev()));
    assert_eq!(set.iter().len(), reference.len());
    assert_eq!(set.first(), reference.first());
    assert_eq!(set.last(), reference.last());
    for value in [0, 1, 31, 63, 64, 65, 100, KEY_SPACE - 1, KEY_SPACE] {
        assert_eq!(set.contains(&value), reference.contains(&value));
        assert_eq!(set.get(&value), reference.get(&value));
    }
    assert!(set.range(40..120).eq(reference.range(40..120)));
    assert!(set.range(64..).rev().eq(reference.range(64..).rev()));
    assert_eq!(set.to_btree_set(), *reference);
    assert_eq!(
        hash_of(set),
        hash_of(&PersistentSet::from(reference.clone()))
    );
    assert_eq!(format!("{set:?}"), format!("{reference:?}"));
    assert_eq!(
        rmp_serde::to_vec(set).expect("set encodes"),
        rmp_serde::to_vec(reference).expect("reference encodes")
    );
}

#[derive(Clone, Debug)]
enum MapStep {
    Insert(u16, u8),
    Remove(u16),
    GetMut(u16, u8),
    EntryOrDefault(u16, u8),
    EntryAndModify(u16, u8),
    EntryMatch(u16, u8),
    RetainBelow(u16),
    RetainMutEven,
    ValuesMutAdd(u8),
    PopFirst,
    PopLast,
    Extend(Vec<(u16, u8)>),
    Snapshot,
    Clear,
}

fn map_step() -> impl Strategy<Value = MapStep> {
    let key = 0..KEY_SPACE;
    prop_oneof![
        12 => (key.clone(), 0..4_u8).prop_map(|(key, value)| MapStep::Insert(key, value)),
        4 => key.clone().prop_map(MapStep::Remove),
        2 => (key.clone(), any::<u8>()).prop_map(|(key, value)| MapStep::GetMut(key, value)),
        2 => (key.clone(), any::<u8>()).prop_map(|(key, add)| MapStep::EntryOrDefault(key, add)),
        2 => (key.clone(), any::<u8>()).prop_map(|(key, add)| MapStep::EntryAndModify(key, add)),
        2 => (key.clone(), any::<u8>()).prop_map(|(key, value)| MapStep::EntryMatch(key, value)),
        1 => key.clone().prop_map(MapStep::RetainBelow),
        1 => Just(MapStep::RetainMutEven),
        1 => any::<u8>().prop_map(MapStep::ValuesMutAdd),
        1 => Just(MapStep::PopFirst),
        1 => Just(MapStep::PopLast),
        1 => proptest::collection::vec((key, 0..4_u8), 0..90).prop_map(MapStep::Extend),
        2 => Just(MapStep::Snapshot),
        1 => Just(MapStep::Clear),
    ]
}

fn apply_map_step(
    step: &MapStep,
    map: &mut PersistentMap<u16, u8>,
    reference: &mut BTreeMap<u16, u8>,
) {
    match step.clone() {
        MapStep::Insert(key, value) => {
            assert_eq!(map.insert(key, value), reference.insert(key, value));
        }
        MapStep::Remove(key) => assert_eq!(map.remove(&key), reference.remove(&key)),
        MapStep::GetMut(key, value) => {
            if let Some(stored) = map.get_mut(&key) {
                *stored = value;
            }
            if let Some(stored) = reference.get_mut(&key) {
                *stored = value;
            }
        }
        MapStep::EntryOrDefault(key, add) => {
            let stored = map.entry(key).or_default();
            *stored = stored.wrapping_add(add);
            let stored = reference.entry(key).or_default();
            *stored = stored.wrapping_add(add);
        }
        MapStep::EntryAndModify(key, add) => {
            map.entry(key)
                .and_modify(|stored| *stored = stored.wrapping_add(add))
                .or_insert(add);
            reference
                .entry(key)
                .and_modify(|stored| *stored = stored.wrapping_add(add))
                .or_insert(add);
        }
        MapStep::EntryMatch(key, value) => {
            let held = match map.entry(key) {
                Entry::Vacant(slot) => {
                    slot.insert(value);
                    None
                }
                Entry::Occupied(mut slot) if *slot.get() < value => Some(slot.insert(value)),
                Entry::Occupied(slot) => Some(slot.remove()),
            };
            let expected = match reference.entry(key) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(value);
                    None
                }
                std::collections::btree_map::Entry::Occupied(mut slot) if *slot.get() < value => {
                    Some(slot.insert(value))
                }
                std::collections::btree_map::Entry::Occupied(slot) => Some(slot.remove()),
            };
            assert_eq!(held, expected);
        }
        MapStep::RetainBelow(bound) => {
            map.retain(|key, _| *key < bound);
            reference.retain(|key, _| *key < bound);
        }
        MapStep::RetainMutEven => {
            let keep = |key: &u16, value: &mut u8| {
                *value = value.wrapping_add(1);
                key % 2 == 0
            };
            map.retain_mut(keep);
            reference.retain(keep);
        }
        MapStep::ValuesMutAdd(add) => {
            for value in map.values_mut() {
                *value = value.wrapping_add(add);
            }
            for value in reference.values_mut() {
                *value = value.wrapping_add(add);
            }
        }
        MapStep::PopFirst => assert_eq!(map.pop_first(), reference.pop_first()),
        MapStep::PopLast => assert_eq!(map.pop_last(), reference.pop_last()),
        MapStep::Extend(entries) => {
            map.extend(entries.iter().copied());
            reference.extend(entries.iter().copied());
        }
        MapStep::Snapshot => {}
        MapStep::Clear => {
            map.clear();
            reference.clear();
        }
    }
}

proptest! {
    #[test]
    fn map_steps_match_btree_map_and_clones_stay_apart(
        steps in proptest::collection::vec(map_step(), 1..160),
    ) {
        let mut map = PersistentMap::new();
        let mut reference = BTreeMap::new();
        let mut snapshots = Vec::new();
        for step in &steps {
            if let MapStep::Snapshot = step {
                snapshots.push((map.clone(), reference.clone()));
                prop_assert!(snapshots.last().is_some_and(|(copy, _)| copy.ptr_eq(&map)));
            }
            apply_map_step(step, &mut map, &mut reference);
            assert_map_matches(&map, &reference);
        }
        for (copy, copy_reference) in &snapshots {
            assert_map_matches(copy, copy_reference);
        }
        let decoded: PersistentMap<u16, u8> =
            rmp_serde::from_slice(&rmp_serde::to_vec(&reference).expect("reference encodes"))
                .expect("map decodes");
        assert_map_matches(&decoded, &reference);
        prop_assert!(map.clone().into_iter().eq(reference.clone()));
    }
}

#[derive(Clone, Debug)]
enum SetStep {
    Insert(u16),
    Remove(u16),
    RetainBelow(u16),
    PopFirst,
    PopLast,
    Extend(Vec<u16>),
    Snapshot,
}

fn set_step() -> impl Strategy<Value = SetStep> {
    let value = 0..KEY_SPACE;
    prop_oneof![
        12 => value.clone().prop_map(SetStep::Insert),
        4 => value.clone().prop_map(SetStep::Remove),
        1 => value.clone().prop_map(SetStep::RetainBelow),
        1 => Just(SetStep::PopFirst),
        1 => Just(SetStep::PopLast),
        1 => proptest::collection::vec(value, 0..90).prop_map(SetStep::Extend),
        2 => Just(SetStep::Snapshot),
    ]
}

fn apply_set_step(step: &SetStep, set: &mut PersistentSet<u16>, reference: &mut BTreeSet<u16>) {
    match step.clone() {
        SetStep::Insert(value) => assert_eq!(set.insert(value), reference.insert(value)),
        SetStep::Remove(value) => assert_eq!(set.remove(&value), reference.remove(&value)),
        SetStep::RetainBelow(bound) => {
            set.retain(|value| *value < bound);
            reference.retain(|value| *value < bound);
        }
        SetStep::PopFirst => assert_eq!(set.pop_first(), reference.pop_first()),
        SetStep::PopLast => assert_eq!(set.pop_last(), reference.pop_last()),
        SetStep::Extend(values) => {
            set.extend(values.iter());
            reference.extend(values.iter());
        }
        SetStep::Snapshot => {}
    }
}

proptest! {
    #[test]
    fn set_steps_match_btree_set_and_clones_stay_apart(
        steps in proptest::collection::vec(set_step(), 1..160),
        other in proptest::collection::btree_set(0..KEY_SPACE, 0..120),
    ) {
        let mut set = PersistentSet::new();
        let mut reference = BTreeSet::new();
        let mut snapshots = Vec::new();
        let other_set = PersistentSet::from(other.clone());
        for step in &steps {
            if let SetStep::Snapshot = step {
                snapshots.push((set.clone(), reference.clone()));
            }
            apply_set_step(step, &mut set, &mut reference);
            assert_set_matches(&set, &reference);
            prop_assert!(set.union(&other_set).eq(reference.union(&other)));
            prop_assert!(set.intersection(&other_set).eq(reference.intersection(&other)));
            prop_assert!(set.difference(&other_set).eq(reference.difference(&other)));
            prop_assert_eq!(set.is_disjoint(&other_set), reference.is_disjoint(&other));
            prop_assert_eq!(set.is_subset(&other_set), reference.is_subset(&other));
            prop_assert_eq!(set.is_superset(&other_set), reference.is_superset(&other));
            prop_assert_eq!(set.cmp(&other_set), reference.cmp(&other));
        }
        for (copy, copy_reference) in &snapshots {
            assert_set_matches(copy, copy_reference);
        }
        prop_assert!(set.clone().into_iter().eq(reference.clone()));
    }
}

fn map_of(len: u16) -> (PersistentMap<u16, u8>, BTreeMap<u16, u8>) {
    let reference: BTreeMap<u16, u8> = (0..len).map(|key| (key, (key % 7) as u8)).collect();
    let mut map = PersistentMap::new();
    for (key, value) in &reference {
        map.insert(*key, *value);
    }
    (map, reference)
}

#[test]
fn map_form_follows_its_length() {
    let (mut map, _) = map_of(SMALL_LIMIT as u16);
    assert_eq!(map.form_name(), "small");
    map.insert(SMALL_LIMIT as u16, 0);
    assert_eq!(map.form_name(), "large");
    for key in 0..(SMALL_LIMIT - SHRINK_LIMIT) as u16 {
        map.remove(&key);
    }
    assert_eq!(map.len(), SHRINK_LIMIT + 1);
    assert_eq!(map.form_name(), "large");
    map.remove(&((SMALL_LIMIT - SHRINK_LIMIT) as u16));
    assert_eq!(map.form_name(), "small");
    map.clear();
    assert_eq!(map.form_name(), "empty");
    map.insert(1, 1);
    map.remove(&1);
    assert_eq!(map.form_name(), "empty");
}

#[test]
fn set_form_follows_its_length() {
    let mut set: PersistentSet<u16> = (0..SMALL_LIMIT as u16).collect();
    assert_eq!(set.form_name(), "small");
    set.insert(SMALL_LIMIT as u16);
    assert_eq!(set.form_name(), "large");
    set.retain(|value| usize::from(*value) < SHRINK_LIMIT);
    assert_eq!(set.form_name(), "small");
    set.retain(|_| false);
    assert_eq!(set.form_name(), "empty");
}

#[test]
fn an_equal_write_keeps_the_shared_root() {
    for len in [3, 200] {
        let (map, reference) = map_of(len);
        let mut copy = map.clone();
        assert_eq!(copy.insert(2, reference[&2]), Some(reference[&2]));
        assert!(
            copy.ptr_eq(&map),
            "an equal value is not written ({len} entries)"
        );
        copy.retain(|_, _| true);
        assert!(copy.ptr_eq(&map), "a retain that keeps all writes nothing");
        assert_eq!(copy.get_mut(&KEY_SPACE), None);
        assert!(copy.ptr_eq(&map), "get_mut of a missing key writes nothing");
        copy.insert(2, reference[&2] + 1);
        assert!(!copy.ptr_eq(&map));
        assert_map_matches(&map, &reference);
    }
    let set: PersistentSet<u16> = (0..200).collect();
    let mut copy = set.clone();
    assert!(!copy.insert(5));
    assert!(!copy.remove(&KEY_SPACE));
    assert!(copy.ptr_eq(&set));
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Held {
    count: u32,
    label: String,
    members: BTreeSet<u16>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct HeldPersistent {
    count: u32,
    label: String,
    members: PersistentSet<u16>,
}

#[test]
fn serde_bytes_match_btree_in_every_form() {
    for len in [0_u16, 1, 2, 31, 32, 33, 63, 64, 65, 66, 300] {
        let reference: BTreeMap<[u8; 32], Held> = (0..len)
            .map(|index| {
                let mut key = [0_u8; 32];
                key[..2].copy_from_slice(&index.to_be_bytes());
                key[31] = (index % 251) as u8;
                let held = Held {
                    count: u32::from(index) * 3,
                    label: format!("row {index}"),
                    members: (0..index % 5).collect(),
                };
                (key, held)
            })
            .collect();
        let map: PersistentMap<[u8; 32], HeldPersistent> = reference
            .iter()
            .map(|(key, held)| {
                let held = HeldPersistent {
                    count: held.count,
                    label: held.label.clone(),
                    members: PersistentSet::from(held.members.clone()),
                };
                (*key, held)
            })
            .collect();
        let compact = rmp_serde::to_vec(&reference).expect("reference encodes");
        let named = rmp_serde::to_vec_named(&reference).expect("reference encodes named");
        assert_eq!(
            rmp_serde::to_vec(&map).expect("map encodes"),
            compact,
            "{len}"
        );
        assert_eq!(
            rmp_serde::to_vec_named(&map).expect("map encodes named"),
            named,
            "{len}"
        );
        let decoded: PersistentMap<[u8; 32], HeldPersistent> =
            rmp_serde::from_slice(&named).expect("map decodes");
        assert_eq!(decoded, map);
        assert_eq!(
            rmp_serde::to_vec_named(&decoded).expect("decoded encodes"),
            named
        );

        let strings: BTreeMap<String, u16> = (0..len)
            .map(|index| (format!("k{index:04}"), index))
            .collect();
        let string_map: PersistentMap<String, u16> = strings.clone().into();
        assert_eq!(
            serde_json::to_string(&string_map).expect("map writes JSON"),
            serde_json::to_string(&strings).expect("reference writes JSON")
        );
        let members: BTreeSet<u16> = (0..len).map(|index| index * 2).collect();
        let set = PersistentSet::from(members.clone());
        assert_eq!(
            serde_json::to_string(&set).expect("set writes JSON"),
            serde_json::to_string(&members).expect("reference writes JSON")
        );
    }
}

#[test]
fn a_repeated_key_keeps_its_last_value_as_btree_map_does() {
    let text = r#"{"a":1,"b":2,"a":3}"#;
    let reference: BTreeMap<String, u8> = serde_json::from_str(text).expect("reference reads");
    let map: PersistentMap<String, u8> = serde_json::from_str(text).expect("map reads");
    assert_eq!(map.to_btree_map(), reference);
    let members: BTreeSet<u8> = serde_json::from_str("[3,1,3,2]").expect("reference reads");
    let set: PersistentSet<u8> = serde_json::from_str("[3,1,3,2]").expect("set reads");
    assert_eq!(set.to_btree_set(), members);
}

#[test]
fn ordering_and_index_match_btree_map() {
    let (left, left_reference) = map_of(70);
    let (right, right_reference) = map_of(10);
    assert_eq!(left.cmp(&right), left_reference.cmp(&right_reference));
    assert_eq!(left.partial_cmp(&left), Some(std::cmp::Ordering::Equal));
    assert_eq!(left[&69], left_reference[&69]);
    assert_eq!(left, left.clone());
    assert_ne!(left, right);
}

/// A value with no `Clone`: reads, equality, Debug and serde need none, so a
/// generic struct that derives them over a map of its parameter compiles
/// with only the derive's own bounds.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Unclonable(u16);

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Holder<P> {
    entries: PersistentMap<u16, P>,
}

#[derive(serde::Serialize)]
struct StdHolder<P> {
    entries: BTreeMap<u16, P>,
}

#[test]
fn reads_equality_and_serde_need_no_clone_of_the_value() {
    let unclonable = |count: u16| -> BTreeMap<u16, Unclonable> {
        (0..count).map(|key| (key, Unclonable(key))).collect()
    };
    for count in [0, 3, 70] {
        let holder = Holder {
            entries: PersistentMap::from(unclonable(count)),
        };
        let reference = StdHolder {
            entries: unclonable(count),
        };
        assert_eq!(holder.entries.len(), reference.entries.len());
        assert!(holder.entries.iter().eq(reference.entries.iter()));
        assert_eq!(holder.entries.get(&2), reference.entries.get(&2));
        assert!(holder.entries.range(1..3).eq(reference.entries.range(1..3)));
        let bytes = rmp_serde::to_vec(&holder).expect("holder encodes");
        assert_eq!(
            bytes,
            rmp_serde::to_vec(&reference).expect("reference encodes")
        );
        let decoded: Holder<Unclonable> = rmp_serde::from_slice(&bytes).expect("holder decodes");
        assert_eq!(decoded, holder);
        assert_eq!(format!("{decoded:?}"), format!("{holder:?}"));
    }
}

#[test]
fn modify_stores_only_a_changed_value() {
    for count in [3, 100] {
        let (mut map, mut reference) = map_of(count);
        let shared = map.clone();
        assert!(map.modify(&1, |value| *value = reference[&1]));
        assert!(
            map.ptr_eq(&shared),
            "an unchanged value copies nothing ({count})"
        );
        map.modify_or_default(1, |value| *value = reference[&1]);
        assert!(
            map.ptr_eq(&shared),
            "an unchanged value copies nothing ({count})"
        );
        assert!(!map.modify(&KEY_SPACE, |value| *value = 9));
        assert!(map.ptr_eq(&shared), "a missing key runs nothing ({count})");
        assert!(map.modify(&1, |value| *value = value.wrapping_add(1)));
        reference.insert(1, reference[&1].wrapping_add(1));
        assert!(!map.ptr_eq(&shared));
        map.modify_or_default(KEY_SPACE, |_| {});
        reference.insert(KEY_SPACE, 0);
        assert_map_matches(&map, &reference);
        assert_eq!(shared.get(&KEY_SPACE), None, "the clone sees no write");
    }
}
