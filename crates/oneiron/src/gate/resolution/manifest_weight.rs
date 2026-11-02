//! What one decoded manifest body weighs in the store's manifest memo
//! (FIX 5987): the bytes it owns, not the length of its input. A decode can
//! own more than its body held (a struct per array element, a default string
//! per bare signature, a tree node per set member), so each field of
//! `decode_manifest.rs`'s decoded pack is charged at its owned capacity:
//! every list at its capacity in elements, every string at its capacity,
//! every set or map entry at its key and value with the tree's node
//! overhead. Inline fields ride the row's own size. The body's own length is
//! charged once beside them, for the strings and nested lists its elements
//! decoded from it. A weight is a cache charge only: it decides what the
//! memo keeps, never whether a body's policy is read.
use std::collections::{BTreeMap, BTreeSet};

use super::manifest_memo::ManifestRow;
use crate::gate::decode::DecodedManifestCarrier;

/// A B-tree entry's share of its node: room for a sparse node's unused
/// slots beside the entry itself, plus the node header and edges.
const TREE_ENTRY_OVERHEAD: usize = 32;

/// The bytes `row`, decoded from a body of `body_len` bytes, owns.
pub(super) fn row_weight(body_len: usize, row: &ManifestRow) -> usize {
    let carried = match &row.carrier {
        None | Some(DecodedManifestCarrier::ProjectDepth(_)) => 0,
        Some(DecodedManifestCarrier::Pack(pack)) => [
            list(&pack.policy_values),
            list(&pack.actor_ceilings),
            list(&pack.delegated_grants),
            strings(&pack.single_valued_predicates),
            list(&pack.scoped_grants),
            list(&pack.federation_grant_rows),
            list(&pack.room_policy_rows),
            pack.shared_act_policies.as_ref().map_or(0, keyed),
            list(&pack.owner_policy_rows),
            text(pack.owner_policy_document.as_ref()),
            text(pack.owner_policy_output_contract.as_ref()),
            list(&pack.owner_policy_patterns),
            list(&pack.signatures),
            pack.signatures.iter().fold(0, |sum, signature| {
                sum.saturating_add(signature.alg.capacity())
                    .saturating_add(text(signature.key_id.as_ref()))
                    .saturating_add(signature.sig.capacity())
            }),
            list(&pack.native_mail_policy),
            text(pack.auto_checker.as_ref()),
            list(&pack.weave_report_policy),
            list(&pack.booking_conversion_rows),
            list(&pack.booking_anti_abuse_rows),
            list(&pack.dreamer_failure_rules),
            pack.connector_class_carry.as_ref().map_or(0, |carry| {
                carry.iter().fold(set(carry), |sum, (class, connector)| {
                    sum.saturating_add(class.capacity())
                        .saturating_add(connector.capacity())
                })
            }),
            list(&pack.failure_signal_policy),
            list(&pack.sheet_answer_limits),
            list(&pack.skill_tradeoff_rows),
            list(&pack.retry_source_policy),
            list(&pack.experiment_selection),
            pack.sync_world_ceiling.as_ref().map_or(0, set),
            strings(&pack.persona_core_prefixes),
            list(&pack.consult_fanout_scope_rows),
        ]
        .into_iter()
        .fold(0, usize::saturating_add),
    };
    size_of::<ManifestRow>()
        .saturating_add(size_of::<DecodedManifestCarrier>())
        .saturating_add(body_len)
        .saturating_add(carried)
}

/// A list's owned buffer: its capacity in elements.
fn list<T>(rows: &Vec<T>) -> usize {
    rows.capacity().saturating_mul(size_of::<T>())
}

/// A set's owned nodes, its members' own heap aside.
fn set<T>(members: &BTreeSet<T>) -> usize {
    members
        .len()
        .saturating_mul(size_of::<T>().saturating_add(TREE_ENTRY_OVERHEAD))
}

/// A set of strings: its nodes and each string's capacity.
fn strings(members: &BTreeSet<String>) -> usize {
    members.iter().fold(set(members), |sum, member| {
        sum.saturating_add(member.capacity())
    })
}

/// A map keyed by strings: its nodes, each value inline, and each key's
/// capacity.
fn keyed<V>(entries: &BTreeMap<String, V>) -> usize {
    let entry = size_of::<String>()
        .saturating_add(size_of::<V>())
        .saturating_add(TREE_ENTRY_OVERHEAD);
    entries
        .keys()
        .fold(entries.len().saturating_mul(entry), |sum, key| {
            sum.saturating_add(key.capacity())
        })
}

/// An optional string's capacity.
fn text(value: Option<&String>) -> usize {
    value.map_or(0, String::capacity)
}
