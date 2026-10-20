//! Actor groups (KS7-2b): the actor parts the getters split out of every
//! owner's rows, grouped under each actor's own entity tree. One
//! compartment holds an actor's atoms wherever they were split from, so the
//! actor's erase retires every checkpoint's copy of them with it.
//!
//! What holds what up, as a restore reads it: an owner's content takes back
//! only the actor parts naming its own parts, from the actors whose
//! compartments opened, and the getter's join puts them back or leaves the
//! family's no-one form. A part that holds only while another owner does
//! drops when that owner's compartment is in the checkpoint and does not
//! open (retired, erased, or with no custody on this host); an owner the
//! checkpoint holds no compartment for holds nothing up. An actor-keyed row
//! rests whole in its actor's part, so it lands only when that actor opens.

use std::collections::{BTreeMap, BTreeSet};

use super::BundleRole;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::checkpoint_payload::rows::{
    ACTOR_KEYED_ROW, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, RowDb, RowLocator,
    RowPart,
};

/// Every actor part `captures` split out, by actor, in capture order.
pub(super) fn group(captures: &[(BundleRole, Captured)]) -> BTreeMap<EntityId, Vec<ActorPart>> {
    let mut groups: BTreeMap<EntityId, Vec<ActorPart>> = BTreeMap::new();
    for (_, captured) in captures {
        for rows in captured.owners() {
            for part in &rows.actor_parts {
                groups
                    .entry(part.actor_entity)
                    .or_default()
                    .push(part.clone());
            }
        }
    }
    groups
}

/// The row an actor-keyed part's actor part holds, as the getters frame it
/// (`rows::actor_keyed`): a u32be length and the key, then a u32be length
/// and the value.
fn held_row(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (key, rest) = framed(bytes)?;
    let (value, rest) = framed(rest)?;
    rest.is_empty().then_some((key, value))
}

fn framed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    rest.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)
}

/// Where one of `rows`' content parts rests in the image: its database,
/// its row's key and what the part holds of its value. An actor-keyed
/// part's row is the one its actor part holds; `None` when there is none.
/// A no-one-form part whose locator does not name its row rests at the key
/// its getter recorded (`OwnerRows::image_keys`, FIX 6075).
pub(super) fn image_row<'a>(
    rows: &'a OwnerRows,
    part: &'a RowPart,
) -> Option<(RowDb, &'a [u8], &'a [u8])> {
    match part {
        RowPart::Exact { at, value } => Some((at.db, at.key.as_slice(), value.as_slice())),
        RowPart::NoActor { at, value } => {
            let key = rows.image_keys.get(at).unwrap_or(&at.key);
            Some((at.db, key.as_slice(), value.as_slice()))
        }
        RowPart::ActorKeyed { at } => rows
            .actor_parts
            .iter()
            .find(|actor| actor.content_locator == *at && actor.field == ACTOR_KEYED_ROW)
            .and_then(|actor| held_row(&actor.bytes))
            .map(|(key, value)| (at.db, key, value)),
    }
}

/// An owner's opened content, `content` as its getter framed it, as that
/// getter's restore takes it: with the parts of the opened actor groups
/// `actors` that name one of its parts, and the owners `unavailable` that
/// did not open.
pub(in crate::recovery::checkpoint) fn opened_content(
    content: &[u8],
    actors: &[ActorPart],
    unavailable: BTreeSet<OwnerRef>,
) -> Result<OpenedOwnerRows> {
    let bare = OpenedOwnerRows::open(content, Vec::new(), BTreeSet::new())?;
    let held: BTreeSet<&RowLocator> = bare.rows.iter().map(RowPart::at).collect();
    let parts = actors
        .iter()
        .filter(|part| held.contains(&part.content_locator))
        .cloned()
        .collect();
    OpenedOwnerRows::open(content, parts, unavailable)
}

/// The owners whose compartments the checkpoint holds, `held`, that did
/// not open: each part one of them holds up drops at the restore.
pub(in crate::recovery::checkpoint) fn unavailable(
    held: &BTreeSet<OwnerRef>,
    opened: &BTreeSet<OwnerRef>,
) -> BTreeSet<OwnerRef> {
    held.difference(opened).copied().collect()
}
