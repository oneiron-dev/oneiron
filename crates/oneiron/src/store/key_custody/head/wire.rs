//! Core half of `store::key_custody::head::wire`: its store-layer items live in `oneiron_store::key_custody::head::wire` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::head::wire::*;

use super::super::body_history::HistoryRows;
use super::super::log::{CustodyPosition, POSITION_LEN};
use super::super::recipients::RecipientRetirement;
use super::holder_debts::HolderDebtWire;
use super::{CompartmentScope, carried_pads, head_corrupt};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeadWire {
    pub(super) version: u16,
    #[serde(with = "serde_bytes_vec")]
    pub(super) position: Vec<u8>,
    pub(super) compartments: Vec<CompartmentWire>,
    /// Earlier heads' world compartments a restore here did not open (PAD-3).
    pub(super) carried_world_pads: Vec<carried_pads::CarriedWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompartmentWire {
    pub(super) scope: u8,
    /// A world compartment's world (FIX 6706); absent on every other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) world: Option<[u8; 16]>,
    /// A world compartment's one pad (PAD-3); absent on every other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pad: Option<carried_pads::PadCompartmentIdentity>,
    #[serde(with = "serde_bytes_vec")]
    pub(super) sealed: Vec<u8>,
    pub(super) wraps: Vec<WrapWire>,
}

/// One compartment's plaintext. The control compartment holds the control
/// secret and the root of every other compartment's digest; the rest hold
/// entries.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BodyWire {
    pub(super) control: Option<[u8; 32]>,
    /// The control compartment's: its commitment to every other compartment
    /// and every carried one (FIX 5800).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) root: Option<DigestRoot>,
    pub(super) live: Vec<EntryWire>,
    pub(super) retired: Vec<FactWire>,
    /// A host-readable compartment's: released escrow recipients the lineage
    /// retired, public facts only (LC FIX 5384/5385), paged with its other
    /// rows (FIX 5800).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) recipients: Vec<RecipientRetirement>,
    /// A host-readable compartment's: body history rows, ids only (FIX
    /// 6229), sealed under the compartment's key like its entries.
    pub(super) history: Vec<HistoryWire>,
    /// A host-readable compartment's: each erased credential's fact (FIX
    /// 10584 item 3), value-free, whatever key eligibility keeps local.
    pub(super) evidence: Vec<EvidenceWire>,
    /// A host-readable compartment's: each holder debt (FIX 11206), a key's
    /// ref and its holder machine, never a key.
    pub(super) holders: Vec<HolderDebtWire>,
}

impl Drop for BodyWire {
    fn drop(&mut self) {
        if let Some(control) = &mut self.control {
            control.zeroize();
        }
    }
}

/// What binds a compartment and its key's wraps to their place in exactly
/// this head: a 32-byte commitment to the whole of `position | u32be index |
/// scope`, and a world compartment's world, which fits an envelope's key id
/// (FIX 6769, 6706).
pub(super) fn key_id(
    position: &[u8; POSITION_LEN],
    index: u32,
    scope: Option<CompartmentScope>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_ID_CONTEXT);
    hasher.update(position);
    hasher.update(&index.to_be_bytes());
    hasher.update(&[scope.map_or(0, CompartmentScope::code)]);
    if let Some(world) = scope.and_then(CompartmentScope::world) {
        hasher.update(world.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn parse(head: &[u8]) -> Result<HeadWire> {
    let body = head.strip_prefix(HEAD_MAGIC).ok_or_else(head_corrupt)?;
    let wire: HeadWire = rmp_serde::from_slice(body).map_err(|_| head_corrupt())?;
    if wire.version != HEAD_VERSION || wire.compartments.is_empty() {
        return Err(head_corrupt());
    }
    Ok(wire)
}

/// The position a head claims, read without opening it: what a target lists
/// and a status reports. Nothing here is authenticated until it opens.
pub(in crate::store::key_custody) fn head_position(head: &[u8]) -> Result<CustodyPosition> {
    CustodyPosition::from_bytes(&parse(head)?.position).ok_or_else(head_corrupt)
}

/// The position the first bytes of a head claim, before the rest of it has
/// arrived: a residence stage an upload is still writing (FIX 6415). The
/// wire is a map whose first two entries are [`HeadWire`]'s version and
/// position, read alone here. `None` when they are not there yet, or are
/// not this engine's. Unauthenticated, as [`head_position`] is.
pub(in crate::store::key_custody) fn staged_position(lead: &[u8]) -> Option<CustodyPosition> {
    use rmpv::Value;
    let body = lead.strip_prefix(HEAD_MAGIC)?;
    let shape = rmp_serde::to_vec_named(&HeadWire {
        version: HEAD_VERSION,
        position: Vec::new(),
        compartments: Vec::new(),
        carried_world_pads: Vec::new(),
    })
    .ok()?;
    let (map, entries) = body.split_first()?;
    if shape.first() != Some(map) {
        return None;
    }
    let mut cursor = std::io::Cursor::new(entries);
    let version_key = rmpv::decode::read_value(&mut cursor).ok()?;
    let version = rmpv::decode::read_value(&mut cursor).ok()?;
    let position_key = rmpv::decode::read_value(&mut cursor).ok()?;
    let position = rmpv::decode::read_value(&mut cursor).ok()?;
    match (version_key, version, position_key, position) {
        (
            Value::String(version_key),
            Value::Integer(version),
            Value::String(position_key),
            Value::Binary(position),
        ) if version_key.as_str() == Some("version")
            && version.as_u64() == Some(u64::from(HEAD_VERSION))
            && position_key.as_str() == Some("position") =>
        {
            CustodyPosition::from_bytes(&position)
        }
        _ => None,
    }
}

/// Each scope's compartment bodies as rows fill them, scopes in order.
#[derive(Default)]
pub(super) struct Bodies {
    scopes: BTreeMap<CompartmentScope, Vec<(BodyWire, usize)>>,
}

impl Bodies {
    /// The body of `scope` a row with `bytes` of byte strings goes in: the
    /// last one while it has room, else a fresh one. A world compartment
    /// holds one pad (PAD-3); a row larger than the bound gets a body alone.
    pub(super) fn body(&mut self, scope: CompartmentScope, bytes: usize) -> &mut BodyWire {
        let bytes = bytes.saturating_add(ROW_OVERHEAD);
        let chunks = self.scopes.entry(scope).or_default();
        let full = chunks
            .last()
            .is_none_or(|(body, used)| match scope.world() {
                Some(_) => !body.live.is_empty() || !body.retired.is_empty(),
                None => *used > 0 && used.saturating_add(bytes) > COMPARTMENT_BYTES,
            });
        if full {
            chunks.push((BodyWire::default(), 0));
        }
        let at = chunks.len() - 1;
        let (body, used) = &mut chunks[at];
        *used = used.saturating_add(bytes);
        body
    }

    /// The history row `key`, `value` in the host-readable compartments, a
    /// value larger than [`HISTORY_FRAGMENT_BYTES`] in fragments, in order.
    pub(super) fn push_history(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let fragments: Vec<&[u8]> = if value.is_empty() {
            vec![value]
        } else {
            value.chunks(HISTORY_FRAGMENT_BYTES).collect()
        };
        let count = fragments.len();
        for (part, fragment) in fragments.into_iter().enumerate() {
            let row = HistoryWire {
                key: key.to_vec(),
                value: fragment.to_vec(),
                part: u32::try_from(part).map_err(|_| head_corrupt())?,
                last: part + 1 == count,
            };
            self.body(CompartmentScope::HostReadable, key.len() + fragment.len())
                .history
                .push(row);
        }
        Ok(())
    }

    /// Every body, scopes in order and each scope's in the order it filled.
    pub(super) fn into_bodies(self) -> impl Iterator<Item = (CompartmentScope, BodyWire)> {
        self.scopes
            .into_iter()
            .flat_map(|(scope, bodies)| bodies.into_iter().map(move |(body, _)| (scope, body)))
    }
}

/// A history row whose fragments are still arriving, compartment by
/// compartment in order (FIX 5800).
#[derive(Default)]
pub(super) struct HistoryJoin {
    pending: Option<HistoryWire>,
}

impl HistoryJoin {
    /// Joins `row` to the row it continues, and lands the row in `into` once
    /// its last fragment has come. A fragment out of order, or of another
    /// row before the pending one ended, is refused.
    pub(super) fn push(&mut self, row: HistoryWire, into: &mut HistoryRows) -> Result<()> {
        let joined = match self.pending.take() {
            None if row.part == 0 => row,
            Some(mut held) if held.key == row.key && held.part.checked_add(1) == Some(row.part) => {
                held.value.extend_from_slice(&row.value);
                held.part = row.part;
                held.last = row.last;
                held
            }
            _ => return Err(head_corrupt()),
        };
        if joined.last {
            into.insert(joined.key, joined.value);
        } else {
            self.pending = Some(joined);
        }
        Ok(())
    }

    /// Refuses a head whose last history row never ended.
    pub(super) fn finish(self) -> Result<()> {
        match self.pending {
            Some(_) => Err(head_corrupt()),
            None => Ok(()),
        }
    }
}
