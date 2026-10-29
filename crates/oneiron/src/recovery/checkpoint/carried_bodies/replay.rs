//! The parts a checkpoint carries of a replay row and of a step start (FIX
//! 9180, coord-b slice d; L04 option (b)): each part's descriptor beside
//! the generic one, the step starts a census finds by their capsules' typed
//! refs, and the restore that recomposes each destination once.
//!
//! A part travels as an inline body of its own, sealed under its instance,
//! its descriptor naming the row it recomposes into ([`ReplayPartCarried`]):
//! a replay row's, whose image row holds its skeleton, or a capsule's,
//! whose row travels as it is. A carried start's whole body travels
//! nowhere: its body row goes without its bytes, and no file or descriptor
//! carries its file, so no stream holds an ask its parts carry apart.
//!
//! A restore reads each part's stream as it reads any inline body, checked
//! against its instance and digest, then recomposes each destination once
//! ([`land`]), every part's disposition known, before any row lands: a row
//! from its reply or its skeleton, a start from its rest, republished
//! inline under the same occurrence. A start whose rest retired goes as a
//! retired body does. Each recomposed destination is counted at its grouped
//! length before anything is opened ([`landed_lengths`]).

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::super::response_rows::row_mut;
use super::super::{CheckpointImage, codec_error};
use super::{BodyCensus, CarriedInline};
use crate::Result;
use crate::code_run::{ReplayPart, ReplayParts, RequestPart};
use crate::store::{ResponseFamily, Store};

/// What a Replay part's descriptor carries beside the generic one (FIX
/// 9180): its carrier, which names the row it recomposes into and which
/// part it is; a request part's call in its erased form, text-free, which
/// the call takes when the ask's instance retired; and the extents its
/// destination's grouped landing length counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::recovery::checkpoint) struct ReplayPartCarried {
    carrier: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    erased: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extents: Vec<(u64, u64)>,
}

/// The descriptor and bytes of `part` of the row `row`, carried under
/// `instance` by `carrier`, its bytes' BLAKE3 `digest`.
pub(in crate::recovery::checkpoint) fn carried_part(
    row: &[u8],
    carrier: Vec<u8>,
    part: ReplayPart,
    instance: [u8; 16],
    digest: [u8; 32],
) -> (CarriedInline, Vec<u8>) {
    let carried = CarriedInline {
        database: "vault_meta".to_owned(),
        key: row.to_vec(),
        keep: 0,
        instance,
        digest,
        len: part.bytes.len() as u64,
        stored_len: 0,
        retired: None,
        landed_len: None,
        opaque: false,
        superseded: false,
        replay: Some(ReplayPartCarried {
            carrier,
            erased: part.erased,
            extents: part.extents,
        }),
    };
    (carried, part.bytes)
}

/// The step starts a census carries as parts, found by their capsules'
/// typed refs before it notes a row, whichever row it meets first: each
/// start's parts by its capsule row, and the digests their whole bodies
/// rest under, which no stream carries.
pub(super) struct StartIndex {
    starts: BTreeMap<Vec<u8>, ReplayParts>,
    digests: BTreeSet<[u8; 32]>,
}

impl StartIndex {
    /// Every kept start `txn` holds whose prefix holds an ask a checkpoint
    /// carries apart.
    fn of(store: &Store, txn: &RoTxn<'_>) -> Result<Self> {
        let mut index = Self {
            starts: BTreeMap::new(),
            digests: BTreeSet::new(),
        };
        for kept in crate::code_run::kept_step_starts_in_txn(store, txn)? {
            if let Some(parts) = crate::code_run::step_start_parts(&kept.bytes) {
                index.digests.insert(kept.digest);
                index.starts.insert(kept.row, parts);
            }
        }
        Ok(index)
    }
}

/// FIX 9180: the census of a `vault_meta` row a carried step start names:
/// its capsule's row carries the start's parts and travels as it is, and
/// its whole body's row travels without its bytes, which no file or
/// descriptor carries either. `None` for any other row. The first
/// `vault_meta` row the census meets indexes every kept start.
///
/// # Errors
///
/// Storage errors, and a binding or descriptor that does not decode.
pub(super) fn note_start(
    census: &mut BodyCensus,
    store: &Store,
    txn: &RoTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<Option<Option<Vec<u8>>>> {
    if census.starts.is_none() {
        census.starts = Some(StartIndex::of(store, txn)?);
    }
    let Some(index) = &census.starts else {
        return Ok(None);
    };
    if let Some(parts) = index.starts.get(key).cloned() {
        let mut carried = Vec::with_capacity(parts.parts.len());
        let mut unbound = false;
        for part in parts.parts {
            let carrier = ResponseFamily::replay_part_carrier(key, part.request);
            let digest = *blake3::hash(&part.bytes).as_bytes();
            match census
                .responses
                .note_part(store, txn, carrier.clone(), &digest)?
            {
                Some(instance) => carried.push(carried_part(key, carrier, part, instance, digest)),
                None => unbound = true,
            }
        }
        if !unbound {
            census.inline.extend(carried);
        }
        return Ok(Some(None));
    }
    let digests = &index.digests;
    if let Some((digest, _)) = crate::code_run::code_run_inline_body_of_row(key, value)
        && digests.contains(&digest)
    {
        return Ok(Some(Some(value[..1].to_vec())));
    }
    if let Some((digest, _)) = crate::code_run::code_run_body_file_of_row(key, value)
        && digests.contains(&digest)
    {
        return Ok(Some(None));
    }
    if let Some((digest, _)) = crate::provenance::body::file_body_of_row(key, value)?
        && digests.contains(&digest)
    {
        return Ok(Some(None));
    }
    Ok(None)
}

/// FIX 9180: each carried Replay part checked before anything is pruned:
/// its carrier names the row it is carried into, a request part keeps its
/// erased facts and extents, and each destination recomposes from exactly
/// one rest. Each part's instance is required with the rest, as its
/// binding row names it.
///
/// # Errors
///
/// [`crate::Error::CorruptedIndex`] for a part that does not fit.
pub(super) fn require(image: &CheckpointImage) -> Result<()> {
    let mut rests: BTreeMap<&[u8], usize> = BTreeMap::new();
    for carried in &image.inline_bodies {
        let Some(part) = &carried.replay else {
            continue;
        };
        let Some((row, request)) = ResponseFamily::replay_part_of(&part.carrier) else {
            return Err(codec_error());
        };
        if carried.database != "vault_meta" || row != carried.key.as_slice() {
            return Err(codec_error());
        }
        let count = rests.entry(row).or_default();
        match request {
            None => *count += 1,
            Some(_) if part.erased.is_empty() || part.extents.len() != 4 => {
                return Err(codec_error());
            }
            Some(_) => {}
        }
    }
    if rests.values().any(|count| *count != 1) {
        return Err(codec_error());
    }
    Ok(())
}

/// The plaintext of each live Replay part a restore read, by its place
/// among the image's inline bodies, until its destination recomposes.
#[derive(Default)]
pub(super) struct ReadParts(BTreeMap<usize, Vec<u8>>);

impl ReadParts {
    /// Keeps the plaintext `body` of the part at `inline`.
    pub(super) fn keep(&mut self, inline: usize, body: Vec<u8>) {
        self.0.insert(inline, body);
    }
}

/// One destination's parts, each by its place among the inline bodies.
struct Destination<'i> {
    rest: Option<(usize, &'i CarriedInline)>,
    requests: Vec<((u32, u64), usize, &'i CarriedInline, &'i ReplayPartCarried)>,
}

/// Each destination `inline` carries parts of, by the row it recomposes
/// into. A superseded part is the live vault's.
fn destinations(inline: &[CarriedInline]) -> BTreeMap<Vec<u8>, Destination<'_>> {
    let mut destinations = BTreeMap::new();
    for (at, carried) in inline.iter().enumerate() {
        let Some(part) = carried.replay.as_ref().filter(|_| !carried.superseded) else {
            continue;
        };
        let Some((row, request)) = ResponseFamily::replay_part_of(&part.carrier) else {
            continue;
        };
        let destination = destinations
            .entry(row.to_vec())
            .or_insert_with(|| Destination {
                rest: None,
                requests: Vec::new(),
            });
        match request {
            None => destination.rest = Some((at, carried)),
            Some(call) => destination.requests.push((call, at, carried, part)),
        }
    }
    destinations
}

/// The plaintext of the part at `at`, carried under `instance`; `None` when
/// its instance retired.
fn live_part<'r>(
    read: &'r ReadParts,
    retired: &BTreeSet<[u8; 16]>,
    at: usize,
    instance: &[u8; 16],
) -> Result<Option<&'r [u8]>> {
    if retired.contains(instance) {
        return Ok(None);
    }
    read.0
        .get(&at)
        .map(|body| Some(body.as_slice()))
        .ok_or_else(codec_error)
}

/// FIX 9180: recomposes each destination the image carries parts of, once,
/// now each part's disposition is known (its instance `retired`, or its
/// plaintext `read`), before any row lands. A replay row is recomposed from
/// its live reply, or from its skeleton when the reply retired; a step
/// start from its live rest, republished among the rows held inline under
/// the same occurrence, or, its rest retired, left as a retired body
/// leaves one. Either way each live ask goes back in its call, and each
/// retired one's call answers `TargetErased`, the one precedence
/// `crate::code_run::recompose_replay_row` defines. The whole bodies the
/// starts rested under are settled last.
///
/// # Errors
///
/// [`crate::Error::CorruptedIndex`] for a live part the restore did not
/// read or a destination the rows do not hold; a part that does not decode
/// or fit.
pub(super) fn land(
    image: &mut CheckpointImage,
    read: &ReadParts,
    retired: &BTreeSet<[u8; 16]>,
) -> Result<()> {
    let destinations = destinations(&image.inline_bodies);
    if destinations.is_empty() {
        return Ok(());
    }
    let rows = image
        .databases
        .get_mut("vault_meta")
        .ok_or_else(codec_error)?;
    let (mut rested, mut landed) = (BTreeSet::new(), BTreeSet::new());
    for (row, destination) in &destinations {
        let Some((rest_at, rest)) = destination.rest else {
            continue;
        };
        let mut requests = Vec::with_capacity(destination.requests.len());
        for (call, at, carried, part) in &destination.requests {
            let part = match live_part(read, retired, *at, &carried.instance)? {
                Some(ask) => RequestPart::Live(ask),
                None => RequestPart::Retired(&part.erased),
            };
            requests.push((*call, part));
        }
        let rest = live_part(read, retired, rest_at, &rest.instance)?;
        if !crate::code_run::step_capsule_row(row) {
            let value = row_mut(rows, row)?;
            *value = crate::code_run::recompose_replay_row(&value[..], rest, &requests)?;
            continue;
        }
        match rest {
            Some(rest) => {
                let bytes = crate::code_run::recompose_step_start(rest, &requests)?;
                if let Some((before, after)) =
                    crate::code_run::republish_step_start_in_rows(rows, row, &bytes)?
                {
                    rested.insert(before);
                    landed.insert(after);
                }
            }
            None => rested.extend(crate::code_run::drop_step_start_in_rows(rows, row)?),
        }
    }
    crate::code_run::settle_start_bodies_in_rows(rows, &rested, &landed)
}

/// The value of the row `key` among sorted `rows`.
fn image_row<'r>(rows: &'r [(Vec<u8>, Vec<u8>)], key: &[u8]) -> Option<&'r [u8]> {
    rows.binary_search_by(|(row, _)| row.as_slice().cmp(key))
        .ok()
        .map(|at| rows[at].1.as_slice())
}

/// FIX 9180 (the `landing_lengths` arm, L04 ACKED 03:50): the length each
/// `vault_meta` row a recomposed destination lands at, counted before
/// anything is opened from what its parts carried and how each stands
/// (`retired`): a replay row's at its recomposed length, never one part's;
/// a start's body row at its recomposed body held inline, or its capsule's
/// row beside its own length when the image keeps no body row to stand for
/// it; a start whose rest retired leaves its body row nothing. No margin is
/// added.
pub(in crate::recovery::checkpoint) fn landed_lengths(
    image: &CheckpointImage,
    retired: &BTreeSet<[u8; 16]>,
) -> Vec<(Vec<u8>, u64)> {
    let mut lengths = Vec::new();
    let Some(rows) = image.databases.get("vault_meta") else {
        return lengths;
    };
    for (row, destination) in destinations(&image.inline_bodies) {
        let Some((_, rest)) = destination.rest else {
            continue;
        };
        let live = !retired.contains(&rest.instance);
        let requests: Vec<(bool, &[(u64, u64)])> = destination
            .requests
            .iter()
            .map(|(_, _, carried, part)| {
                (
                    !retired.contains(&carried.instance),
                    part.extents.as_slice(),
                )
            })
            .collect();
        if !crate::code_run::step_capsule_row(&row) {
            let base = if live {
                rest.len
            } else {
                image_row(rows, &row).map_or(0, |value| value.len() as u64)
            };
            let landed = crate::code_run::recomposed_len(base, None, !live, &requests);
            lengths.push((row, landed));
            continue;
        }
        let Some(capsule) = image_row(rows, &row) else {
            continue;
        };
        let Some(body_row) = crate::code_run::step_start_body_row(capsule) else {
            continue;
        };
        let body = if live {
            let record = rest
                .replay
                .as_ref()
                .and_then(|part| part.extents.first().copied());
            crate::code_run::recomposed_len(rest.len, record, false, &requests).saturating_add(1)
        } else {
            0
        };
        if image_row(rows, &body_row).is_some() {
            lengths.push((body_row, body));
        } else if body > 0 {
            let beside = (capsule.len() as u64)
                .saturating_add(body_row.len() as u64)
                .saturating_add(body);
            lengths.push((row, beside));
        }
    }
    lengths
}
