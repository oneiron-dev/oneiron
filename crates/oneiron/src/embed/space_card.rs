//! What a space move's check stands on beside its paired interval (FIX 1638; ARCH-0053
//! `#eval-sufficiency`, `#eval-canary`, `#r3-reliability`).
//!
//! Each kind's reading is read again on its sufficiency card, as every not-worse decision is. The
//! card reads unknown when the kind's probe set, or its answer key, moved while the runs were
//! made, or when the unrewarded canary diverges from the scored reciprocal rank: the canary is
//! whether a target is found within [`SPACE_PROBE_DEPTH`] at all, which no move optimises. A
//! kind it reads unknown for those reasons waits for the owner's yes instead of swapping
//! automatically ([`crate::Vault::approve_space_move`], unchanged); the interval's own reading
//! is the check's, as before. The incumbent's same-probe retest of each probe is recorded as
//! `learning.retest_noise`, scored by the space, after the move's own write, so a recording that
//! fails is logged and never fails the move.

use std::collections::BTreeMap;

use super::space::{InputKind, space_setup_id, text_index_setup_id};
use super::space_move::{
    KindProbeCheck, NotWorse, SPACE_PROBE_DEPTH, SPACE_PROBE_MIN_FAMILIES, SpaceMove,
    SpaceMoveCheck, SpaceRef, move_verdict,
};
use super::space_probe::SpaceProbe;
use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::learning::{Retest, RetestScore, record_retest};
use crate::skill_optimize::{SufficiencyInput, sufficiency_card};

/// One probe's two runs on the incumbent: the same query encoded twice, its retest.
pub(super) struct ProbeRetest {
    pub(super) probe: [u8; 16],
    pub(super) kind: InputKind,
    pub(super) first: f32,
    pub(super) second: f32,
}

/// The versions of `kind`'s probe set and of its answer key, each 32 hex, over the stored
/// `probes`: the set is which probes of the kind are stored (each id names its kind, family,
/// query and media query); the key is each one's targets and how a run is scored.
pub(super) fn probe_versions(
    probes: &[([u8; 16], SpaceProbe)],
    kind: InputKind,
) -> (String, String) {
    let mut set = blake3::Hasher::new();
    set.update(b"oneiron/space_probe_set/v1");
    set.update(&[kind as u8]);
    let mut key = blake3::Hasher::new();
    key.update(b"oneiron/space_probe_rubric/v1");
    key.update(&(SPACE_PROBE_DEPTH as u64).to_le_bytes());
    key.update(&[kind as u8]);
    for (id, probe) in probes.iter().filter(|(_, probe)| probe.kind == kind) {
        set.update(id);
        key.update(id);
        key.update(&(probe.targets.len() as u64).to_le_bytes());
        for target in &probe.targets {
            key.update(target.as_bytes());
        }
    }
    let hex = |hasher: blake3::Hasher| bytes_to_hex_lower(&hasher.finalize().as_bytes()[..16]);
    (hex(set), hex(key))
}

/// `check` with each kind read on its sufficiency card against the `probes` stored now, and
/// the move's verdict read again from the kinds. A kind that read not worse reads unknown when
/// its probe set or answer key is not the one its runs used, or its canary diverged: it waits
/// for the owner's yes. Nothing else moves: a worse kind stays worse, and a card that cannot be
/// read (an owner margin below zero) is left off, the reading as before.
pub(super) fn read_cards(
    mut check: SpaceMoveCheck,
    margin: Option<f32>,
    probes: &[([u8; 16], SpaceProbe)],
) -> SpaceMoveCheck {
    for kind in &mut check.kinds {
        let (set_now, rubric_now) = probe_versions(probes, kind.kind);
        let set_changed = kind.set_version.as_deref() != Some(set_now.as_str());
        let rubric_changed = kind.rubric.as_deref() != Some(rubric_now.as_str());
        let canary_diverged = canary_diverged(kind);
        let families = u32::try_from(kind.families).unwrap_or(u32::MAX);
        kind.card = sufficiency_card(SufficiencyInput {
            families,
            floor_slices: BTreeMap::from([(format!("{:?}", kind.kind).to_lowercase(), families)]),
            min_families_per_slice: u32::try_from(SPACE_PROBE_MIN_FAMILIES).unwrap_or(u32::MAX),
            retest_noise: kind
                .retest
                .map(|retest| f64::from(retest.low.abs().max(retest.high.abs()))),
            owner_margin: margin.map(f64::from),
            paired_interval: kind
                .difference
                .map(|difference| (f64::from(difference.low), f64::from(difference.high))),
            detectable_effect: None,
            set_changed,
            rubric_changed,
            canary_diverged,
        })
        .ok();
        if kind.verdict == NotWorse::NotWorse && (set_changed || rubric_changed || canary_diverged)
        {
            kind.verdict = NotWorse::Unknown;
        }
    }
    check.verdict = move_verdict(&check.kinds);
    check
}

/// Whether `kind`'s canary reads the other way from its scored reading: one not worse, the
/// other worse.
fn canary_diverged(kind: &KindProbeCheck) -> bool {
    matches!(
        (kind.verdict, kind.canary_verdict),
        (NotWorse::NotWorse, Some(NotWorse::Worse)) | (NotWorse::Worse, Some(NotWorse::NotWorse))
    )
}

/// Records each probe's retest of `moving`'s incumbent from the check made at `checked_at` as
/// `learning.retest_noise` (`learning::record_retest`): scored by the incumbent space, on the
/// reciprocal rank at [`SPACE_PROBE_DEPTH`] of the probe's kind, one receipt per probe and
/// check. The move's write is already done: a recording that fails is logged, stops the rest,
/// and never fails the move.
pub(super) fn record_space_retests(
    vault: &Vault,
    moving: &SpaceMove,
    checked_at: u64,
    retests: &[ProbeRetest],
) {
    let not_recorded = |error: &crate::error::Error| {
        tracing::warn!(
            kind = ?error.kind(),
            candidate = %moving.candidate,
            "a space move's retest noise was not recorded; the move stands"
        );
    };
    let (scorer, executor) = match scorer_of(&moving.incumbent) {
        Ok(scorer) => scorer,
        Err(error) => return not_recorded(&error),
    };
    let now = vault.store.clock.now_recorded_at();
    for retest in retests {
        let kind = format!("{:?}", retest.kind).to_lowercase();
        let row = Retest {
            scorer,
            executor: executor.clone(),
            axis: format!("space_probe.{kind}.reciprocal_rank@{SPACE_PROBE_DEPTH}"),
            type_ref: None,
            receipt: retest_receipt(&moving.candidate, checked_at, &retest.probe),
            first: RetestScore::Value(f64::from(retest.first)),
            second: RetestScore::Value(f64::from(retest.second)),
            at: checked_at,
        };
        if let Err(error) = record_retest(vault, &row, now) {
            return not_recorded(&error);
        }
    }
}

/// The scorer a space's retest names, and its executor: a declared space's own setup row id
/// and its id, or the vault's text index.
fn scorer_of(incumbent: &SpaceRef) -> Result<(EntityId, String)> {
    match incumbent {
        SpaceRef::Declared(id) => Ok((space_setup_id(id)?, id.clone())),
        SpaceRef::TextIndex => Ok((text_index_setup_id()?, "text_index".to_owned())),
    }
}

/// One retest's receipt: the move, the check and the probe, hashed to a bounded reference.
fn retest_receipt(candidate: &str, checked_at: u64, probe: &[u8; 16]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron/space_move_retest/v1");
    hasher.update(&(candidate.len() as u64).to_le_bytes());
    hasher.update(candidate.as_bytes());
    hasher.update(&checked_at.to_le_bytes());
    hasher.update(probe);
    format!(
        "space_move:{}",
        bytes_to_hex_lower(&hasher.finalize().as_bytes()[..16])
    )
}
