//! A space move check's probe cohort metadata (FIX 6744; ARCH-0053 `#eval-exposure`): the
//! date-cut cohort each probe it runs belongs to, each kind's one fixed reference cohort, and
//! what the check served from them, kept in the exposure ledger under the `space_probe.<kind>`
//! seats (`Vault::record_space_probe_cohort_metadata`). Metadata only: nothing here drops,
//! filters or reorders a probe or moves the check's reading. Every write is its own, made
//! outside any transaction the check holds, and a failed one is logged and dropped. There is
//! no retirement threshold: exposure is counted, and no cohort is retired or released.

use std::collections::BTreeMap;
use std::ops::Range;

use heed::RoTxn;

use super::{SPACE_PROBE_COHORT_SECS, SpaceProbe, cohort_of};
use crate::Vault;
use crate::embed::media::PendingMedia;
use crate::embed::space::InputKind;
use crate::embed::{CohortProbe, SpaceMoveCheck};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::skill_optimize::EvalExposureKind;

/// The exposures one probe's serving counts, just before the check encodes it (FIX 6744
/// CALLS): one query for its three runs together, and the candidate's scoring once per cohort
/// and check.
const SERVED_EXPOSURES: [EvalExposureKind; 2] =
    [EvalExposureKind::Query, EvalExposureKind::Candidate];
/// The exposure a swap the check decided counts, once per cohort it served (FIX 6744 CALLS).
const SWAP_EXPOSURES: [EvalExposureKind; 1] = [EvalExposureKind::Promotion];

/// One probe as the ledger holds it: its id, its source document and its date window.
type Member = ([u8; 16], EntityId, Range<u64>);

/// A probe id from the 32 hex [`CohortProbe::probe`] holds.
fn probe_from_hex(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut id = [0_u8; 16];
    for (byte, pair) in id.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(id)
}

/// The cut policy (FIX 6744 CALLS): a date window is cut into a cohort only once it has
/// ended by `now`, as an eval cohort is cut from a past window. Until then its probes have no
/// cohort and count no exposure.
fn window_ended(window: &Range<u64>, now: u64) -> bool {
    window.end <= now
}

/// The reference policy (FIX 6744 CALLS): of a kind's `windows`, the newest that has ended by
/// `now`; `None` while none has, and the reference waits for a later check.
fn reference_window(windows: impl Iterator<Item = Range<u64>>, now: u64) -> Option<Range<u64>> {
    windows
        .filter(|window| window_ended(window, now))
        .max_by_key(|window| window.start)
}

/// The date cut policy (FIX 6744 CALLS): a probe's window starts at its stored cohort. One put
/// by hand, with none, starts where its source document's `learned_at` falls, read at the
/// check and never written back. A source gone or unreadable leaves it with no window: it runs
/// as before, logged, and joins no cohort.
fn probe_window(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &[u8; 16],
    probe: &SpaceProbe,
) -> Option<Range<u64>> {
    let start = match probe.cohort {
        Some(start) => start,
        None => match vault.store.port_entity_record(txn, &probe.family) {
            Ok(Some(row)) => cohort_of(row.learned_at),
            Ok(None) => {
                tracing::info!(
                    probe = %bytes_to_hex_lower(id),
                    "a hand-put space probe's source is gone; it joins no cohort"
                );
                return None;
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    probe = %bytes_to_hex_lower(id),
                    "a hand-put space probe's source was not read; it joins no cohort"
                );
                return None;
            }
        },
    };
    Some(start..start.saturating_add(SPACE_PROBE_COHORT_SECS))
}

/// The ended windows of the `probes` whose query enters a space through a tower both spaces
/// have, as the check's own runs do, on a read of its own that closes before any write opens.
fn members_in(
    vault: &Vault,
    probes: &[([u8; 16], SpaceProbe, Option<PendingMedia>)],
    towers: impl Fn(InputKind) -> bool,
    now: u64,
) -> Result<BTreeMap<[u8; 16], (InputKind, EntityId, Range<u64>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut members = BTreeMap::new();
    for (id, probe, query) in probes {
        if !towers(query.as_ref().map_or(InputKind::Text, |media| media.kind)) {
            continue;
        }
        if let Some(window) =
            probe_window(vault, &rtxn, id, probe).filter(|window| window_ended(window, now))
        {
            members.insert(*id, (probe.kind, probe.family, window));
        }
    }
    Ok(members)
}

/// One check's probe cohort metadata.
pub(in crate::embed) struct ProbeCohortLedger {
    /// The check's fresh token and the candidate it measures; `None` when no token was made,
    /// and nothing is kept.
    check: Option<(String, String)>,
    /// Each probe the check runs whose window has ended: its kind, source document and window.
    members: BTreeMap<[u8; 16], (InputKind, EntityId, Range<u64>)>,
    /// Each kind's answer-key version, the rubric its cohorts are cut under.
    rubrics: BTreeMap<InputKind, String>,
}

impl ProbeCohortLedger {
    /// Keeps the cohorts of the `probes` a check of the move to `candidate` is about to run,
    /// those whose query has its tower in both spaces (`towers`): each kind's reference is
    /// decided first, then its other ended windows are cut. Called outside any transaction.
    pub(in crate::embed) fn prepare(
        vault: &Vault,
        candidate: &str,
        probes: &[([u8; 16], SpaceProbe, Option<PendingMedia>)],
        towers: impl Fn(InputKind) -> bool,
        versions: &BTreeMap<InputKind, (String, String)>,
    ) -> Self {
        let mut ledger = Self {
            check: None,
            members: BTreeMap::new(),
            rubrics: versions
                .iter()
                .map(|(kind, (_, rubric))| (*kind, rubric.clone()))
                .collect(),
        };
        let now = vault.store.clock.now_recorded_at();
        let read = vault.store.clock.entity_id().and_then(|token| {
            members_in(vault, probes, towers, now).map(|members| (token, members))
        });
        let (token, members) = match read {
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    candidate = %candidate,
                    "a space move check keeps no probe cohort metadata; the check stands"
                );
                return ledger;
            }
        };
        ledger.check = Some((
            format!("space_move.check:{}", token.to_hex()),
            candidate.to_owned(),
        ));
        ledger.members = members;
        for (kind, members) in ledger.by_kind(ledger.members.keys().copied()) {
            let reference =
                reference_window(members.iter().map(|(_, _, window)| window.clone()), now);
            ledger.record(vault, kind, &members, reference, &[]);
        }
        ledger
    }

    /// Counts `probe`'s serving just before the check encodes it: a query, and the candidate's
    /// scoring once per cohort and check. A probe with no ended window counts nothing. Called
    /// outside any transaction.
    pub(in crate::embed) fn served(&self, vault: &Vault, probe: &[u8; 16]) {
        if let Some((kind, family, window)) = self.members.get(probe) {
            let member = [(*probe, *family, window.clone())];
            self.record(vault, *kind, &member, None, &SERVED_EXPOSURES);
        }
    }

    /// Counts the swap the check decided on each cohort its `runs` served, once per cohort,
    /// after the move's own write committed. Called outside any transaction.
    pub(in crate::embed) fn promoted(&self, vault: &Vault, runs: impl Iterator<Item = [u8; 16]>) {
        for (kind, members) in self.by_kind(runs) {
            self.record(vault, kind, &members, None, &SWAP_EXPOSURES);
        }
    }

    /// Keeps on `check` what its swap counts on: its token and, on each kind, the ledger's
    /// members among its `runs`. A check that kept no metadata keeps nothing.
    pub(in crate::embed) fn keep_on(
        &self,
        check: &mut SpaceMoveCheck,
        runs: impl Iterator<Item = [u8; 16]>,
    ) {
        let Some((token, _)) = &self.check else {
            return;
        };
        check.cohort_check = Some(token.clone());
        let mut kinds = self.by_kind(runs);
        for kind in &mut check.kinds {
            kind.cohort_members = kinds
                .remove(&kind.kind)
                .unwrap_or_default()
                .into_iter()
                .map(|(probe, source, window)| CohortProbe {
                    probe: bytes_to_hex_lower(&probe),
                    source,
                    from: window.start,
                    until: window.end,
                })
                .collect();
        }
    }

    /// Counts the owner's yes over `check`, the check of the move to `candidate` it acted on,
    /// as the swap that check would have decided (FIX 7040): once per cohort the members it
    /// kept served, under its own token, after the move's own write committed. A check that
    /// kept no metadata counts nothing. Called outside any transaction.
    pub(in crate::embed) fn promoted_from(vault: &Vault, candidate: &str, check: &SpaceMoveCheck) {
        let Some(token) = &check.cohort_check else {
            return;
        };
        let mut ledger = Self {
            check: Some((token.clone(), candidate.to_owned())),
            members: BTreeMap::new(),
            rubrics: BTreeMap::new(),
        };
        for kind in &check.kinds {
            if let Some(rubric) = &kind.rubric {
                ledger.rubrics.insert(kind.kind, rubric.clone());
            }
            for member in &kind.cohort_members {
                if let Some(probe) = probe_from_hex(&member.probe) {
                    ledger
                        .members
                        .insert(probe, (kind.kind, member.source, member.from..member.until));
                }
            }
        }
        ledger.promoted(vault, ledger.members.keys().copied());
    }

    /// The ledger's members among `probes`, by kind.
    fn by_kind(&self, probes: impl Iterator<Item = [u8; 16]>) -> BTreeMap<InputKind, Vec<Member>> {
        let mut kinds: BTreeMap<InputKind, Vec<Member>> = BTreeMap::new();
        for probe in probes {
            if let Some((kind, family, window)) = self.members.get(&probe) {
                kinds
                    .entry(*kind)
                    .or_default()
                    .push((probe, *family, window.clone()));
            }
        }
        kinds
    }

    /// One write of `members` of `kind`, in a transaction of its own; one that fails is logged
    /// and dropped, and the check goes on as before.
    fn record(
        &self,
        vault: &Vault,
        kind: InputKind,
        members: &[Member],
        reference: Option<Range<u64>>,
        exposures: &[EvalExposureKind],
    ) {
        let (Some((token, candidate)), Some(rubric)) = (&self.check, self.rubrics.get(&kind))
        else {
            return;
        };
        if members.is_empty() {
            return;
        }
        let name = format!("{kind:?}").to_lowercase();
        let at = vault.store.clock.now_recorded_at();
        if let Err(error) = vault.record_space_probe_cohort_metadata(
            &name,
            rubric,
            members,
            reference,
            exposures,
            token,
            Some(candidate.as_str()),
            at,
        ) {
            tracing::warn!(
                kind = ?error.kind(),
                probe_kind = %name,
                candidate = %candidate,
                probes = members.len(),
                "space probe cohort metadata was not recorded; the check stands"
            );
        }
    }
}
