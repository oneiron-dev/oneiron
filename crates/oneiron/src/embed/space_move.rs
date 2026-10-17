//! A kind slot's version move, checked before it swaps in (OF-370; ARCH-0004
//! `#swap-check-ruling` SWAP-CHECK = B, `#swap-check-not-worse` E2E G06 = A).
//!
//! A new model version fills a new declared space while the old one serves:
//! [`Vault::begin_space_move`] names the candidate, and the backfill fills it for every kind the
//! move carries, as if the slot bound it, while every search still reads the incumbent. Once the
//! candidate holds every document of those kinds, [`Vault::check_space_move`] runs the vault's
//! own probes ([`super::SpaceProbe`]) paired on both spaces, and on the incumbent twice for its
//! retest noise. A kind is not worse (NOT-WORSE = A, ARCH-0053 `#not-worse`) when the low end of
//! its family-grouped paired interval stays at or above minus that noise, or minus the owner's
//! stricter margin. Every kind not worse swaps the candidate in, automatically and with no
//! consent; the incumbent stays declared for [`Vault::undo_space_move`]. A kind whose whole
//! interval sits below the margin is worse: the incumbent keeps serving and the candidate's rows
//! go, so the vault tries again with the next model version. Too few probe families, or an
//! interval across the margin, reads unknown, and unknown never swaps automatically: the
//! incumbent keeps serving and the move stays open for a later check or the owner's yes
//! ([`Vault::approve_space_move`]). A swap, a keep and an undo each leave a short result note.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::space::{
    EmbeddingSpace, InputKind, KindSlotBindings, drop_space_rows_in_txn, embedding_space_in_txn,
    kind_slot_bindings_in_txn, search_media_space_in_txn, set_kind_slot_in_txn,
};
use super::space_probe::{SpaceProbe, space_probes_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// Ranks a probe reads: a target found below this depth scores as missed.
pub const SPACE_PROBE_DEPTH: usize = 10;
/// Fewest independent source families a kind needs before its interval is judged; fewer reads
/// unknown.
pub const SPACE_PROBE_MIN_FAMILIES: usize = 10;

/// Producer name of a space move's result note.
pub const SPACE_MOVE_NOTE_PRODUCER: &str = "embedding.space_move";

/// Open and concluded moves. Key: candidate space id string.
const EMBEDDING_MOVE: SideTable<String, SpaceMove, Named> =
    SideTable::new(&side_table::EMBEDDING_MOVE);

/// Where a kind slot's vectors are searched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceRef {
    /// The vault's own text vector index: the unbound text slot.
    TextIndex,
    /// A declared space.
    Declared(String),
}

impl SpaceRef {
    /// Whether `kind`'s slot reads here under `bindings`.
    fn serves(&self, bindings: &KindSlotBindings, kind: InputKind) -> bool {
        match self {
            Self::TextIndex => kind == InputKind::Text && bindings.text.is_none(),
            Self::Declared(id) => bindings.space_for(kind) == Some(id.as_str()),
        }
    }

    fn declared(&self) -> Option<&str> {
        match self {
            Self::TextIndex => None,
            Self::Declared(id) => Some(id),
        }
    }
}

impl std::fmt::Display for SpaceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TextIndex => f.write_str("the vault's text index"),
            Self::Declared(id) => write!(f, "embedding space {id}"),
        }
    }
}

/// A paired comparison's reading (NOT-WORSE = A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotWorse {
    /// The interval's low end is at or above minus the tolerance.
    NotWorse,
    /// The whole interval is below minus the tolerance.
    Worse,
    /// Too few families, or the interval spans the tolerance.
    Unknown,
}

/// A family-grouped mean paired difference and its two-sided 95% interval.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PairedInterval {
    pub mean: f32,
    pub low: f32,
    pub high: f32,
}

/// One kind's paired probe run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KindProbeCheck {
    pub kind: InputKind,
    /// Probes that ran: those of this kind with a live target.
    pub probes: usize,
    /// The independent source families those probes come from.
    pub families: usize,
    /// Candidate minus incumbent, of each probe's reciprocal rank at [`SPACE_PROBE_DEPTH`],
    /// averaged per family; `None` under [`SPACE_PROBE_MIN_FAMILIES`].
    pub difference: Option<PairedInterval>,
    /// The incumbent's second run minus its first, likewise: its same-probe retest.
    pub retest: Option<PairedInterval>,
    /// What the difference's low end is held to: the retest interval's widest bound, or the
    /// owner's stricter margin.
    pub tolerance: Option<f32>,
    pub verdict: NotWorse,
}

/// One paired probe run over every kind a move carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpaceMoveCheck {
    /// Vault seconds.
    pub checked_at: u64,
    pub kinds: Vec<KindProbeCheck>,
    /// Not worse when every kind is; worse when any kind is; unknown otherwise.
    pub verdict: NotWorse,
}

/// Where a move stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceMoveState {
    /// The candidate fills beside the incumbent, which serves.
    Open,
    /// The candidate serves; the incumbent stays declared for undo. `by_owner` is the owner's
    /// yes over a check that did not read not worse.
    SwappedIn { at: u64, by_owner: bool },
    /// The incumbent kept serving; the candidate's rows of the moved kinds went.
    Kept { at: u64 },
    /// An undo bound the incumbent again.
    Undone { at: u64 },
}

/// A kind slot version move: every kind slot the incumbent served, moving to the candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpaceMove {
    pub candidate: String,
    pub incumbent: SpaceRef,
    pub kinds: BTreeSet<InputKind>,
    /// The owner's margin, held only where it is stricter than the measured retest noise.
    pub margin: Option<f32>,
    /// Vault seconds.
    pub started_at: u64,
    pub state: SpaceMoveState,
    pub last_check: Option<SpaceMoveCheck>,
}

/// What [`Vault::check_space_move`] did.
#[derive(Debug, Clone, PartialEq)]
pub enum SpaceMoveOutcome {
    /// The candidate still lacks a vector of some moving document; no probe ran.
    Filling,
    /// Every kind read not worse: the candidate serves now.
    SwappedIn(SpaceMoveCheck),
    /// A kind read worse: the incumbent keeps serving and the move is closed.
    Kept(SpaceMoveCheck),
    /// A kind read unknown: the incumbent keeps serving and the move stays open.
    Undecided(SpaceMoveCheck),
}

/// The host's query towers for a probe run.
pub trait SpaceProbeEncoder {
    /// One probe query encoded into `space` through its text tower. Called afresh for every
    /// run, so two calls for the incumbent are its retest; a caching encoder reads no noise.
    fn encode_probe(&self, space: &SpaceRef, query: &str) -> Result<Vec<f32>>;
}

/// The kinds a backfill fills `space` for: those whose slot binds it, and those an open move
/// carries to it, that it accepts.
pub(crate) fn space_fill_kinds_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    space: &EmbeddingSpace,
) -> Result<BTreeSet<InputKind>> {
    let bindings = kind_slot_bindings_in_txn(store, txn)?;
    let mut kinds: BTreeSet<InputKind> = InputKind::ALL
        .into_iter()
        .filter(|kind| bindings.space_for(*kind) == Some(space.id.as_str()))
        .collect();
    if let Some(open) = EMBEDDING_MOVE
        .get(store, txn, &space.id)?
        .filter(|row| row.state == SpaceMoveState::Open)
    {
        kinds.extend(open.kinds);
    }
    kinds.retain(|kind| space.accepts.contains(kind));
    Ok(kinds)
}

/// Whether an open move names `space_id` as its candidate or its incumbent.
pub(crate) fn open_move_names_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    space_id: &str,
) -> Result<bool> {
    Ok(EMBEDDING_MOVE
        .scan(store, txn)?
        .into_iter()
        .any(|(_, row)| {
            row.state == SpaceMoveState::Open
                && (row.candidate == space_id || row.incumbent.declared() == Some(space_id))
        }))
}

/// The candidate of the open move that carries `kind`'s slot, when one does.
pub(crate) fn moving_kind_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    kind: InputKind,
) -> Result<Option<String>> {
    Ok(EMBEDDING_MOVE
        .scan(store, txn)?
        .into_iter()
        .find(|(_, row)| row.state == SpaceMoveState::Open && row.kinds.contains(&kind))
        .map(|(_, row)| row.candidate))
}

fn open_move_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    candidate: &str,
) -> Result<SpaceMove> {
    EMBEDDING_MOVE
        .get(store, txn, &candidate.to_owned())?
        .filter(|row| row.state == SpaceMoveState::Open)
        .ok_or_else(|| Error::InvalidConfig(format!("no open embedding space move to {candidate}")))
}

/// Refuses a move whose kinds no longer read where it began: a slot rebound by hand since.
fn check_bindings(moving: &SpaceMove, bindings: &KindSlotBindings) -> Result<()> {
    if let Some(kind) = moving
        .kinds
        .iter()
        .find(|kind| !moving.incumbent.serves(bindings, **kind))
    {
        return Err(Error::InvalidConfig(format!(
            "the {kind:?} slot no longer reads {} as the move to {} began; abandon the move",
            moving.incumbent, moving.candidate
        )));
    }
    Ok(())
}

/// One probe's three runs: the incumbent, its retest, and the candidate.
struct ProbeRun {
    kind: InputKind,
    family: EntityId,
    incumbent: f32,
    retest: f32,
    candidate: f32,
}

/// The reciprocal rank of `probe`'s first target among `hits`, zero when none is there.
fn reciprocal_rank(probe: &SpaceProbe, hits: &[ScoredEntity]) -> f32 {
    hits.iter()
        .position(|hit| probe.targets.contains(&hit.id))
        .map_or(0.0, |rank| 1.0 / (rank as f32 + 1.0))
}

/// Two-sided 95% Student t quantiles for 1..=30 degrees of freedom; 1.96 past them.
const T_975: [f64; 30] = [
    12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160,
    2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056,
    2.052, 2.048, 2.045, 2.042,
];

/// The mean of per-family values and its 95% t interval; `None` for fewer than two.
fn paired_interval(values: &[f64]) -> Option<PairedInterval> {
    let n = values.len();
    if n < 2 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / n as f64;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
    let t = T_975.get(n - 2).copied().unwrap_or(1.96);
    let half = t * (variance / n as f64).sqrt();
    Some(PairedInterval {
        mean: mean as f32,
        low: (mean - half) as f32,
        high: (mean + half) as f32,
    })
}

/// One kind's reading from its probes' runs.
fn judge_kind(kind: InputKind, runs: &[&ProbeRun], margin: Option<f32>) -> KindProbeCheck {
    let mut families: BTreeMap<EntityId, (f64, f64, usize)> = BTreeMap::new();
    for run in runs {
        let family = families.entry(run.family).or_default();
        family.0 += f64::from(run.candidate - run.incumbent);
        family.1 += f64::from(run.retest - run.incumbent);
        family.2 += 1;
    }
    let mut check = KindProbeCheck {
        kind,
        probes: runs.len(),
        families: families.len(),
        difference: None,
        retest: None,
        tolerance: None,
        verdict: NotWorse::Unknown,
    };
    if families.len() < SPACE_PROBE_MIN_FAMILIES {
        return check;
    }
    let (differences, retests): (Vec<f64>, Vec<f64>) = families
        .values()
        .map(|(difference, retest, n)| (difference / *n as f64, retest / *n as f64))
        .unzip();
    let (Some(difference), Some(retest)) =
        (paired_interval(&differences), paired_interval(&retests))
    else {
        return check;
    };
    let noise = retest.low.abs().max(retest.high.abs());
    let tolerance = margin.map_or(noise, |margin| margin.min(noise));
    check.verdict = if difference.low >= -tolerance {
        NotWorse::NotWorse
    } else if difference.high < -tolerance {
        NotWorse::Worse
    } else {
        NotWorse::Unknown
    };
    check.difference = Some(difference);
    check.retest = Some(retest);
    check.tolerance = Some(tolerance);
    check
}

/// The result note's one line: what moved where, and each kind's reading.
fn space_move_summary(moving: &SpaceMove) -> String {
    let kinds = moving
        .kinds
        .iter()
        .map(|kind| format!("{kind:?}").to_lowercase())
        .collect::<Vec<_>>()
        .join(", ");
    let head = match moving.state {
        SpaceMoveState::SwappedIn {
            by_owner: false, ..
        } => format!(
            "{kinds} search now uses embedding space {}; it scored not worse than {} on the \
             vault's own probes",
            moving.candidate, moving.incumbent
        ),
        SpaceMoveState::SwappedIn { by_owner: true, .. } => format!(
            "{kinds} search now uses embedding space {} on the owner's yes; {} stays for undo",
            moving.candidate, moving.incumbent
        ),
        SpaceMoveState::Kept { .. } => format!(
            "{kinds} search stays on {}; embedding space {} scored worse on the vault's own \
             probes",
            moving.incumbent, moving.candidate
        ),
        SpaceMoveState::Undone { .. } => format!(
            "{kinds} search is back on {}; the move to embedding space {} was undone",
            moving.incumbent, moving.candidate
        ),
        SpaceMoveState::Open => format!(
            "{kinds} search stays on {} while embedding space {} fills",
            moving.incumbent, moving.candidate
        ),
    };
    let Some(check) = &moving.last_check else {
        return head;
    };
    let readings = check
        .kinds
        .iter()
        .map(|kind| {
            let name = format!("{:?}", kind.kind).to_lowercase();
            match (kind.difference, kind.tolerance) {
                (Some(difference), Some(tolerance)) => format!(
                    "{name} {:?} over {} probes: {:+.3} [{:+.3}, {:+.3}], margin {:.3}",
                    kind.verdict,
                    kind.probes,
                    difference.mean,
                    difference.low,
                    difference.high,
                    tolerance
                ),
                _ => format!(
                    "{name} unknown: {} probes from {} families, {SPACE_PROBE_MIN_FAMILIES} needed",
                    kind.probes, kind.families
                ),
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("{head} ({readings})")
}

impl Vault {
    /// Leaves the short result note a concluded move owes the user (SWAP-CHECK = B): one
    /// NOTIFICATION per state the move reaches. How the note looks waits for co-design (RD-18).
    fn note_space_move_in_txn(&self, wtxn: &mut heed::RwTxn<'_>, moving: &SpaceMove) -> Result<()> {
        let (state, at) = match moving.state {
            SpaceMoveState::Open => return Ok(()),
            SpaceMoveState::SwappedIn { at, .. } => ("swapped_in", at),
            SpaceMoveState::Kept { at } => ("kept", at),
            SpaceMoveState::Undone { at } => ("undone", at),
        };
        self.record_notification_in_txn(
            wtxn,
            &crate::inbox::NotificationEvent {
                kind: crate::inbox::NotificationKind::Finding,
                source: crate::inbox::NotificationSource {
                    producer: SPACE_MOVE_NOTE_PRODUCER.to_owned(),
                    event: format!("{}#{state}@{at}", moving.candidate),
                    result: Some(space_move_summary(moving)),
                    ..crate::inbox::NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: None,
                created_at: at,
                origin_conversation: None,
            },
        )?;
        Ok(())
    }

    /// Starts moving every kind slot `incumbent` serves to declared space `candidate`: the
    /// candidate fills for those kinds while `incumbent` keeps serving them. `margin` is the
    /// owner's tolerance for [`Self::check_space_move`], held only where it is stricter than the
    /// measured retest noise; `None` holds the noise.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when a space is undeclared, the incumbent serves no slot, the
    /// candidate cannot serve one of its kinds, a kind already moves elsewhere, the candidate
    /// already has an open move, or the margin is not finite.
    pub fn begin_space_move(
        &self,
        candidate: &str,
        incumbent: SpaceRef,
        margin: Option<f32>,
    ) -> Result<SpaceMove> {
        if margin.is_some_and(|margin| !margin.is_finite()) {
            return Err(Error::InvalidConfig(
                "an embedding space move's margin must be finite".into(),
            ));
        }
        if incumbent.declared() == Some(candidate) {
            return Err(Error::InvalidConfig(format!(
                "embedding space {candidate} cannot move to itself"
            )));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let Some(space) = embedding_space_in_txn(&self.store, &wtxn, candidate)? else {
            return Err(Error::InvalidConfig(format!(
                "embedding space {candidate} is not declared"
            )));
        };
        if let Some(id) = incumbent.declared()
            && embedding_space_in_txn(&self.store, &wtxn, id)?.is_none()
        {
            return Err(Error::InvalidConfig(format!(
                "embedding space {id} is not declared"
            )));
        }
        let bindings = kind_slot_bindings_in_txn(&self.store, &wtxn)?;
        let kinds: BTreeSet<InputKind> = InputKind::ALL
            .into_iter()
            .filter(|kind| incumbent.serves(&bindings, *kind))
            .collect();
        if kinds.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "{incumbent} serves no kind slot"
            )));
        }
        for kind in &kinds {
            space.admit_binding(*kind)?;
        }
        for (_, other) in EMBEDDING_MOVE.scan(&self.store, &wtxn)? {
            if other.state != SpaceMoveState::Open {
                continue;
            }
            if other.candidate == candidate {
                return Err(Error::InvalidConfig(format!(
                    "a move to embedding space {candidate} is already open"
                )));
            }
            if let Some(kind) = other.kinds.intersection(&kinds).next() {
                return Err(Error::InvalidConfig(format!(
                    "the {kind:?} slot already moves to embedding space {}",
                    other.candidate
                )));
            }
        }
        let row = SpaceMove {
            candidate: candidate.to_owned(),
            incumbent,
            kinds,
            margin,
            started_at: self.store.clock.now_recorded_at(),
            state: SpaceMoveState::Open,
            last_check: None,
        };
        EMBEDDING_MOVE.put(&self.store, &mut wtxn, &row.candidate, &row)?;
        wtxn.commit()?;
        Ok(row)
    }

    /// Every move, open and concluded, in candidate id order.
    pub fn space_moves(&self) -> Result<Vec<SpaceMove>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(EMBEDDING_MOVE
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, row)| row)
            .collect())
    }

    /// Ends an open move without a swap: the incumbent keeps serving, and the candidate's rows
    /// of the moving kinds go (its declaration too, when no slot binds it).
    pub fn abandon_space_move(&self, candidate: &str) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let moving = open_move_in_txn(&self.store, &wtxn, candidate)?;
        EMBEDDING_MOVE.delete(&self.store, &mut wtxn, &moving.candidate)?;
        drop_space_rows_in_txn(&self.store, &mut wtxn, candidate, &moving.kinds)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Runs the vault's probes paired on an open move's incumbent and candidate, and concludes
    /// the move by the reading: every kind not worse swaps the candidate in; a kind worse keeps
    /// the incumbent and closes the move; a kind unknown keeps the incumbent and the move open.
    /// While the candidate lacks a vector of some moving document no probe runs
    /// ([`SpaceMoveOutcome::Filling`]). Each probe is encoded outside any transaction: twice
    /// into the incumbent, once into the candidate.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when no move to `candidate` is open, a space it names is gone,
    /// or a slot it moves was rebound since it began; encoder and storage errors otherwise.
    pub fn check_space_move(
        &self,
        candidate: &str,
        encoder: &dyn SpaceProbeEncoder,
    ) -> Result<SpaceMoveOutcome> {
        let (moving, candidate_space, incumbent_space, probes) = {
            let rtxn = self.store.env.read_txn()?;
            let moving = open_move_in_txn(&self.store, &rtxn, candidate)?;
            check_bindings(&moving, &kind_slot_bindings_in_txn(&self.store, &rtxn)?)?;
            let Some(candidate_space) = embedding_space_in_txn(&self.store, &rtxn, candidate)?
            else {
                return Err(Error::InvalidConfig(format!(
                    "embedding space {candidate} is not declared"
                )));
            };
            let mut report = super::MediaEmbedReport::default();
            if !self
                .media_backlog_in_txn(&rtxn, &candidate_space, &moving.kinds, 1, &mut report)?
                .is_empty()
            {
                return Ok(SpaceMoveOutcome::Filling);
            }
            let incumbent_space = match &moving.incumbent {
                SpaceRef::TextIndex => self.text_index_space(),
                SpaceRef::Declared(id) => embedding_space_in_txn(&self.store, &rtxn, id)?
                    .ok_or_else(|| {
                        Error::InvalidConfig(format!("embedding space {id} is not declared"))
                    })?,
            };
            let mut probes = Vec::new();
            for (_, probe) in space_probes_in_txn(&self.store, &rtxn)? {
                if !moving.kinds.contains(&probe.kind) {
                    continue;
                }
                let mut live = false;
                for target in &probe.targets {
                    live |= crate::ports::EntityStoreRead::port_entity_record(
                        &self.store,
                        &rtxn,
                        target,
                    )?
                    .is_some();
                }
                if live {
                    probes.push(probe);
                }
            }
            (moving, candidate_space, incumbent_space, probes)
        };

        // A probe is a text query, so it enters a space only through a text tower; a space
        // without one runs no probe and its kinds read unknown.
        let towers = candidate_space.query_towers.contains(&InputKind::Text)
            && incumbent_space.query_towers.contains(&InputKind::Text);
        let candidate_ref = SpaceRef::Declared(candidate.to_owned());
        let mut encoded = Vec::new();
        if towers {
            for probe in &probes {
                let first = encoder.encode_probe(&moving.incumbent, &probe.query)?;
                let retest = encoder.encode_probe(&moving.incumbent, &probe.query)?;
                let next = encoder.encode_probe(&candidate_ref, &probe.query)?;
                incumbent_space.admit_query(InputKind::Text, &first)?;
                incumbent_space.admit_query(InputKind::Text, &retest)?;
                candidate_space.admit_query(InputKind::Text, &next)?;
                encoded.push((probe, first, retest, next));
            }
        }

        let runs = {
            let rtxn = self.store.env.read_txn()?;
            let search = |space: &SpaceRef, kind: InputKind, query: &[f32]| match space {
                SpaceRef::TextIndex => crate::ports::RetrievalIndex::port_retrieval_vector_search(
                    self,
                    &rtxn,
                    query,
                    SPACE_PROBE_DEPTH,
                ),
                SpaceRef::Declared(id) => {
                    let space = if *id == candidate_space.id {
                        &candidate_space
                    } else {
                        &incumbent_space
                    };
                    search_media_space_in_txn(
                        &self.store,
                        &rtxn,
                        space,
                        query,
                        &[kind],
                        SPACE_PROBE_DEPTH,
                        |_| Ok(true),
                    )
                }
            };
            let mut runs = Vec::with_capacity(encoded.len());
            for (probe, first, retest, next) in &encoded {
                runs.push(ProbeRun {
                    kind: probe.kind,
                    family: probe.family,
                    incumbent: reciprocal_rank(
                        probe,
                        &search(&moving.incumbent, probe.kind, first)?,
                    ),
                    retest: reciprocal_rank(probe, &search(&moving.incumbent, probe.kind, retest)?),
                    candidate: reciprocal_rank(probe, &search(&candidate_ref, probe.kind, next)?),
                });
            }
            runs
        };

        let kinds: Vec<KindProbeCheck> = moving
            .kinds
            .iter()
            .map(|kind| {
                let of_kind: Vec<&ProbeRun> = runs.iter().filter(|run| run.kind == *kind).collect();
                judge_kind(*kind, &of_kind, moving.margin)
            })
            .collect();
        let verdict = if kinds.iter().all(|kind| kind.verdict == NotWorse::NotWorse) {
            NotWorse::NotWorse
        } else if kinds.iter().any(|kind| kind.verdict == NotWorse::Worse) {
            NotWorse::Worse
        } else {
            NotWorse::Unknown
        };
        let check = SpaceMoveCheck {
            checked_at: self.store.clock.now_recorded_at(),
            kinds,
            verdict,
        };
        self.conclude_space_move(candidate, Some(check), false)
    }

    /// The owner's yes to an open move whose check did not read not worse: once the candidate
    /// holds every moving document, it swaps in as a passing check would, and the incumbent
    /// stays for undo.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when no move to `candidate` is open, the candidate is still
    /// filling, or a slot it moves was rebound since it began.
    pub fn approve_space_move(&self, candidate: &str) -> Result<()> {
        let check = {
            let rtxn = self.store.env.read_txn()?;
            let moving = open_move_in_txn(&self.store, &rtxn, candidate)?;
            let Some(space) = embedding_space_in_txn(&self.store, &rtxn, candidate)? else {
                return Err(Error::InvalidConfig(format!(
                    "embedding space {candidate} is not declared"
                )));
            };
            let mut report = super::MediaEmbedReport::default();
            if !self
                .media_backlog_in_txn(&rtxn, &space, &moving.kinds, 1, &mut report)?
                .is_empty()
            {
                return Err(Error::InvalidConfig(format!(
                    "embedding space {candidate} is still filling"
                )));
            }
            moving.last_check
        };
        self.conclude_space_move(candidate, check, true).map(|_| ())
    }

    /// Binds a swapped-in move's incumbent again for every kind it moved: the one-click undo.
    /// The candidate stays declared, and the backfill fills the incumbent again for what
    /// arrived since.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the move to `candidate` has not swapped in, a slot it moved
    /// no longer binds the candidate, or the incumbent space is retired.
    pub fn undo_space_move(&self, candidate: &str) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let Some(mut moving) = EMBEDDING_MOVE
            .get(&self.store, &wtxn, &candidate.to_owned())?
            .filter(|row| matches!(row.state, SpaceMoveState::SwappedIn { .. }))
        else {
            return Err(Error::InvalidConfig(format!(
                "no swapped-in embedding space move to {candidate}"
            )));
        };
        let bindings = kind_slot_bindings_in_txn(&self.store, &wtxn)?;
        if let Some(kind) = moving
            .kinds
            .iter()
            .find(|kind| bindings.space_for(**kind) != Some(candidate))
        {
            return Err(Error::InvalidConfig(format!(
                "the {kind:?} slot no longer binds embedding space {candidate}"
            )));
        }
        let incumbent = moving.incumbent.declared();
        if let Some(id) = incumbent
            && embedding_space_in_txn(&self.store, &wtxn, id)?.is_none()
        {
            return Err(Error::InvalidConfig(format!(
                "embedding space {id} is retired; the move cannot be undone"
            )));
        }
        for kind in &moving.kinds {
            set_kind_slot_in_txn(&self.store, &mut wtxn, *kind, incumbent)?;
        }
        let at = self.store.clock.now_recorded_at();
        moving.state = SpaceMoveState::Undone { at };
        self.note_space_move_in_txn(&mut wtxn, &moving)?;
        EMBEDDING_MOVE.put(&self.store, &mut wtxn, &moving.candidate, &moving)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Records `check` on the open move to `candidate` and acts on it: a passing check, or the
    /// owner's yes, binds the candidate for every moving kind; a worse one closes the move and
    /// drops the candidate's rows; an unknown one leaves the move open.
    fn conclude_space_move(
        &self,
        candidate: &str,
        check: Option<SpaceMoveCheck>,
        by_owner: bool,
    ) -> Result<SpaceMoveOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut moving = open_move_in_txn(&self.store, &wtxn, candidate)?;
        check_bindings(&moving, &kind_slot_bindings_in_txn(&self.store, &wtxn)?)?;
        let verdict = check
            .as_ref()
            .map_or(NotWorse::Unknown, |check| check.verdict);
        let at = self.store.clock.now_recorded_at();
        let concluded = if by_owner || verdict == NotWorse::NotWorse {
            for kind in &moving.kinds {
                set_kind_slot_in_txn(&self.store, &mut wtxn, *kind, Some(candidate))?;
            }
            moving.state = SpaceMoveState::SwappedIn {
                at,
                by_owner: by_owner && verdict != NotWorse::NotWorse,
            };
            true
        } else if verdict == NotWorse::Worse {
            moving.state = SpaceMoveState::Kept { at };
            true
        } else {
            false
        };
        if check.is_some() {
            moving.last_check.clone_from(&check);
        }
        EMBEDDING_MOVE.put(&self.store, &mut wtxn, &moving.candidate, &moving)?;
        if matches!(moving.state, SpaceMoveState::Kept { .. }) {
            drop_space_rows_in_txn(&self.store, &mut wtxn, candidate, &moving.kinds)?;
        }
        if concluded {
            self.note_space_move_in_txn(&mut wtxn, &moving)?;
        }
        wtxn.commit()?;
        let check = check.unwrap_or(SpaceMoveCheck {
            checked_at: at,
            kinds: Vec::new(),
            verdict,
        });
        Ok(match moving.state {
            SpaceMoveState::SwappedIn { .. } => SpaceMoveOutcome::SwappedIn(check),
            SpaceMoveState::Kept { .. } => SpaceMoveOutcome::Kept(check),
            SpaceMoveState::Open | SpaceMoveState::Undone { .. } => {
                SpaceMoveOutcome::Undecided(check)
            }
        })
    }
}
