//! `duplicate_work` on action digests (agent-mind §3.4, OF-568): two attempts
//! ran the same action on the same input snapshot, an equal known action
//! digest on their runs' bridge calls, and the pattern did not plan it. Two
//! members of one team whose pattern runs members on the same work by design
//! are planned redundancy; a pair whose team cannot be told is unknown. A
//! call whose inputs were not captured is never equal to another. Every pair
//! gets its `dup_of` label under its team (agent-mind §3.4: "the health
//! recipe or an audit writes it"); only a redundant one is a finding.

use std::collections::{BTreeMap, BTreeSet};

use super::{Attempts, Dispatches, entity};
use crate::agent_dispatch::{TeamRunStamp, attempt_team_stamp};
use crate::learning::DuplicateWorkKind;
use crate::team::{TeamPattern, team_spawn_context_for_attempt};
use crate::{Result, Vault};

/// Two attempts that ran one action on the same inputs, `second` after
/// `first`.
pub(super) struct DigestPair {
    pub(super) first: [u8; 16],
    pub(super) second: [u8; 16],
    pub(super) kind: DuplicateWorkKind,
    /// The team its label goes under: the second's own stamp, else the
    /// first's. A pair with neither has no label key.
    pub(super) team: Option<String>,
}

/// Whether `pattern` runs members on the same work by design: "a vote, a
/// committee or an independent checker is excluded by the pattern on the
/// team receipt" (agent-mind §3.4). A market's referee judges members that
/// each did the work.
pub(super) const fn plans_redundancy(pattern: TeamPattern) -> bool {
    matches!(
        pattern,
        TeamPattern::Committee | TeamPattern::Vote | TeamPattern::Market
    )
}

/// Each pair of attempts updated since `since` in which the second ran an
/// action the first had run first on the same inputs, with what the repeat
/// was.
pub(super) fn digest_duplicates(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    since: u64,
) -> Result<Vec<DigestPair>> {
    // Each digest's runs: when each attempt first ran it.
    let mut runs: BTreeMap<String, Vec<(u64, [u8; 16])>> = BTreeMap::new();
    for key in dispatched.keys() {
        let Some(record) = attempts
            .get(key)
            .filter(|record| record.updated_at >= since)
        else {
            continue;
        };
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let Some(run) = vault.get_code_run_replay_record(&attempt)? else {
            continue;
        };
        let mut first: BTreeMap<&str, u64> = BTreeMap::new();
        for call in &run.bridge_calls {
            if let Some(digest) = call.action_digest.as_deref() {
                let at = first.entry(digest).or_insert(call.started_at_ms);
                *at = (*at).min(call.started_at_ms);
            }
        }
        for (digest, at) in first {
            runs.entry(digest.to_owned()).or_default().push((at, *key));
        }
    }
    let mut teams: BTreeMap<[u8; 16], Option<Option<TeamRunStamp>>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for mut ran in runs.into_values().filter(|ran| ran.len() > 1) {
        ran.sort_unstable();
        let (_, first) = ran[0];
        for &(_, second) in &ran[1..] {
            if !seen.insert((first, second)) {
                continue;
            }
            let team = [second, first]
                .iter()
                .filter_map(|key| attempts.get(key))
                .find_map(|record| attempt_team_stamp(record).ok().flatten())
                .map(|stamp| stamp.team_ref);
            out.push(DigestPair {
                first,
                second,
                kind: kind(vault, attempts, &mut teams, first, second),
                team,
            });
        }
    }
    Ok(out)
}

/// What `second` repeating `first` was: a planned check when both work in
/// one team whose pattern plans the overlap, unknown when a team cannot be
/// told, else redundant.
fn kind(
    vault: &Vault,
    attempts: &Attempts,
    teams: &mut BTreeMap<[u8; 16], Option<Option<TeamRunStamp>>>,
    first: [u8; 16],
    second: [u8; 16],
) -> DuplicateWorkKind {
    let mut team = |key: [u8; 16]| {
        teams
            .entry(key)
            .or_insert_with(|| {
                let record = attempts.get(&key)?;
                team_spawn_context_for_attempt(vault, record.id).ok()
            })
            .clone()
    };
    match (team(first), team(second)) {
        (Some(Some(first)), Some(Some(second)))
            if first.team_ref == second.team_ref && plans_redundancy(first.pattern) =>
        {
            DuplicateWorkKind::PlannedCheck
        }
        (Some(_), Some(_)) => DuplicateWorkKind::Redundant,
        // A team the host could not tell may have planned it.
        _ => DuplicateWorkKind::Unknown,
    }
}
