//! `duplicate_work` on action digests (agent-mind §3.4, OF-568): two attempts
//! ran the same action on the same input snapshot, an equal known action
//! digest on their runs' bridge calls, and the pattern did not plan it. Two
//! members of one team whose pattern runs members on the same work by design
//! are planned redundancy; so is a pair whose team cannot be told. A call
//! whose inputs were not captured is never equal to another.

use std::collections::{BTreeMap, BTreeSet};

use super::{Attempts, Dispatches, entity};
use crate::agent_dispatch::TeamRunStamp;
use crate::team::{TeamPattern, team_spawn_context_for_attempt};
use crate::{Result, Vault};

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

/// Each attempt updated since `since` that ran an action another attempt
/// had run first on the same inputs, by attempt bytes, with those earlier
/// attempts.
pub(super) fn digest_duplicates(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    since: u64,
) -> Result<BTreeMap<[u8; 16], BTreeSet<[u8; 16]>>> {
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
    let mut out: BTreeMap<[u8; 16], BTreeSet<[u8; 16]>> = BTreeMap::new();
    for mut ran in runs.into_values().filter(|ran| ran.len() > 1) {
        ran.sort_unstable();
        let (_, first) = ran[0];
        for &(_, second) in &ran[1..] {
            if !planned(vault, attempts, &mut teams, first, second) {
                out.entry(second).or_default().insert(first);
            }
        }
    }
    Ok(out)
}

/// Whether `first` and `second` work in one team whose pattern plans the
/// overlap, or in teams that cannot be told.
fn planned(
    vault: &Vault,
    attempts: &Attempts,
    teams: &mut BTreeMap<[u8; 16], Option<Option<TeamRunStamp>>>,
    first: [u8; 16],
    second: [u8; 16],
) -> bool {
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
        (Some(Some(first)), Some(Some(second))) => {
            first.team_ref == second.team_ref && plans_redundancy(first.pattern)
        }
        (Some(_), Some(_)) => false,
        // A team the host could not tell may have planned it.
        _ => true,
    }
}
