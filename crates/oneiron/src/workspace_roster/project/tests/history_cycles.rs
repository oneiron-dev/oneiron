//! The parent-cycle oracle (Astra #1434b): on small random multi-project
//! graphs, every door serves what the brute-force reference in
//! `cycle_model.rs` computes from the definition, in two arrival orders on
//! two replicas and from every entry point.
use super::super::fold::{ProjectEffective, reason};
use super::super::history_policy::{PROJECT_FRONTIER, ProjectHistoryPolicy};
use super::super::read::{ProjectReader, ProjectVerdict};
use super::super::revision::{
    ProjectRevision, project_revision_type, revision_entity_id, revisions_of_row,
};
use super::super::*;
use super::authority::{holder_key, put_signed_project, root_leader, spawn_signed};
use super::cycle_model::{self as model, EXTRA, Graph, KEPT, Label, Rank, View};
use super::history::{copy_of, open};
use super::history_resolution::{holder_slip, put_companion};
use crate::llm::ScopeResource;
use ed25519_dalek::Signer;
use std::collections::BTreeMap;

const SEEDS: u64 = 64;

pub(super) fn readable(mask: u8) -> BTreeSet<ScopeResource> {
    let mut set = BTreeSet::new();
    if mask & KEPT != 0 {
        set.insert(ScopeResource::Bucket { key: "kept".into() });
    }
    if mask & EXTRA != 0 {
        set.insert(ScopeResource::Bucket {
            key: "extra".into(),
        });
    }
    set
}

pub(super) fn owner(vault: &Vault) -> Result<crate::consent::AuthenticatedOwner> {
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )
}

/// The vault's bound on a cycle member's worlds.
pub(super) fn set_bound(vault: &Vault, worlds: usize) -> Result<()> {
    vault.set_project_history_policy(
        &owner(vault)?,
        ProjectHistoryPolicy {
            cycle_worlds_max: worlds as u64,
            ..ProjectHistoryPolicy::default()
        },
    )
}

/// The graph signed once: births live, every revision signed and kept for
/// delivery. Copies of `dir` are the replicas.
pub(super) struct Scaffold {
    pub(super) dir: tempfile::TempDir,
    pub(super) ids: Vec<EntityId>,
    pub(super) leaders: Vec<EntityId>,
    pub(super) revisions: Vec<(ProjectRevisionHash, ProjectRevision)>,
}

pub(super) fn scaffold(graph: &Graph) -> Result<Scaffold> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    set_bound(&vault, graph.bound)?;
    let (root, mut root_row, holder) = root_leader(&vault)?;
    root_row.slice.readable = readable(KEPT | EXTRA);
    put_signed_project(&vault, root, &mut root_row, holder, 1)?;
    let (mut ids, mut leaders, mut boards) = (Vec::new(), Vec::new(), Vec::new());
    let mut births: Vec<ProjectRecord> = Vec::new();
    for project in 0..graph.projects {
        let (id, leader) = (EntityId::now(), EntityId::now());
        let birth = match graph.born_under[project] {
            None => {
                boards.push(holder);
                spawn_signed(&vault, root, id, holder, leader, root_row.slice.clone(), 2)?
            }
            Some(parent) => {
                let spawner = leaders[parent];
                boards.push(spawner);
                let slice = births[parent].slice.clone();
                spawn_signed(&vault, ids[parent], id, spawner, leader, slice, 2)?
            }
        };
        ids.push(id);
        leaders.push(leader);
        births.push(birth);
    }
    // One slip per (project, signer), every revision signed under it.
    let mut slips = BTreeMap::new();
    let mut records = births;
    let mut revisions = Vec::new();
    for (index, rev) in graph.revs.iter().enumerate() {
        let id = ids[rev.project];
        let signer = match rev.signer {
            Rank::Board => boards[rev.project],
            Rank::Leader => leaders[rev.project],
        };
        let key = (rev.project, rev.signer);
        let slip = match slips.entry(key) {
            std::collections::btree_map::Entry::Occupied(slot) => slot.into_mut(),
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(holder_slip(&vault, signer, id)?)
            }
        };
        let base = &records[rev
            .prior
            .map_or(rev.project, |prior| graph.projects + prior)];
        let mut next = base.clone();
        next.parents = vec![rev.parent.map_or(root, |parent| ids[parent]).to_hex()];
        next.slice.readable = readable(rev.mask);
        next.depth_remaining = rev.depth;
        let anchor = base.anchor();
        let version = ProjectProofVersion::V3;
        // Each revision signs at its own second: equal content never shares a hash.
        let signed_at = slip.claims.issued_at + index as u64;
        let challenge =
            next.authority_at(version)
                .write_challenge(id, version, signed_at, Some(&anchor))?;
        next.write_proof = Some(ProjectWriteProof {
            slip_wire: slip.to_token()?,
            holder_signature: holder_key(signer)
                .sign(&slip.binding_transcript(&challenge)?)
                .to_bytes()
                .to_vec(),
            signed_at,
            anchor: Some(Box::new(anchor)),
            version,
        });
        revisions.push(revisions_of_row(id, &next)?.pop().ok_or_else(invalid)?);
        records.push(next);
    }
    drop(vault);
    Ok(Scaffold {
        dir,
        ids,
        leaders,
        revisions,
    })
}

impl Scaffold {
    /// A replica holding `order`'s revisions, delivered as companions.
    pub(super) fn replica(&self, order: &[usize]) -> Result<(tempfile::TempDir, Vault)> {
        let (dir, vault) = copy_of(&self.dir)?;
        self.deliver(&vault, order)?;
        Ok((dir, vault))
    }

    pub(super) fn deliver(&self, vault: &Vault, order: &[usize]) -> Result<()> {
        for (at, index) in (10..).zip(order) {
            put_companion(vault, &self.revisions[*index].1, at)?;
        }
        Ok(())
    }

    /// Every revision in one replicated batch, so one batch-end refresh.
    pub(super) fn deliver_batch(&self, vault: &Vault) -> Result<()> {
        let kind = project_revision_type(&vault.store).ok_or_else(invalid)?;
        vault.with_write_txn(|txn| {
            let mut batch = vault.batch_in();
            for (at, (hash, revision)) in (10..).zip(&self.revisions) {
                batch = batch.put_replicated(
                    &revision_entity_id(*hash)?,
                    kind,
                    TimeRange { start: at, end: at },
                    at,
                    &revision.canonical_bytes()?,
                );
            }
            batch.apply(txn)
        })
    }

    pub(super) fn view(&self, effective: Option<&ProjectEffective>) -> Option<View> {
        let effective = effective?;
        let mask = (effective.slice.as_ref()).map_or(0, |slice| {
            let has = |key: &str| {
                slice
                    .readable
                    .contains(&ScopeResource::Bucket { key: key.into() })
            };
            (u8::from(has("kept")) * KEPT) | (u8::from(has("extra")) * EXTRA)
        });
        let parent = effective
            .parents
            .first()
            .and_then(|parent| (self.ids.iter()).position(|id| id.to_hex() == *parent));
        Some(View {
            mask,
            depth: effective.depth_remaining,
            parent,
        })
    }

    /// Every project's view through the public door, one fresh reader each.
    pub(super) fn public(&self, vault: &Vault) -> Result<Vec<Option<View>>> {
        (self.ids.iter())
            .map(|id| {
                let frontier = vault.project_frontier(*id)?;
                Ok(self.view(frontier.as_ref().and_then(|f| f.effective.as_ref())))
            })
            .collect()
    }
}

pub(super) fn permutations(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for rest in permutations(n - 1) {
        for at in 0..=rest.len() {
            let mut next = rest.clone();
            next.insert(at, n - 1);
            out.push(next);
        }
    }
    out
}

/// What every door serves on `vault`, against `expected`; mismatches as text.
pub(super) fn doors(
    scaffold: &Scaffold,
    vault: &Vault,
    graph: &Graph,
    expected: &model::Expected,
    held: &[bool],
) -> Result<Vec<String>> {
    let mut wrong = Vec::new();
    let public = scaffold.public(vault)?;
    if public != expected.served {
        wrong.push(format!("project_frontier {public:?}"));
    }
    for entry in permutations(graph.projects) {
        let txn = vault.store.env.read_txn()?;
        let reader =
            ProjectReader::new(&vault.store, &txn, vault.privacy_posture())?.ok_or_else(invalid)?;
        let mut served = vec![None; graph.projects];
        for project in &entry {
            let frontier = reader.frontier(scaffold.ids[*project])?;
            served[*project] = scaffold.view(frontier.as_ref().and_then(|f| f.effective.as_ref()));
        }
        if served != expected.served {
            wrong.push(format!("reader entered at {entry:?}: {served:?}"));
        }
    }
    for project in 0..graph.projects {
        let listed: BTreeMap<ProjectRevisionHash, ProjectVerdict> = vault
            .project_revisions(scaffold.ids[project])?
            .into_iter()
            .collect();
        for (index, rev) in graph.revs.iter().enumerate() {
            if rev.project != project || !held[index] {
                continue;
            }
            let verdict = listed.get(&scaffold.revisions[index].0).copied();
            // Past the bound every held revision is still listed.
            let agrees = match expected.labels[index] {
                _ if expected.dark[project] => verdict.is_some(),
                Label::Valid => verdict == Some(ProjectVerdict::Visible),
                Label::Undefined => verdict == Some(ProjectVerdict::Quarantined(reason::CYCLE)),
                Label::Invalid => verdict != Some(ProjectVerdict::Visible),
            };
            if !agrees {
                wrong.push(format!(
                    "project_revisions: revision {index} is {verdict:?}, not {:?}",
                    expected.labels[index]
                ));
            }
        }
    }
    // The batch-end refresh from each project alone persists the same view.
    for project in 0..graph.projects {
        let id = scaffold.ids[project];
        vault.with_write_txn(|txn| {
            super::super::refresh_project_frontiers(
                &vault.store,
                txn,
                vault.privacy_posture(),
                &BTreeSet::from([id]),
            )
        })?;
        let txn = vault.store.env.read_txn()?;
        let record = PROJECT_FRONTIER.get(&vault.store, &txn, &id)?;
        let persisted = scaffold.view(record.as_ref().and_then(|r| r.effective.as_ref()));
        if persisted != expected.served[project] {
            wrong.push(format!("refresh of {project}: {persisted:?}"));
        }
    }
    Ok(wrong)
}

/// The two invariants, on what the public door serves: a served child fits
/// under its served parent and closes no cycle, and a replay widens nothing
/// unless a replayed revision of that project itself installs.
fn invariants(
    graph: &Graph,
    before: &[Option<View>],
    after: &[Option<View>],
    installed: &dyn Fn(usize) -> bool,
) -> Vec<String> {
    let mut wrong = Vec::new();
    for project in 0..graph.projects {
        let Some(view) = after[project] else {
            continue;
        };
        let mut seen = BTreeSet::from([project]);
        let mut at = view;
        while let Some(parent) = at.parent {
            let Some(above) = after[parent] else {
                wrong.push(format!("{project} served under hidden {parent}"));
                break;
            };
            if at.depth >= above.depth || at.mask & !above.mask != 0 {
                wrong.push(format!("{project} does not fit under {parent}"));
                break;
            }
            if !seen.insert(parent) {
                wrong.push(format!("{project} serves a cycle"));
                break;
            }
            at = above;
        }
        let wider =
            before[project].is_some_and(|was| view.mask & !was.mask != 0 || view.depth > was.depth);
        let replayed = (graph.revs.iter().enumerate())
            .any(|(index, rev)| rev.project == project && rev.withheld && installed(index));
        if wider && !replayed {
            wrong.push(format!("a replay widened {project}"));
        }
    }
    wrong
}

/// One replay on a replica: the live revisions in `order`, then the
/// withheld ones. What the public door served before and after, and every
/// disagreement with the reference or the invariants, as text.
pub(super) struct Replay {
    pub(super) _dir: tempfile::TempDir,
    pub(super) vault: Vault,
    pub(super) before: Vec<Option<View>>,
    pub(super) after: Vec<Option<View>>,
    pub(super) wrong: Vec<String>,
}

pub(super) fn replay(scaffold: &Scaffold, graph: &Graph, order: &[usize]) -> Result<Replay> {
    let all = vec![true; graph.revs.len()];
    let live: Vec<bool> = graph.revs.iter().map(|rev| !rev.withheld).collect();
    let expected = model::solve(graph, &all);
    let (first, last): (Vec<usize>, Vec<usize>) = order
        .iter()
        .partition(|index| !graph.revs[**index].withheld);
    let (dir, vault) = scaffold.replica(&first)?;
    let mut wrong = Vec::new();
    let before = scaffold.public(&vault)?;
    if before != model::solve(graph, &live).served {
        wrong.push(format!("before the replay: {before:?}"));
    }
    scaffold.deliver(&vault, &last)?;
    let after = scaffold.public(&vault)?;
    let listed: Vec<BTreeMap<ProjectRevisionHash, ProjectVerdict>> = (scaffold.ids.iter())
        .map(|id| Ok(vault.project_revisions(*id)?.into_iter().collect()))
        .collect::<Result<_>>()?;
    let installed = |index: usize| {
        listed[graph.revs[index].project].get(&scaffold.revisions[index].0)
            == Some(&ProjectVerdict::Visible)
    };
    wrong.extend(invariants(graph, &before, &after, &installed));
    wrong.extend(doors(scaffold, &vault, graph, &expected, &all)?);
    Ok(Replay {
        _dir: dir,
        vault,
        before,
        after,
        wrong,
    })
}

/// The definition's answer is every door's answer, for every seed, in both
/// arrival orders, on two replicas and from every entry point. The reference
/// models the world bound, not the decision's work budget, so no generated
/// case may pass the budget (Astra r15 F5).
#[test]
fn every_door_serves_the_least_fixpoint_of_the_parent_cycle_rule() -> Result<()> {
    use super::super::joint::WORK_DARK;
    let mut failures = Vec::new();
    let mut bounded = 0;
    for seed in 0..SEEDS {
        let graph = model::generate(seed);
        let expected = model::solve(&graph, &vec![true; graph.revs.len()]);
        bounded += usize::from(expected.dark.iter().any(|dark| *dark));
        let scaffold = scaffold(&graph)?;
        let forward: Vec<usize> = (0..graph.revs.len()).collect();
        for order in [forward.clone(), forward.into_iter().rev().collect()] {
            let wrong = replay(&scaffold, &graph, &order)?.wrong;
            if !wrong.is_empty() {
                failures.push(format!(
                    "seed {seed} order {order:?}: expected {:?}\n  {graph:?}\n  {}",
                    expected.served,
                    wrong.join("\n  ")
                ));
            }
        }
    }
    assert!(bounded > 0, "no generated case passed the bound");
    assert_eq!(
        WORK_DARK.with(std::cell::Cell::get),
        0,
        "a case passed the work budget"
    );
    assert!(
        failures.is_empty(),
        "{} failing runs:\n{}",
        failures.len(),
        failures.join("\n")
    );
    Ok(())
}
