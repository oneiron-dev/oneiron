//! Same-file composition inside a reviewed stack (FIX 4360).
//!
//! Members of one tested batch may each change one file from one verified
//! base `B`. A critic accepted each member's own change `B -> P`. The stack
//! lands that change on the bytes `S` the earlier members left there, as
//! `C`. The application proof sealed on the member's slot says exactly how:
//! the earlier members, the path, the digests of `B`, `P`, `S` and `C`, and
//! the staged prefix trees before and after it. It is not a review of `C`.
//!
//! This is the owner staging composition. CALL A is unchanged: the
//! automatic driver still hands two proposals that replace one path to
//! reconciliation. Composition only lets the checker see the combined file;
//! it never says the combined program is valid.
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::proposal::{RepoProposal, RepoProposalOperation, invalid};
use super::queue::PreparedRepoMutationExecution;
use super::types::{RepoMutationOperation, RepoMutationRequest};
use crate::error::{Error, Result};
use crate::git_wire::{GitWire, GitWireRepo};
use crate::merge_queue::{
    LineComposition, MergeBatch, MergeFileExpected, MergeProposal, read_tree_file,
};

/// How one member's reviewed change lands on its stack prefix, sealed on
/// its slot when the stack is admitted. Byte material stays in the retained
/// proposal, its base snapshot and the staged Git objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StackApplication {
    /// The earlier members, hex ids in stack order, whose changes `S` holds
    /// at this path.
    earlier: Vec<String>,
    path: String,
    /// The BLAKE3 of the verified base `B`.
    base: [u8; 32],
    /// The BLAKE3 of the reviewed postimage `P`.
    postimage: [u8; 32],
    /// The BLAKE3 of the prefix bytes `S` this member lands on.
    staged: [u8; 32],
    /// The BLAKE3 of the composed bytes `C` this member lands.
    composed: [u8; 32],
    /// The staged tree of the prefix before this member.
    input_tree: String,
    /// The staged tree of the prefix through this member.
    output_tree: String,
}

/// One member's application with the texts admission checks; never stored.
pub(super) struct MemberApplication {
    pub(super) proof: StackApplication,
    staged: Vec<u8>,
    composed: Vec<u8>,
}

impl MemberApplication {
    /// The prefix text `S` and the composed text `C`.
    pub(super) fn texts(&self) -> Result<(&str, &str)> {
        Ok((utf8(&self.staged)?, utf8(&self.composed)?))
    }
}

/// One path's state while a stack is planned.
enum PlannedPath<'a> {
    /// Written whole: a bundle, a new file, a hash-only base or bytes that
    /// are not UTF-8 text. A repeat refuses.
    Whole,
    /// Composed from its verified base, with the members composed so far.
    Composed {
        composition: LineComposition,
        members: Vec<&'a str>,
    },
}

/// Every member's application in stack order, rederived from the tested
/// batch alone, so admission and replay derive the same proofs. A first or
/// unshared path has none and lands its reviewed whole file. A repeated
/// path refuses unless every member on it is an ordinary one-file text
/// write from the same verified base, no change overlaps another, and the
/// one span the document writer lowers `S -> C` as covers no earlier
/// member's changed text. That last rule keeps attribution until the
/// L11-A writer keeps equal islands inside a span.
pub(super) fn plan_stack_applications(
    batch: &MergeBatch,
) -> Result<Vec<Option<MemberApplication>>> {
    let repeats = || invalid("reviewed stack repeats a proposal or path");
    let mut paths: BTreeMap<&str, PlannedPath<'_>> = BTreeMap::new();
    let mut plan = Vec::with_capacity(batch.proposals.len());
    for (index, candidate) in batch.proposals.iter().enumerate() {
        let Some((path, base, postimage)) = ordinary_text_write(candidate) else {
            for file in &candidate.files {
                if paths
                    .insert(file.path.as_str(), PlannedPath::Whole)
                    .is_some()
                {
                    return Err(repeats());
                }
            }
            plan.push(None);
            continue;
        };
        let state = match paths.entry(path) {
            Entry::Vacant(vacant) => {
                vacant.insert(LineComposition::new(base, postimage).map_or(
                    PlannedPath::Whole,
                    |composition| PlannedPath::Composed {
                        composition,
                        members: vec![candidate.id.as_str()],
                    },
                ));
                plan.push(None);
                continue;
            }
            Entry::Occupied(occupied) => occupied.into_mut(),
        };
        let PlannedPath::Composed {
            composition,
            members,
        } = state
        else {
            return Err(repeats());
        };
        if composition.base() != base {
            return Err(repeats());
        }
        let staged = composition.output();
        let composed = composition
            .compose(&staged, postimage)
            .ok_or_else(repeats)?;
        if composed.covers_earlier {
            return Err(repeats());
        }
        plan.push(Some(MemberApplication {
            proof: StackApplication {
                earlier: members.iter().map(|id| (*id).to_owned()).collect(),
                path: path.to_owned(),
                base: digest(base),
                postimage: digest(postimage),
                staged: digest(&staged),
                composed: digest(&composed.bytes),
                input_tree: prefix_tree(batch, index)?,
                output_tree: prefix_tree(batch, index + 1)?,
            },
            staged,
            composed: composed.bytes,
        }));
        members.push(candidate.id.as_str());
    }
    Ok(plan)
}

/// The path, verified base and reviewed postimage of an ordinary one-file
/// write whose base bytes the candidate carries.
fn ordinary_text_write(candidate: &MergeProposal) -> Option<(&str, &[u8], &[u8])> {
    let [file] = candidate.files.as_slice() else {
        return None;
    };
    match (&file.metadata_edit, &file.expected, &file.content) {
        (None, Some(MergeFileExpected::Bytes(base)), Some(content)) => {
            Some((file.path.as_str(), base.as_slice(), content.as_slice()))
        }
        _ => None,
    }
}

/// The staged tree of the batch's first `count` members. Every landed
/// prefix is a staged path.
fn prefix_tree(batch: &MergeBatch, count: usize) -> Result<String> {
    let mask = (1_u64 << count) - 1;
    batch
        .paths
        .iter()
        .find(|path| path.mask == mask)
        .map(|path| path.tree.clone())
        .ok_or(Error::CorruptedIndex("landing path missing"))
}

/// Every member a composed path involves is an ordinary reviewed file
/// commit. A conflict resolution keeps its exact whole-file path.
pub(super) fn require_composed_commits(
    rows: &[RepoProposal],
    plan: &[Option<MemberApplication>],
) -> Result<()> {
    let earlier: BTreeSet<&str> = plan
        .iter()
        .flatten()
        .flat_map(|application| application.proof.earlier.iter().map(String::as_str))
        .collect();
    for (row, application) in rows.iter().zip(plan) {
        let involved = application.is_some() || earlier.contains(row.id.to_hex().as_str());
        if involved && !matches!(row.operation, RepoProposalOperation::CommitFile) {
            return Err(invalid("reviewed stack repeats a proposal or path"));
        }
    }
    Ok(())
}

/// Each composed member's prefix bytes, rederived in memory, are the bytes
/// its staged prefix trees hold at its path, before and through it.
pub(super) fn require_staged_prefixes(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    plan: &[Option<MemberApplication>],
) -> Result<()> {
    for application in plan.iter().flatten() {
        let proof = &application.proof;
        let staged = read_tree_file(wire, repo, &proof.input_tree, &proof.path)?;
        let composed = read_tree_file(wire, repo, &proof.output_tree, &proof.path)?;
        if staged.as_deref() != Some(application.staged.as_slice())
            || composed.as_deref() != Some(application.composed.as_slice())
        {
            return Err(Error::ConcurrentWrite(
                "reviewed stack differs from tested tree",
            ));
        }
    }
    Ok(())
}

/// A composed member's sealed proof with its composed bytes `C`, read from
/// the staged output tree for one execution and checked against the proof.
pub(super) struct StepApplication {
    proof: StackApplication,
    composed: Vec<u8>,
}

/// The request a composed member executes, and the texts its document
/// lowering writes, `S -> C`.
pub(super) struct EffectiveApplication {
    pub(super) request: RepoMutationRequest,
    pub(super) staged: String,
    pub(super) composed: String,
}

impl StepApplication {
    pub(super) fn read(
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        proof: &StackApplication,
    ) -> Result<Self> {
        let composed = read_tree_file(wire, repo, &proof.output_tree, &proof.path)?
            .filter(|bytes| blake3::hash(bytes).as_bytes() == &proof.composed)
            .ok_or(Error::ConcurrentWrite(
                "reviewed stack differs from tested tree",
            ))?;
        Ok(Self {
            proof: proof.clone(),
            composed,
        })
    }

    /// The effective request, derived after `proposal::authorize` accepted
    /// the original: only the file's content changes, to `C`. Its path,
    /// message, actor, session and provenance stay the original's. The live
    /// HEAD must be the staged input prefix and its file `S`.
    pub(super) fn effective(
        &self,
        request: &RepoMutationRequest,
        repo_root: &Path,
    ) -> Result<EffectiveApplication> {
        let RepoMutationOperation::CommitFile {
            path,
            content,
            message,
        } = &request.operation
        else {
            return Err(invalid("stack step does not authorize this proposal"));
        };
        if *path != self.proof.path || blake3::hash(content).as_bytes() != &self.proof.postimage {
            return Err(invalid("stack step does not authorize this proposal"));
        }
        let prefix_changed = || Error::ConcurrentWrite("reviewed stack prefix changed");
        if super::conflict::tree_hash_for_ref(repo_root, "HEAD")? != self.proof.input_tree {
            return Err(prefix_changed());
        }
        super::git::validate_relative_repo_path(path)?;
        let staged = std::fs::read(super::git::repo_path_on_disk(repo_root, path)?)?;
        if blake3::hash(&staged).as_bytes() != &self.proof.staged {
            return Err(prefix_changed());
        }
        let mut effective = request.clone();
        effective.operation = RepoMutationOperation::CommitFile {
            path: path.clone(),
            content: self.composed.clone(),
            message: message.clone(),
        };
        Ok(EffectiveApplication {
            request: effective,
            staged: utf8(&staged)?.to_owned(),
            composed: utf8(&self.composed)?.to_owned(),
        })
    }

    /// The prepared commit's tree is the staged next-prefix tree. Checked
    /// before any intent is recorded.
    pub(super) fn require_prepared_tree(
        &self,
        repo_root: &Path,
        execution: &PreparedRepoMutationExecution,
    ) -> Result<()> {
        let commit = execution.commit_file()?;
        if super::conflict::tree_hash_for_ref(repo_root, &commit.new_head)?
            != self.proof.output_tree
        {
            return Err(Error::ConcurrentWrite(
                "reviewed stack differs from tested tree",
            ));
        }
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| invalid("reviewed code requires UTF-8"))
}
