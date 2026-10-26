//! The `repo.secret_remediation` links (FIX 7608 slice 6): value-free
//! facts tying the marked keys in a repository's code to a remediation,
//! kept in the claim store like the marks themselves.
//!
//! - `offered`: an accepted push's candidate bundle carries files whose
//!   whole bytes a mark names. It is written in the candidate's own
//!   writer, after publication, and never changes the candidate's bytes;
//!   the remediation itself is a SEPARATE proposal, made later.
//! - `proposed`: a remediation bundle was staged at a commit.
//!
//! A fact names its proposal, the repository, the commit and the paths,
//! never a value, span, excerpt or custody record. Its id is derived from
//! its state and proposal, so it is written once. Nothing here decides,
//! approves or enqueues anything.

use heed::RwTxn;
use rmpv::Value;

use super::super::proposal::RepoProposal;
use super::super::proposal::persist::PreparedRepoProposal;
use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::codebase::{RepoRef, entity_id_from_hash_material};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::secret_marks::{RepoMarkFacts, RepoSecretMarkLookup};
use crate::secret_custody::MASKED_FILE_BAND;
use crate::temporal::TimeRange;

/// The predicate of one remediation link.
pub(crate) const REPO_SECRET_REMEDIATION_PREDICATE: &str = "repo.secret_remediation";

/// The hash domain a link's id is derived under, from (state, proposal).
const LINK_ID_DOMAIN: &[u8] = b"oneiron:repo-secret-remediation:v1";

/// The one schema these links are written at.
const LINK_SCHEMA: u16 = 1;

/// One link, as written.
struct RemediationLink<'a> {
    /// `offered` or `proposed`.
    state: &'static str,
    /// The candidate bundle (offered) or the remediation bundle (proposed).
    proposal: EntityId,
    /// The served store's id (`lfs_repo_id` of its identity).
    store_id: EntityId,
    repo: &'a str,
    commit: Option<&'a str>,
    paths: &'a [String],
    at: u64,
}

/// Writes the `offered` link of the candidate bundle `proposal` in
/// `wtxn`, the candidate's own writer, when any file it carries is a blob
/// a readable mark names. `store_identity` is the canonical object store
/// the push landed in. Answers whether a link was newly written.
///
/// # Errors
/// A mark walk, id or claim failure: the candidate's writer aborts with it.
pub(crate) fn offer_secret_remediation_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    store_identity: &str,
    proposal: &PreparedRepoProposal,
) -> Result<bool> {
    let row = &proposal.row;
    let hashes: Vec<(&str, [u8; 32])> = row
        .files
        .iter()
        .filter_map(|file| {
            let content = file.content.as_ref()?;
            Some((file.path.as_str(), *blake3::hash(content).as_bytes()))
        })
        .collect();
    if hashes.is_empty() {
        return Ok(false);
    }
    let facts = RepoMarkFacts::read_in_txn(vault, wtxn, RepoSecretMarkLookup::ReadableClaims)?;
    let paths: Vec<String> = hashes
        .into_iter()
        .filter(|(_, hash)| !facts.for_hash(hash).is_empty())
        .map(|(path, _)| path.to_owned())
        .collect();
    if paths.is_empty() {
        return Ok(false);
    }
    let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let repo = RepoRef::parse(&row.repo)?;
    put_link_in_txn(
        vault,
        wtxn,
        &RemediationLink {
            state: "offered",
            proposal: row.id,
            store_id: lfs_repo_id(store_identity)?,
            repo: &row.repo,
            commit: repo.commit_hash(),
            paths: &paths,
            at,
        },
    )
}

/// Writes the `proposed` link of the remediation bundle `row`, staged at
/// its pinned commit in the store `store_identity`, naming `paths`, in
/// its own writer.
///
/// # Errors
/// An id, claim or store failure.
pub(super) fn record_remediation_proposed(
    vault: &Vault,
    store_identity: &str,
    row: &RepoProposal,
    paths: &[String],
) -> Result<()> {
    let repo = RepoRef::parse(&row.repo)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let at = crate::ports::recorded_at_in_txn(&vault.store, &mut wtxn)?;
    if put_link_in_txn(
        vault,
        &mut wtxn,
        &RemediationLink {
            state: "proposed",
            proposal: row.id,
            store_id: lfs_repo_id(store_identity)?,
            repo: &row.repo,
            commit: repo.commit_hash(),
            paths,
            at,
        },
    )? {
        wtxn.commit()?;
    }
    Ok(())
}

/// Writes `link` once: the same link again writes nothing, and its id
/// holding anything else is a corrupt store.
fn put_link_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    link: &RemediationLink<'_>,
) -> Result<bool> {
    let id = entity_id_from_hash_material(
        LINK_ID_DOMAIN,
        &[link.state.as_bytes(), link.proposal.as_bytes()],
    )?;
    if vault.get_claim_in_txn(wtxn, &id)?.is_some() {
        return Ok(false);
    }
    if vault.get_raw_in(wtxn, &id)?.is_some() {
        return Err(Error::CorruptedIndex(
            "a repo secret remediation link's id holds another record",
        ));
    }
    let paths = link
        .paths
        .iter()
        .map(|path| Value::from(path.as_str()))
        .collect();
    let value = fields(vec![
        ("schema_version", Value::from(LINK_SCHEMA)),
        ("state", Value::from(link.state)),
        ("proposal", Value::from(link.proposal.to_hex())),
        ("repo", Value::from(link.repo)),
        ("commit", link.commit.map_or(Value::Nil, Value::from)),
        ("paths", Value::Array(paths)),
        ("linked_at", Value::from(link.at)),
    ]);
    let mut body = ClaimBody::new(
        REPO_SECRET_REMEDIATION_PREDICATE,
        ClaimSubject::Edge {
            source: link.proposal,
            kind: EdgeKind::PartOf,
            target: link.store_id,
        },
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    // Engine bookkeeping, in the band of the files whose keys it names.
    body.source = Some(ClaimSource::Observed);
    body.scope = Some(fields(vec![(
        "sensitivity",
        Value::from(MASKED_FILE_BAND.as_str()),
    )]));
    let occurred = TimeRange {
        start: link.at,
        end: link.at,
    };
    vault.put_reserved_claim_in_txn(wtxn, &id, &body, occurred, link.at)?;
    Ok(true)
}

fn fields(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}
