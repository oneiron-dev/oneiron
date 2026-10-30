//! The publication gate (FIX 7608 slice 9, owner ruling SECRETS-IN-REPOS =
//! A; A1, A2, C2, C3): a send to a public mirror never carries history that
//! holds a marked live key.
//!
//! A destination has an audience: its visibility, which only the owner
//! states (`unknown` when unstated, and held as public: C3; no URL
//! heuristic and no agent's own label), and its role. Every mirror and
//! publish destination is a `mirror`. An exact return to an item's own
//! original source is the export door's (A2), never a mirror or publish
//! send, and nothing here infers it from a URL.
//!
//! At each send, after its claim and before any credential leaves custody,
//! [`Vault::require_no_marked_live_history`] reads the destination's
//! audience as its row stands then, and joins the vault's readable marks
//! against the whole history each tip reaches: every annotated tag on its
//! way, every commit, and every path any commit introduces, read with no
//! bound; a tree or blob tip whole. Nothing is subtracted for what the
//! mirror already holds. A tip whose history names a marked object is held
//! `marked_live_secret` while any of its marks blocks (C2: a live key and a
//! key of unknown liveness block; only the owner's not-a-secret or the
//! provider's revocation clears one, and a local rotation proves nothing).
//! Until those dispositions land (slice 8), nothing proves a key dead, so
//! every mark blocks. Marks are read per blob (CALL S4FIX-UNKNOWN-MARK): a
//! mark that does not decode but names its blob holds, as marked, only the
//! tips whose history carries a blob of those bytes; one that names no
//! blob, or a store failure in the mark walk, holds every tip
//! `secret_history_unknown` under the same policy hook the sync release
//! reads. A history read that fails holds its tip `secret_history_unknown`.
//! Clean tips, private destinations and a vault with no marks send exactly
//! as before, and the gate never rewrites history (slice 10).
//!
//! A history is walked once per store and mark join, not once per send
//! (FIX 10970): a commit proven clean, and a tip met marked, are kept for
//! that store under a digest of exactly the join they were judged against,
//! across batches, same-plan resends and runs. A commit's history never
//! changes, so a later send reuses them while the join is the same, and its
//! walk stops at every kept clean commit; a new, settled or erased mark is
//! another join, judged afresh.
//!
//! The hold is value-free: it names its reason and its ways out, never a
//! key, a mark, a path, an object or a count.

use std::collections::{BTreeSet, HashMap};
use std::sync::{LazyLock, Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use super::mirror::{OriginMirrorTarget, TARGETS};
use super::secret_marks::{RepoMarkFacts, RepoSecretMark};
use super::secret_projection::index::UNATTRIBUTABLE_MARK_FAILS_CLOSED;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefEnd, GitReviewItem, GitWire, GitWireRepo};

/// The hold's ways out after a marked live key (A1), one constant so a
/// later ruling changes one line (CALLS HOLD-NOTICE).
pub const SECRET_PUBLICATION_HOLD_NOTICE: &str = "this history holds a key marked as a live \
                                                  secret, or of unknown liveness, so a public \
                                                  or unstated mirror does not take it. Ways \
                                                  out: mark it not a secret, revoke it at its \
                                                  provider, purge it, or state the mirror \
                                                  private.";

/// The hold's ways out after a read that failed (A1: unknown is live).
pub const SECRET_HISTORY_UNKNOWN_NOTICE: &str = "this history or its secret marks could not be \
                                                 read whole, so it is held as live. Ways out: \
                                                 retry, mark it not a secret, revoke it at its \
                                                 provider, purge it, or state the mirror \
                                                 private.";

/// Who can read a destination, as the owner states it (C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoDestinationVisibility {
    /// Anyone can read it.
    Public,
    /// Only those its host admits can read it.
    Private,
    /// Not stated: held as public.
    Unknown,
}

impl RepoDestinationVisibility {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Unknown => "unknown",
        }
    }
}

/// What a destination is to the repository (C3, A2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoDestinationRole {
    /// A mirror or publish destination: each send to it obeys the hold
    /// unless it is private.
    Mirror,
    /// The repository's own original source: an exact return there stays
    /// exact (A2), through the export door only.
    OriginalSource,
}

impl RepoDestinationRole {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mirror => "mirror",
            Self::OriginalSource => "original_source",
        }
    }
}

/// A destination's audience: who can read it, and what it is (C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoDestinationAudience {
    pub visibility: RepoDestinationVisibility,
    pub role: RepoDestinationRole,
}

impl RepoDestinationAudience {
    /// A mirror of the stated visibility.
    #[must_use]
    pub const fn mirror(visibility: RepoDestinationVisibility) -> Self {
        Self {
            visibility,
            role: RepoDestinationRole::Mirror,
        }
    }

    /// Whether a send there obeys the hold: every destination but a
    /// private one and the item's own original source (A1, A2, C3).
    #[must_use]
    pub const fn holds_marked_history(self) -> bool {
        matches!(self.role, RepoDestinationRole::Mirror)
            && !matches!(self.visibility, RepoDestinationVisibility::Private)
    }
}

/// What the vault knows of one marked key's liveness (C2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoSecretLiveness {
    /// Live at its provider.
    Active,
    /// Nothing proves it dead: held as live.
    Unknown,
    /// The owner marked it not a secret.
    NotASecret,
    /// Its provider revoked it, and the provider's own answer proves it.
    RevokedAtProvider,
}

impl RepoSecretLiveness {
    /// Whether the key holds a public send (C2: live and unknown do).
    #[must_use]
    pub const fn blocks_public(self) -> bool {
        matches!(self, Self::Active | Self::Unknown)
    }
}

/// One mark's liveness: the one hook slice 8's dispositions answer. Until
/// they land nothing proves a key dead, a local rotation included (C2), so
/// every mark is `Unknown` and blocks.
pub(crate) const fn repo_secret_liveness(_mark: &RepoSecretMark) -> RepoSecretLiveness {
    RepoSecretLiveness::Unknown
}

/// Why the gate held a tip (A1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretPublicationHold {
    /// Its history names an object a blocking mark marks.
    MarkedLiveSecret,
    /// Its history, or the vault's marks, could not be read whole.
    SecretHistoryUnknown,
}

impl SecretPublicationHold {
    /// The hold's typed code.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::MarkedLiveSecret => "marked_live_secret",
            Self::SecretHistoryUnknown => "secret_history_unknown",
        }
    }

    /// Its value-free notice: the code, then its ways out.
    pub(crate) fn notice(self) -> String {
        let ways_out = match self {
            Self::MarkedLiveSecret => SECRET_PUBLICATION_HOLD_NOTICE,
            Self::SecretHistoryUnknown => SECRET_HISTORY_UNKNOWN_NOTICE,
        };
        format!("{}: {ways_out}", self.code())
    }
}

/// The audience a mirror row takes from its setup: the visibility the owner
/// states; unstated, the same URL keeps its own and a new one is `unknown`
/// (CALLS OLD-AUDIENCE).
pub(crate) fn configured_audience(
    stated: Option<RepoDestinationVisibility>,
    previous: Option<&OriginMirrorTarget>,
    url: &str,
) -> RepoDestinationAudience {
    let kept = previous
        .filter(|row| row.url == url)
        .map(|row| row.audience.visibility);
    RepoDestinationAudience::mirror(
        stated
            .or(kept)
            .unwrap_or(RepoDestinationVisibility::Unknown),
    )
}

/// What a public send's history is joined against: every object a blocking
/// mark marks, in any store, and the whole-blob BLAKE3 of each blob whose
/// marks do not decode (CALL S4FIX-UNKNOWN-MARK), with the blobs already
/// hashed clean against those in this call.
struct MarkJoin {
    blocking: BTreeSet<GitOid>,
    unread: BTreeSet<[u8; 32]>,
    hashed: BTreeSet<GitOid>,
}

/// The domain of a mark join's digest.
const MARK_JOIN_DIGEST_CONTEXT: &str = "oneiron.secret-publication.mark-join.v1";

impl MarkJoin {
    /// Exactly what the join holds, as one digest: the key a judged tip is
    /// kept under.
    fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(MARK_JOIN_DIGEST_CONTEXT);
        hasher.update(&(self.blocking.len() as u64).to_be_bytes());
        for oid in &self.blocking {
            hasher.update(oid.as_str().as_bytes());
        }
        for hash in &self.unread {
            hasher.update(hash);
        }
        *hasher.finalize().as_bytes()
    }
}

/// Clean commits kept per store and join, newest last: a mirror's tips move
/// forward, so the newest cover most of the rest, and each is one exclusion
/// on a later walk's command line. A memory floor, never a refusal.
const JUDGED_CLEAN_KEPT: usize = 64;

/// Marked tips kept per store and join; past it they start over. A memory
/// floor, never a refusal.
const JUDGED_MARKED_KEPT: usize = 4096;

/// Stores and joins kept at once; past it every one starts over. A memory
/// floor, never a refusal.
const JUDGED_JOINS_KEPT: usize = 64;

/// What one store's tips came to under one mark join (FIX 10970).
#[derive(Debug, Clone, Default)]
struct JudgedTips {
    /// Commits proven clean, newest last.
    clean: Vec<GitOid>,
    /// Tips held `marked_live_secret`.
    marked: BTreeSet<GitOid>,
}

/// Every store's judged tips, by its identity and its join's digest.
static JUDGED_TIPS: LazyLock<Mutex<HashMap<(String, [u8; 32]), JudgedTips>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The tips `key` already judged, or none.
fn judged_tips(key: &(String, [u8; 32])) -> JudgedTips {
    JUDGED_TIPS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(key)
        .cloned()
        .unwrap_or_default()
}

/// Keeps what one send judged under `key`: its clean commits, newest last,
/// and the tips it met marked.
fn keep_judged_tips(key: (String, [u8; 32]), mut clean: Vec<GitOid>, marked: Vec<GitOid>) {
    let mut kept = JUDGED_TIPS.lock().unwrap_or_else(PoisonError::into_inner);
    if !kept.contains_key(&key) && kept.len() >= JUDGED_JOINS_KEPT {
        kept.clear();
    }
    let judged = kept.entry(key).or_default();
    if clean.len() > JUDGED_CLEAN_KEPT {
        clean.drain(..clean.len() - JUDGED_CLEAN_KEPT);
    }
    judged.clean = clean;
    if judged.marked.len() + marked.len() > JUDGED_MARKED_KEPT {
        judged.marked.clear();
    }
    judged.marked.extend(marked);
}

impl Vault {
    /// Each of `tips`' hold at `repo_id`'s mirror, in order: `None` sends as
    /// before (module docs). It reads the mirror's audience as its row
    /// stands now; a row that is gone reads `unknown`. It never fails: what
    /// it cannot read holds.
    pub(crate) fn require_no_marked_live_history(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        repo_id: EntityId,
        tips: &[GitOid],
    ) -> Vec<Option<SecretPublicationHold>> {
        if tips.is_empty() {
            return Vec::new();
        }
        let mut join = match self.public_mark_join(repo_id) {
            Ok(None) => return vec![None; tips.len()],
            Ok(Some(join)) => join,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "secret marks could not be read whole; a public send is held"
                );
                return vec![Some(SecretPublicationHold::SecretHistoryUnknown); tips.len()];
            }
        };
        let key = (handle.identity().as_hex(), join.digest());
        let judged = judged_tips(&key);
        let mut clean = judged.clean;
        let mut marked = Vec::new();
        let holds = tips
            .iter()
            .map(|tip| {
                if judged.marked.contains(tip) {
                    return Some(SecretPublicationHold::MarkedLiveSecret);
                }
                if clean.contains(tip) {
                    return None;
                }
                let (hold, commit) = tip_hold(wire, handle, tip, &clean, &mut join);
                match (hold, commit) {
                    (None, Some(commit)) => {
                        clean.retain(|kept| *kept != commit);
                        clean.push(commit);
                    }
                    (Some(SecretPublicationHold::MarkedLiveSecret), _) => marked.push(tip.clone()),
                    _ => {}
                }
                hold
            })
            .collect();
        keep_judged_tips(key, clean, marked);
        holds
    }

    /// What a public send's history is joined against, read once through
    /// the per-blob mark reader; `None` for a destination that does not
    /// hold, or a vault with no mark. A mark that does not decode and names
    /// no blob, or a store failure in the walk, fails the read under
    /// [`UNATTRIBUTABLE_MARK_FAILS_CLOSED`] (A1: unknown is live); one tied
    /// to its blob holds only the refs whose history carries that blob.
    fn public_mark_join(&self, repo_id: EntityId) -> Result<Option<MarkJoin>> {
        let txn = self.store.env.read_txn()?;
        let audience = TARGETS.get(&self.store, &txn, &repo_id)?.map_or(
            RepoDestinationAudience::mirror(RepoDestinationVisibility::Unknown),
            |row| row.audience,
        );
        if !audience.holds_marked_history() {
            return Ok(None);
        }
        let (facts, unread) =
            RepoMarkFacts::read_scoped_in_txn(self, &txn, UNATTRIBUTABLE_MARK_FAILS_CLOSED)?;
        let blocking =
            facts.blob_oids(|mark: &RepoSecretMark| repo_secret_liveness(mark).blocks_public());
        Ok(
            (!blocking.is_empty() || !unread.is_empty()).then(|| MarkJoin {
                blocking,
                unread,
                hashed: BTreeSet::new(),
            }),
        )
    }
}

/// Ends a walk at its first marked object.
const MARKED_OBJECT_MET: &str = "secret publication walk met a marked object";

/// A submodule entry's mode: a commit of another repository, never a blob
/// of this one.
const GITLINK_MODE: &str = "160000";

/// One tip's hold, and the commit it ends at. `clean` are commits already
/// proven clean, whose history is not walked again: a marked object a tip
/// reaches through one of them would have held that one.
fn tip_hold(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    tip: &GitOid,
    clean: &[GitOid],
    join: &mut MarkJoin,
) -> (Option<SecretPublicationHold>, Option<GitOid>) {
    let peeled = match wire.peel_ref_tip_retained(handle, tip) {
        Ok(peeled) => peeled,
        Err(error) => return (Some(unknown(&error)), None),
    };
    let blocking = &join.blocking;
    let tagged =
        blocking.contains(tip) || peeled.tags.iter().any(|tag| blocking.contains(&tag.tag));
    let end = match &peeled.end {
        GitRefEnd::Commit(oid) | GitRefEnd::Tree(oid) | GitRefEnd::Blob(oid) => oid,
    };
    if tagged || blocking.contains(end) {
        return (Some(SecretPublicationHold::MarkedLiveSecret), None);
    }
    let hashing = !join.unread.is_empty();
    let mut blobs = BTreeSet::new();
    let mut met = false;
    let mut visit = |item: GitReviewItem| {
        let (object, blob) = match item {
            GitReviewItem::Commit { commit, .. } => (Some(commit), false),
            GitReviewItem::Path { mode, object, .. } => (object, mode != GITLINK_MODE),
        };
        let Some(object) = object else {
            return Ok(());
        };
        if blocking.contains(&object) {
            met = true;
            return Err(Error::InvariantViolation(MARKED_OBJECT_MET));
        }
        if hashing && blob {
            blobs.insert(object);
        }
        Ok(())
    };
    let (walked, commit) = match &peeled.end {
        GitRefEnd::Commit(commit) => (
            wire.for_each_review_item_retained(handle, commit, clean, &mut visit),
            Some(commit.clone()),
        ),
        GitRefEnd::Tree(tree) => (
            wire.for_each_tree_path_retained(handle, tree, &mut visit),
            None,
        ),
        GitRefEnd::Blob(_) => (Ok(()), None),
    };
    match walked {
        Ok(()) => {}
        Err(_) if met => return (Some(SecretPublicationHold::MarkedLiveSecret), None),
        Err(error) => return (Some(unknown(&error)), None),
    }
    if hashing && let GitRefEnd::Blob(blob) = &peeled.end {
        blobs.insert(blob.clone());
    }
    match unread_blob_met(wire, handle, blobs, join) {
        Ok(false) => (None, commit),
        Ok(true) => (Some(SecretPublicationHold::MarkedLiveSecret), None),
        Err(error) => (Some(unknown(&error)), None),
    }
}

/// Whether one of `blobs` hashes to a blob whose marks do not decode: it
/// holds as marked (CALL S4FIX-UNKNOWN-MARK). Each blob is read whole once a
/// call, and only while such a mark exists.
fn unread_blob_met(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    blobs: BTreeSet<GitOid>,
    join: &mut MarkJoin,
) -> Result<bool> {
    for blob in blobs {
        if join.hashed.contains(&blob) {
            continue;
        }
        let object = wire.read_object_to_spool(handle, &blob)?;
        if join.unread.contains(&object.content_blake3()) {
            return Ok(true);
        }
        join.hashed.insert(blob);
    }
    Ok(false)
}

/// A read that failed: the tip is held as live.
fn unknown(error: &Error) -> SecretPublicationHold {
    tracing::warn!(
        kind = ?error.kind(),
        "a public send's history could not be read whole; it is held"
    );
    SecretPublicationHold::SecretHistoryUnknown
}
