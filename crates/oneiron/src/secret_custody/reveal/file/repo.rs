//! An agent's real-byte read of one marked repo file (FIX 7608 slice
//! 2b-ii-A, GAP-B / FIX 8960; ARCH-0069 #binary-secrets "the real bytes
//! need a grant").
//!
//! A repo file is read through the same check every agent's file read runs
//! ([`Vault::read_sight_in_txn`]): its placed keys in one group per custody
//! class, each judged by the one reveal check, and opaque residue as one
//! sealed group with no custody record behind it, so no lease is stamped
//! for it. What a repo read adds is its target: the ORIGINAL file (repo,
//! store, snapshot, path, blob, source and marks) and the actual recipient
//! (agent, connection, provider, project, run and attempt). The target
//! enters the read's fingerprint, so its ask id, every reveal row's digest
//! and the owner's answer bind that exact file and that exact recipient.
//!
//! The bound a repo read asks for is the reveal's own (this connection ×
//! this class × this project) with the repo's selectors added: digests of
//! the repo's and the file's identities, a scope word, and the run for a
//! task-scoped grant. An ordinary class or project grant holds none of them,
//! so it never opens repo bytes; the owner's explicit grant on this file or
//! on the whole repo, for this task or until revoked, does, through the same
//! evaluator and with no new grant kind. The selectors are fixed in number
//! and value-free: a long path or many marks add no selector.
//!
//! A delivered read hands back a [`RepoFileRevealDelivery`] only after the
//! grouped write that holds its receipts has committed: nothing about the
//! read leaves the writer before every Delivered row is durable. A delivery
//! is no standing permission: each later read checks the live grant again
//! and logs its own reason.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: inert until 2b-ii-B wires the repo readers that take a why"
)]

use serde::{Deserialize, Serialize};

use super::{KeyRead, ReadGroup, SEALED_FILE_CLASS, admitted_keys_in_txn, class_groups};
use crate::consent::{
    AudienceBound, DisclosureClass, DisclosureEnvelope, GrantBound, StandingConsentGrant,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::GitOid;
use crate::secret_custody::reveal::{
    RevealAsker, checked_text, covering_grant, project_selector, reveal_class,
};
use crate::secret_custody::{CustodyClass, SecretSight};
use crate::vault::Vault;

mod grants;

/// Domain of a repo file read's identity digests and its fingerprint.
const REPO_FILE_DOMAIN: &[u8] = b"oneiron.secret_reveal.repo_file.v1";

/// The handle a repo file's opaque residue is read as, in place of keys'.
const REPO_SEALED_HANDLE: &str = "sealed repo file";

/// One marked repo file as its door pinned it: the ORIGINAL, never a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoFileOriginal {
    /// The repo the file is read from.
    pub(crate) repo: EntityId,
    /// The canonical store identity the blob is kept in.
    pub(crate) store: String,
    /// The snapshot the read is pinned to, when its door names one.
    pub(crate) snapshot: Option<EntityId>,
    /// The file's path in the repo.
    pub(crate) path: String,
    /// The stored blob.
    pub(crate) blob: GitOid,
    /// The import source the repo came from, when it has one.
    pub(crate) source: Option<EntityId>,
    /// Every readable mark on the blob, sorted.
    pub(crate) marks: Vec<EntityId>,
}

/// The keys a repo file's marks hold, value-free: each placed key's custody
/// record, and whether residue no span isolates is marked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RepoFileKeys {
    pub(crate) custody: Vec<EntityId>,
    pub(crate) opaque: bool,
}

/// The reach of the owner's grant on a repo file read: the scope the
/// owner's standing answer to one repo file reveal picks (FIX 9236).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoFileRevealScope {
    /// This file, until revoked.
    File,
    /// This file, for this task (run) only.
    FileTask,
    /// Every marked file of this repo, until revoked.
    Repo,
    /// Every marked file of this repo, for this task (run) only.
    RepoTask,
}

impl RepoFileRevealScope {
    /// Every scope, the narrowest first: the order a read's bound is tried.
    pub(crate) const ALL: [Self; 4] = [Self::FileTask, Self::File, Self::RepoTask, Self::Repo];

    /// The pinned scope word.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::FileTask => "file_task",
            Self::Repo => "repo",
            Self::RepoTask => "repo_task",
        }
    }

    const fn names_file(self) -> bool {
        matches!(self, Self::File | Self::FileTask)
    }

    const fn names_task(self) -> bool {
        matches!(self, Self::FileTask | Self::RepoTask)
    }
}

/// What a repo file read names beside its keys, as its reveal rows keep it:
/// digests of the ORIGINAL file's identity and of its actual recipient, the
/// blob's id and the path the ask card shows. No key, excerpt or hash of a
/// key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RepoFileRevealTarget {
    /// The repo's identity: its id and store.
    repo: [u8; 32],
    /// The file's identity in its repo: the repo's and the path.
    file: [u8; 32],
    /// The exact source read: store, snapshot, path, blob, import source and
    /// marks.
    source: [u8; 32],
    /// The actual recipient: agent, connection, provider, project, run and
    /// leased try.
    recipient: [u8; 32],
    /// The stored blob's Git id, lower hex.
    blob: String,
    /// The path the owner's ask card names.
    path: String,
}

impl RepoFileRevealTarget {
    /// The target of `asker`'s read of `original`.
    pub(crate) fn new(original: &RepoFileOriginal, asker: &RevealAsker) -> Self {
        let repo = digest(&[b"repo", original.repo.as_bytes(), original.store.as_bytes()]);
        let file = digest(&[b"file", &repo, original.path.as_bytes()]);
        let snapshot = original
            .snapshot
            .map(|snapshot| snapshot.to_hex())
            .unwrap_or_default();
        let source_id = original
            .source
            .map(|source| source.to_hex())
            .unwrap_or_default();
        let marks = original
            .marks
            .iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .join(",");
        let source = digest(&[
            b"source",
            &file,
            original.store.as_bytes(),
            snapshot.as_bytes(),
            original.blob.as_str().as_bytes(),
            source_id.as_bytes(),
            marks.as_bytes(),
        ]);
        let project = asker
            .project
            .map(|project| project.to_hex())
            .unwrap_or_default();
        let attempt: &[u8] = match &asker.attempt {
            Some(attempt) => attempt.as_bytes(),
            None => &[],
        };
        let recipient = digest(&[
            b"recipient",
            asker.agent.as_bytes(),
            asker.connection().as_bytes(),
            asker.provider.as_deref().unwrap_or_default().as_bytes(),
            project.as_bytes(),
            asker.run.as_deref().unwrap_or_default().as_bytes(),
            attempt,
        ]);
        Self {
            repo,
            file,
            source,
            recipient,
            blob: original.blob.as_str().to_owned(),
            path: original.path.clone(),
        }
    }

    /// The stored blob this target reads.
    pub(crate) fn blob(&self) -> &str {
        &self.blob
    }

    /// The exact source digest every delivery of this target binds.
    pub(crate) const fn source(&self) -> &[u8; 32] {
        &self.source
    }

    /// The actual recipient's digest.
    pub(crate) const fn recipient(&self) -> &[u8; 32] {
        &self.recipient
    }

    /// The bound a grant of `scope` covers this read under: the reveal's own
    /// class × connection × project, with this repo's selectors. `None` for
    /// a task scope when the read names no run.
    ///
    /// # Errors
    /// A selector the consent bound refuses.
    pub(crate) fn bound(
        &self,
        scope: RepoFileRevealScope,
        connection: &str,
        class: CustodyClass,
        project: Option<&EntityId>,
        run: Option<&str>,
    ) -> Result<Option<GrantBound>> {
        let mut selectors = vec![
            project_selector(project),
            format!("repo:{}", hex(&self.repo)),
            format!("repo_scope:{}", scope.as_str()),
        ];
        if scope.names_file() {
            selectors.push(format!("repo_file:{}", hex(&self.file)));
        }
        if scope.names_task() {
            let Some(run) = run else {
                return Ok(None);
            };
            let task = digest(&[b"task", run.as_bytes()]);
            selectors.push(format!("repo_task:{}", hex(&task)));
        }
        GrantBound::disclosure(
            AudienceBound::singleton(connection)?,
            DisclosureClass::new(reveal_class(class))?,
            DisclosureEnvelope::new(selectors)?,
        )
        .map(Some)
    }

    /// The bound "approve and stop asking" mints for this read: this file,
    /// until revoked. A wider reach is the owner's explicit choice of scope.
    ///
    /// # Errors
    /// As [`Self::bound`].
    pub(crate) fn standing_bound(
        &self,
        connection: &str,
        class: CustodyClass,
        project: Option<&EntityId>,
    ) -> Result<GrantBound> {
        self.bound(RepoFileRevealScope::File, connection, class, project, None)?
            .ok_or(crate::error::Error::InvariantViolation(
                "a repo file's standing bound names no task",
            ))
    }

    /// The registry ref of the standing grant that covers this read now,
    /// under any scope the owner may have granted; `None` when none does.
    ///
    /// # Errors
    /// As [`Self::bound`].
    pub(crate) fn covering_grant(
        &self,
        connection: &str,
        class: CustodyClass,
        project: Option<EntityId>,
        run: Option<&str>,
        grants: &[StandingConsentGrant],
    ) -> Result<Option<String>> {
        for scope in RepoFileRevealScope::ALL {
            let Some(bound) = self.bound(scope, connection, class, project.as_ref(), run)? else {
                continue;
            };
            if let Some(grant_ref) = covering_grant(&bound, project, grants)? {
                return Ok(Some(grant_ref));
            }
        }
        Ok(None)
    }

    /// Feeds this target into a reveal row's once digest, each field
    /// length-prefixed by `part`.
    pub(crate) fn bind_digest<F: FnMut(&[u8])>(&self, part: &mut F) {
        part(REPO_FILE_DOMAIN);
        part(&self.repo);
        part(&self.file);
        part(&self.source);
        part(&self.recipient);
        part(self.blob.as_bytes());
        part(self.path.as_bytes());
    }

    /// What the disclosure line says the read sends, naming no value.
    pub(crate) fn disclosure_what(&self, handle: &str) -> String {
        format!(
            "Reading repo file {} (blob {}) unmasked sends its keys {handle}",
            self.path, self.blob
        )
    }

    /// The fingerprint a repo read's rows name in place of the stored
    /// bytes' hash: the stored hash and this exact target, so its ask is
    /// this file's for this recipient and never another read's.
    fn read_hash(&self, stored: &[u8; 32]) -> [u8; 32] {
        digest(&[b"read", stored, &self.source, &self.recipient])
    }
}

/// Whether a repo file read asks the owner: CALL 3, one hook. An absent
/// `why` is today's masked or opaque read, with no ask and no refusal; a
/// `why` from a known actual recipient runs the file check. A read whose
/// recipient the host did not prove reads masked whatever its `why` says,
/// and is never treated as an agent's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoFileReadDisclosure {
    /// The masked or opaque read.
    Masked,
    /// The file check, asked by `asker` for its checked `why`.
    Ask { asker: RevealAsker, why: String },
}

impl RepoFileReadDisclosure {
    /// CALL 3: absent why -> masked; why + proven recipient -> the file
    /// check. A malformed why that opted in is refused by the file read's
    /// own validation, never a new condition on a why-less read.
    ///
    /// # Errors
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound)
    /// for a present `why` that is empty, too long or more than one line;
    /// the scan's refusal for one that holds a credential.
    pub(crate) fn from_optional_why(why: Option<&str>, asker: Option<RevealAsker>) -> Result<Self> {
        let (Some(why), Some(asker)) = (why, asker) else {
            return Ok(Self::Masked);
        };
        let why = checked_text(
            why,
            "a read of a repo file with keys in it says why it needs them",
            "a repo file read's why is one line of at most 512 bytes",
        )?;
        Ok(Self::Ask { asker, why })
    }
}

/// A committed real-byte delivery of one repo file read: its target, the
/// stored bytes' hash it was judged on and each reveal row it delivered.
/// Only [`Vault::repo_file_sight`] builds one, after its receipts commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoFileRevealDelivery {
    target: RepoFileRevealTarget,
    raw_blake3: [u8; 32],
    reveals: Vec<EntityId>,
}

impl RepoFileRevealDelivery {
    pub(crate) const fn target(&self) -> &RepoFileRevealTarget {
        &self.target
    }

    pub(crate) const fn raw_blake3(&self) -> &[u8; 32] {
        &self.raw_blake3
    }

    /// Each delivered reveal row: the read's receipts.
    pub(crate) fn reveals(&self) -> &[EntityId] {
        &self.reveals
    }
}

/// How a repo file read went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoFileSight {
    /// The masked or opaque copy; any ask it filed stays.
    Masked,
    /// The stored bytes may go to the recipient: every receipt committed.
    Delivered(RepoFileRevealDelivery),
}

impl Vault {
    /// How `asker` reads the marked repo file `target` names when it says
    /// `why`: judged by the one file check over `keys`, its placed keys in
    /// one group per class and its opaque residue as one sealed group. The
    /// stored bytes' hash `raw_blake3` is the mark's own. Nothing is read or
    /// released here: a [`RepoFileSight::Delivered`] is returned only once
    /// the grouped write holding every Delivered row has committed.
    ///
    /// # Errors
    /// As [`Vault::file_sight`], and a store failure.
    pub(crate) fn repo_file_sight(
        &self,
        asker: &RevealAsker,
        target: &RepoFileRevealTarget,
        raw_blake3: &[u8; 32],
        keys: &RepoFileKeys,
        why: &str,
    ) -> Result<RepoFileSight> {
        let why = checked_text(
            why,
            "a read of a repo file with keys in it says why it needs them",
            "a repo file read's why is one line of at most 512 bytes",
        )?;
        let artifact = crate::codebase::snapshot_asset_entity_id(raw_blake3)?;
        let delivered = self.with_write_txn_grouped(|txn| {
            let mut groups = Vec::new();
            if !keys.custody.is_empty() {
                let custody = keys.custody.iter().copied();
                let Some(admitted) = admitted_keys_in_txn(self, txn, custody)? else {
                    return Ok(None);
                };
                groups = class_groups(admitted)?;
            }
            if keys.opaque {
                groups.push(ReadGroup {
                    class: SEALED_FILE_CLASS,
                    first: artifact,
                    keys: Vec::new(),
                    handle: REPO_SEALED_HANDLE.to_owned(),
                });
            }
            if groups.is_empty() {
                return Ok(None);
            }
            let per_class = groups.len() > 1;
            let read = KeyRead {
                asker,
                artifact: &artifact,
                why: &why,
                hash: target.read_hash(raw_blake3),
                groups,
                per_class,
                repo: Some(target),
            };
            self.read_sight_core_in_txn(txn, &read).map(Some)
        })?;
        // The grouped write has committed: only now may a delivery leave.
        Ok(match delivered {
            Some((SecretSight::Granted, reveals)) => {
                RepoFileSight::Delivered(RepoFileRevealDelivery {
                    target: target.clone(),
                    raw_blake3: *raw_blake3,
                    reveals,
                })
            }
            _ => RepoFileSight::Masked,
        })
    }
}

/// The BLAKE3 of `fields` under [`REPO_FILE_DOMAIN`], each length-prefixed.
fn digest(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REPO_FILE_DOMAIN);
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

fn hex(bytes: &[u8; 32]) -> String {
    crate::entity_id::bytes_to_hex_lower(bytes)
}
