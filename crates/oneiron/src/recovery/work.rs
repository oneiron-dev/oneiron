//! A canonical window recovery as resumable work (Rule 5, FIX 8821).
//!
//! How much a recovery repairs never refuses it. Its work runs a page at a
//! time on the vault's one task-work line: each page waits its turn there,
//! in the fair line (each principal's oldest work first, principals in
//! turn, the host's own work only when no caller waits), runs, and hands its
//! turn back before the next page queues again. A turn that does not come by
//! the caller's deadline leaves the work pending where it stands, never run
//! without a turn, never refused and never reported Healthy.
//!
//! Artifact validation yields between ordered groups, rows and nested history
//! checks over one immutable source, using the existing row page size. Single
//! metadata values, text splices, head and quote equality/hash, container sort,
//! retained-parent and workflow checks still run whole. Encoding yields between
//! top-level named fields and source rows, and within entity blobs, edge/tombstone
//! values, custody carriers, room turn/side rows, document pins, head receipts,
//! row births and ASSET body-reference byte arrays. NOTE text and titles and
//! EntityDoc current text copies yield within their native UTF-8 bodies, after the whole
//! string's original budget admission and capacity reservation. Fixed prefixes,
//! keys, other scalar and nested row serializers and that reservation still
//! run whole. The envelope checksum and outer canonical digest yield between
//! BLAKE3 chunks.
//! NOTE scope and immutable plan lookups yield between source rows; store-bound
//! workflow checks and the aborted-transaction preflight still run whole. Manifest construction
//! yields between whole packs and within each chunk hash.
//! Recapture yields between structural stages while retaining one store read
//! view. After that view drops, native pad normalization runs whole in the
//! completion turn; pure snapshot equality resumes between rows, within native
//! strings and byte payloads (including native SKILL witnesses), and between
//! nested EntityDoc history items.
//! EntityDoc metadata maps resume between owned entries and within their value
//! bytes on the same work budget; each entry's native key lookup remains whole.
//! The rebuild, forward replay and per-row checks run a page at a time, with
//! replay's cross-pass ledgers kept between pages. The manifest is published
//! last, only after all work completes.

mod encoded_digest;
use encoded_digest::EncodedDigest;

use std::path::{Path, PathBuf};
use std::time::Instant;

use loro::LoroDoc;

use super::canonical::{
    CANONICAL_SNAPSHOT_MAX_BYTES, CanonicalCapture, CanonicalEncoding, CanonicalSnapshot,
    CanonicalValidation, RebuildAt, StoreCapturedCanonical, invalid, rebuild_page, rebuild_start,
};
use super::document::{NotePlanRows, NoteScopeRows};
use super::ladder::{
    CanonicalComparison, ManifestChunks, PreparedRecovery, RecoveryBudget, RecoveryTier, limit,
    prepare_rebuilt_with_manifest, verify_page,
};
use crate::error::Result;
use crate::sync::bridge::Materializer;
use crate::sync::types::WindowKey;
use crate::sync::window::ForwardRun;
use crate::work_line::{LinePermit, WaitTimedOut};
use crate::{EntityId, Vault};

/// The phase a recovery stands in, in the order it runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryPhase {
    /// The artifact as this vault recovers it, one group or window-row page per turn.
    Validate,
    /// The fresh window, a page of rows at a time.
    Rebuild,
    /// The whole-bundle preflight, the manifest's tier and its quarantine.
    Preflight,
    /// The forward replay, a page of rows at a time.
    Replay,
    /// Paged row checks, staged recapture and row-by-row snapshot comparison.
    Verify,
    /// The repaired manifest, published last.
    Publish,
    Complete,
}

/// Where a recovery stands: the artifact it is bound to, its phase, and
/// where its next page starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryCursor {
    pub(crate) digest: [u8; 32],
    pub(crate) phase: RecoveryPhase,
    pub(crate) next_key: Option<String>,
}

/// What one [`RecoveryWork::step`] left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryProgress {
    /// More pages are owed; the work resumes where the cursor stands.
    Pending(RecoveryCursor),
    Complete,
}

/// Both forms own one snapshot. Only the actual Store capture can provide
/// the native restore source; an ordinary decoded snapshot remains raw.
enum RecoverySource {
    Raw(CanonicalSnapshot),
    Captured(StoreCapturedCanonical),
}

impl std::ops::Deref for RecoverySource {
    type Target = CanonicalSnapshot;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Raw(snapshot) => snapshot,
            Self::Captured(source) => source.snapshot(),
        }
    }
}

impl RecoverySource {
    fn captured(&self) -> Option<&StoreCapturedCanonical> {
        match self {
            Self::Raw(_) => None,
            Self::Captured(source) => Some(source),
        }
    }

    fn erase_actors_here(&mut self, vault: &Vault) -> Result<()> {
        match self {
            Self::Raw(snapshot) => *snapshot = snapshot.with_actors_erased_here(vault)?,
            Self::Captured(source) => source.erase_actors_here(vault)?,
        }
        Ok(())
    }
}

/// One window's recovery from its canonical artifact, owning that artifact
/// for its whole life: every page reads the same source.
pub(crate) struct RecoveryWork {
    path: PathBuf,
    budget: RecoveryBudget,
    /// Whose turns the pages take: the owner of an owner act, else the
    /// host's own work.
    principal: Option<EntityId>,
    source: RecoverySource,
    digest: [u8; 32],
    phase: RecoveryPhase,
    validation: Option<CanonicalValidation>,
    encoding: Option<CanonicalEncoding>,
    encoded_digest: Option<EncodedDigest>,
    preflight_manifest: Option<ManifestChunks>,
    preflight_note_scope: Option<NoteScopeRows>,
    preflight_note_plan: Option<NotePlanRows>,
    doc: Option<LoroDoc>,
    rebuilt: RebuildAt,
    prepared: Option<PreparedRecovery>,
    forward: Option<ForwardRun>,
    verified: usize,
    /// In-progress structural recapture (FIX 10316 partial), if any.
    capture: Option<CanonicalCapture>,
    comparison: Option<CanonicalComparison>,
}

impl RecoveryWork {
    pub(crate) fn new(
        manifest_path: &Path,
        snapshot: &CanonicalSnapshot,
        budget: RecoveryBudget,
        principal: Option<EntityId>,
    ) -> Self {
        Self::from_source(
            manifest_path,
            RecoverySource::Raw(snapshot.clone()),
            budget,
            principal,
        )
    }

    pub(crate) fn from_store_capture(
        manifest_path: &Path,
        source: StoreCapturedCanonical,
        budget: RecoveryBudget,
        principal: Option<EntityId>,
    ) -> Self {
        Self::from_source(
            manifest_path,
            RecoverySource::Captured(source),
            budget,
            principal,
        )
    }

    fn from_source(
        manifest_path: &Path,
        source: RecoverySource,
        budget: RecoveryBudget,
        principal: Option<EntityId>,
    ) -> Self {
        Self {
            path: manifest_path.to_owned(),
            budget,
            principal,
            source,
            digest: [0; 32],
            phase: RecoveryPhase::Validate,
            validation: None,
            encoding: None,
            encoded_digest: None,
            preflight_manifest: None,
            preflight_note_scope: None,
            preflight_note_plan: None,
            doc: None,
            rebuilt: RebuildAt::default(),
            prepared: None,
            forward: None,
            verified: 0,
            capture: None,
            comparison: None,
        }
    }

    /// Runs pages, each on its own turn, until the work completes or
    /// `deadline` passes. `None` waits for each turn as long as the line
    /// waits; a wait that ends without a turn leaves the work pending.
    pub(crate) fn step(
        &mut self,
        vault: &Vault,
        materializer: &Materializer,
        deadline: Option<Instant>,
    ) -> Result<RecoveryProgress> {
        loop {
            if self.phase == RecoveryPhase::Complete {
                return Ok(RecoveryProgress::Complete);
            }
            let Ok(turn) = self.turn(vault, deadline) else {
                return Ok(RecoveryProgress::Pending(self.cursor()));
            };
            let result = self.page(vault, materializer);
            if result.is_err() && self.phase == RecoveryPhase::Validate {
                self.validation = None;
                self.encoding = None;
                self.encoded_digest = None;
            }
            if result.is_err() && self.phase == RecoveryPhase::Preflight {
                self.preflight_manifest = None;
                self.preflight_note_scope = None;
                self.preflight_note_plan = None;
                self.doc = None;
            }
            result?;
            drop(turn);
            if self.phase != RecoveryPhase::Complete
                && deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                return Ok(RecoveryProgress::Pending(self.cursor()));
            }
        }
    }

    /// Runs the work to its end, as a synchronous call or the CLI does: the
    /// same pages and turns, each wait that ends without a turn queued again.
    pub(crate) fn drain(
        mut self,
        vault: &Vault,
        materializer: &Materializer,
    ) -> Result<PreparedRecovery> {
        while let RecoveryProgress::Pending(cursor) = self.step(vault, materializer, None)? {
            tracing::debug!(
                artifact = %crate::entity_id::bytes_to_hex_lower(&cursor.digest[..16]),
                phase = ?cursor.phase,
                next = cursor.next_key.as_deref().unwrap_or(""),
                "canonical recovery waits for its next turn"
            );
        }
        self.prepared
            .ok_or_else(|| invalid("recovery completed without its preparation"))
    }

    /// Where the work stands.
    pub(crate) fn cursor(&self) -> RecoveryCursor {
        let next_key = match self.phase {
            RecoveryPhase::Validate => self
                .encoding
                .as_ref()
                .map(CanonicalEncoding::position)
                .or_else(|| {
                    self.validation
                        .as_ref()
                        .map(|validation| format!("validate {}", validation.position()))
                }),
            RecoveryPhase::Rebuild => Some(self.rebuilt.position()),
            RecoveryPhase::Replay => self.forward.as_ref().map(|forward| {
                let (pass, key) = forward.position();
                format!("{pass}:{}", key.unwrap_or_default())
            }),
            RecoveryPhase::Verify => Some(format!("check {}", self.verified)),
            _ => None,
        };
        RecoveryCursor {
            digest: self.digest,
            phase: self.phase,
            next_key,
        }
    }

    /// This work's next turn on the vault's task-work line.
    fn turn(
        &self,
        vault: &Vault,
        deadline: Option<Instant>,
    ) -> std::result::Result<LinePermit, WaitTimedOut> {
        let wait = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        match (self.principal, wait) {
            (Some(principal), Some(wait)) => vault.task_work.admit_blocking_for(principal, wait),
            (Some(principal), None) => vault.task_work.admit_blocking(principal),
            (None, Some(wait)) => vault.task_work.admit_background_blocking_for(wait),
            (None, None) => vault.task_work.admit_background_blocking(),
        }
    }

    /// One page of the phase the work stands in.
    fn page(&mut self, vault: &Vault, materializer: &Materializer) -> Result<()> {
        let page = self.budget.max_obligations.max(1);
        match self.phase {
            RecoveryPhase::Validate => {
                if self.encoded_digest.is_none() {
                    if self.encoding.is_none() {
                        // An actor this vault erased reads as no one in the artifact
                        // too (FIX 3878): the recovery checks, installs and compares
                        // only that form. Full domain validation precedes quarantine
                        // and every durable write.
                        if self.validation.is_none() {
                            self.source.erase_actors_here(vault)?;
                        }
                        if !self
                            .validation
                            .get_or_insert_with(CanonicalValidation::default)
                            .advance(&self.source, page)?
                        {
                            return Ok(());
                        }
                        self.encoding = Some(CanonicalEncoding::new(CANONICAL_SNAPSHOT_MAX_BYTES)?);
                    }
                    if !self
                        .encoding
                        .as_mut()
                        .expect("validated source encoding is retained")
                        .advance(&self.source, page)?
                    {
                        return Ok(());
                    }
                    let encoded = self
                        .encoding
                        .take()
                        .expect("completed canonical encoding")
                        .into_bytes();
                    limit(encoded.len(), self.budget.max_bytes)?;
                    self.encoded_digest = Some(EncodedDigest::new(encoded));
                }
                if !self
                    .encoded_digest
                    .as_mut()
                    .expect("validated encoding is retained for hashing")
                    .advance(page)
                {
                    return Ok(());
                }
                self.digest = self
                    .encoded_digest
                    .take()
                    .expect("completed canonical hashing")
                    .into_digest();
                self.validation = None;
                self.doc = Some(rebuild_start());
                self.phase = RecoveryPhase::Rebuild;
            }
            RecoveryPhase::Rebuild => {
                let doc = self
                    .doc
                    .as_ref()
                    .ok_or_else(|| invalid("recovery rebuild"))?;
                if rebuild_page(doc, &self.source, &mut self.rebuilt, page)? {
                    doc.commit();
                    self.phase = RecoveryPhase::Preflight;
                }
            }
            RecoveryPhase::Preflight => self.preflight(vault, materializer)?,
            RecoveryPhase::Replay => {
                let (Some(forward), Some(prepared)) = (self.forward.as_mut(), &self.prepared)
                else {
                    return Err(invalid("recovery replay"));
                };
                let key = WindowKey::new(&self.source.window);
                if forward
                    .recovery_page_with_source(
                        vault,
                        &prepared.window,
                        materializer,
                        &key,
                        &self.source,
                        self.source.captured(),
                        page,
                    )?
                    .is_some()
                {
                    self.forward = None;
                    self.phase = RecoveryPhase::Verify;
                }
            }
            RecoveryPhase::Verify => {
                let prepared = self
                    .prepared
                    .as_ref()
                    .ok_or_else(|| invalid("recovery verify"))?;
                if verify_page(
                    vault,
                    prepared,
                    &self.source,
                    &mut self.verified,
                    page,
                    &mut self.capture,
                    &mut self.comparison,
                )? {
                    self.phase = RecoveryPhase::Publish;
                }
            }
            RecoveryPhase::Publish => {
                let prepared = self
                    .prepared
                    .as_ref()
                    .ok_or_else(|| invalid("recovery publish"))?;
                if prepared.tier != RecoveryTier::Healthy {
                    prepared.publish(&self.path)?;
                }
                self.phase = RecoveryPhase::Complete;
            }
            RecoveryPhase::Complete => {}
        }
        Ok(())
    }

    /// The whole-bundle preflight over the rebuilt window, then the
    /// manifest's tier and quarantine, before any durable write.
    fn preflight(&mut self, vault: &Vault, materializer: &Materializer) -> Result<()> {
        if self.preflight_manifest.is_none() {
            let doc = self
                .doc
                .take()
                .ok_or_else(|| invalid("recovery preflight"))?;
            let rows = self
                .preflight_note_scope
                .get_or_insert_with(NoteScopeRows::default);
            if !rows.advance(&self.source, self.budget.max_obligations) {
                self.doc = Some(doc);
                return Ok(());
            }
            let plan = self
                .preflight_note_plan
                .get_or_insert_with(NotePlanRows::default);
            if !plan.advance(&self.source, rows.scope(), self.budget.max_obligations) {
                self.doc = Some(doc);
                return Ok(());
            }
            crate::sync::bridge::preflight_validated_canonical_recovery_with_source(
                vault,
                materializer,
                &self.source,
                &doc,
                self.source.captured(),
                rows.scope(),
                plan,
            )?;
            self.preflight_note_scope = None;
            self.preflight_note_plan = None;
            self.doc = Some(doc);
            self.preflight_manifest = Some(ManifestChunks::default());
        }
        if !self
            .preflight_manifest
            .as_mut()
            .expect("preflight started manifest construction")
            .advance(&self.source, self.budget.max_obligations)?
        {
            return Ok(());
        }
        let expected = self
            .preflight_manifest
            .take()
            .expect("completed manifest construction")
            .into_manifest(self.digest);
        let doc = self
            .doc
            .take()
            .ok_or_else(|| invalid("recovery preflight"))?;
        let prepared = prepare_rebuilt_with_manifest(&self.path, expected, self.budget, doc)?;
        // A task whose fact the source refused reads as a refusal here before
        // the replay can read its authority.
        if !self.source.suppressed_tasks.is_empty() {
            vault.with_write_txn(|txn| {
                crate::task_authority::restore_suppressed_in_txn(
                    &vault.store,
                    txn,
                    &self.source.suppressed_tasks,
                )
            })?;
        }
        let key = WindowKey::new(&self.source.window);
        self.forward = Some(ForwardRun::open_recovery(
            vault,
            &prepared.window,
            materializer,
            &key,
            &self.source,
        )?);
        self.prepared = Some(prepared);
        self.phase = RecoveryPhase::Replay;
        Ok(())
    }
}
