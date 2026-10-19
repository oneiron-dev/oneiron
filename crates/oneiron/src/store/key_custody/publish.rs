//! Publishing one lineage's custody (KS-4, FIX 5685): its keyless log, then
//! its latest sealed head, to a target, then its anchor.
//!
//! The journal is synced before anything is shipped (each frame at its
//! act). A pass seals a head at the local log position, ships every frame
//! the target lacks, switches the target's latest head in one atomic step,
//! deletes every superseded key-bearing head the target held, and advances
//! the anchor by compare-and-swap. Nothing here is ever waited on by a save
//! or a backup: a pass that fails leaves its step pending by name, and the
//! next pass retries. The head always publishes; the anchor is the one
//! optional step (Engine 10-20 04:0x), pending by name while no anchor root
//! is set up. Each pass records where it got (`<journal>/status`, no
//! secret in it), which the owner's status read reports.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::store::Store;

use super::anchor::{AnchorAdvance, AnchorStore, anchor_record, verified_position};
use super::files::{EntryState, open_dir, read_whole, replace_file, write_once};
use super::head::{CustodyRecipients, HeadEntry, head_position, seal_head};
use super::identity::{CustodyNamespace, CustodyVaultId};
use super::log::{CustodyPosition, POSITION_LEN, frame_name, log_corrupt};

const FOLDER: &str = "oneiron-custody";
const HEAD: &str = "head";
const LOG: &str = "log";
const STATUS: &str = "status";

/// One lineage a target holds: a vault's custody in one namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lineage {
    pub(crate) vault: CustodyVaultId,
    pub(crate) namespace: CustodyNamespace,
}

impl Lineage {
    pub(super) fn of(position: &CustodyPosition) -> Self {
        Self {
            vault: position.vault,
            namespace: position.namespace,
        }
    }
}

/// Where a restore reads a lineage's custody from: an archive target or
/// the kit's fetch, through the same validator.
pub(crate) trait CustodySource {
    /// The lineage's latest head there, if any.
    fn head(&self, lineage: Lineage) -> Result<Option<Vec<u8>>>;
    /// The lineage's log frame at `seq` there, if any.
    fn frame(&self, lineage: Lineage, seq: u64) -> Result<Option<Vec<u8>>>;
}

/// Where a pass publishes a lineage's custody.
pub(crate) trait CustodyTarget: CustodySource {
    /// Ships `frames` (by sequence number, ascending) the target lacks,
    /// then makes `head` its latest head in one atomic step, then deletes
    /// every superseded head and temporary it holds for the lineage and
    /// shows, by listing again, that none is left.
    fn publish(&self, lineage: Lineage, frames: &[(u64, Vec<u8>)], head: &[u8]) -> Result<()>;
}

/// A folder target: `<folder>/oneiron-custody/<namespace hex>.<vault hex>/`
/// holding `head` and `log/f<seq hex16>`, every directory owner-only.
pub(crate) struct FolderTarget {
    folder: PathBuf,
}

impl FolderTarget {
    pub(crate) fn at(folder: PathBuf) -> Self {
        Self { folder }
    }

    fn dir(&self, lineage: Lineage) -> PathBuf {
        self.folder.join(FOLDER).join(format!(
            "{}.{}",
            crate::entity_id::bytes_to_hex_lower(lineage.namespace.as_bytes()),
            crate::entity_id::bytes_to_hex_lower(lineage.vault.as_bytes())
        ))
    }
}

impl CustodySource for FolderTarget {
    fn head(&self, lineage: Lineage) -> Result<Option<Vec<u8>>> {
        read_whole(&self.dir(lineage).join(HEAD))
    }

    fn frame(&self, lineage: Lineage, seq: u64) -> Result<Option<Vec<u8>>> {
        read_whole(&self.dir(lineage).join(LOG).join(frame_name(seq)))
    }
}

impl CustodyTarget for FolderTarget {
    fn publish(&self, lineage: Lineage, frames: &[(u64, Vec<u8>)], head: &[u8]) -> Result<()> {
        let dir = self.dir(lineage);
        open_dir(&self.folder.join(FOLDER), true, None)?;
        open_dir(&dir, true, None)?;
        let log = dir.join(LOG);
        open_dir(&log, true, None)?;
        for (seq, frame) in frames {
            let name = frame_name(*seq);
            // A frame already there must be this one: the log is append-only.
            if !write_once(&log, &name, frame)?
                && read_whole(&log.join(&name))?.as_deref() != Some(frame.as_slice())
            {
                return Err(log_corrupt());
            }
        }
        replace_file(&dir, HEAD, head)?;
        sweep(&dir)?;
        sweep(&log)?;
        let left = fs::read_dir(&dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        if left.iter().any(|name| name != HEAD && name != LOG) {
            return Err(crate::error::Error::InvalidConfig(
                "a superseded custody head is still on the folder target".into(),
            ));
        }
        Ok(())
    }
}

/// Removes every temporary an interrupted write left in `dir`, a head's
/// among them, and syncs it.
fn sweep(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with(".t") && name.ends_with(".pending"))
        {
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
    }
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Where one lineage's publication stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationState {
    /// Nothing is in custody yet, so there is no head to publish.
    Nothing,
    /// The head at the local log position is on the target and anchored.
    Published,
    /// The target does not hold the head at the local position yet.
    TargetPending,
    /// The anchor step is not done: no anchor root is set up, it is
    /// missing, or its advance has not gone through.
    AnchorPending,
    /// The anchor names a newer writer epoch: another install took this
    /// lineage over in a disaster recovery, and this one publishes no more.
    Fenced,
}

/// One lineage's publication: its state, the positions it compared, and
/// why a step is pending, in words naming no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Publication {
    pub(crate) state: PublicationState,
    pub(crate) local: Option<CustodyPosition>,
    pub(crate) published: Option<CustodyPosition>,
    pub(crate) anchored: Option<CustodyPosition>,
    pub(crate) detail: Option<String>,
}

impl Publication {
    fn nothing() -> Self {
        Self {
            state: PublicationState::Nothing,
            local: None,
            published: None,
            anchored: None,
            detail: None,
        }
    }

    fn pending(
        state: PublicationState,
        local: CustodyPosition,
        published: Option<CustodyPosition>,
        anchored: Option<CustodyPosition>,
        detail: String,
    ) -> Self {
        Self {
            state,
            local: Some(local),
            published,
            anchored,
            detail: Some(detail),
        }
    }
}

/// What the anchor step reads when no anchor root is set up (CALLS
/// CUSTODY_ANCHOR_ROOT: unset by default).
pub(crate) const ANCHOR_UNSET: &str = "no custody anchor root is set (backup.custody_anchor_root)";

/// The head position a target holds for `lineage`, unauthenticated.
fn target_position(target: &dyn CustodySource, lineage: Lineage) -> Option<CustodyPosition> {
    target
        .head(lineage)
        .ok()
        .flatten()
        .and_then(|head| head_position(&head).ok())
}

impl PublicationState {
    fn code(self) -> u8 {
        match self {
            Self::Nothing => 0,
            Self::Published => 1,
            Self::TargetPending => 2,
            Self::AnchorPending => 3,
            Self::Fenced => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Nothing,
            1 => Self::Published,
            2 => Self::TargetPending,
            3 => Self::AnchorPending,
            4 => Self::Fenced,
            _ => return None,
        })
    }
}

/// `state | 3 x (0 | 1 position) | detail utf-8`.
fn encode_status(publication: &Publication) -> Vec<u8> {
    let mut out = vec![publication.state.code()];
    for position in [
        publication.local,
        publication.published,
        publication.anchored,
    ] {
        match position {
            Some(position) => {
                out.push(1);
                out.extend_from_slice(&position.to_bytes());
            }
            None => out.push(0),
        }
    }
    out.extend_from_slice(publication.detail.as_deref().unwrap_or("").as_bytes());
    out
}

fn decode_status(bytes: &[u8]) -> Option<Publication> {
    let (&state, mut rest) = bytes.split_first()?;
    let mut positions = [None; 3];
    for slot in &mut positions {
        let (&present, after) = rest.split_first()?;
        rest = after;
        if present == 1 {
            *slot = Some(CustodyPosition::from_bytes(rest.get(..POSITION_LEN)?)?);
            rest = &rest[POSITION_LEN..];
        }
    }
    let detail = std::str::from_utf8(rest).ok()?;
    Some(Publication {
        state: PublicationState::from_code(state)?,
        local: positions[0],
        published: positions[1],
        anchored: positions[2],
        detail: (!detail.is_empty()).then(|| detail.to_owned()),
    })
}

impl Store {
    /// One publication pass over this vault's custody lineage: its head to
    /// `target`, then `anchor` (`None`: no anchor root is set up, the step
    /// left pending by name). What happens on the way is the pass's state,
    /// recorded for the status read, never a refusal of anything; only a
    /// fault in the local custody itself is an error.
    pub(crate) fn publish_custody(
        &self,
        recipients: &CustodyRecipients,
        target: &dyn CustodyTarget,
        anchor: Option<&dyn AnchorStore>,
    ) -> Result<Publication> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Publication::nothing());
        };
        // An archived vault's custody is the one of the vault that replaced
        // it.
        if self.archived_in_txn(&self.env.read_txn()?)? {
            return Ok(Publication::nothing());
        }
        let journal = custody.journal()?;
        let publication = self.publish_pass(custody, &journal, recipients, target, anchor)?;
        if publication.state != PublicationState::Nothing {
            replace_file(journal.dir(), STATUS, &encode_status(&publication))?;
        }
        Ok(publication)
    }

    fn publish_pass(
        &self,
        custody: super::files::LocalCustody<'_>,
        journal: &super::log::Journal,
        recipients: &CustodyRecipients,
        target: &dyn CustodyTarget,
        anchor: Option<&dyn AnchorStore>,
    ) -> Result<Publication> {
        // The position first, then the entries, under the read guard: every
        // entry a frame up to the position mints is published before its
        // frame, and no retirement runs until the head is sealed.
        let (position, control, head) = {
            let _guard = self.core.key_custody.read_guard()?;
            let position = journal.position()?;
            let census = custody.census()?;
            if census.is_empty() && position.seq == 0 {
                return Ok(Publication::nothing());
            }
            let control = journal.control_or_create()?;
            let mut entries = Vec::new();
            let mut retired = Vec::new();
            for (id, state) in census {
                match state {
                    EntryState::Live => entries.push(HeadEntry {
                        secret: custody.read(&id)?,
                        id,
                    }),
                    EntryState::Retired => retired.push(id),
                    EntryState::Missing => {}
                }
            }
            let head = match seal_head(&position, &control, entries, retired, recipients) {
                Ok(head) => head,
                Err(error) => {
                    return Ok(Publication::pending(
                        PublicationState::TargetPending,
                        position,
                        None,
                        None,
                        error.to_string(),
                    ));
                }
            };
            (position, control, head)
        };
        let lineage = Lineage::of(&position);
        // The anchor is read before the target is written: a newer writer
        // epoch fenced this one, and its head would only overwrite the new
        // writer's.
        let current = match anchor.map(|anchor| anchor.read(lineage.vault, lineage.namespace)) {
            None => None,
            Some(Ok(current)) => current,
            Some(Err(error)) => {
                return Ok(Publication::pending(
                    PublicationState::AnchorPending,
                    position,
                    target_position(target, lineage),
                    None,
                    error.to_string(),
                ));
            }
        };
        let anchored = current
            .as_deref()
            .map(|record| verified_position(record, &control.anchor_key()))
            .transpose()?;
        if anchored.is_some_and(|anchored| anchored.epoch > position.epoch) {
            return Ok(Publication::pending(
                PublicationState::Fenced,
                position,
                target_position(target, lineage),
                anchored,
                "another install took this vault's custody over in a disaster recovery".into(),
            ));
        }
        let start = target_position(target, lineage)
            .filter(|published| published.same_lineage(&position) && published.seq <= position.seq)
            .map_or(0, |published| published.seq);
        let mut frames = Vec::new();
        for seq in start.saturating_add(1)..=position.seq {
            if target.frame(lineage, seq).ok().flatten().is_some() {
                continue;
            }
            // A lineage a disaster recovery took over starts its local log
            // after the admitted position; the target held what came before.
            if let Some(frame) = journal.frame(seq)? {
                frames.push((seq, frame));
            }
        }
        if let Err(error) = target.publish(lineage, &frames, &head) {
            return Ok(Publication::pending(
                PublicationState::TargetPending,
                position,
                target_position(target, lineage),
                anchored,
                error.to_string(),
            ));
        }
        drop(head);
        let Some(anchor) = anchor else {
            return Ok(Publication::pending(
                PublicationState::AnchorPending,
                position,
                Some(position),
                None,
                ANCHOR_UNSET.into(),
            ));
        };
        let done = |anchored| Publication {
            state: PublicationState::Published,
            local: Some(position),
            published: Some(position),
            anchored: Some(anchored),
            detail: None,
        };
        if anchored == Some(position) {
            return Ok(done(position));
        }
        let expected = current
            .as_deref()
            .map(|record| *blake3::hash(record).as_bytes());
        Ok(
            match anchor.advance(expected, &anchor_record(&position, &control)) {
                Ok(AnchorAdvance::Advanced) => done(position),
                Ok(AnchorAdvance::Moved) => Publication::pending(
                    PublicationState::AnchorPending,
                    position,
                    Some(position),
                    anchored,
                    "the custody anchor moved during this pass; the next pass retries".into(),
                ),
                Err(error) => Publication::pending(
                    PublicationState::AnchorPending,
                    position,
                    Some(position),
                    anchored,
                    error.to_string(),
                ),
            },
        )
    }

    /// Where this vault's custody publication stands, read without
    /// publishing: the last pass's record, behind the local log when a
    /// change since waits for the next pass.
    pub(crate) fn custody_publication(&self) -> Result<Publication> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Publication::nothing());
        };
        let journal = custody.journal()?;
        let local = journal.position()?;
        let recorded =
            read_whole(&journal.dir().join(STATUS))?.and_then(|bytes| decode_status(&bytes));
        Ok(match recorded {
            None if local.seq == 0 && custody.census()?.is_empty() => Publication::nothing(),
            None => Publication::pending(
                PublicationState::TargetPending,
                local,
                None,
                None,
                "no publication pass has run yet".into(),
            ),
            Some(recorded)
                if recorded.local != Some(local) && recorded.state != PublicationState::Fenced =>
            {
                Publication::pending(
                    PublicationState::TargetPending,
                    local,
                    recorded.published,
                    recorded.anchored,
                    "a custody change waits for the next publication pass".into(),
                )
            }
            Some(recorded) => recorded,
        })
    }
}
