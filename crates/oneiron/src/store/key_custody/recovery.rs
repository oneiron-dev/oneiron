//! Recovering a lineage's custody from its published head (KS-4, FIX 5685):
//! the requirement a sealed image names, the admission that checks a head
//! against it, and the landing a disaster recovery makes.
//!
//! An image names what it needs, never a key: the position its custody had
//! reached and every live id it held then ([`CustodyRequirement`]). A
//! restore on a host without that custody reads the source's latest head
//! and, when an anchor is configured, the lineage's current anchor record.
//! It opens the head (the kit's root, or the data key the backup unlocked
//! with: one validator, two openers), checks the anchor's tag under the
//! head's control secret, reconciles head and anchor through the keyless
//! log (a head behind its anchor replays the retirements after it, a head
//! ahead of it proves the anchor's position is its ancestor), proves the
//! image's position is an ancestor of the result, and finds every required
//! id live or retired. Anything short of that refuses. With no anchor
//! configured the head is used as it is, and the restore says rollback is
//! not proven (CALLS CUSTODY_ANCHOR_UNSET_RESTORE).
//!
//! A disaster recovery lands the admitted custody beside its destination in
//! the same namespace, every retirement fact first, then the live entries,
//! then the journal at the next writer epoch; with an anchor configured, its
//! advance to that epoch fences the lineage's old writer before the restore
//! is kept.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::store::Store;

use super::anchor::{
    AnchorAdvance, AnchorStore, anchor_record, anchored_position, verified_position,
};
use super::files::{EntryState, LocalCustody, container, make_new_dir};
use super::fork::ForkedCustodyDir;
use super::head::{CustodyOpener, OpenedHead, open_head, serde_bytes_vec};
use super::identity::{CustodyBinding, CustodyId, CustodyKind, CustodySecret, CustodySubject};
use super::log::{Control, CustodyPosition, FrameHeader, LogEntry, frame_hash, open_frame};
use super::publish::{CustodySource, Lineage};

/// What a restore with no anchor configured says about the head it used
/// (Engine 10-20 04:0x).
pub(crate) const ROLLBACK_NOT_PROVEN: &str = "rollback not proven: no custody anchor configured";

/// CALLS CUSTODY_ANCHOR_UNSET_RESTORE (Engine 10-20 04:0x): with no anchor
/// configured, a restore uses the head it finds and proceeds with
/// [`ROLLBACK_NOT_PROVEN`] in its report; `false` would refuse it.
pub(crate) const CUSTODY_ANCHOR_UNSET_RESTORE: bool = true;

fn refused(reason: String) -> Error {
    Error::InvalidConfig(reason)
}

/// What a sealed image needs of its custody: the position it had reached
/// and every id live in it then. Never a key, and never a frozen head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyRequirement {
    #[serde(with = "serde_bytes_vec")]
    position: Vec<u8>,
    required: Vec<RequiredId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredId {
    kind: u8,
    #[serde(with = "serde_bytes_vec")]
    item: Vec<u8>,
    generation: u64,
}

impl CustodyRequirement {
    fn position(&self) -> Result<CustodyPosition> {
        CustodyPosition::from_bytes(&self.position)
            .ok_or_else(|| refused("the backup's custody requirement does not parse".into()))
    }

    fn ids(&self) -> Result<Vec<CustodyId>> {
        let position = self.position()?;
        self.required
            .iter()
            .map(|id| {
                let kind = CustodyKind::from_tag(id.kind).ok_or_else(|| {
                    refused("the backup names a custody kind this build lacks".into())
                })?;
                Ok(CustodySubject::new(position.vault, kind, &id.item)?.at(id.generation))
            })
            .collect()
    }
}

impl Store {
    /// What an image taken now needs of this vault's custody; `None` while
    /// nothing was ever published under it. The caller holds the custody
    /// read guard across this and the image's snapshot.
    pub(crate) fn custody_requirement(&self) -> Result<Option<CustodyRequirement>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(None);
        };
        let position = custody.journal()?.position()?;
        let census = custody.census()?;
        if position.seq == 0 && census.is_empty() {
            return Ok(None);
        }
        Ok(Some(CustodyRequirement {
            position: position.to_bytes().to_vec(),
            required: census
                .into_iter()
                .filter(|(_, state)| *state == EntryState::Live)
                .map(|(id, _)| RequiredId {
                    kind: id.kind().tag(),
                    item: id.subject().item().to_vec(),
                    generation: id.generation(),
                })
                .collect(),
        }))
    }
}

/// A lineage's custody as admitted for a restore.
pub(crate) struct AdmittedCustody {
    /// The position admitted: the anchor's, or the head's where it is newer
    /// or no anchor is configured, at the newer of their writer epochs.
    position: CustodyPosition,
    control: Zeroizing<[u8; 32]>,
    live: BTreeMap<CustodyId, CustodySecret>,
    retired: BTreeSet<CustodyId>,
    /// Subjects whose generations through this one the log after the head
    /// retired.
    retired_through: BTreeMap<CustodySubject, u64>,
    /// The anchor record admission read; `None` with no anchor configured.
    anchor: Option<Vec<u8>>,
}

impl AdmittedCustody {
    /// What the restore says about this admission: rollback is not proven
    /// when no anchor was configured.
    pub(crate) fn note(&self) -> Option<&'static str> {
        self.anchor.is_none().then_some(ROLLBACK_NOT_PROVEN)
    }

    fn retires(&self, id: &CustodyId) -> bool {
        self.retired.contains(id)
            || self
                .retired_through
                .get(id.subject())
                .is_some_and(|through| id.generation() <= *through)
    }
}

/// The frames of `source` after `from` through `to`, each checked to
/// extend the one before it, from `from`'s tip to `to`'s.
fn chain(
    source: &dyn CustodySource,
    lineage: Lineage,
    from: &CustodyPosition,
    to: &CustodyPosition,
) -> Result<Vec<Vec<u8>>> {
    let mut tip = from.tip;
    let mut frames = Vec::new();
    for seq in from.seq.saturating_add(1)..=to.seq {
        let frame = source.frame(lineage, seq)?.ok_or_else(|| {
            refused("the custody log beside the backup is missing a frame".into())
        })?;
        let (header, _): (FrameHeader, _) = FrameHeader::parse(&frame)?;
        if header.seq != seq
            || header.prev != tip
            || header.epoch > to.epoch
            || header.vault != lineage.vault
            || header.namespace != lineage.namespace
        {
            return Err(refused(
                "the custody log beside the backup does not chain".into(),
            ));
        }
        tip = frame_hash(&frame);
        frames.push(frame);
    }
    if tip != to.tip {
        return Err(refused(
            "the custody log beside the backup does not chain".into(),
        ));
    }
    Ok(frames)
}

/// Admits the custody `required` names from `source`, opened with
/// `opener`, against `anchor` when one is configured. Refuses a missing
/// head; with an anchor, a missing or stale anchor record; and a bad seal,
/// lineage, chain or coverage.
pub(crate) fn admit_recovery(
    required: &CustodyRequirement,
    source: &dyn CustodySource,
    opener: &CustodyOpener<'_>,
    anchor: Option<&dyn AnchorStore>,
) -> Result<AdmittedCustody> {
    let wanted = required.position()?;
    let lineage = Lineage::of(&wanted);
    let record =
        match anchor {
            Some(anchor) => Some(anchor.read(lineage.vault, lineage.namespace)?.ok_or_else(
                || refused("the custody anchor holds no record of this vault's custody".into()),
            )?),
            None if CUSTODY_ANCHOR_UNSET_RESTORE => None,
            None => return Err(refused(ROLLBACK_NOT_PROVEN.into())),
        };
    let head = source
        .head(lineage)?
        .ok_or_else(|| refused("no custody head of this vault is beside the backup".into()))?;
    let opened: OpenedHead = open_head(&head, opener)?;
    drop(head);
    if !opened.position.same_lineage(&wanted) {
        return Err(refused(
            "the custody head beside the backup is another vault's".into(),
        ));
    }
    let control = Control::for_secret(opened.control);
    // Ids the log after the head mints: their keys are in no head admitted.
    let mut minted_after = BTreeSet::new();
    let mut admitted = AdmittedCustody {
        position: opened.position,
        control: Zeroizing::new(*control.secret()),
        live: opened.live,
        retired: opened.retired,
        retired_through: BTreeMap::new(),
        anchor: None,
    };
    if let Some(record) = record {
        let anchored = verified_position(&record, &control.anchor_key())?;
        let head = admitted.position;
        if !anchored.same_lineage(&head) {
            return Err(refused(
                "the custody anchor record is another vault's".into(),
            ));
        }
        let epoch = head.epoch.max(anchored.epoch);
        if anchored.seq == head.seq && anchored.tip == head.tip && head.epoch <= anchored.epoch {
            admitted.position = anchored;
        } else if head.seq > anchored.seq && head.epoch >= anchored.epoch {
            chain(source, lineage, &anchored, &head)?;
        } else if head.seq < anchored.seq {
            // The head is older than its anchor: the retirements after it
            // still apply, and a key minted after it is not in it.
            for frame in chain(source, lineage, &head, &anchored)? {
                match open_frame(&control, &frame)?.1 {
                    LogEntry::Retire {
                        subject, through, ..
                    } => {
                        admitted.live.retain(|id, _| {
                            !(id.subject() == &subject && id.generation() <= through)
                        });
                        let slot = admitted.retired_through.entry(subject).or_insert(through);
                        *slot = (*slot).max(through);
                    }
                    LogEntry::Mint(id) => {
                        minted_after.insert(id);
                    }
                }
            }
            admitted.position = anchored;
        } else {
            return Err(refused(
                "the custody head and its anchor have diverged".into(),
            ));
        }
        admitted.position.epoch = epoch;
        admitted.anchor = Some(record);
    }
    // The image's position is the admitted one, or its ancestor.
    let current = admitted.position;
    if wanted.seq > current.seq || wanted.epoch > current.epoch {
        return Err(refused(
            "the custody head is older than the backup: it cannot hold every key the backup needs"
                .into(),
        ));
    }
    if wanted.seq == current.seq {
        if wanted.tip != current.tip {
            return Err(refused(
                "the custody head and the backup have diverged".into(),
            ));
        }
    } else {
        chain(source, lineage, &wanted, &current)?;
    }
    let missing: Vec<CustodyId> = required
        .ids()?
        .into_iter()
        .filter(|id| !admitted.live.contains_key(id) && !admitted.retires(id))
        .collect();
    if !missing.is_empty() {
        let count = missing.len();
        return Err(refused(
            if missing.iter().any(|id| minted_after.contains(id)) {
                format!(
                    "{count} key(s) the backup needs were minted after the newest custody head \
                     beside it"
                )
            } else if opened.unopened.is_empty() {
                format!("the custody head does not hold {count} key(s) the backup needs")
            } else {
                format!(
                    "the custody head holds {count} key(s) the backup needs in a compartment only \
                     the recovery kit opens: restore with --unlock kit"
                )
            },
        ));
    }
    Ok(admitted)
}

/// Lands `admitted` beside the restore's destination under `binding`, the
/// image's own rebound there (the same namespace): a new container, every
/// retirement fact first, then every live entry, then the journal at the
/// next writer epoch, all synced. The directory it made is removed when the
/// restore fails.
pub(crate) fn land_recovery(
    admitted: &AdmittedCustody,
    binding: &CustodyBinding,
) -> Result<ForkedCustodyDir> {
    let path = container(binding.root())?;
    let directory = make_new_dir(&path, None)?;
    let landed = ForkedCustodyDir::made(path, directory)?;
    let staged = (|| -> Result<()> {
        let custody = LocalCustody::at(binding);
        custody.open_compartment()?;
        for id in &admitted.retired {
            custody.retire_local(id)?;
        }
        for (subject, through) in &admitted.retired_through {
            for generation in 0..=*through {
                custody.retire_local(&subject.at(generation))?;
            }
        }
        for (id, secret) in &admitted.live {
            custody.publish(id, secret)?;
        }
        let control = Control::taken_over(admitted.control.clone(), &admitted.position)?;
        custody.journal()?.install(&control)?;
        landed.sync()
    })();
    match staged {
        Ok(()) => Ok(landed),
        Err(error) => {
            landed.remove();
            Err(error)
        }
    }
}

/// Advances the anchor admission read to the next writer epoch at the
/// admitted position, fencing the lineage's old writer. Refused when the
/// anchor moved since admission: a retirement may have completed there.
pub(crate) fn fence_takeover(admitted: &AdmittedCustody, anchor: &dyn AnchorStore) -> Result<()> {
    let Some(record) = &admitted.anchor else {
        return Ok(());
    };
    let control = Control::taken_over(admitted.control.clone(), &admitted.position)?;
    let taken = CustodyPosition {
        epoch: control.epoch,
        ..admitted.position
    };
    let current = anchored_position(record)?;
    if !current.same_lineage(&taken) {
        return Err(refused(
            "the custody anchor record is another vault's".into(),
        ));
    }
    match anchor.advance(
        Some(*blake3::hash(record).as_bytes()),
        &anchor_record(&taken, &control),
    )? {
        AnchorAdvance::Advanced => Ok(()),
        AnchorAdvance::Moved => Err(refused(
            "this vault's custody moved on while the restore ran; run the restore again".into(),
        )),
    }
}

/// Where a restore that keeps its image's custody takes it from.
pub(crate) enum CustodyRoute {
    /// As before: the custody is on this host, the image binds none, or the
    /// caller reads no head (a wake, a migration, an engine restore).
    Local,
    /// The image names a head, and its custody is not on this host: the
    /// head was admitted and landed beside the destination.
    Landed(Box<CustodyLanding>),
    /// The image names no head (or needs no live key and none is beside
    /// it), and its custody is not on this host: its claim-bound rows whose
    /// keys stayed there are dropped and named (CALLS
    /// CUSTODY_NO_HEAD_GATE_ROWS).
    Absent,
}

/// Where a restore on a new host finds its custody head, and what opens it:
/// the folder beside the backup, the anchor root when one is configured,
/// and the kit's recovery root when the restore was unlocked with the kit.
pub(crate) struct CustodySourceAt<'a> {
    pub(crate) folder: &'a std::path::Path,
    pub(crate) anchor_root: Option<&'a std::path::Path>,
    pub(crate) root: Option<&'a oneiron_crypto::HybridSecretKey>,
}

/// A head's custody landed beside a restore's destination: removed unless
/// the restore keeps it.
pub(crate) struct CustodyLanding {
    landed: Option<ForkedCustodyDir>,
    admitted: AdmittedCustody,
    anchor_root: Option<std::path::PathBuf>,
}

impl CustodyLanding {
    /// What the restore's report says about the head it used.
    pub(crate) fn note(&self) -> Option<&'static str> {
        self.admitted.note()
    }

    /// With an anchor configured, fences the lineage's old writer before
    /// the restore is kept.
    pub(crate) fn fence(&self) -> Result<()> {
        match &self.anchor_root {
            Some(root) => {
                fence_takeover(&self.admitted, &super::anchor::FileAnchor::at(root.clone()))
            }
            None => Ok(()),
        }
    }

    /// The restore is kept, and its custody with it.
    pub(crate) fn keep(mut self) {
        self.landed = None;
    }
}

impl Drop for CustodyLanding {
    fn drop(&mut self) {
        if let Some(landed) = self.landed.take() {
            landed.remove();
        }
    }
}

/// The route a restore that keeps its image's custody takes, decided on the
/// image's `rows` before anything is made at `destination`. A landed head
/// rebinds the image's binding row beside `destination` in `rows`, so the
/// restore's preflight reads the landed custody. `data_key` is the backup
/// key's custody subkey; `source` is `None` where the caller reads no head,
/// which restores as before.
pub(crate) fn route_custody(
    rows: &mut [(Vec<u8>, Vec<u8>)],
    required: Option<&CustodyRequirement>,
    destination: &std::path::Path,
    data_key: Zeroizing<[u8; 32]>,
    source: Option<&CustodySourceAt<'_>>,
) -> Result<CustodyRoute> {
    let Some(bound) = super::binding_in_rows(rows)? else {
        return Ok(CustodyRoute::Local);
    };
    if super::custody_present(bound.root())? {
        return Ok(CustodyRoute::Local);
    }
    let Some(source) = source else {
        return Ok(CustodyRoute::Local);
    };
    let Some(required) = required else {
        return Ok(CustodyRoute::Absent);
    };
    let target = super::publish::FolderTarget::at(source.folder.to_path_buf());
    // An image that needs no live key has nothing for a head to recover.
    if required.required.is_empty() && target.head(Lineage::of(&required.position()?))?.is_none() {
        return Ok(CustodyRoute::Absent);
    }
    let opener = CustodyOpener {
        root: source.root,
        data_key: Some(data_key),
    };
    let anchor = source
        .anchor_root
        .map(|root| super::anchor::FileAnchor::at(root.to_path_buf()));
    let admitted = admit_recovery(
        required,
        &target,
        &opener,
        anchor.as_ref().map(|anchor| anchor as &dyn AnchorStore),
    )?;
    // The restored vault opens at its canonical root: its parent resolved,
    // its own name as made.
    let name = destination
        .file_name()
        .ok_or_else(|| refused("the restore destination has no name".into()))?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let root = parent.canonicalize()?.join(name);
    if super::custody_present(&root)? {
        return Err(refused(
            "key custody already exists beside the restore destination; restore elsewhere".into(),
        ));
    }
    let binding = bound.rebind_to(root);
    let landed = land_recovery(&admitted, &binding)?;
    let landing = Box::new(CustodyLanding {
        landed: Some(landed),
        admitted,
        anchor_root: source.anchor_root.map(std::path::Path::to_path_buf),
    });
    let raw = crate::side_table::RawValue::to_raw(&binding)
        .map_err(|_| super::identity::custody_corrupt())?;
    for (key, value) in rows.iter_mut() {
        if key.as_slice() == super::binding_key() {
            *value = raw.clone();
        }
    }
    Ok(CustodyRoute::Landed(landing))
}
