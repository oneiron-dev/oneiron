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

mod admission;
mod credentials;
mod pads;
mod unopened;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::recovery::checkpoint::{Rejected, RestoreAdmissionReason as R, because};
use crate::store::Store;

use self::admission::{AdmittedCustody, admit_recovery};
use super::anchor::{anchor_record, anchored_position};
use super::body_history::merge_history_into_rows;
use super::erase_evidence::CredentialFenceFact;
use super::files::{EntryState, LocalCustody, container, make_new_dir};
use super::folder::FolderTarget;
use super::fork::ForkedCustodyDir;
use super::head::{CustodyOpener, serde_bytes_vec};
use super::identity::{CustodyBinding, CustodyId, CustodyKind, CustodySubject, decode_native_path};
use super::log::{Control, CustodyPosition};
use super::protocol::{AnchorAdvance, AnchorStore, CustodySource, Lineage};
use super::recipients::RecipientRetirement;

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
    /// The custody position the requirement names.
    pub(crate) fn position(&self) -> Result<CustodyPosition> {
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
    /// The local custody log's writer epoch and sequence, for a backup
    /// watermark: `(0, 0)` where this vault keeps no custody log. A cached
    /// read in the normal case.
    pub(crate) fn custody_log_mark(&self) -> Result<(u64, u64)> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok((0, 0));
        };
        let position = custody.journal()?.position()?;
        Ok((position.epoch.get(), position.seq))
    }

    /// What an image taken now needs of this vault's custody; `None` while
    /// nothing was ever published under it. The caller holds the custody
    /// read guard across this and the image's snapshot. Body instances are
    /// not listed: an image names each one its rows need beside them, and a
    /// restore requires each against the custody it lands (KS-2A), so the
    /// sealed manifest stays one frame however many bodies a vault keeps.
    /// Nor is the known-value index's master or history (KS-3): an image's
    /// references name each one it needs, which a restore requires the same
    /// way, and an entry no reference names is never needed. Nor is a world
    /// pad (KS-5): an image names each pad by its row's reference, which a
    /// restore plans the same way and decides per row (FIX 5686 part 2).
    /// Nor is a credential's value or carrier key (KS-6): each is planned by
    /// the row or carrier that names it, never by the whole census. Nor is
    /// a connector call's resume key (FIX 9157): each is required by its
    /// call row when one names it, never by the whole census. Nor is an
    /// erasable key (FIX 8875): each is planned by the ref its row names.
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
                .filter(|(id, state)| {
                    *state == EntryState::Live
                        && !matches!(
                            id.kind(),
                            CustodyKind::BodyInstance
                                | CustodyKind::KnownValueIndex
                                | CustodyKind::KnownValueEntry
                                | CustodyKind::WorldPad
                                | CustodyKind::CredentialValue
                                | CustodyKind::CustodyTransition
                                | CustodyKind::CustodyRequestInput
                                | CustodyKind::ConnectorResume
                                | CustodyKind::ErasableKey
                        )
                })
                .map(|(id, _)| RequiredId {
                    kind: id.kind().tag(),
                    item: id.subject().item().to_vec(),
                    generation: id.generation(),
                })
                .collect(),
        }))
    }
}

/// Lands `admitted` beside the restore's destination under `binding`, the
/// image's own rebound there (the same namespace): a new container, every
/// retirement fact first, then every live entry but an erased credential's,
/// which lands retired, then each world pad compartment the head left
/// unopened, carried on (PAD-3, FIX 11133), then the journal at the next
/// writer epoch and every erased credential's fact, all synced. The admitted
/// retirements stay owed as one takeover obligation at the admitted
/// position: the new writer's targets and anchor must reach it at its epoch
/// before they count complete (KS-4A2). The directory it made is removed
/// when the restore fails.
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
        // A key of a credential the head's evidence fences lands retired,
        // never live (FIX 10584 item 4).
        let mut suppressed = false;
        for (id, secret) in &admitted.live {
            if credentials::fenced(&admitted.evidence, id) {
                custody.retire_local(id)?;
                suppressed = true;
                continue;
            }
            custody.publish(id, secret)?;
        }
        for carried in &admitted.carried {
            custody.put_carried(carried)?;
        }
        let control = Control::taken_over(admitted.control.clone(), &admitted.position)?;
        let journal = custody.journal()?;
        journal.install(&control)?;
        journal.put_history_base(&control, &admitted.position, &admitted.history)?;
        // The released recipients the lineage retired stay retired in it.
        for fact in admitted.recipients.values() {
            journal.put_recipient_fact(fact)?;
        }
        // So does every erased credential's fact (FIX 10584 item 3): the
        // restore's fences read it, and the next head carries it.
        for (&credential, &fact) in &admitted.evidence {
            custody.put_erase_evidence(&CredentialFenceFact { credential, fact })?;
        }
        if !admitted.retired.is_empty()
            || !admitted.retired_through.is_empty()
            || !admitted.recipients.is_empty()
            || suppressed
        {
            journal.record_takeover(&CustodyPosition {
                epoch: control.epoch,
                ..admitted.position
            })?;
        }
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
pub(crate) fn fence_takeover(
    admitted: &AdmittedCustody,
    anchor: &dyn AnchorStore,
) -> std::result::Result<(), Rejected> {
    let Some(record) = &admitted.anchor else {
        return Ok(());
    };
    let (taken, control) = admitted.taken_over()?;
    let current = anchored_position(record).map_err(because(R::AnchorInvalid))?;
    if !current.same_lineage(&taken) {
        return Err(Rejected::new(
            R::CustodyLineageMismatch,
            refused("the custody anchor record is another vault's".into()),
        ));
    }
    match anchor
        .advance(
            Some(*blake3::hash(record).as_bytes()),
            &anchor_record(&taken, &control),
        )
        .map_err(because(R::AnchorUnavailable))?
    {
        AnchorAdvance::Advanced => Ok(()),
        AnchorAdvance::Moved => Err(Rejected::new(
            R::AnchorMoved,
            refused(
                "this vault's custody moved on while the restore ran; run the restore again".into(),
            ),
        )),
    }
}

impl AdmittedCustody {
    /// The admitted position at the next writer epoch, and that epoch's
    /// control state: the takeover a landing journals at and a fence
    /// advances the anchor to.
    fn taken_over(&self) -> Result<(CustodyPosition, Control)> {
        let control = Control::taken_over(self.control.clone(), &self.position)?;
        let taken = CustodyPosition {
            epoch: control.epoch,
            ..self.position
        };
        Ok((taken, control))
    }
}

/// What a cold managed restore reports of a landing (LC FIX 5384/5385):
/// positions, the takeover writer epoch and anchor record digests, public
/// structure only.
pub(crate) struct LandingFacts {
    pub(crate) head: CustodyPosition,
    pub(crate) admitted: CustodyPosition,
    pub(crate) takeover_epoch: u64,
    pub(crate) anchor_read: Option<[u8; 32]>,
    pub(crate) anchor_advanced: Option<[u8; 32]>,
    pub(crate) retired_ids: usize,
}

/// Where a restore that keeps its image's custody takes it from.
pub(crate) enum CustodyRoute {
    /// As before: the custody is on this host, or the image binds none.
    Local,
    /// The image names a head, and its custody is not on this host: the
    /// head was admitted and landed beside the destination.
    Landed(Box<CustodyLanding>),
    /// No head is found for the image (none named, none beside the backup
    /// with no anchor to owe one, or the caller reads none: a wake, a
    /// migration, an engine restore), or it carries only the legacy untyped
    /// marker, and its custody is not on this host: its claim-bound rows
    /// whose keys stayed there are dropped and named (CALLS
    /// CUSTODY_NO_HEAD_GATE_ROWS).
    Absent,
}

/// Where a restore on a new host finds its custody head, and what opens it:
/// the folder beside the backup, the anchor when one is configured (a root
/// or a door), the kit's recovery root when the restore was unlocked with
/// the kit, and an admitted machine's key when one is given (FIX 9178).
pub(crate) struct CustodySourceAt<'a> {
    pub(crate) folder: &'a std::path::Path,
    pub(crate) anchor: Option<&'a dyn AnchorStore>,
    pub(crate) root: Option<&'a oneiron_crypto::HybridSecretKey>,
    pub(crate) machine: Option<(crate::EntityId, &'a oneiron_crypto::HybridSecretKey)>,
}

/// A head's custody landed beside a restore's destination: removed unless
/// the restore keeps it.
pub(crate) struct CustodyLanding {
    landed: Option<ForkedCustodyDir>,
    admitted: AdmittedCustody,
}

impl CustodyLanding {
    /// What the restore's report says about the head it used.
    pub(crate) fn note(&self) -> Option<&'static str> {
        self.admitted.note()
    }

    /// With an anchor configured (the one admission read), fences the
    /// lineage's old writer before the restore is kept.
    pub(crate) fn fence(
        &self,
        anchor: Option<&dyn AnchorStore>,
    ) -> std::result::Result<(), Rejected> {
        match anchor {
            Some(anchor) => fence_takeover(&self.admitted, anchor),
            None => Ok(()),
        }
    }

    /// The landing's positions, takeover epoch and anchor records, for a
    /// cold managed restore's receipt.
    pub(crate) fn facts(&self) -> Result<LandingFacts> {
        let admitted = &self.admitted;
        let (taken, control) = admitted.taken_over()?;
        let digest = |record: &[u8]| *blake3::hash(record).as_bytes();
        Ok(LandingFacts {
            head: admitted.head,
            admitted: admitted.position,
            takeover_epoch: taken.epoch.get(),
            anchor_read: admitted.anchor.as_deref().map(digest),
            anchor_advanced: admitted
                .anchor
                .as_ref()
                .map(|_| digest(&anchor_record(&taken, &control))),
            retired_ids: admitted.retired.len() + admitted.retired_through.len(),
        })
    }

    /// The released escrow recipients the admitted lineage retired.
    pub(crate) fn retired_recipients(&self) -> Vec<RecipientRetirement> {
        self.admitted.recipients.values().cloned().collect()
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

/// The pre-typed-custody marker (`gate_decision:custody_root:v1`): the
/// absolute vault root whose `.<name>.gate-decision-keys` held the claim
/// keys. No reader of those keys exists; the marker only says where they
/// were.
const LEGACY_CUSTODY_ROOT: &[u8] = b"gate_decision:custody_root:v1";

/// Whether `rows` carry only the legacy untyped marker, no typed binding,
/// and the keys it names are not on this host: the image binds no custody
/// here (Engine 10-20 05:2x). The marker leaves the rows with it.
fn legacy_binding_absent(rows: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<bool> {
    let Some(root) = rows
        .iter()
        .find(|(key, _)| key.as_slice() == LEGACY_CUSTODY_ROOT)
        .and_then(|(_, value)| decode_native_path(value))
    else {
        return Ok(false);
    };
    let Some(name) = root.file_name() else {
        return Ok(false);
    };
    let mut keys = std::ffi::OsString::from(".");
    keys.push(name);
    keys.push(".gate-decision-keys");
    match std::fs::symlink_metadata(root.with_file_name(keys)) {
        Ok(_) => Ok(false),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            rows.retain(|(key, _)| key.as_slice() != LEGACY_CUSTODY_ROOT);
            Ok(true)
        }
        Err(err) => Err(err.into()),
    }
}

/// A cold managed restore's check before its route (LC FIX 5384/5385): the
/// custody the image's rows bind is the lineage its manifest requires. No
/// other restore asks it.
pub(crate) fn refuse_foreign_binding(
    rows: &[(Vec<u8>, Vec<u8>)],
    required: Option<&CustodyRequirement>,
) -> std::result::Result<(), Rejected> {
    let bound = super::binding_in_rows(rows).map_err(because(R::CustodyRequirementInvalid))?;
    let (Some(bound), Some(required)) = (bound, required) else {
        return Ok(());
    };
    let wanted = required
        .position()
        .map_err(because(R::CustodyRequirementInvalid))?;
    if bound.vault() != wanted.vault || bound.namespace() != wanted.namespace {
        return Err(Rejected::new(
            R::CustodyLineageMismatch,
            refused("the backup's custody binding is not the lineage its manifest requires".into()),
        ));
    }
    Ok(())
}

/// The route a restore that keeps its image's custody takes, decided on the
/// image's `rows` before anything is made at `destination`. A landed head
/// rebinds the image's binding row beside `destination` in `rows`, so the
/// restore's preflight reads the landed custody. `data_key` is the backup
/// key's custody subkey; `source` is `None` where the caller reads no head
/// (a wake, a migration, an engine restore).
///
/// Whatever the entry point, an image opened where no head is found and its
/// custody is not (no source root, or only the legacy untyped marker with
/// its keys elsewhere) routes [`CustodyRoute::Absent`]: its claim-bound rows
/// whose keys stayed behind drop and are named, and the restore completes
/// (Engine 10-20 05:2x, ruling 4 widened). A head the image names, with an
/// anchor configured, is still admitted fail-closed.
pub(crate) fn route_custody(
    rows: &mut Vec<(Vec<u8>, Vec<u8>)>,
    required: Option<&CustodyRequirement>,
    destination: &std::path::Path,
    data_key: Zeroizing<[u8; 32]>,
    source: Option<&CustodySourceAt<'_>>,
) -> std::result::Result<CustodyRoute, Rejected> {
    let Some(bound) =
        super::binding_in_rows(rows).map_err(because(R::CustodyRequirementInvalid))?
    else {
        return Ok(if legacy_binding_absent(rows)? {
            CustodyRoute::Absent
        } else {
            CustodyRoute::Local
        });
    };
    if super::custody_present(bound.root())? {
        // The image takes its lineage's latest body history (FIX 6229); a
        // journal that does not fold restores as before, warned.
        match LocalCustody::at(&bound).body_history() {
            Ok(history) => merge_history_into_rows(rows, &history),
            Err(error) => tracing::warn!(kind = ?error.kind(), "body history did not fold"),
        }
        return Ok(CustodyRoute::Local);
    }
    let Some(source) = source else {
        return Ok(CustodyRoute::Absent);
    };
    let Some(required) = required else {
        return Ok(CustodyRoute::Absent);
    };
    let wanted = required
        .position()
        .map_err(because(R::CustodyRequirementInvalid))?;
    let target = FolderTarget::at(source.folder.to_path_buf());
    // No head beside the backup: an image that needs no live key has
    // nothing for one to recover, and with no anchor configured nothing
    // says one is owed. With an anchor, admission refuses (fail-closed).
    if target.head(Lineage::of(&wanted))?.is_none()
        && (required.required.is_empty() || source.anchor.is_none())
    {
        return Ok(CustodyRoute::Absent);
    }
    let opener = CustodyOpener {
        root: source.root,
        data_key: Some(data_key),
        machine: source.machine,
    };
    let admitted = admit_recovery(required, &target, &opener, source.anchor)?;
    let landing = |error: Error| {
        let reason = match error {
            Error::Io(_) | Error::Storage(_) => R::StorageIo,
            _ => R::CustodyLandingFailed,
        };
        Rejected::new(reason, error)
    };
    // The restored vault opens at its canonical root: its parent resolved,
    // its own name as made.
    let name = destination
        .file_name()
        .ok_or_else(|| refused("the restore destination has no name".into()))
        .map_err(landing)?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let root = parent.canonicalize().map_err(Error::from)?.join(name);
    if super::custody_present(&root)? {
        return Err(landing(refused(
            "key custody already exists beside the restore destination; restore elsewhere".into(),
        )));
    }
    let binding = bound.rebind_to(root);
    let landed = land_recovery(&admitted, &binding).map_err(landing)?;
    merge_history_into_rows(rows, &admitted.history);
    let landing = Box::new(CustodyLanding {
        landed: Some(landed),
        admitted,
    });
    let raw = crate::side_table::RawValue::to_raw(&binding)
        .map_err(|_| Rejected::new(R::CustodyLandingFailed, super::identity::custody_corrupt()))?;
    for (key, value) in rows.iter_mut() {
        if key.as_slice() == super::binding_key() {
            *value = raw.clone();
        }
    }
    Ok(CustodyRoute::Landed(landing))
}
