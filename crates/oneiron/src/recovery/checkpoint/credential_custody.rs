//! A restore's credential values (KS-6 part 2, FIX-LIST 5687, 7403; CALLS
//! `KS-6 required restore set`, `KS-6 restore note form`). An image carries
//! each credential row as it rests, its value sealed under its generation's
//! custody key, and the restore takes that key from current custody through
//! the one plan its claim keys, bodies, history and pads go through, by
//! exact id, so a fork copies it with them and no older generation besides.
//!
//! Before the destination exists, each value a row commits to is planned
//! where the restore takes its custody from. The vault's own custody on this
//! host, a live source's a copy forks, and the custody of a vault a restore
//! takes the place of: live, it lands sealed; retired since, it lands sealed
//! and unavailable (ErasedUnavailable); missing there, it lands sealed,
//! PendingCustody, never a refusal: a restore cannot tell a key lost since
//! the image from a row its source already could not read. A head landed
//! on a new host carries an eligible credential's keys only in its owner-only
//! compartment: one it lacks is Withheld, any other's LocalOnlyReenter, and a
//! restore with no custody and no head names every one LocalOnlyReenter
//! (CALLS `KS-6 device-only recovery`, K29). A custody fault planning or
//! reading back one value is that value's alone: its row rests sealed,
//! PendingCustody, warned (CALLS `KS-6 credential fork fault`). A row an
//! image carried in the clear never lands as a value: it lands withheld,
//! PendingCustody, and the rest restores (CALLS `KS-6 image value form`).

use super::{CheckpointImage, Custody, Rejected, codec_error};
use crate::Vault;
use crate::secret_custody::{CredentialDisposition, CredentialRoute, PlannedCredentials};
use crate::store::Store;

/// What a restore says of a credential value its rows commit to that it did
/// not land readable, by its handle and generation, each with its remedy
/// (CALLS `KS-6 restore note form`). Logs name a credential by id and kind
/// only; a note names no value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialRestoreNote {
    /// The custody the restore took retired its key after the image was
    /// taken: its row rests sealed, its value unavailable.
    ErasedUnavailable { handle: String, generation: u32 },
    /// Its keys stay on the machine that held them: no custody head carries
    /// them, or none was found. Re-enter or reissue it here, or import the
    /// owner's archive.
    LocalOnlyReenter { handle: String, generation: u32 },
    /// Its keys ride only the custody head's owner-only compartment, which
    /// this restore did not open: restore with the recovery root, or
    /// re-enter it.
    Withheld { handle: String, generation: u32 },
    /// A carrier this host only relays: its key is with the request's
    /// executor or recipient. None is named while the carrier wire ships
    /// off (CALLS `KS-6 carrier wire`).
    RelayOnly { handle: String, generation: u32 },
    /// Its key did not read from custody now, or its row came in the clear:
    /// its row rests sealed, pending. Retry, or re-enter it.
    PendingCustody { handle: String, generation: u32 },
}

/// The form a restore's credential diagnostics take (CALLS `KS-6 restore
/// note form`, Engine 10-21 22:2x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyRestoreNoteForm {
    /// One note per credential handle and generation that did not land
    /// readable, typed by its disposition, beside `pad_notes`; none when
    /// every one landed. No restore refuses for a credential value.
    PerHandleGenerationDisposition,
}

const CUSTODY_RESTORE_NOTE_FORM: CustodyRestoreNoteForm =
    CustodyRestoreNoteForm::PerHandleGenerationDisposition;

impl CredentialRestoreNote {
    fn of(handle: String, generation: u32, disposition: CredentialDisposition) -> Self {
        match CUSTODY_RESTORE_NOTE_FORM {
            CustodyRestoreNoteForm::PerHandleGenerationDisposition => {}
        }
        match disposition {
            CredentialDisposition::ErasedUnavailable => {
                Self::ErasedUnavailable { handle, generation }
            }
            CredentialDisposition::LocalOnlyReenter => {
                Self::LocalOnlyReenter { handle, generation }
            }
            CredentialDisposition::Withheld => Self::Withheld { handle, generation },
            CredentialDisposition::PendingCustody => Self::PendingCustody { handle, generation },
        }
    }
}

impl std::fmt::Display for CredentialRestoreNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ErasedUnavailable { handle, generation } => write!(
                f,
                "credential {handle} generation {generation}: its key was erased since the \
                 image; its value is unavailable"
            ),
            Self::LocalOnlyReenter { handle, generation } => write!(
                f,
                "credential {handle} generation {generation}: its key stays on the machine that \
                 held it; re-enter or reissue it here, or import the owner's archive"
            ),
            Self::Withheld { handle, generation } => write!(
                f,
                "credential {handle} generation {generation}: its key rides only the custody \
                 head's owner-only compartment; restore with the recovery root, or re-enter it"
            ),
            Self::RelayOnly { handle, generation } => write!(
                f,
                "credential {handle} generation {generation}: this host only relays it; its key \
                 is with its executor"
            ),
            Self::PendingCustody { handle, generation } => write!(
                f,
                "credential {handle} generation {generation}: its key did not read from custody; \
                 it rests sealed, pending: retry, or re-enter it"
            ),
        }
    }
}

/// The credential values a restore owes once its rows landed.
pub(super) struct CredentialLanding(PlannedCredentials);

/// Before the destination exists: plans each credential value a row of
/// `image` commits to through `plan`, the restore's one plan, under the
/// custody `custody` names, and withholds the value of any row the image
/// carried in the clear. Never refuses for a value.
pub(super) fn require(
    image: &mut CheckpointImage,
    plan: &mut crate::store::CustodyPlan,
    custody: Custody<'_>,
) -> std::result::Result<CredentialLanding, Rejected> {
    let route = match custody {
        Custody::Keep | Custody::Replace(..) | Custody::Fork(_) => CredentialRoute::Required,
        Custody::Landed => CredentialRoute::Landed,
        Custody::NewHost => CredentialRoute::Absent,
    };
    let rows = image
        .databases
        .get_mut("entities")
        .ok_or_else(codec_error)?;
    let mut withheld = Vec::new();
    let mut refs = Vec::new();
    for (key, raw) in rows.iter_mut() {
        if let Some((row, credential)) =
            crate::secret_custody::withhold_plain_image_credential(key, raw)
        {
            *raw = row;
            withheld.extend(credential);
        } else if let Some(credential) = crate::secret_custody::image_credential_ref(key, raw) {
            refs.push(credential);
        }
    }
    let mut planned = PlannedCredentials::plan(plan, refs, route);
    for credential in withheld {
        planned.pending(credential);
    }
    Ok(CredentialLanding(planned))
}

/// Once the rows landed and `vault` reopened under its own custody: reads
/// each landed value's key back from the custody the vault now holds, and
/// returns what the restore says of each it did not land readable.
pub(super) fn land(vault: &Vault, landing: CredentialLanding) -> Vec<CredentialRestoreNote> {
    let CredentialLanding(mut planned) = landing;
    planned.read_back(|credential, generation| {
        vault
            .store
            .read_credential_value_leaf(credential, generation)
            .is_ok()
    });
    notes(&vault.store, planned)
}

/// What a restore or an activation says of the credential values `planned`
/// names, by their handles in `store`.
pub(super) fn notes(store: &Store, planned: PlannedCredentials) -> Vec<CredentialRestoreNote> {
    planned
        .outcomes(store)
        .into_iter()
        .map(|(handle, generation, disposition)| {
            CredentialRestoreNote::of(handle, generation, disposition)
        })
        .collect()
}
