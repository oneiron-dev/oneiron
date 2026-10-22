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
//! PendingCustody; a credential row neither form validates never lands at
//! all, PendingCustody; the rest restores (CALLS `KS-6 image value form`).
//! A landed value is read back by opening it under its exact leaf.
//!
//! A credential an erase fenced never comes back (KS-6 part 2, CALLS `KS-6
//! erase fence form`): the evidence a restore takes is a live source's
//! fences and erase debt (a fork's source, the live rows a restore over a
//! live vault carried, or the vault whose custody a kept restore takes,
//! read before anything lands), and a retired value key in the custody it
//! takes, never an image's own: an image's fence and credential intent
//! rows never land. Each handle is looked up alone. A fenced row lands with
//! its value withheld, ErasedUnavailable, and no fork copies its key; one
//! whose own evidence did not read lands withheld, PendingCustody, warned,
//! with a retry. The restored vault takes each fence, its discovery owed,
//! so its own finisher retires every key the id names in the custody it
//! holds now.

use super::{CheckpointImage, Custody, Rejected, codec_error};
use crate::Vault;
use crate::secret_custody::{
    CredentialDisposition, CredentialRoute, ImageCredentialRow, PlannedCredentials,
};
use crate::store::{CredentialFences, CustodyPlan, Store};

/// What a restore says of a credential value its rows commit to that it did
/// not land readable, by its handle and generation, each with its remedy
/// (CALLS `KS-6 restore note form`). Logs name a credential by id and kind
/// only; a note names no value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialRestoreNote {
    /// The custody the restore took retired its key after the image was
    /// taken, or an erase fenced its id (KS-6 part 2): its row rests sealed
    /// or withheld, its value unavailable.
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
    /// Its key is not in the custody taken, or its value did not open
    /// under it now, or its row came in the clear or malformed (withheld;
    /// generation 0 when its row did not read): pending. Retry, or re-enter
    /// it.
    PendingCustody { handle: String, generation: u32 },
    /// The credential census stopped after `listed` rows: those were
    /// planned, and any other credential rests as it was, its discovery
    /// pending, never a complete pass.
    CensusPending { listed: u64 },
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
                "credential {handle} generation {generation}: its value did not open from \
                 custody here; it rests sealed or withheld, pending: retry, or re-enter it"
            ),
            Self::CensusPending { listed } => write!(
                f,
                "the credential census stopped after {listed} row(s); any other credential rests \
                 as it was, its discovery pending"
            ),
        }
    }
}

/// The credential values a restore owes once its rows landed.
pub(super) struct CredentialLanding(PlannedCredentials);

/// The erase evidence a restore by `custody`'s route takes (CALLS `KS-6
/// erase fence form`): its live source's, the live rows a restore over a
/// live vault carried into `image`, or those of the vault whose custody a
/// kept restore takes, read now, its fences and debt alike; and the
/// retired credential value keys of the custody `plan` takes, by handle.
/// Never an image's own.
fn route_fences(
    image: &CheckpointImage,
    plan: &CustodyPlan,
    custody: Custody<'_>,
) -> CredentialFences {
    let mut fences = match custody {
        Custody::Fork(Some((live, _))) => live.credential_fences(),
        Custody::Fork(None) | Custody::Replace(..) => image
            .databases
            .get("vault_meta")
            .map(|rows| CredentialFences::in_rows(rows))
            .unwrap_or_default(),
        Custody::Keep => plan
            .source()
            .map(|source| CredentialFences::at_vault(source.root(), None))
            .unwrap_or_default(),
        Custody::Landed | Custody::NewHost => CredentialFences::default(),
    };
    if let Some(source) = plan.source() {
        fences.with_custody(source);
    }
    fences
}

/// Before the destination exists: plans each credential value a row of
/// `image` commits to through `plan`, the restore's one plan, under the
/// custody `custody` names, and withholds the value of any row the image
/// carried in the clear, and of any credential an erase fenced or whose
/// own evidence did not read, which is never planned. An image's own fence
/// and credential intent rows never land, but where a restore carries its
/// live source's rows; each fence the route's evidence names lands with the
/// rows instead. Never refuses for a value.
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
    let mut fences = route_fences(image, plan, custody);
    let rows = image
        .databases
        .get_mut("entities")
        .ok_or_else(codec_error)?;
    let mut withheld = Vec::new();
    let mut refs = Vec::new();
    let mut malformed = std::collections::BTreeSet::new();
    let mut fenced = PlannedCredentials::default();
    for (key, raw) in rows.iter_mut() {
        match crate::secret_custody::image_credential_row(key, raw) {
            ImageCredentialRow::Other => {}
            ImageCredentialRow::Sealed(Some(credential))
                if fenced.fenced(&mut fences, &credential) =>
            {
                // Its value never opens here, whatever key custody holds.
                match crate::secret_custody::withheld_credential_row(raw) {
                    Some(row) => *raw = row,
                    None => {
                        malformed.insert(key.clone());
                    }
                }
            }
            ImageCredentialRow::Sealed(credential) => refs.extend(credential),
            ImageCredentialRow::Withheld(row, credential) => {
                *raw = row;
                withheld.extend(credential);
            }
            ImageCredentialRow::Malformed(credential) => {
                malformed.insert(key.clone());
                withheld.extend(credential);
            }
        }
    }
    // A credential row neither form validates never lands raw.
    rows.retain(|(key, _)| !malformed.contains(key));
    let mut planned = PlannedCredentials::plan(plan, refs, route);
    for credential in withheld {
        if !fenced.fenced(&mut fences, &credential) {
            planned.pending(credential);
        }
    }
    planned.merge(fenced);
    let vault_meta = image
        .databases
        .get_mut("vault_meta")
        .ok_or_else(codec_error)?;
    // An image never supplies erase evidence: its own rows go, but where
    // they are its live source's, carried (both families stay LIVE).
    if !matches!(custody, Custody::Fork(None) | Custody::Replace(..)) {
        vault_meta.retain(|(key, _)| !CredentialFences::image_owned(key));
    }
    // The restored vault keeps every fence, its discovery owed.
    for (key, value) in fences.rows()? {
        match vault_meta.binary_search_by(|(held, _)| held.as_slice().cmp(key.as_slice())) {
            Ok(at) => vault_meta[at].1 = value,
            Err(at) => vault_meta.insert(at, (key, value)),
        }
    }
    Ok(CredentialLanding(planned))
}

/// Once the rows landed and `vault` reopened under its own custody: opens
/// each landed value under its exact leaf from the custody the vault now
/// holds, the bytes wiped at once, and returns what the restore says of
/// each it did not land readable.
pub(super) fn land(vault: &Vault, landing: CredentialLanding) -> Vec<CredentialRestoreNote> {
    let CredentialLanding(mut planned) = landing;
    let txn = vault.store.env.read_txn().ok();
    planned.read_back(|credential, generation| {
        txn.as_ref().is_some_and(|txn| {
            crate::secret_custody::stored_value_opens_in_txn(
                &vault.store,
                txn,
                credential,
                generation,
                |credential, generation| {
                    vault
                        .store
                        .read_credential_value_leaf(credential, generation)
                },
            )
        })
    });
    drop(txn);
    notes(&vault.store, planned)
}

/// What a restore or an activation says of the credential values `planned`
/// names, by their handles in `store`.
pub(super) fn notes(store: &Store, planned: PlannedCredentials) -> Vec<CredentialRestoreNote> {
    let census = planned.census_pending();
    planned
        .outcomes(store)
        .into_iter()
        .map(|(handle, generation, disposition)| {
            CredentialRestoreNote::of(handle, generation, disposition)
        })
        .chain(census.map(|listed| CredentialRestoreNote::CensusPending {
            listed: u64::try_from(listed).unwrap_or(u64::MAX),
        }))
        .collect()
}
