//! A credential row in a checkpoint image, and a restore's or an archived
//! vault's activation's plan of the value it commits to (KS-6 part 2,
//! FIX-LIST 5687, 7403).
//!
//! An image carries each credential row as it rests, its value sealed
//! under its generation's custody key, never opened (CALLS `KS-6 image
//! value form`). A restore, and an activation, plans each value its rows
//! commit to by exact id through the one custody plan its claim keys,
//! bodies, history and pads go through, so one fork copies them all and no
//! older generation besides (CALLS `KS-6 required restore set`). Nothing
//! here opens a value or mints a key: a value a restore's custody does not
//! hold is named, never brought back from the image.

use std::borrow::Borrow;

use zeroize::Zeroize;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::store::{
    CredentialFences, CustodyPlan, FenceLookup, PlannedCredential, Store, plan_credential_value,
};

use super::super::codec::{BodyValue, decode_custody_map, encode_custody_map};
use super::{NONCE_BYTES, StoredCustody, StoredValue, credential_handle, head_eligible};

/// The form a credential row takes in a checkpoint or backup image (CALLS
/// `KS-6 image value form`, Engine 10-21 22:2x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyImageValueForm {
    /// The row as it rests: the stored form, its value sealed under its
    /// generation's custody key (`sealed_value`), copied byte for byte and
    /// never opened. The transitional carrier a restore sealed again is
    /// gone, with no old-format reader; the owner archive's plaintext DTO
    /// stays its own (CALLS `KS-6 archive form`). A row an image still
    /// carries in the clear never lands as a value: it lands withheld,
    /// PendingCustody, and the rest of the image restores.
    StoredSealedOnly,
}

const CUSTODY_IMAGE_VALUE_FORM: CustodyImageValueForm = CustodyImageValueForm::StoredSealedOnly;

/// The value slot a credential row an image carried in the clear lands
/// with: a nonce and no ciphertext, which no key opens, so every open of it
/// answers `credential_leaf_unreadable` naming its handle (retry, or
/// re-enter or reissue it), as a row whose key custody lacks does.
const WITHHELD_SEALED_VALUE: [u8; NONCE_BYTES] = [0; NONCE_BYTES];

/// What a credential fork or install fault leaves (CALLS `KS-6 credential
/// fork fault`, Engine 10-21 22:2x, applying the accepted F7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyCredentialForkFault {
    /// A custody fault planning, copying or reading back one value's key
    /// never stops the restore, fork or activation: that row rests sealed
    /// as it is, its handle PendingCustody with a warned retry, never named
    /// recovered; everything else proceeds.
    WarnSealedPending,
}

const CUSTODY_CREDENTIAL_FORK_FAULT: CustodyCredentialForkFault =
    CustodyCredentialForkFault::WarnSealedPending;

/// One credential value a row commits to.
#[derive(Clone, Debug)]
pub(crate) struct CredentialRef {
    pub(crate) id: EntityId,
    pub(crate) generation: u32,
    /// Its custody name, the handle a note falls back to.
    pub(crate) name: String,
    /// Whether its keys may ride a custody head (CALLS `KS-6 entry
    /// eligibility`).
    pub(crate) head_eligible: bool,
}

fn credential_ref(id: EntityId, stored: &StoredCustody) -> Option<CredentialRef> {
    let StoredValue::Sealed { generation, bytes } = &stored.value;
    (!bytes.is_empty()).then(|| CredentialRef {
        id,
        generation: *generation,
        name: stored.record.name.clone(),
        head_eligible: head_eligible(&stored.record),
    })
}

/// A credential row a value could not be read from: named by its id,
/// its generation unknown (0).
fn faulted(id: EntityId) -> CredentialRef {
    CredentialRef {
        id,
        generation: 0,
        name: id.to_hex(),
        head_eligible: false,
    }
}

fn row_id(key: &[u8]) -> Option<EntityId> {
    <[u8; 16]>::try_from(key)
        .ok()
        .and_then(|key| EntityId::from_bytes(key).ok())
}

/// What a restore does with one entity row of an image (CALLS `KS-6 image
/// value form`).
pub(crate) enum ImageCredentialRow {
    /// Not a credential row: it rides as it is.
    Other,
    /// A credential row as it rests, sealed: the value it commits to, if
    /// any, is planned.
    Sealed(Option<CredentialRef>),
    /// A credential row with its value in the clear (no current snapshot
    /// writes one): it lands as this stored form, its value slot withheld
    /// ([`WITHHELD_SEALED_VALUE`]; none for a row that holds none), never
    /// as a value; the value it named is PendingCustody.
    Withheld(Vec<u8>, Option<CredentialRef>),
    /// A credential row whose body is neither form: it never lands, and
    /// the record it names is PendingCustody.
    Malformed(Option<CredentialRef>),
}

/// Classifies entity row `raw`, under row key `key`, for a restore: a row
/// whose header is a credential's is never kept unvalidated.
pub(crate) fn image_credential_row(key: &[u8], raw: &[u8]) -> ImageCredentialRow {
    match CUSTODY_IMAGE_VALUE_FORM {
        CustodyImageValueForm::StoredSealedOnly => {}
    }
    if !EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_SECRET_CUSTODY)
    {
        return ImageCredentialRow::Other;
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if let Ok(stored) = super::decode_stored_custody_body(body) {
        return ImageCredentialRow::Sealed(row_id(key).and_then(|id| credential_ref(id, &stored)));
    }
    let withheld = match decode_custody_map(body) {
        Ok((record, BodyValue::Plain(mut value))) => {
            let held = !value.is_empty();
            value.zeroize();
            let sealed = if held {
                WITHHELD_SEALED_VALUE.to_vec()
            } else {
                Vec::new()
            };
            encode_custody_map(&record, BodyValue::Sealed(sealed))
                .ok()
                .map(|stored| {
                    let mut row = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
                    row.extend_from_slice(&stored);
                    let credential = row_id(key).filter(|_| held).map(|id| CredentialRef {
                        id,
                        generation: record.rotation_generation,
                        name: record.name.clone(),
                        head_eligible: head_eligible(&record),
                    });
                    (row, credential)
                })
        }
        Ok((_, BodyValue::Sealed(_))) | Err(_) => None,
    };
    let id = row_id(key);
    let shown = id.map(|id| id.to_hex()).unwrap_or_default();
    match withheld {
        Some((row, credential)) => {
            tracing::warn!(
                credential = %shown,
                "a credential row rode its image in the clear; it lands withheld, never as a value"
            );
            ImageCredentialRow::Withheld(row, credential)
        }
        None => {
            tracing::warn!(
                credential = %shown,
                "a credential row in this image is malformed; it is withheld, pending"
            );
            ImageCredentialRow::Malformed(id.map(faulted))
        }
    }
}

/// Entity row `raw`, a credential's as it rests, its value slot withheld
/// ([`WITHHELD_SEALED_VALUE`]; none for a row that holds none): how a
/// restore lands the row of a credential an erase fenced, or whose fence
/// did not read, so nothing opens it whatever key custody still holds
/// (CALLS `KS-6 erase fence form`). `None` for a row that is no stored
/// credential row.
pub(crate) fn withheld_credential_row(raw: &[u8]) -> Option<Vec<u8>> {
    let header = raw.get(..ENTITY_METADATA_HEADER_LEN)?;
    let stored = super::decode_stored_custody_body(raw.get(ENTITY_METADATA_HEADER_LEN..)?).ok()?;
    let StoredValue::Sealed { bytes, .. } = &stored.value;
    let sealed = if bytes.is_empty() {
        Vec::new()
    } else {
        WITHHELD_SEALED_VALUE.to_vec()
    };
    let body = encode_custody_map(&stored.record, BodyValue::Sealed(sealed)).ok()?;
    let mut row = header.to_vec();
    row.extend_from_slice(&body);
    Some(row)
}

/// Where a restore, or an activation, takes its credentials' keys from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialRoute {
    /// The vault's own custody on this host, a live source's a copy forks,
    /// or the custody of the vault a restore takes the place of: it holds
    /// every value the rows commit to that its source could read, so one
    /// missing there is pending, never a refusal (a restore cannot tell a
    /// key lost since from a row its source already could not read).
    Required,
    /// A custody head landed on a host the vault's custody is not on: it
    /// carries an eligible credential's keys only in its owner-only
    /// compartment, and no other credential's (CALLS `KS-6 entry
    /// eligibility`).
    Landed,
    /// No custody on this host and no head for it: none is here.
    Absent,
}

/// What a restore or an activation says of one credential value it did
/// not land readable (CALLS `KS-6 restore note form`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialDisposition {
    /// The custody taken retired its key after the rows were written.
    ErasedUnavailable,
    /// Its keys stay on the machine that held them (no head carries them,
    /// or no head was found): re-enter or reissue it here.
    LocalOnlyReenter,
    /// Its keys ride only the landed head's owner-only compartment, which
    /// this restore did not open.
    Withheld,
    /// Its key is not in the custody taken, or did not read now, or its
    /// row carried no sealed value: it rests sealed, pending, with a warned
    /// retry, or re-enter it.
    PendingCustody,
}

/// A restore's or an activation's credentials, planned: each value whose
/// key the custody taken holds live, read back once landed or forked, and
/// each it names, with what it says.
#[derive(Default)]
pub(crate) struct PlannedCredentials {
    live: Vec<CredentialRef>,
    noted: Vec<(CredentialRef, CredentialDisposition)>,
    /// The rows listed before a census that did not finish: discovery
    /// pending for the rest, never an empty success.
    census_pending: Option<usize>,
}

impl PlannedCredentials {
    /// Plans each of `refs` through `plan` by exact id, its keys taken by
    /// `route`. A custody fault planning one is that value's alone: pending,
    /// warned, never absence (CALLS `KS-6 credential fork fault`).
    pub(crate) fn plan(
        plan: &mut CustodyPlan,
        refs: Vec<CredentialRef>,
        route: CredentialRoute,
    ) -> Self {
        let mut planned = Self::default();
        let route = if plan.source().is_none() {
            CredentialRoute::Absent
        } else {
            route
        };
        for credential in refs {
            if route == CredentialRoute::Absent {
                planned
                    .noted
                    .push((credential, CredentialDisposition::LocalOnlyReenter));
                continue;
            }
            match plan_credential_value(plan, &credential.id, credential.generation) {
                Ok(PlannedCredential::Live) => planned.live.push(credential),
                Ok(PlannedCredential::Retired) => planned
                    .noted
                    .push((credential, CredentialDisposition::ErasedUnavailable)),
                Ok(PlannedCredential::Missing) => match route {
                    CredentialRoute::Required => {
                        tracing::warn!(
                            credential = %credential.id.to_hex(),
                            "a credential's custody key is not in the custody this restore \
                             takes; its row rests sealed, pending"
                        );
                        planned.pending(credential);
                    }
                    CredentialRoute::Landed if credential.head_eligible => planned
                        .noted
                        .push((credential, CredentialDisposition::Withheld)),
                    CredentialRoute::Landed | CredentialRoute::Absent => planned
                        .noted
                        .push((credential, CredentialDisposition::LocalOnlyReenter)),
                },
                Err(error) => {
                    tracing::warn!(
                        credential = %credential.id.to_hex(),
                        kind = ?error.kind(),
                        "a credential's custody key did not plan; its row rests sealed, pending"
                    );
                    planned.pending(credential);
                }
            }
        }
        planned
    }

    /// What `fences` say of `credential` before a restore, a fork or an
    /// activation plans it (CALLS `KS-6 erase fence form`): `true` when it
    /// is named here, never planned, so no fork copies its key and nothing
    /// reads it back. An erase fenced it: ErasedUnavailable. Its fence did
    /// not read: PendingCustody, warned, with a retry. An id no fence names
    /// is left to the plan as before.
    pub(crate) fn fenced(
        &mut self,
        fences: &mut CredentialFences,
        credential: &CredentialRef,
    ) -> bool {
        let disposition = match fences.lookup(&credential.id) {
            FenceLookup::Clear => return false,
            FenceLookup::Fenced => CredentialDisposition::ErasedUnavailable,
            FenceLookup::Faulted => {
                tracing::warn!(
                    credential = %credential.id.to_hex(),
                    "a credential's erase fence did not read; it is withheld here, pending"
                );
                CredentialDisposition::PendingCustody
            }
        };
        self.noted.push((credential.clone(), disposition));
        true
    }

    /// Names `credential` LocalOnlyReenter, never planned: a cloud
    /// registration slot a copy beside its source never holds a usable key
    /// of (CALLS G7_COPY_RECOVERY), so its owner signs in again there.
    pub(crate) fn reenter(&mut self, credential: CredentialRef) {
        self.noted
            .push((credential, CredentialDisposition::LocalOnlyReenter));
    }

    /// Takes every value `other` named or planned as this one's too.
    pub(crate) fn merge(&mut self, mut other: Self) {
        self.live.append(&mut other.live);
        self.noted.append(&mut other.noted);
        self.census_pending = self.census_pending.or(other.census_pending);
    }

    /// Names `credential` PendingCustody (CALLS `KS-6 credential fork
    /// fault`).
    pub(crate) fn pending(&mut self, credential: CredentialRef) {
        match CUSTODY_CREDENTIAL_FORK_FAULT {
            CustodyCredentialForkFault::WarnSealedPending => {}
        }
        self.noted
            .push((credential, CredentialDisposition::PendingCustody));
    }

    /// Reads back each live value's key through `reads`, from the custody
    /// the restored or activated vault now holds: one that does not read
    /// stays sealed, pending, warned.
    pub(crate) fn read_back(&mut self, reads: impl Fn(&EntityId, u32) -> bool) {
        for credential in std::mem::take(&mut self.live) {
            if reads(&credential.id, credential.generation) {
                self.live.push(credential);
            } else {
                tracing::warn!(
                    credential = %credential.id.to_hex(),
                    "a credential's custody key did not read back where it landed; its row rests \
                     sealed, pending"
                );
                self.pending(credential);
            }
        }
    }

    /// How many rows a census listed before it failed, when it did not
    /// finish: the rest rest as they are, discovery pending.
    pub(crate) fn census_pending(&self) -> Option<usize> {
        self.census_pending
    }

    /// What is said of each value named, by handle and generation, read
    /// from `store`'s short ids; empty when every value landed readable.
    pub(crate) fn outcomes(self, store: &Store) -> Vec<(String, u32, CredentialDisposition)> {
        named(store, self.noted.iter().map(|(credential, _)| credential))
            .into_iter()
            .zip(self.noted.iter().map(|(_, disposition)| *disposition))
            .map(|((handle, generation), disposition)| (handle, generation, disposition))
            .collect()
    }
}

/// Each of `refs` by its handle in `store`, else its name, and generation.
fn named<R: Borrow<CredentialRef>>(
    store: &Store,
    refs: impl Iterator<Item = R>,
) -> Vec<(String, u32)> {
    let txn = store.env.read_txn().ok();
    refs.map(|credential| {
        let credential = credential.borrow();
        let handle = match &txn {
            Some(txn) => credential_handle(store, txn, &credential.id, &credential.name),
            None => credential.name.clone(),
        };
        (handle, credential.generation)
    })
    .collect()
}

/// Plans every credential value this archived store's rows seal through its
/// activation's one `plan` (KS-6 part 2): by exact id, from its source's
/// custody, required ([`CredentialRoute::Required`]). A row that does not
/// read stays as it rests, PendingCustody; a census that stops part way
/// plans what it listed and says the rest is pending discovery. One
/// `fences` names is named and never planned, so its key is never forked
/// ([`PlannedCredentials::fenced`]). Never stops the activation.
pub(crate) fn plan_archived_credentials(
    store: &Store,
    plan: &mut CustodyPlan,
    fences: &mut CredentialFences,
) -> PlannedCredentials {
    let mut refs = Vec::new();
    let mut faulted_rows = Vec::new();
    let census = (|| -> Result<()> {
        let txn = store.env.read_txn()?;
        for entry in store.port_entity_ids_by_type(&txn, ENTITY_TYPE_SECRET_CUSTODY, None)? {
            let id = entry?;
            match super::read_stored_custody_in_txn(store, &txn, &id) {
                Ok(Some(stored)) => refs.extend(credential_ref(id, &stored)),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        credential = %id.to_hex(),
                        kind = ?error.kind(),
                        "an archived credential row did not read; it stays as it rests, pending"
                    );
                    faulted_rows.push(faulted(id));
                }
            }
        }
        Ok(())
    })();
    let listed = refs.len() + faulted_rows.len();
    let mut fenced = PlannedCredentials::default();
    refs.retain(|credential| !fenced.fenced(fences, credential));
    let mut planned = PlannedCredentials::plan(plan, refs, CredentialRoute::Required);
    planned.merge(fenced);
    for credential in faulted_rows {
        planned.pending(credential);
    }
    if let Err(error) = census {
        tracing::warn!(
            kind = ?error.kind(),
            listed,
            "an archived vault's credential census did not finish; the rows it listed are \
             planned, the rest rest sealed, discovery pending"
        );
        planned.census_pending = Some(listed);
    }
    planned
}
