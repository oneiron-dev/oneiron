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
use crate::store::{CustodyPlan, PlannedCredential, Store, plan_credential_value};

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

/// The value credential row `raw`, under row key `key`, commits to: `None`
/// for any other row, one that does not decode (it rides and lands as it
/// is), and one that holds no value (a revoked record's).
pub(crate) fn image_credential_ref(key: &[u8], raw: &[u8]) -> Option<CredentialRef> {
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != ENTITY_TYPE_SECRET_CUSTODY {
        return None;
    }
    let id = EntityId::from_bytes(<[u8; 16]>::try_from(key).ok()?).ok()?;
    let stored = super::decode_stored_custody_body(&raw[ENTITY_METADATA_HEADER_LEN..]).ok()?;
    credential_ref(id, &stored)
}

/// A credential row `raw`, under row key `key`, that an image carries with
/// its value in the clear (no current snapshot writes one): its stored form
/// with the value withheld ([`WITHHELD_SEALED_VALUE`]; none for a row that
/// holds none), and the value it names, for its PendingCustody note. The
/// value is never landed (CALLS `KS-6 image value form`). `None` for any
/// other row.
pub(crate) fn withhold_plain_image_credential(
    key: &[u8],
    raw: &[u8],
) -> Option<(Vec<u8>, Option<CredentialRef>)> {
    match CUSTODY_IMAGE_VALUE_FORM {
        CustodyImageValueForm::StoredSealedOnly => {}
    }
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != ENTITY_TYPE_SECRET_CUSTODY {
        return None;
    }
    let (record, BodyValue::Plain(mut value)) =
        decode_custody_map(&raw[ENTITY_METADATA_HEADER_LEN..]).ok()?
    else {
        return None;
    };
    let held = !value.is_empty();
    value.zeroize();
    let sealed = if held {
        WITHHELD_SEALED_VALUE.to_vec()
    } else {
        Vec::new()
    };
    let mut row = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    row.extend_from_slice(&encode_custody_map(&record, BodyValue::Sealed(sealed)).ok()?);
    let id = <[u8; 16]>::try_from(key)
        .ok()
        .and_then(|key| EntityId::from_bytes(key).ok());
    let credential = id.filter(|_| held).map(|id| CredentialRef {
        id,
        generation: record.rotation_generation,
        name: record.name.clone(),
        head_eligible: head_eligible(&record),
    });
    if let Some(credential) = &credential {
        tracing::warn!(
            credential = %credential.id.to_hex(),
            "a credential row rode its image in the clear; it lands withheld, never as a value"
        );
    }
    Some((row, credential))
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
/// read is warned and left as it rests; a fault listing the rows plans
/// none, warned, and the activation goes on as before.
pub(crate) fn plan_archived_credentials(
    store: &Store,
    plan: &mut CustodyPlan,
) -> PlannedCredentials {
    let refs = (|| -> Result<Vec<CredentialRef>> {
        let txn = store.env.read_txn()?;
        let mut refs = Vec::new();
        for entry in store.port_entity_ids_by_type(&txn, ENTITY_TYPE_SECRET_CUSTODY, None)? {
            let id = entry?;
            match super::read_stored_custody_in_txn(store, &txn, &id) {
                Ok(Some(stored)) => refs.extend(credential_ref(id, &stored)),
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    credential = %id.to_hex(),
                    kind = ?error.kind(),
                    "an archived credential row did not read; it stays as it rests"
                ),
            }
        }
        Ok(refs)
    })();
    match refs {
        Ok(refs) => PlannedCredentials::plan(plan, refs, CredentialRoute::Required),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "an archived vault's credential rows did not list; none is planned, each rests \
                 sealed"
            );
            PlannedCredentials::default()
        }
    }
}
