//! The holder's side of a holder-mediated export (FIX 4624(b)), and the
//! owner's fetch and open of what it sealed.
//!
//! An export secret request ([`OwnerWorkBody::ExportSecret`]) names this
//! install when the fold proves it holds the secret at the generation an
//! owner export met (`crate::authority::export_secret_executor`). Its pickup
//! reads the request and the export's own act again in the writer, checks
//! the owner still owns the vault, the record is the same active, portable,
//! non-cloud secret at that generation, and the recipient machine still a
//! live linked install with the very key the owner chose; then opens the
//! value here, under this install's own custody, and nowhere else. The
//! value goes out as the archive row the export would have carried, sealed
//! to that recipient alone ([`sealed`]); the sealed copy is kept under the
//! request's entry and its result names the copy's digest, both in one
//! commit, once. A value this install cannot open stays pending, awaiting
//! its holder; nothing in custody changes.
//!
//! The owner whose export it was reads the sealed copy by the request's
//! entry ([`Vault::export_secret_supplement`]) from whichever install keeps
//! it: the bytes stay sealed through any server. The recipient machine opens
//! it ([`Vault::open_export_secret_supplement`]) into the archive row the
//! owner imports (`crate::batch::export`'s secret supplement).

mod sealed;

use base64::Engine as _;
use zeroize::Zeroizing;

use self::sealed::{SupplementBinding, open_supplement, output_of, seal_supplement};
use super::control::permits::{permit_for, permitted_keys};
use super::storage_seal::{read_opened_in_txn, read_secret_custody_meta_in_txn};
use super::{CustodyClass, SecretCustodyRecord, SecretCustodyStatus};
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, CustodyRecipientPermit, ExportSecretSupplement,
    ExportSecretWork, OpenedSecretSupplement, OwnerWorkBody, OwnerWorkOutcome, OwnerWorkRefusal,
    OwnerWorkRequest, SealedWorkOutput,
};
use crate::batch::export::ArchiveSecretCustody;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{OwnerWorkReceipt, OwnerWorkStatus};
use crate::{EntityId, Vault};

/// Each export secret request's sealed copy, by the request's entry hash:
/// written once, in the commit of the result that names its digest.
const OUTPUTS: SideTable<[u8; 32], Vec<u8>, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_EXPORT_OUTPUT);

/// The permit the owner gives `machine` to receive an export's sealed
/// copies, as `fold` stands: its live linked revision whose encryption key
/// imports. `None` when it is no such install.
pub(crate) fn recipient_permit(
    fold: &AuthorityFold,
    machine: EntityId,
) -> Option<CustodyRecipientPermit> {
    permit_for(fold, machine)
}

fn no_supplement() -> Error {
    Error::InvalidConfig(
        "no export secret request of this owner's is recorded under this entry".to_owned(),
    )
}

impl Vault {
    /// The pickup's arm for the export secret request signed as entry
    /// `hash`, naming this install, in the caller's writer: the sealed copy
    /// it commits, or why it refuses. A copy committed before answers a
    /// retry unchanged. `None` leaves it pending: this install holds no row,
    /// key or value of the secret, or the vault has no genesis to seal for.
    pub(crate) fn export_secret_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        hash: AuthorityEntryHash,
        request: &OwnerWorkRequest,
        work: &ExportSecretWork,
    ) -> Result<Option<OwnerWorkOutcome>> {
        if let Some(kept) = OUTPUTS.get(&self.store, txn, &hash)? {
            return Ok(Some(OwnerWorkOutcome::Sealed {
                output: output_of(&kept)?,
            }));
        }
        let Some(record) = read_secret_custody_meta_in_txn(&self.store, txn, &work.secret)? else {
            return Ok(None);
        };
        if let Some(reason) = self.export_secret_refusal(txn, fold, request, work, &record)? {
            return Ok(Some(OwnerWorkOutcome::Refused { reason }));
        }
        let Some((_, public)) =
            permitted_keys(fold, &[work.recipient]).and_then(|keys| keys.into_iter().next())
        else {
            return Ok(Some(OwnerWorkOutcome::Refused {
                reason: OwnerWorkRefusal::RecipientChanged,
            }));
        };
        let Some(vault_id) = fold.vault_id else {
            return Ok(None);
        };
        // Key possession: the value opens here, under this install's own
        // custody, or the work waits for it.
        let mut opened = match read_opened_in_txn(&self.store, txn, &work.secret) {
            Ok(Some(opened)) => opened,
            Ok(None) | Err(Error::Secret(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let plain = supplement_row(self, txn, &work.secret, &mut opened)?;
        let binding = SupplementBinding {
            request: hash,
            export: work.export,
            secret: work.secret,
            generation: work.generation,
            owner: request.act.owner,
            recipient: work.recipient,
        };
        let (sealed, envelopes) = seal_supplement(&vault_id, &binding, &public, &plain)?;
        let output = SealedWorkOutput {
            digest: *blake3::hash(&sealed).as_bytes(),
            bytes: u64::try_from(sealed.len())
                .map_err(|_| Error::InvariantViolation("sealed export secret length"))?,
            envelopes,
        };
        OUTPUTS.put(&self.store, txn, &hash, &sealed)?;
        Ok(Some(OwnerWorkOutcome::Sealed { output }))
    }

    /// The first recheck an export secret request fails in this writer:
    /// its owner no longer owns the vault; the record is no longer active,
    /// or an admitted revoke ended it; it moved past the generation the
    /// export met; it may not leave its device (device bound, not portable,
    /// or a cloud registration slot); or the recipient no longer stands with
    /// the key the owner chose.
    fn export_secret_refusal(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        request: &OwnerWorkRequest,
        work: &ExportSecretWork,
        record: &SecretCustodyRecord,
    ) -> Result<Option<OwnerWorkRefusal>> {
        Ok(
            if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &request.act.owner)? {
                Some(OwnerWorkRefusal::OwnerNotLive)
            } else if record.status != SecretCustodyStatus::Active
                || fold.custody_revoked(&work.secret)
            {
                Some(OwnerWorkRefusal::SecretNotActive)
            } else if record.rotation_generation != work.generation {
                Some(OwnerWorkRefusal::StaleRevision)
            } else if record.device_only
                || record.class != CustodyClass::CustodyPortable
                || super::is_cloud_registration_slot(&record.name)
            {
                Some(OwnerWorkRefusal::SecretNotPortable)
            } else if permitted_keys(fold, &[work.recipient]).is_none() {
                Some(OwnerWorkRefusal::RecipientChanged)
            } else {
                None
            },
        )
    }

    /// The export secret request signed as entry `request`, as the owner
    /// `owner` whose export it was reads it (FIX 4624(b)): where it stands
    /// and, once its holder sealed it, the sealed copy when this install
    /// keeps it, checked against the digest the signed result names. The
    /// bytes stay sealed to the recipient: no install that relays them can
    /// open them. `None` when this install folds no such request of his.
    pub fn export_secret_supplement(
        &self,
        owner: &AuthenticatedOwner,
        request: AuthorityEntryHash,
    ) -> Result<Option<ExportSecretSupplement>> {
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let Some(asked) = fold.owner_work_request(&request) else {
            return Ok(None);
        };
        let OwnerWorkBody::ExportSecret(work) = &asked.work else {
            return Ok(None);
        };
        if asked.act.owner != actor {
            return Ok(None);
        }
        let status = OwnerWorkReceipt::of(&fold, request)
            .map_or(OwnerWorkStatus::RecordedAwaitingHolder, |receipt| {
                receipt.status
            });
        let output = fold
            .owner_work_result(&request)
            .and_then(|answer| answer.outcome.sealed_output().copied());
        let sealed = match output {
            Some(output) => OUTPUTS
                .get(&self.store, &txn, &request)?
                .filter(|kept| *blake3::hash(kept).as_bytes() == output.digest),
            None => None,
        };
        Ok(Some(ExportSecretSupplement {
            request: blake3::Hash::from_bytes(request).to_hex().to_string(),
            secret: work.secret,
            generation: work.generation,
            export: work.export,
            holder: asked.executor,
            recipient: work.recipient.machine,
            status,
            digest: output.map(|output| blake3::Hash::from_bytes(output.digest).to_hex().to_string()),
            bytes: output.map(|output| output.bytes),
            sealed: sealed.map(|kept| base64::engine::general_purpose::STANDARD.encode(kept)),
        }))
    }

    /// Opens `sealed`, the copy of the export secret request signed as entry
    /// `request`, on this install, the recipient the owner chose, for
    /// `owner` whose export it was: the archive row of its secret, with its
    /// value, for his import. A copy whose digest is not the one its signed
    /// result names, or that is sealed to another machine, request or
    /// position, does not open.
    pub fn open_export_secret_supplement(
        &self,
        owner: &AuthenticatedOwner,
        request: AuthorityEntryHash,
        sealed: &[u8],
    ) -> Result<OpenedSecretSupplement> {
        let secret = self.machine_secret_outside_txn()?;
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let asked = fold
            .owner_work_request(&request)
            .filter(|asked| asked.act.owner == actor)
            .ok_or_else(no_supplement)?;
        let OwnerWorkBody::ExportSecret(work) = &asked.work else {
            return Err(no_supplement());
        };
        if work.recipient.machine != secret.machine {
            return Err(Error::InvalidConfig(
                "this export secret supplement is sealed to another machine; open it there"
                    .to_owned(),
            ));
        }
        if let Some(output) = fold
            .owner_work_result(&request)
            .and_then(|answer| answer.outcome.sealed_output())
            && *blake3::hash(sealed).as_bytes() != output.digest
        {
            return Err(Error::InvalidConfig(
                "this export secret supplement is not the copy its holder's result names"
                    .to_owned(),
            ));
        }
        let vault_id = fold
            .vault_id
            .ok_or_else(|| Error::InvalidConfig("the vault has no authority genesis".to_owned()))?;
        let binding = SupplementBinding {
            request,
            export: work.export,
            secret: work.secret,
            generation: work.generation,
            owner: asked.act.owner,
            recipient: work.recipient,
        };
        let plain = open_supplement(&vault_id, &binding, &secret.secret, sealed)?;
        let row: ArchiveSecretCustody = serde_json::from_slice(&plain).map_err(|_| {
            Error::InvalidConfig("this export secret supplement holds no archive row".to_owned())
        })?;
        let opened = OpenedSecretSupplement { row };
        if opened.row.id != work.secret.to_hex() {
            return Err(Error::InvalidConfig(
                "this export secret supplement names another secret".to_owned(),
            ));
        }
        Ok(opened)
    }
}

/// The archive row of record `id`, opened, as the owner's archive carries
/// one with its value: the plaintext a supplement seals, as JSON. The
/// record's value is wiped here.
fn supplement_row(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    opened: &mut SecretCustodyRecord,
) -> Result<Zeroizing<Vec<u8>>> {
    let body = super::codec::encode_secret_custody_body(opened).map(Zeroizing::new);
    zeroize::Zeroize::zeroize(&mut opened.value_bytes);
    let body = body?;
    let handle = crate::ports::ShortIdStoreRead::port_short_id_reference(&vault.store, txn, id)?
        .map(|(name, hash)| format!("{name}:{hash:02x}"));
    let mut row = ArchiveSecretCustody {
        id: id.to_hex(),
        name: opened.name.clone(),
        handle,
        metadata: opened.metadata(),
        body: Some(base64::engine::general_purpose::STANDARD.encode(&*body)),
    };
    let json = serde_json::to_vec(&row)
        .map(Zeroizing::new)
        .map_err(|_| Error::InvariantViolation("export secret supplement row encoding"));
    if let Some(body) = row.body.as_mut() {
        zeroize::Zeroize::zeroize(body);
    }
    json
}
