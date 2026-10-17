//! An agent's sight of a file stored with keys in it (OF-560; owner ruling
//! G04 binary = C2): "Agent with a grant: the real bytes."
//!
//! An agent that reads a marked file and says why is asking for every key in
//! it at once, so the read runs the one reveal check over the file's keys:
//! this connection × their class × this project. Inside a standing grant the
//! read gets the stored bytes, and each read leaves its own reveal row with
//! its why, a quiet use receipt and a T1 lease per key, as a delivered reveal
//! does. Outside one, the read gets the masked copy and files one ask for
//! this agent, this file, this project and this run; the owner answers it
//! as any reveal ask, and an approval once opens the next such read.
//!
//! A file whose keys are not all active, admitted to a model (T1) and of one
//! custody class reads masked, with no ask.
//!
//! A sealed file (a container the write door could not read whole, stored
//! as it is and unmarked) holds keys no mark names. Its read asks for the
//! file whole, as for one key of [`SEALED_FILE_CLASS`]: under a standing
//! grant, or once the owner approves the read, the agent gets the stored
//! bytes and the read leaves its reveal row. No lease is stamped, as no
//! custody record holds a key of it.

use super::agent::{file_ask_in_txn, standing};
use super::{
    FileSight, READER_AGENT, REVEAL_ASK_TTL_SECS, REVEAL_LEASE_TTL_SECS, REVEALS, RevealAsker,
    RevealAuthority, RevealRow, SecretRevealState, checked_text, covering_grant, reveal_bound,
};
use crate::consent::{
    approve_once_authorization_in_txn, approve_once_decision_in_txn, load_active_standing_grants,
    spend_approve_once_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{
    CustodyClass, SecretCustodyFloor, SecretCustodyStatus, SecretSight, masked_file_in_txn,
    read_secret_custody_admission_in_txn,
};
use crate::vault::Vault;

/// Domain of the id of the one ask an agent's read of a file files.
const FILE_ASK_DOMAIN: &[u8] = b"oneiron.secret_reveal.file_ask.v1";

/// The class a sealed file's read is granted as: the class the write door
/// gives each key it lifts from a file (CALLS, open).
const SEALED_FILE_CLASS: CustodyClass = CustodyClass::CustodyPortable;

/// The handle a sealed file's read names in place of its keys'.
const SEALED_FILE_HANDLE: &str = "sealed file";

impl Vault {
    /// How `asker` reads the stored `bytes` of `artifact` when it says `why`:
    /// [`SecretSight::Granted`] once a grant covers every key in them and
    /// this read's receipt is written, [`SecretSight::Masked`] otherwise. A
    /// file with no keys in it writes nothing, unless it is sealed: its read
    /// is asked for as one key of [`SEALED_FILE_CLASS`].
    ///
    /// # Errors
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound)
    /// for a `why` that is empty, longer than 512 bytes or more than one
    /// line; the scan's refusal for one that holds a credential.
    pub(crate) fn file_sight(
        &self,
        asker: &RevealAsker,
        artifact: &EntityId,
        bytes: &[u8],
        why: &str,
    ) -> Result<SecretSight> {
        let hash = *blake3::hash(bytes).as_bytes();
        let sealed = {
            let txn = self.store.env.read_txn()?;
            masked_file_in_txn(&self.store, &txn, &hash)?.is_none()
        };
        if sealed && !crate::batch::secret_scan::is_sealed(bytes) {
            return Ok(SecretSight::Masked);
        }
        let why = checked_text(
            why,
            "a read of a file with keys in it says why it needs them",
            "a file read's why is one line of at most 512 bytes",
        )?;
        self.with_write_txn_grouped(|txn| {
            let (class, first, keys) = if sealed {
                (SEALED_FILE_CLASS, *artifact, Vec::new())
            } else {
                let Some(found) = marked_keys_in_txn(self, txn, &hash)? else {
                    return Ok(SecretSight::Masked);
                };
                found
            };
            let handle = if sealed {
                SEALED_FILE_HANDLE.to_owned()
            } else {
                keys.iter()
                    .map(|(_, handle)| handle.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let row = |state| RevealRow {
                reader: READER_AGENT.to_owned(),
                actor: asker.agent,
                connection: Some(asker.connection()),
                provider: asker.provider.clone(),
                secret: first,
                handle: handle.clone(),
                class: class.as_str().to_owned(),
                why: why.clone(),
                project: asker.project,
                run: asker.run.clone(),
                created_at: now,
                expires_at: now.saturating_add(REVEAL_ASK_TTL_SECS),
                state,
                once_digest: None,
                asked_decision: None,
                answered_by: None,
                decision: None,
                lease: None,
                delivered_at: None,
                file: Some(FileSight {
                    artifact: *artifact,
                    hash,
                    keys: keys.clone(),
                    leases: Vec::new(),
                }),
            };
            let grants = load_active_standing_grants(&self.store, txn)?;
            let bound = reveal_bound(&asker.connection(), class, asker.project.as_ref())?;
            if let Some(grant_ref) = covering_grant(&bound, asker.project, &grants)? {
                // Each read under a grant is its own receipt.
                let reveal = self.store.clock.entity_id()?;
                let mut read = row(SecretRevealState::Covered);
                let digest = read.ask_digest(&reveal);
                read.once_digest = Some(*digest.as_bytes());
                let used = self.record_standing_grant_use_in_txn(txn, &grant_ref, digest)?;
                read.answered_by = Some(standing(&grant_ref));
                read.decision = Some(used.decision_id());
                deliver_file_in_txn(self, txn, &reveal, read)?;
                return Ok(SecretSight::Granted);
            }
            let ask = file_ask_id(asker, &hash)?;
            match REVEALS.get(&self.store, txn, &ask)? {
                Some(mut asked)
                    if asked.state == SecretRevealState::ApprovedOnce && now < asked.expires_at =>
                {
                    let digest = asked.stored_once_digest()?;
                    let authorization =
                        approve_once_authorization_in_txn(&self.store, txn, &digest)?.ok_or(
                            Error::InvariantViolation(
                                "an approved file read has no approve-once marker",
                            ),
                        )?;
                    spend_approve_once_in_txn(&self.store, txn, &authorization)?;
                    asked.decision = approve_once_decision_in_txn(&self.store, txn, &digest)?;
                    deliver_file_in_txn(self, txn, &ask, asked)?;
                    Ok(SecretSight::Granted)
                }
                // Still waiting on the owner, or denied: the masked copy, and
                // no second ask while the window is open.
                Some(asked)
                    if matches!(
                        asked.state,
                        SecretRevealState::Asked | SecretRevealState::Denied
                    ) && now < asked.expires_at =>
                {
                    Ok(SecretSight::Masked)
                }
                _ => {
                    let mut asked = row(SecretRevealState::Asked);
                    file_ask_in_txn(self, txn, &ask, &mut asked, now)?;
                    REVEALS.put(&self.store, txn, &ask, &asked)?;
                    Ok(SecretSight::Masked)
                }
            }
        })
    }
}

/// The keys the mark of the file `hash` names, each with its handle, in the
/// file's order, with their one class and the first key: `None` when no mark
/// covers the file, or when a key is not active, not admitted to a model
/// (T1), or of another class than the rest.
fn marked_keys_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hash: &[u8; 32],
) -> Result<Option<(CustodyClass, EntityId, Vec<(EntityId, String)>)>> {
    let Some(mark) = masked_file_in_txn(&vault.store, txn, hash)? else {
        return Ok(None);
    };
    let floor = SecretCustodyFloor::resolve(&vault.store, txn)?;
    let mut keys: Vec<(EntityId, String)> = Vec::new();
    let mut class = None;
    // Every key the mark places: in the stored bytes, and in each member of a
    // container.
    let marked = mark
        .keys
        .iter()
        .chain(mark.members.iter().flat_map(|member| member.keys.iter()));
    for key in marked {
        if keys.iter().any(|(secret, _)| *secret == key.custody) {
            continue;
        }
        let Some(rec) = read_secret_custody_admission_in_txn(&vault.store, txn, &key.custody)?
        else {
            return Ok(None);
        };
        if rec.status != SecretCustodyStatus::Active
            || crate::secret_lease::reveal_tier_admission(&rec, &floor).is_err()
            || class.is_some_and(|class| class != rec.class)
        {
            return Ok(None);
        }
        class = Some(rec.class);
        let handle = crate::ports::ShortIdStoreRead::port_short_id_reference(
            &vault.store,
            txn,
            &key.custody,
        )?
        .map_or(rec.name, |(short, _)| short);
        keys.push((key.custody, handle));
    }
    let (Some(class), Some((first, _))) = (class, keys.first()) else {
        return Ok(None);
    };
    let first = *first;
    Ok(Some((class, first, keys)))
}

/// The one ask an agent's reads of a file file: by the agent, the stored
/// bytes, the project and the run.
fn file_ask_id(asker: &RevealAsker, hash: &[u8; 32]) -> Result<EntityId> {
    let project = asker
        .project
        .map(|project| project.to_hex())
        .unwrap_or_default();
    let parts: [&[u8]; 4] = [
        asker.agent.as_bytes(),
        hash,
        project.as_bytes(),
        asker.run.as_deref().unwrap_or_default().as_bytes(),
    ];
    crate::codebase::entity_id_from_hash_material(FILE_ASK_DOMAIN, &parts)
}

/// Delivers a granted file read in `txn`: a T1 lease per key, each receipt
/// first, as a delivered reveal stamps one, then the row. The file's bytes
/// carry the keys; the values the leases read go nowhere.
fn deliver_file_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reveal: &EntityId,
    mut row: RevealRow,
) -> Result<()> {
    let connection = row
        .connection
        .clone()
        .ok_or(Error::CorruptedIndex("secret reveal connection"))?;
    let class = row.class()?;
    let mut file = row
        .file
        .take()
        .ok_or(Error::CorruptedIndex("secret reveal file"))?;
    let mut delivered_at = None;
    for (secret, handle) in &file.keys {
        let authority = RevealAuthority {
            secret: *secret,
            handle: handle.clone(),
            class,
            effector: format!("model:{connection}"),
        };
        let materialized = crate::secret_lease::stamp_reveal_lease_in_txn(
            vault,
            txn,
            &authority,
            REVEAL_LEASE_TTL_SECS,
        )?;
        file.leases.push(materialized.lease.lease_id);
        delivered_at.get_or_insert(materialized.lease.granted_at);
        drop(materialized.value);
    }
    // A sealed file's read stamps no lease: it is delivered now.
    if delivered_at.is_none() {
        delivered_at = Some(crate::ports::recorded_at_in_txn(&vault.store, txn)?);
    }
    row.state = SecretRevealState::Delivered;
    row.lease = file.leases.first().copied();
    row.delivered_at = delivered_at;
    row.file = Some(file);
    REVEALS.put(&vault.store, txn, reveal, &row)
}
