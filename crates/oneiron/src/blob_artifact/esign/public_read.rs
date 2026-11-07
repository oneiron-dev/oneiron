//! Capability-scoped PDF bytes. Canonical reads never follow a mutable blob head.
use super::{
    SigningAction,
    capability::{EsignCapability, binding},
    ledger::state_in,
    model::*,
};
use crate::{EntityId, Result, Vault};
use sha2::{Digest, Sha256};

/// A preview read's vault error or input-memory refusal. File-plane and plain
/// inline ASSET bytes reserve memory before their output allocation; record-head
/// bytes lease it after the read.
#[derive(Debug)]
pub enum EsignLeasedReadError {
    Vault(crate::Error),
    Refused(crate::host_memory::MemoryRefusal),
}

impl From<crate::Error> for EsignLeasedReadError {
    fn from(error: crate::Error) -> Self {
        Self::Vault(error)
    }
}

impl Vault {
    /// During signing this returns the pinned original, and after sealing the
    /// pinned, hash-checked output (verified at seal time). The HTTP carrier serves it as an attachment.
    pub fn esign_pdf_for_capability(
        &self,
        token: &EsignCapability,
        item: usize,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Vec<u8>> {
        self.esign_pdf_for_capability_as(
            token,
            item,
            super::SigningCaller::Bearer,
            None,
            ip,
            user_agent,
        )
    }
    /// [`Self::esign_pdf_for_capability`] with the verified caller's receipt evidence.
    pub fn esign_pdf_for_capability_as(
        &self,
        token: &EsignCapability,
        item: usize,
        caller: super::SigningCaller,
        verified_actor: Option<EntityId>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Vec<u8>> {
        self.esign_pdf_for_capability_within(
            token,
            item,
            caller,
            verified_actor,
            ip,
            user_agent,
            &|_, _| Ok(true),
        )
    }
    /// [`Self::esign_pdf_for_capability`] under a narrowed caller's
    /// credential ceiling (FIX 6403): the ceremony Load and the read judge
    /// the document the capability binds as soon as the binding names it.
    /// The capability authorizes the item it names, original or sealed.
    pub(super) fn esign_pdf_for_capability_within(
        &self,
        token: &EsignCapability,
        item: usize,
        caller: super::SigningCaller,
        verified_actor: Option<EntityId>,
        ip: Option<String>,
        user_agent: Option<String>,
        ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
    ) -> Result<Vec<u8>> {
        self.execute_signing_action_within(
            token,
            &SigningAction::Load,
            caller,
            verified_actor,
            ip,
            user_agent,
            ceiling,
        )?;
        self.esign_pdf_after_admission(token, item, ceiling)
    }
    /// One capability admission for a page and its pinned PDF, for preview callers.
    pub fn esign_preview_for_capability(
        &self,
        token: &EsignCapability,
        item: usize,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(super::SigningPage, Vec<u8>)> {
        self.esign_preview_for_capability_as(
            token,
            item,
            super::SigningCaller::Bearer,
            None,
            ip,
            user_agent,
        )
    }
    /// [`Self::esign_preview_for_capability`] with the verified caller's receipt evidence.
    pub fn esign_preview_for_capability_as(
        &self,
        token: &EsignCapability,
        item: usize,
        caller: super::SigningCaller,
        verified_actor: Option<EntityId>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(super::SigningPage, Vec<u8>)> {
        let super::SigningOutcome::Page(page) = self.execute_signing_action_as(
            token,
            &SigningAction::Load,
            caller,
            verified_actor,
            ip,
            user_agent,
        )?
        else {
            return Err(invalid("preview is unavailable"));
        };
        let bytes = self.esign_pdf_after_admission(token, item, &|_, _| Ok(true))?;
        Ok((page, bytes))
    }
    fn esign_pdf_after_admission(
        &self,
        token: &EsignCapability,
        item: usize,
        ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
    ) -> Result<Vec<u8>> {
        self.esign_pdf_after_admission_with(token, item, ceiling, |txn, artifact, version| {
            self.read_blob_artifact_version_in_txn(txn, artifact, version)
                .map(|bytes| bytes.map(|bytes| (bytes, ())))
        })
        .map(|(bytes, _guard)| bytes)
    }

    /// [`Self::esign_pdf_after_admission`] with its bytes read by `read`: the
    /// binding, ceiling, state, revocation, expiry, status, canonical and hash
    /// gates stay, and the closure reads the admitted version in the same
    /// snapshot. Its guard rides with the bytes through the hash check.
    fn esign_pdf_after_admission_with<G, E>(
        &self,
        token: &EsignCapability,
        item: usize,
        ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
        read: impl FnOnce(
            &heed::RoTxn<'_>,
            &EntityId,
            u64,
        ) -> std::result::Result<Option<(Vec<u8>, G)>, E>,
    ) -> std::result::Result<(Vec<u8>, G), E>
    where
        E: From<crate::Error>,
    {
        let now = self.now_recorded_at();
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let cap = binding(self, &txn, token)?;
        super::lane_scope::ceiling_admits_in(ceiling, &txn, &cap.document)?;
        let id = EntityId::from_hex(&cap.document).map_err(crate::Error::from)?;
        let state = state_in(self, &txn, id)?;
        let recipient = state
            .recipients
            .get(&cap.recipient)
            .ok_or_else(|| invalid("invalid capability"))?;
        if cap.revoked_at.is_some()
            || now >= cap.hard_expires_at
            || now >= recipient.expires_at
            || (state.status == DocumentStatus::Pending
                && recipient.signing == SigningStatus::Waiting)
            || matches!(
                state.status,
                DocumentStatus::Draft | DocumentStatus::Voided | DocumentStatus::Expired
            )
        {
            return Err(E::from(invalid("PDF is unavailable")));
        }
        if matches!(
            state.status,
            DocumentStatus::Completed | DocumentStatus::Rejected
        ) {
            // Read the canonical swap in THIS snapshot, then the immutable version.
            let manifest = super::seal::CANONICAL
                .get(&self.store, &txn, &id)?
                .ok_or_else(|| invalid("sealed manifest missing"))?;
            let item = manifest
                .items
                .get(item)
                .ok_or_else(|| invalid("item missing"))?;
            let pair = read(
                &txn,
                &EntityId::from_hex(&item.sealed_artifact).map_err(crate::Error::from)?,
                item.sealed_version,
            )?
            .ok_or_else(|| invalid("sealed artifact missing"))?;
            if <[u8; 32]>::from(Sha256::digest(&pair.0)) != item.sha256 {
                return Err(E::from(invalid("sealed artifact hash mismatch")));
            }
            Ok(pair)
        } else {
            let item = state
                .document
                .items
                .get(item)
                .ok_or_else(|| invalid("item missing"))?;
            read(
                &txn,
                &EntityId::from_hex(&item.artifact_ref).map_err(crate::Error::from)?,
                item.original_version,
            )?
            .ok_or_else(|| E::from(invalid("original missing")))
        }
    }

    /// [`Self::esign_preview_for_capability_as`] with its PDF bytes leased
    /// from this machine's memory: file-plane and plain inline ASSET bodies
    /// reserve their exact output length before allocating it. The lease then
    /// names the returned buffer's reported capacity as allocated. Record-head
    /// bodies lease that capacity after reading and name it allocated as well.
    /// The lease rides through inspection.
    pub fn esign_preview_for_capability_leased_as(
        &self,
        token: &EsignCapability,
        item: usize,
        caller: super::SigningCaller,
        verified_actor: Option<EntityId>,
        ip: Option<String>,
        user_agent: Option<String>,
        memory: &crate::host_memory::MachineMemory,
        deadline: std::time::Instant,
    ) -> std::result::Result<
        (super::SigningPage, Vec<u8>, crate::host_memory::MemoryLease),
        EsignLeasedReadError,
    > {
        let super::SigningOutcome::Page(page) = self.execute_signing_action_as(
            token,
            &SigningAction::Load,
            caller,
            verified_actor,
            ip,
            user_agent,
        )?
        else {
            return Err(EsignLeasedReadError::Vault(invalid(
                "preview is unavailable",
            )));
        };
        let pair = self.esign_pdf_after_admission_with(
            token,
            item,
            &|_, _| Ok(true),
            |txn, artifact, version| {
                self.read_blob_artifact_version_in_txn_with(txn, artifact, version, |txn, hash| {
                    let leased = self
                        .blob_get_with_body_admission(txn, hash, |len| {
                            memory
                                .lease(len, deadline)
                                .map(|lease| (lease, len))
                                .map_err(EsignLeasedReadError::Refused)
                        })
                        .map_err(|error| match error {
                            crate::ports::BodyReadError::Store(error) => {
                                EsignLeasedReadError::Vault(error)
                            }
                            crate::ports::BodyReadError::Admission(error) => error,
                        })?;
                    match leased {
                        Some(leased) => Ok(leased),
                        None => Err(EsignLeasedReadError::Vault(crate::Error::EntityNotFound)),
                    }
                })
            },
        )?;
        let actual = u64::try_from(pair.0.capacity()).unwrap_or(u64::MAX);
        let (bytes, guard) = pair;
        match guard {
            Some((mut lease, reserved)) => {
                lease.materialized(reserved, actual);
                Ok((page, bytes, lease))
            }
            None => {
                let mut lease = memory
                    .lease(actual, deadline)
                    .map_err(EsignLeasedReadError::Refused)?;
                lease.materialized(actual, actual);
                Ok((page, bytes, lease))
            }
        }
    }

    /// A typed preview on the engine's document-memory operation, under the
    /// capability and the caller's existing credential ceiling. The same
    /// canonical/hash snapshot reader admits actual FILE/inline ASSET bodies
    /// before allocation; record-head bodies retain their post-read admission.
    pub(super) fn esign_preview_for_capability_admitted_within(
        &self,
        token: &EsignCapability,
        item: usize,
        caller: super::SigningCaller,
        verified_actor: Option<EntityId>,
        resources: &oneiron_docedit::resource::Resources,
        ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
    ) -> Result<(super::SigningPage, Vec<u8>, oneiron_docedit::resource::Hold)> {
        use crate::entity_doc::document_resources::machine_memory_refused;
        let super::SigningOutcome::Page(page) = self.execute_signing_action_within(
            token,
            &SigningAction::Load,
            caller,
            verified_actor,
            None,
            None,
            ceiling,
        )?
        else {
            return Err(invalid("preview is unavailable"));
        };
        let pair =
            self.esign_pdf_after_admission_with(token, item, ceiling, |txn, artifact, version| {
                self.read_blob_artifact_version_in_txn_with(txn, artifact, version, |txn, hash| {
                    let admitted = self
                        .blob_get_with_body_admission(txn, hash, |len| {
                            resources
                                .reserve(len)
                                .map(|hold| (hold, len))
                                .map_err(machine_memory_refused)
                        })
                        .map_err(|error| match error {
                            crate::ports::BodyReadError::Store(error) => error,
                            crate::ports::BodyReadError::Admission(error) => error,
                        })?;
                    admitted.ok_or(crate::Error::EntityNotFound)
                })
            })?;
        let (buffered, guard) = pair;
        let actual = u64::try_from(buffered.capacity()).unwrap_or(u64::MAX);
        let (mut hold, reserved) = match guard {
            Some(guard) => guard,
            None => (
                resources.reserve(actual).map_err(machine_memory_refused)?,
                actual,
            ),
        };
        // The bytes drop before their hold if capacity settlement is refused.
        let bytes = buffered;
        hold.take(actual.saturating_sub(reserved))
            .map_err(machine_memory_refused)?;
        Ok((page, bytes, hold))
    }
}
