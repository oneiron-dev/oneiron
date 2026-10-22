//! The receive seams of a projection-bound push (FIX 7608 slice 2b-ii-B2).
//!
//! A push received into a masked copy's private ingress carries its ingress
//! proof's id on its stamp and intent. These seams are the only readers of
//! that id, and each reads it through `validate_projection_ingress_in_txn`
//! for the very stamp it holds, at the physical ingress it observed:
//!
//! - the host check of admission, intent and landing source maps to the
//!   canonical store the proof names ONLY when that validation succeeds;
//!   an absent proof, a failed validation or a validation fault keeps
//!   today's check on the physical store, with no fallback to canonical;
//! - G1 is rechecked on the canonical repository for every proof stamp,
//!   in the same final intent writer, before any write or publication;
//! - a landing publishes with no host lease only on the private ingress a
//!   validated proof names, which has no authority row of its own, and
//!   never through the canonical publisher.
//!
//! The proof is never scope or admission authority; G1 stays the canonical
//! stamp's.

use std::path::Path;

use heed::RoTxn;

use super::super::door::DoorAdmissionStamp;
use super::super::landing::ReceivePackAttribution;
use super::super::evidence::{
    RECEIVE_PACK_OUTCOME_PREDICATE, receive_pack_field, receive_pack_provenance_refused,
};
use super::super::paths::origin_repo_dir;
use super::super::push_projection::recovery::recover_projection_ingress;
use super::super::push_projection::{
    RepoProjectionIngressProof, validate_projection_ingress_in_txn,
};
use super::super::serve::unpinned_repo_ref;
use super::{INTENTS, ReceivePackIntentKey, push_admission, receive_pack_repo_identity_hex};
use crate::Vault;
use crate::claim::ClaimBody;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::GitWire;
use crate::origin::residence::OriginAuthorityStamp;

/// The ingress proof id an admission's evidence names, when it names one.
pub(super) fn admission_ingress_proof(admission: &ClaimBody) -> Option<String> {
    admission
        .value
        .as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some("ingress_proof"))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

impl Vault {
    /// The canonical store `stamp`'s ingress proof names, when that proof
    /// validates for exactly this stamp at the physical ingress `root`;
    /// `None` for an ordinary stamp, and for one whose proof does not
    /// validate or whose validation faulted (logged).
    fn validated_ingress_store_in_txn(
        &self,
        txn: &RoTxn<'_>,
        stamp: &DoorAdmissionStamp,
        root: &Path,
    ) -> Option<EntityId> {
        let id = stamp.ingress_proof?;
        let validated = (|| -> Result<Option<EntityId>> {
            let Some(recovered) = recover_projection_ingress(self, txn, &id, stamp)? else {
                return Ok(None);
            };
            let identity = GitWire::new(self)?.repository_identity(root)?.as_hex();
            let proof = RepoProjectionIngressProof::reopen(recovered, root);
            if proof.ingress_store() != identity {
                return Ok(None);
            }
            Ok(validate_projection_ingress_in_txn(self, txn, &proof, stamp)?
                .then(|| proof.canonical_store()))
        })();
        match validated {
            Ok(store) => store,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a projection ingress proof did not validate; the physical store's host check stands"
                );
                None
            }
        }
    }

    /// The host check of a receive's admission and intent: on the canonical
    /// store a validated ingress proof names, else today's on `root`.
    ///
    /// # Errors
    /// The host authority refuses, or a store failure.
    pub(in crate::origin::smart_http) fn require_receive_pack_host_for(
        &self,
        root: &Path,
        stamp: &DoorAdmissionStamp,
    ) -> Result<()> {
        let projected = {
            let txn = self.store.env.read_txn()?;
            self.validated_ingress_store_in_txn(&txn, stamp, root)
        };
        match projected {
            Some(store) => self.require_receive_pack_host(store, stamp.origin_authority.as_ref()),
            None => self.require_receive_pack_host_at(root, stamp.origin_authority.as_ref()),
        }
    }

    /// The repository G1 is rechecked on in the final intent writer: the
    /// canonical served repository for every proof stamp, the physical
    /// `repo` for every other.
    ///
    /// # Errors
    /// A proof stamp with no admitted push, or a served name that does not
    /// resolve.
    pub(in crate::origin::smart_http) fn receive_pack_g1_repo(
        &self,
        stamp: &DoorAdmissionStamp,
        repo: &RepoRef,
    ) -> Result<RepoRef> {
        if stamp.ingress_proof.is_none() {
            return Ok(repo.clone());
        }
        let push = stamp.push.as_ref().ok_or_else(|| {
            receive_pack_provenance_refused("a projection-bound push names no admitted push")
        })?;
        Ok(unpinned_repo_ref(&origin_repo_dir(self, push.served_name())?))
    }

    /// The accepted stamp of `operation` on the physical store at `root`,
    /// from its intent; `None` with no intent.
    fn receive_pack_stamp_in_txn(
        &self,
        txn: &RoTxn<'_>,
        root: &Path,
        operation: EntityId,
    ) -> Result<Option<DoorAdmissionStamp>> {
        let key = ReceivePackIntentKey {
            repo_identity_hex: receive_pack_repo_identity_hex(self, root)?,
            operation_id: operation,
        };
        INTENTS
            .get(&self.store, txn, &key)?
            .map(|intent| push_admission::recovered_stamp(&intent))
            .transpose()
    }

    /// The store a landing source's host authority is checked on: the
    /// canonical store a validated ingress proof of `operation`'s intent
    /// names, else `repo_id` itself.
    ///
    /// # Errors
    /// A store failure reading the intent.
    pub(in crate::origin::smart_http) fn receive_pack_host_store_in_txn(
        &self,
        txn: &RoTxn<'_>,
        repo_id: EntityId,
        root: &Path,
        operation: EntityId,
    ) -> Result<EntityId> {
        Ok(self
            .receive_pack_stamp_in_txn(txn, root, operation)?
            .and_then(|stamp| self.validated_ingress_store_in_txn(txn, &stamp, root))
            .unwrap_or(repo_id))
    }

    /// The host lease a landing publishes under: the producer-backed one
    /// its source proved, except on a private ingress a validated proof
    /// names, which has no authority row and publishes under none (its
    /// canonical authority was checked through the proof above). The
    /// canonical publisher is never reached with none.
    ///
    /// # Errors
    /// As `receive_pack_landing_authority`.
    pub(in crate::origin::smart_http) fn receive_pack_publication_authority(
        &self,
        repo_id: EntityId,
        root: &Path,
        attribution: &ReceivePackAttribution,
    ) -> Result<Option<OriginAuthorityStamp>> {
        let authority = self.receive_pack_landing_authority(repo_id, root, attribution)?;
        let rtxn = self.store.env.read_txn()?;
        let body = self.receive_pack_evidence_in_txn(
            &rtxn,
            attribution.provenance_claim_id,
            RECEIVE_PACK_OUTCOME_PREDICATE,
        )?;
        let operation = receive_pack_field(&body, "operation_id")?
            .as_str()
            .and_then(|id| EntityId::from_hex(id).ok())
            .ok_or_else(|| receive_pack_provenance_refused("invalid operation identity"))?;
        let ingress = self
            .receive_pack_stamp_in_txn(&rtxn, root, operation)?
            .and_then(|stamp| self.validated_ingress_store_in_txn(&rtxn, &stamp, root));
        Ok(if ingress.is_some() { None } else { authority })
    }

    /// Resume's check of a projection-bound intent: its proof validated
    /// and the canonical host it names standing. An ordinary intent is
    /// untouched.
    ///
    /// # Errors
    /// The host authority refuses, or a store failure.
    pub(in crate::origin::smart_http) fn require_resumed_ingress(
        &self,
        root: &Path,
        stamp: &DoorAdmissionStamp,
    ) -> Result<()> {
        if stamp.ingress_proof.is_none() {
            return Ok(());
        }
        self.require_receive_pack_host_for(root, stamp)
    }
}
