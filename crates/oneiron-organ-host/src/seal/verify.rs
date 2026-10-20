//! The seal's fresh verification and its suffix gate (OF-415, C032, Engine
//! ruling D). A sealed PDF that may carry revisions after the one the
//! engine wrote is admitted only on a second `seal.verify` call, in a
//! process of its own and with no handlers, over the exact output bytes:
//! its native verification must pass, cover the whole file with one proven
//! revision chain, find the signature this call bound, and classify every
//! later revision as validation data or a passed document timestamp.
//! Whether a suffix may follow at all is the requested profile's, never
//! the organ's achieved one. The host never links the organ (the of060 F4
//! fence) and never parses a PDF: it compares offsets, digests and kinds.

use oneiron::blob_artifact::esign::{EsignSealerError, EsignVerdict, SealProfile};
use oneiron_organ_protocol::seal::{
    SealCheckVerdict, SealModificationLevel, SealModifications, SealRevisionClassification,
    SealRevisionEvidence, SealRevisionKind, SealSignatureKind,
};
use sha2::{Digest, Sha256};

use super::binding::AdmittedRevision;
use super::observe::measure_input;
use super::{
    HostedSealer, PDF, VERB_VERIFY, VerifyArgs, VerifyReply, from_value, reply_invalid, to_value,
};
use crate::handlers::AskHandlers;
use crate::spec::LentInput;

impl HostedSealer<'_> {
    /// One `seal.verify` call over `pdf`, in a process of its own: never
    /// the one that sealed. Its verdict, and the revision classification
    /// beside it.
    pub(super) fn verify_classified(
        &self,
        pdf: &[u8],
    ) -> Result<(EsignVerdict, SealRevisionClassification), EsignSealerError> {
        let args = to_value(&VerifyArgs {
            now_ms: self.now_ms(),
            config: self.config(false)?,
        })
        .map_err(|_| reply_invalid())?;
        measure_input(self.vault, pdf);
        let lent = vec![LentInput {
            media_type: PDF.to_owned(),
            bytes: pdf.to_vec(),
        }];
        let (reply, _) =
            self.sized_call(self.call(VERB_VERIFY, 1, args), lent, &AskHandlers::none())?;
        match from_value(&reply)? {
            VerifyReply::Verified(verdict) => Ok(verdict.into_classified()),
            VerifyReply::Failed(failure) => Err(failure.into_error()),
        }
    }

    /// Admits `sealed`, bound to `witness` by the seal call, on a fresh
    /// verification of the whole of it. `achieved` is the seal's claim, which
    /// the fresh verdict must repeat; `profile` is the one requested, which
    /// alone decides whether anything may follow the bound revision.
    pub(super) fn admit_fresh(
        &self,
        sealed: &[u8],
        witness: &AdmittedRevision,
        achieved: SealProfile,
        profile: SealProfile,
    ) -> Result<(), EsignSealerError> {
        let (verdict, classification) = self.verify_classified(sealed)?;
        if !verdict.valid() || !verdict.self_verify_ok {
            return Err(EsignSealerError::VerifyFailed {
                verdict: Box::new(verdict),
            });
        }
        let digest: [u8; 32] = Sha256::digest(sealed).into();
        if classification.artifact_sha256.as_slice() != digest
            || classification.classified_through != Some(sealed.len() as u64)
            || verdict.achieved != Some(achieved)
        {
            return Err(reply_invalid());
        }
        if admits(&classification, witness, profile >= SealProfile::BaselineLt) {
            Ok(())
        } else {
            Err(EsignSealerError::Fatal {
                stage: "binding".to_owned(),
                code: "unbound_output".to_owned(),
            })
        }
    }
}

/// Whether the classification holds the bound signature, passed, over the
/// engine's own ByteRange to the end the engine wrote, and after its
/// revision only validation data and passed document timestamps, in one
/// increasing chain, and those only when `suffix` allows any.
fn admits(
    classification: &SealRevisionClassification,
    witness: &AdmittedRevision,
    suffix: bool,
) -> bool {
    if !matches!(
        classification.modifications,
        SealModifications::Clean(SealModificationLevel::None | SealModificationLevel::LtaUpdates)
    ) {
        return false;
    }
    let Some(bound) = classification.signatures.iter().find(|signature| {
        signature.kind == SealSignatureKind::Signature
            && signature.byte_range.values == witness.byte_range
    }) else {
        return false;
    };
    let revisions = &classification.revisions;
    let Some(at) = revisions
        .iter()
        .position(|revision| revision.signed_by.as_deref() == Some(bound.id.as_str()))
    else {
        return false;
    };
    let later = &revisions[at + 1..];
    bound.byte_range.well_formed
        && bound.byte_range.covers_to == Some(witness.byte_end)
        && bound.integrity == SealCheckVerdict::Passed
        && bound.verdict == SealCheckVerdict::Passed
        && revisions[at].kind == SealRevisionKind::Signature
        && revisions[at].byte_end <= witness.byte_end
        && revisions
            .windows(2)
            .all(|pair| pair[0].index < pair[1].index && pair[0].byte_end < pair[1].byte_end)
        && (suffix || later.is_empty())
        && later
            .iter()
            .all(|revision| archival(classification, revision))
}

/// Whether a revision after the bound one is validation data, or a
/// document timestamp whose signature passed.
fn archival(classification: &SealRevisionClassification, revision: &SealRevisionEvidence) -> bool {
    match revision.kind {
        SealRevisionKind::Dss => revision.signed_by.is_none(),
        SealRevisionKind::DocumentTimestamp => revision.signed_by.as_deref().is_some_and(|id| {
            classification.signatures.iter().any(|signature| {
                signature.id == id
                    && signature.kind == SealSignatureKind::DocumentTimestamp
                    && signature.integrity == SealCheckVerdict::Passed
                    && signature.verdict == SealCheckVerdict::Passed
            })
        }),
        SealRevisionKind::Original | SealRevisionKind::Signature | SealRevisionKind::Other => false,
    }
}
