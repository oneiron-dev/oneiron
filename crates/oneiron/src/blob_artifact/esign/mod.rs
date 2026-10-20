//! Native signing requests on versioned blob artifacts; claims are the state machine.
mod dispatch_key;
mod field_admission;
mod fold;
mod ledger;
mod lifecycle;
mod model;
mod notice_dispatch;
mod notice_door;
mod notice_scope;
mod notice_send_act;
mod notice_unattended;
pub use lifecycle::{
    EsignLifecycleRules, EsignNoticeSwitches, EsignReminderSweep, HeldEsignReminder,
};
pub use notice_dispatch::{ESIGN_NOTICE_ATTEMPT_KIND, EsignNotice};
pub use notice_door::{EsignNoticeOutcome, EsignNoticesDispatchRequest, EsignNoticesDispatchView};
pub(crate) use notice_send_act::erase_notice_send_act_actor_in_txn;
pub use notice_unattended::{EsignNoticeGroup, EsignUnattendedNotices};
#[cfg(test)]
mod tests;
pub use ledger::PROJECT_MEMBERS_ONLY;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use ledger::mark_sent_for_test;
pub(crate) use ledger::{esign_document_page_in_txn, reject_event_delete, validate_event_claim};
pub use model::{
    AccessStatus, DeliveryStatus, DocumentKind, DocumentStatus, EsignAuditActor, EsignDocument,
    EsignEvent, EsignEventRow, EsignField, EsignItem, EsignRecipient, EsignState, FieldGeometry,
    FieldMeta, FieldValue, RecipientRole, RecipientState, SignatureRow, SigningStatus,
};

mod capability;
mod ceremony;
mod delivery_capability;
pub use delivery_capability::{EsignDeliveryLink, EsignDeliveryMint, EsignDeliveryWait};
mod delivery_settlement;
pub use delivery_settlement::{
    EsignDeliveryEndReason, EsignDeliveryReceipt, EsignDeliveryReceiptState,
};
mod ingress;
pub use ingress::EsignIngress;
mod document_view;
pub use document_view::{EsignDocumentTrail, EsignDocumentView, EsignSealTrail};
mod door;
pub use door::{
    EsignCreateRequest, EsignDispatchRequest, EsignDispatchView, EsignDraftView, EsignGetRequest,
    EsignIssuedLink, EsignLinksIssueRequest, EsignLinksView, EsignSealAttemptView,
    EsignSealGetRequest, EsignSealView, EsignSealedItemView, EsignSealedView,
    EsignSigningImageRequest, EsignSigningImageView, EsignSigningPdfRequest, EsignSigningPdfView,
    EsignSigningRequest, EsignSigningSignatureRequest, EsignSigningSignatureView, EsignVoidRequest,
};
mod escalation;
pub use escalation::{
    ESIGN_ASK_CLIMB_HOURS, HOLD_ALLOW, HOLD_DECLINE, HeldAskWait, HeldSigning, HeldSigningAnswer,
    HeldSigningState,
};
mod principals;
pub use capability::EsignCapability;
pub(crate) use capability::recipient_capability_unrevoked_in;
pub use ceremony::{
    ESIGN_SEAL_ATTEMPT_KIND, SigningAction, SigningCaller, SigningOutcome, SigningPage,
};
pub use principals::{SigningAutonomy, SigningPrincipal};
pub(crate) use principals::{automated_outbound_allowed, automated_signing_allowed};

mod outbound;
pub use outbound::{EsignOutboundCommand, EsignOutboundVerb};

mod signature_image;

mod rate;
pub use rate::{EsignRateCheck, EsignRateReceipt};

pub mod render;
mod seal;
pub use seal::{EsignSealError, SealedDocument, SealedItem};
mod seal_run;
pub use seal_run::EsignSealRun;
mod sealer;
pub use sealer::{
    EsignSealInput, EsignSealRequest, EsignSealed, EsignSealer, EsignSealerError,
    EsignSignatureRevision, EsignVerdict, SealDegrade, SealProfile, SealVerdict,
};
mod signature_revision;
pub use signature_revision::SEAL_CONTENTS_LADDER;

mod reseal;

mod public_read;

mod artifact_actor;
pub(crate) use artifact_actor::actor as artifact_machine;

pub mod template;
