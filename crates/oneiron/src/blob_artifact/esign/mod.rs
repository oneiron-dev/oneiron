//! Native signing requests on versioned blob artifacts; claims are the state machine.
mod field_admission;
mod fold;
mod ledger;
mod lifecycle;
mod model;
mod notice_dispatch;
pub use lifecycle::{EsignLifecycleRules, EsignNoticeSwitches};
pub use notice_dispatch::{ESIGN_NOTICE_ATTEMPT_KIND, EsignNotice};
#[cfg(test)]
mod tests;
pub(crate) use ledger::{reject_event_delete, validate_event_claim};
pub use model::{
    AccessStatus, DeliveryStatus, DocumentKind, DocumentStatus, EsignAuditActor, EsignDocument,
    EsignEvent, EsignEventRow, EsignField, EsignItem, EsignRecipient, EsignState, FieldGeometry,
    FieldMeta, FieldValue, RecipientRole, RecipientState, SignatureRow, SigningStatus,
};

mod capability;
mod ceremony;
mod principals;
pub use capability::EsignCapability;
pub(crate) use capability::recipient_capability_unrevoked_in;
pub use ceremony::{ESIGN_SEAL_ATTEMPT_KIND, SigningAction, SigningOutcome, SigningPage};
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

mod reseal;

#[cfg(test)]
mod seal_tests;

mod public_read;

mod artifact_actor;
pub(crate) use artifact_actor::actor as artifact_machine;

pub mod template;
