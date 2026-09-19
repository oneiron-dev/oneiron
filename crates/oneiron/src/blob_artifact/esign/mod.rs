//! Native signing requests on versioned blob artifacts; claims are the state machine.
mod fold;
mod ledger;
mod model;
#[cfg(test)]
mod tests;
pub(crate) use ledger::validate_event_claim;
pub use model::{
    AccessStatus, DeliveryStatus, DocumentKind, DocumentStatus, EsignAuditActor, EsignDocument,
    EsignEvent, EsignEventRow, EsignField, EsignItem, EsignRecipient, EsignState, FieldGeometry,
    FieldMeta, FieldValue, RecipientRole, RecipientState, SignatureRow, SigningStatus,
};

mod capability;
mod ceremony;
mod principals;
pub use capability::EsignCapability;
pub use ceremony::{ESIGN_SEAL_ATTEMPT_KIND, SigningAction, SigningOutcome, SigningPage};
pub use principals::{SigningAutonomy, SigningPrincipal};

mod outbound;
pub use outbound::{EsignOutboundCommand, EsignOutboundVerb};

mod signature_image;

mod rate;

pub mod render;
mod seal;
pub use seal::{EsignSealError, SealedDocument, SealedItem};

mod reseal;

#[cfg(test)]
mod seal_tests;

mod public_read;

mod artifact_actor;
