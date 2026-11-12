//! The shapes of one exact publish request (FIX 6866): what it names, the
//! review it carries, where it stands and the refusal that ended it. The
//! stored row is the answer every publish verb gives.

#[doc(hidden)]
pub use oneiron_verb_wire::origin::publish::types::{
    OriginPublishAct, OriginPublishAuthority, OriginPublishDestination, OriginPublishForce,
    OriginPublishLfsBytes, OriginPublishRefusal, OriginPublishRefusalReason, OriginPublishRemote,
    OriginPublishRequestView, OriginPublishReview, OriginPublishReviewItem,
    OriginPublishReviewPage, OriginPublishState,
};
