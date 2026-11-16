//! Provider-neutral mailbox placement and read policy.
//!
//! A host maps provider labels to these facts before returning a page. The
//! engine never receives Gmail API flags or trusts a wire response whose
//! placement is outside the policy that was requested.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[doc(hidden)]
pub use oneiron_records::channel_identity_provider::mail_placement::{
    MailPlacement, PlacementPolicy,
};
