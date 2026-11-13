//! An unflagged window's sieve audit as a weave report serves it (OF-498f):
//! refs as hex, offsets as bytes, kinds by name.

use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::claim::scoped_read::weave_serve::sieve_audit::{
    WeaveSieveDiscoveryView, WeaveSieveFindingView,
};
