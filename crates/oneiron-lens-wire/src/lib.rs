//! The lens wire vocabulary of the oneiron engine: the closed generated-lens
//! atom kit, the Generated-UI card/segment/`$state` protocol, the `self.ui`
//! controls, the bounded wire ids and the validators over them. The `oneiron`
//! crate keeps host mediation, proposals and the lens store, and re-exports
//! every item here at its old `oneiron::lens` path.

pub mod lens;

// The engine error type, as `crate::{Error, Result}` names it in these modules.
pub(crate) use oneiron_base::error::{Error, Result};
