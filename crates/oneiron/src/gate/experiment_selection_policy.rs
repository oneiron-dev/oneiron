//! Trusted experiment-selection policy rows and their narrowing rules.

use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::gate::experiment_selection_policy::{
    SelectionPolicy, SelectionPolicyRow, SelectionPolicyScope, SelectionPrecedence,
    StagnationAction,
};
