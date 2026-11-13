//! Versioned task-type references retained with receipt attribution.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::receipt::task_type_ref::{ROOT_TYPE_NODE, TypeRef};
