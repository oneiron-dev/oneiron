//! Connect delivery and rejoin wire vocabulary.
use crate::authority::ConnectWindow;
use crate::federation::SelectorRange;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::connect_delivery::{
    ConnectDelivery, ConnectExportRequest, ConnectRejoinStatus, ConnectRejoined,
};
