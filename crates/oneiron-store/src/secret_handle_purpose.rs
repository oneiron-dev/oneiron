//! Owner-authored purpose text on a custody handle. The authored side-row
//! wall masks values before storage; the receipt is a native Gate id.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretHandlePurpose {
    pub purpose: String,
    pub receipt: [u8; 16],
}
