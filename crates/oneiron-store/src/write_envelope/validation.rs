//! Write-envelope shape validation.

use super::WriteEnvelope;
use oneiron_contracts::error::{Error, Result};
use rmpv::Value;

pub fn validate_write_envelope(envelope: &WriteEnvelope) -> Result<()> {
    if matches!(envelope.provenance().value(), &Value::Nil) {
        return Err(Error::InvalidClaimBody("write envelope missing provenance"));
    }

    Ok(())
}
