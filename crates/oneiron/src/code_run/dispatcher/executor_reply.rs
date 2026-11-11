//! Native result metadata kept beside a write's answer in its own receipt.

use crate::code_run::codec::{decode_raw_output, encode_raw_output};
use crate::code_run::support::{entity_value, invalid_code_run_replay};
use crate::code_run::{CodeRunRawOutput, CodeRunResultBinding};
use crate::{EntityId, Result};
use serde_json::Value;

/// A host-published occurrence, never reconstructed from a guest result card.
#[derive(Clone)]
pub(crate) struct ExecutorReply {
    pub(crate) owner: EntityId,
    pub(crate) name: String,
    pub(crate) output: CodeRunRawOutput,
}

/// Lent by one recording host for one synchronous dispatch.
pub(crate) trait ExecutorReplyPublisher {
    fn publish(
        &self,
        value: &mut Value,
        commit: &mut dyn FnMut(&mut heed::RwTxn<'_>, &Value, &ExecutorReply) -> Result<()>,
    ) -> Result<Option<ExecutorReply>>;
    fn adopt(&self, reply: ExecutorReply, value: &Value) -> Result<()>;
}

impl ExecutorReply {
    /// Metadata belongs to the receipt, not its `outputs`: the occurrence
    /// remains owned by the original executor run, not the receipt's id.
    pub(super) fn keep(&self, outcome: &mut rmpv::Value) -> Result<()> {
        let rmpv::Value::Map(fields) = outcome else {
            return Err(invalid_code_run_replay(
                "executor reply outcome is not a map",
            ));
        };
        fields.push((
            rmpv::Value::from("executor_reply"),
            rmpv::Value::Array(vec![
                rmpv::Value::Binary(self.owner.as_bytes().to_vec()),
                rmpv::Value::from(self.name.as_str()),
                encode_raw_output(&self.output),
            ]),
        ));
        Ok(())
    }

    pub(crate) fn kept(outcome: &rmpv::Value, owner: EntityId) -> Result<Option<Self>> {
        let rmpv::Value::Map(fields) = outcome else {
            return Ok(None);
        };
        let Some((_, value)) = fields
            .iter()
            .find(|(key, _)| key.as_str() == Some("executor_reply"))
        else {
            return Ok(None);
        };
        let rmpv::Value::Array(fields) = value else {
            return Err(invalid_code_run_replay("invalid executor reply metadata"));
        };
        let [stored_owner, name, output] = fields.as_slice() else {
            return Err(invalid_code_run_replay("invalid executor reply metadata"));
        };
        let stored_owner = entity_value(stored_owner)?;
        let name = name
            .as_str()
            .filter(|name| CodeRunResultBinding::is_valid_name(name))
            .ok_or_else(|| invalid_code_run_replay("invalid executor reply binding"))?;
        if stored_owner != owner {
            return Err(invalid_code_run_replay("executor reply owner mismatch"));
        }
        Ok(Some(Self {
            owner,
            name: name.to_owned(),
            output: decode_raw_output(output)?,
        }))
    }
}
