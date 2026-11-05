//! The same credential-gated file projection for point reads and indexed
//! hydration. A non-owner never receives a lifted value through raw bytes.
use crate::ports::point_read::PointRead;
use crate::ports::read_result::ScopedReadResult;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::gate::RetrievalFilter;

pub fn strings<'a>(value: &'a rmpv::Value, out: &mut Vec<&'a str>) {
    match value {
        rmpv::Value::String(text) => {
            if let Some(text) = text.as_str() {
                out.push(text);
            }
        }
        rmpv::Value::Array(items) => {
            for item in items {
                strings(item, out);
            }
        }
        rmpv::Value::Map(items) => {
            for (key, value) in items {
                strings(key, out);
                strings(value, out);
            }
        }
        _ => {}
    }
}
