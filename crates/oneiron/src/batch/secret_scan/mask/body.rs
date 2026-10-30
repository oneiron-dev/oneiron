//! A body as the door reads it (OF-560): JSON, a whole MessagePack value, or
//! text.

use rmpv::Value;

use super::Masker;
use super::wipe::PlanTree;
use crate::error::{Error, Result};

impl Masker {
    /// A body read as the door reads it: JSON, a whole MessagePack value, or
    /// text. `None` when nothing in it was placed.
    pub(super) fn mask_body(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        // A decoded tree holds the body's secrets too: wiped as it drops.
        if let Ok(value) = serde_json::from_slice::<Value>(data) {
            let mut tree = PlanTree(value);
            if !self.mask_value(&mut tree.0)? {
                return Ok(None);
            }
            return serde_json::to_vec(&tree.0)
                .map(Some)
                .map_err(|_| Error::InvariantViolation("a masked JSON body did not encode"));
        }
        let mut cursor = std::io::Cursor::new(data);
        if let Ok(value) = rmpv::decode::read_value(&mut cursor) {
            let mut tree = PlanTree(value);
            if cursor.position() == data.len() as u64 {
                if !self.mask_value(&mut tree.0)? {
                    return Ok(None);
                }
                let mut out = Vec::with_capacity(data.len());
                rmpv::encode::write_value(&mut out, &tree.0).map_err(|_| {
                    Error::InvariantViolation("a masked MessagePack body did not encode")
                })?;
                return Ok(Some(out));
            }
        }
        match std::str::from_utf8(data) {
            Ok(text) => Ok(self.mask_text(text)?.map(String::into_bytes)),
            Err(_) => Ok(None),
        }
    }
}
