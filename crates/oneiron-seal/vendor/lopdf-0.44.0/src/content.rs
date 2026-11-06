use super::Object;
use crate::Result;
use crate::writer::Writer;
use std::io::Write;

#[derive(Debug, Clone)]
pub struct Operation {
    pub operator: String,
    pub operands: Vec<Object>,
}

impl Operation {
    pub fn new(operator: &str, operands: Vec<Object>) -> Operation {
        Operation {
            operator: operator.to_string(),
            operands,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Content<Operations: AsRef<[Operation]> = Vec<Operation>> {
    pub operations: Operations,
}

impl<Operations: AsRef<[Operation]>> Content<Operations> {
    /// Encode content operations.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.encode_to(&mut buffer)?;
        Ok(buffer)
    }

    /// Encode content operations to a caller-owned writer.
    pub fn encode_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut first_operation = true;
        for operation in self.operations.as_ref() {
            // Add new line after each operation except the last one.
            if first_operation {
                first_operation = false;
            } else {
                writer.write_all(b"\n")?;
            }
            for operand in &operation.operands {
                Writer::write_object(writer, operand)?;
                writer.write_all(b" ")?;
            }
            writer.write_all(operation.operator.as_bytes())?;
        }
        Ok(())
    }
}
