//! Host-authored prelude plus source under one guest program ceiling.
use super::{MAX_PROGRAM_BYTES, Result, refused};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramBudget {
    prelude_reserved: usize,
}
impl ProgramBudget {
    pub fn new(prelude_reserved: usize) -> Result<Self> {
        if prelude_reserved > MAX_PROGRAM_BYTES {
            return Err(refused("program prelude reservation limit"));
        }
        Ok(Self { prelude_reserved })
    }
    #[must_use]
    pub const fn prelude_reserved(self) -> usize {
        self.prelude_reserved
    }
    pub fn qualify_source(self, source_bytes: usize) -> Result<()> {
        if source_bytes > MAX_PROGRAM_BYTES - self.prelude_reserved {
            return Err(refused("program source leaves no room for prelude"));
        }
        Ok(())
    }
    pub fn assemble(self, source_bytes: usize, prelude_bytes: usize) -> Result<()> {
        self.qualify_source(source_bytes)?;
        if prelude_bytes > self.prelude_reserved
            || source_bytes
                .checked_add(prelude_bytes)
                .is_none_or(|n| n > MAX_PROGRAM_BYTES)
        {
            return Err(refused("assembled program exceeds guest budget"));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assembled_program_respects_reservation() {
        let budget = ProgramBudget::new(128 * 1024).unwrap();
        assert!(budget.qualify_source(MAX_PROGRAM_BYTES).is_err());
        budget
            .assemble(MAX_PROGRAM_BYTES - 128 * 1024, 128 * 1024)
            .unwrap();
        assert!(
            budget
                .assemble(MAX_PROGRAM_BYTES - 128 * 1024, 128 * 1024 + 1)
                .is_err()
        );
    }
}
