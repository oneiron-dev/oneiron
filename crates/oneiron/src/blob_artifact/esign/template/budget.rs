//! Traversal backing on the caller's memory, with a separate work deadline.
use super::{ContentTemplateError, Result, render};
use std::io::{self, Write};
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub(super) struct Budget {
    memory: Option<Arc<dyn render::InspectionMemory>>,
    deadline: Option<Instant>,
}
impl Budget {
    pub(super) const UNADMITTED: Self = Self {
        memory: None,
        deadline: None,
    };

    pub(super) fn new(memory: Arc<dyn render::InspectionMemory>, deadline: Instant) -> Self {
        Self {
            memory: Some(memory),
            deadline: Some(deadline),
        }
    }

    pub(super) fn checkpoint(&self) -> Result<()> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(ContentTemplateError::WorkDeadline);
        }
        Ok(())
    }
}

pub(super) struct Backing {
    budget: Budget,
    bytes: u64,
}
impl Backing {
    pub(super) fn new(budget: Budget) -> Self {
        Self { budget, bytes: 0 }
    }

    fn resize(&mut self, bytes: usize) -> Result<()> {
        let bytes = u64::try_from(bytes).map_err(|_| ContentTemplateError::Overflow)?;
        if let Some(memory) = &self.budget.memory {
            if bytes > self.bytes {
                self.budget.checkpoint()?;
                memory.admit(bytes - self.bytes).map_err(|refusal| {
                    render::PdfPreparationError::from(lopdf::Error::DecodeAdmission(refusal))
                })?;
            } else if bytes < self.bytes {
                memory.release(self.bytes - bytes);
            }
        }
        self.bytes = bytes;
        Ok(())
    }

    // Both guards belong to flows created with the same caller budget.
    pub(super) fn absorb(&mut self, source: &mut Self) -> Result<()> {
        let bytes = self
            .bytes
            .checked_add(source.bytes)
            .ok_or(ContentTemplateError::Overflow)?;
        self.bytes = bytes;
        source.bytes = 0;
        Ok(())
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        if let Some(memory) = &self.budget.memory {
            if self.bytes != 0 {
                memory.release(self.bytes);
            }
        }
    }
}

/// Field order frees the container before returning its backing admission.
pub(super) struct ScratchVec<T> {
    values: Vec<T>,
    backing: Backing,
}
impl<T> ScratchVec<T> {
    pub(super) fn new(budget: &Budget) -> Self {
        Self {
            values: Vec::new(),
            backing: Backing::new(budget.clone()),
        }
    }

    pub(super) fn push(&mut self, value: T) -> Result<()> {
        self.backing.budget.checkpoint()?;
        if self.backing.budget.memory.is_some() && self.values.len() == self.values.capacity() {
            self.grow()?;
        }
        self.values.push(value);
        Ok(())
    }

    fn grow(&mut self) -> Result<()> {
        let required = self
            .values
            .len()
            .checked_add(1)
            .ok_or(ContentTemplateError::Overflow)?;
        let capacity = required.max(self.values.capacity().saturating_mul(2));
        let bytes = capacity
            .checked_mul(size_of::<T>())
            .ok_or(ContentTemplateError::Overflow)?;
        // A realloc may keep the whole old block live until the new one exists.
        // Keep both guards and free the old block before its guard drops.
        let mut replacement = Self::new(&self.backing.budget);
        replacement.backing.resize(bytes)?;
        replacement
            .values
            .try_reserve_exact(capacity)
            .map_err(|_| ContentTemplateError::Overflow)?;
        let actual = replacement
            .values
            .capacity()
            .checked_mul(size_of::<T>())
            .ok_or(ContentTemplateError::Overflow)?;
        // std permits allocator surplus; settle reported capacity, not a guessed size.
        replacement.backing.resize(actual)?;
        replacement.values.append(&mut self.values);
        std::mem::swap(self, &mut replacement);
        Ok(())
    }

    pub(super) fn extend(&mut self, values: impl IntoIterator<Item = T>) -> Result<()> {
        for value in values {
            self.push(value)?;
        }
        Ok(())
    }

    pub(super) fn pop(&mut self) -> Option<T> {
        self.values.pop()
    }

    pub(super) fn drain(&mut self, range: std::ops::RangeFull) -> std::vec::Drain<'_, T> {
        self.values.drain(range)
    }
}
impl ScratchVec<u8> {
    pub(super) fn into_bytes_charged_to(mut self, destination: &mut Backing) -> Result<Vec<u8>> {
        destination.absorb(&mut self.backing)?;
        Ok(self.values)
    }
}
impl<T> AsRef<[T]> for ScratchVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.values
    }
}
impl<T> Deref for ScratchVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.values
    }
}
impl<T> DerefMut for ScratchVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}

pub(super) struct ScratchIter<T> {
    values: std::vec::IntoIter<T>,
    _backing: Backing,
}
impl<T> IntoIterator for ScratchVec<T> {
    type Item = T;
    type IntoIter = ScratchIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        ScratchIter {
            values: self.values.into_iter(),
            _backing: self.backing,
        }
    }
}
impl<T> Iterator for ScratchIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.values.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}

/// The PDF writer uses the caller's work deadline, not a memory-wait deadline.
pub(super) struct WorkDeadlineWriter<'a> {
    output: &'a mut Vec<u8>,
    budget: &'a Budget,
    refused: Option<ContentTemplateError>,
}
impl<'a> WorkDeadlineWriter<'a> {
    pub(super) fn new(output: &'a mut Vec<u8>, budget: &'a Budget) -> Self {
        Self {
            output,
            budget,
            refused: None,
        }
    }

    fn checkpoint(&mut self) -> io::Result<()> {
        self.budget.checkpoint().map_err(|error| {
            self.refused.get_or_insert(error.clone());
            io::Error::new(io::ErrorKind::TimedOut, error)
        })
    }

    pub(super) fn into_refusal(self) -> Option<ContentTemplateError> {
        self.refused
    }
}
impl Write for WorkDeadlineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.checkpoint()?;
        self.output.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.checkpoint()?;
        self.output.flush()
    }
}
