//! Normalized event data, owned in memory or in one anonymous spool.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use oneiron::Vault;
use oneiron::outbound_consent::RawOutboundBody;
use serde_json::Value;
use zeroize::Zeroizing;

mod event_value;

pub(super) enum Data {
    Memory(Zeroizing<String>),
    Spooled { file: File, len: u64 },
}

impl Default for Data {
    fn default() -> Self {
        Self::Memory(Zeroizing::default())
    }
}

impl Data {
    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Memory(data) => data.is_empty(),
            Self::Spooled { len, .. } => *len == 0,
        }
    }

    pub(super) fn append(&mut self, field: &str, vault: Option<&Vault>) -> Result<(), ()> {
        self.append_fragment(field, true, vault)
    }

    pub(super) fn append_fragment(
        &mut self,
        field: &str,
        join: bool,
        vault: Option<&Vault>,
    ) -> Result<(), ()> {
        if let Self::Memory(data) = self
            && data.is_empty()
            && !field.is_empty()
            && let Some(vault) = vault
            && let Ok(file) = vault.archive_spool_file()
        {
            *self = Self::Spooled { file, len: 0 };
        }
        match self {
            Self::Memory(data) => {
                if join {
                    append_text(data, field);
                } else {
                    data.push_str(field);
                }
                Ok(())
            }
            Self::Spooled { file, len } => {
                let before = *len;
                let separator = join && before != 0;
                let next = before
                    .checked_add(u64::from(separator))
                    .and_then(|len| len.checked_add(field.len() as u64))
                    .ok_or(())?;
                let written = (|| -> std::io::Result<()> {
                    if separator {
                        file.write_all(b"\n")?;
                    }
                    file.write_all(field.as_bytes())
                })();
                if written.is_ok() {
                    *len = next;
                    return Ok(());
                }
                // Recover only the last complete prefix: a failed write may
                // have already written part of this field or its separator.
                let mut data = recover_prefix(file, before)?;
                if join {
                    append_text(&mut data, field);
                } else {
                    data.push_str(field);
                }
                *self = Self::Memory(data);
                Ok(())
            }
        }
    }

    pub(super) fn append_crs(&mut self, count: usize, vault: &Vault) -> Result<(), ()> {
        if count == 0 {
            return Ok(());
        }
        self.append_fragment("\r", false, Some(vault))?;
        let count = count - 1;
        match self {
            Self::Memory(data) => data.extend(std::iter::repeat_n('\r', count)),
            Self::Spooled { file, len } => {
                let before = *len;
                let next = before.checked_add(count as u64).ok_or(())?;
                if std::io::copy(&mut std::io::repeat(b'\r').take(count as u64), file).is_ok() {
                    *len = next;
                } else {
                    let mut data = recover_prefix(file, before)?;
                    data.extend(std::iter::repeat_n('\r', count));
                    *self = Self::Memory(data);
                }
            }
        }
        Ok(())
    }

    pub(super) fn read(self) -> Result<Option<(Value, RawOutboundBody)>, ()> {
        match self {
            Self::Memory(mut event) => Ok(serde_json::from_str(&event).ok().map(|message| {
                let body = RawOutboundBody::from_bytes(std::mem::take(&mut *event).into_bytes());
                (message, body)
            })),
            Self::Spooled { file, .. } => {
                let body = RawOutboundBody::from_spooled_file(file).map_err(|_| ())?;
                match event_value::read(body.reader()) {
                    Ok(message) => Ok(message.map(|message| (message, body))),
                    Err(error) if error.is_io() => Err(()),
                    Err(_) => Ok(None),
                }
            }
        }
    }
}

fn recover_prefix(file: &mut File, before: u64) -> Result<Zeroizing<String>, ()> {
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let mut data = Zeroizing::new(String::new());
    file.take(before)
        .read_to_string(&mut data)
        .map_err(|_| ())?;
    if data.len() as u64 != before {
        return Err(());
    }
    Ok(data)
}

fn append_text(data: &mut String, field: &str) {
    if !data.is_empty() {
        data.push('\n');
    }
    data.push_str(field);
}
