//! Strict, bounded host/guest JSON framing and admission state machine.

use crate::{Error, Result, filesystem::virtual_relative};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

pub(crate) const MAX_FRAME: usize = 8 * 1024 * 1024;
pub(crate) const MAX_COMPONENT: usize = 64 * 1024 * 1024;
pub(crate) const MAX_FILE: usize = 1024 * 1024;
pub(crate) const MAX_TOTAL: usize = 16 * 1024 * 1024;
pub(crate) const MAX_FILES: usize = 8192;
pub(crate) const MAX_REQUESTS: usize = 16_384;
pub(crate) const MAX_SOURCE: usize = 1024 * 1024;

pub(crate) type Snapshot = BTreeMap<String, Vec<u8>>;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum HostFrame {
    Start {
        version: u32,
        vm_id: String,
        tier: String,
        pids: u32,
        component_bytes: usize,
        source: String,
    },
    Component {
        offset: usize,
        bytes: Vec<u8>,
    },
    File {
        path: String,
        bytes: Vec<u8>,
    },
    Ready,
    Receipt {
        accepted: bool,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GuestFrame<'a> {
    Hello {
        version: u32,
    },
    CredentialRead {
        handle: &'a str,
        operation: &'a str,
        scheme: &'a str,
        host: &'a str,
    },
    Write {
        path: &'a str,
        bytes: &'a [u8],
    },
    Finish {
        status: i32,
    },
}

pub(crate) struct Input {
    pub(crate) pids: u32,
    pub(crate) source: String,
    pub(crate) component: Vec<u8>,
    pub(crate) files: Snapshot,
}

pub(crate) struct Session<T> {
    channel: T,
    requests: usize,
    finished: bool,
}

impl<T: Read + Write> Session<T> {
    pub(crate) fn new(channel: T) -> Self {
        Self {
            channel,
            requests: 0,
            finished: false,
        }
    }

    pub(crate) fn receive(&mut self) -> Result<Input> {
        self.send(&GuestFrame::Hello { version: 1 })?;
        let HostFrame::Start {
            version,
            vm_id,
            tier,
            pids,
            component_bytes,
            source,
        } = self.read()?
        else {
            return Err(Error::Protocol("expected start"));
        };
        if version != 1
            || !matches!(tier.as_str(), "foreign" | "untrusted")
            || !(1..=4096).contains(&pids)
            || component_bytes == 0
            || component_bytes > MAX_COMPONENT
            || source.len() > MAX_SOURCE
            || vm_id.is_empty()
            || vm_id.len() > 128
            || !vm_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Protocol("invalid start bounds or authority"));
        }
        let mut component = Vec::new();
        let mut files = BTreeMap::new();
        let mut total = 0;
        for _ in 1..MAX_REQUESTS {
            match self.read()? {
                HostFrame::Component { offset, bytes }
                    if files.is_empty()
                        && component.len() < component_bytes
                        && offset == component.len()
                        && !bytes.is_empty()
                        && bytes.len() <= component_bytes - component.len() =>
                {
                    component.extend(bytes);
                }
                HostFrame::File { path, bytes } if component.len() == component_bytes => {
                    virtual_relative(&path)?;
                    if files.len() >= MAX_FILES
                        || bytes.len() > MAX_FILE
                        || files.contains_key(&path)
                    {
                        return Err(Error::Protocol("source file bounds or duplicate"));
                    }
                    total += bytes.len();
                    if total > MAX_TOTAL {
                        return Err(Error::Protocol("source aggregate bytes"));
                    }
                    files.insert(path, bytes);
                }
                HostFrame::Ready if component.len() == component_bytes => {
                    return Ok(Input {
                        pids,
                        source,
                        component,
                        files,
                    });
                }
                _ => return Err(Error::Protocol("unexpected or out-of-order host frame")),
            }
        }
        Err(Error::Protocol("source request count exhausted"))
    }

    pub(crate) fn credential(
        &mut self,
        handle: &str,
        operation: &str,
        scheme: &str,
        host: &str,
    ) -> Result<bool> {
        self.request(&GuestFrame::CredentialRead {
            handle,
            operation,
            scheme,
            host,
        })
    }

    pub(crate) fn write(&mut self, path: &str, bytes: &[u8]) -> Result<()> {
        if !self.request(&GuestFrame::Write { path, bytes })? {
            return Err(Error::Protocol("host refused proposal"));
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self, status: i32) -> Result<()> {
        if self.finished {
            return Err(Error::Protocol("finish is consume-once"));
        }
        self.finished = true;
        self.send(&GuestFrame::Finish { status })
    }

    fn request(&mut self, frame: &GuestFrame<'_>) -> Result<bool> {
        // Reserve one of the host's request slots for finish.
        if self.finished || self.requests >= MAX_REQUESTS - 1 {
            return Err(Error::Protocol("outbound request count exhausted"));
        }
        self.requests += 1;
        self.send(frame)?;
        match self.read()? {
            HostFrame::Receipt { accepted } => Ok(accepted),
            _ => Err(Error::Protocol("expected secret-free receipt")),
        }
    }

    fn read(&mut self) -> Result<HostFrame> {
        let mut header = [0; 4];
        self.channel.read_exact(&mut header)?;
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > MAX_FRAME {
            return Err(Error::Protocol("frame size"));
        }
        let mut bytes = vec![0; len];
        self.channel.read_exact(&mut bytes)?;
        serde_json::from_slice(&bytes).map_err(|_| Error::Protocol("invalid host frame"))
    }

    fn send(&mut self, frame: &GuestFrame<'_>) -> Result<()> {
        let bytes = serde_json::to_vec(frame).map_err(|_| Error::Protocol("encoding"))?;
        if bytes.len() > MAX_FRAME {
            return Err(Error::Protocol("outbound frame size"));
        }
        self.channel
            .write_all(&(bytes.len() as u32).to_be_bytes())?;
        self.channel.write_all(&bytes)?;
        self.channel.flush()?;
        Ok(())
    }
}
