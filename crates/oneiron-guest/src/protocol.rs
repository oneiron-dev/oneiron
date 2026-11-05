//! Strict, bounded host/guest JSON framing and admission state machine.

use crate::{Error, Result, filesystem::Workspace};
use oneiron_sandbox_contract::{GUEST_PROTOCOL_VERSION, WorkspacePath, WorkspaceShape};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
};

pub(crate) const MAX_FRAME: usize = oneiron_sandbox_contract::MAX_FRAME_BYTES;
pub(crate) const MAX_COMPONENT: usize = oneiron_sandbox_contract::MAX_COMPONENT_BYTES;
pub(crate) const MAX_FILE: usize = oneiron_sandbox_contract::MAX_FILE_BYTES;
pub(crate) const MAX_CHUNK: usize = oneiron_sandbox_contract::MAX_CHUNK_BYTES;
pub(crate) const MAX_REQUESTS: usize = oneiron_sandbox_contract::MAX_REQUESTS;
pub(crate) const MAX_SOURCE: usize = oneiron_sandbox_contract::MAX_PROGRAM_BYTES;

/// Source identities and exact lengths; seeded bytes stay in the workspace.
pub(crate) type Snapshot = BTreeMap<String, usize>;

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
    FileOpen {
        path: String,
        len: u64,
    },
    FileChunk {
        bytes: Vec<u8>,
    },
    FileClose,
    Ready,
    Receipt {
        accepted: bool,
    },
    Failure {
        code: String,
        detail: String,
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
    /// A proposed file streams out: its path, then its frames, then its end.
    WriteOpen {
        path: &'a str,
    },
    WriteChunk {
        bytes: &'a [u8],
    },
    WriteClose,
    Delete {
        path: &'a str,
    },
    Rename {
        from: &'a str,
        to: &'a str,
    },
    StepResult {
        result_json: &'a str,
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

struct SeedFile {
    path: WorkspacePath,
    file: File,
    len: usize,
    received: usize,
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

    pub(crate) fn receive(&mut self, workspace: &Workspace) -> Result<Input> {
        self.send(&GuestFrame::Hello {
            version: GUEST_PROTOCOL_VERSION,
        })?;
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
        if version != GUEST_PROTOCOL_VERSION
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
        let mut shape = WorkspaceShape::new();
        let mut open: Option<SeedFile> = None;
        let mut requests = 1;
        loop {
            let frame = self.read()?;
            // One logical file spends one request, regardless of byte length.
            if !matches!(frame, HostFrame::FileChunk { .. } | HostFrame::FileClose) {
                if requests == MAX_REQUESTS {
                    return Err(Error::Protocol("source request count exhausted"));
                }
                requests += 1;
            }
            if open.is_some()
                && !matches!(frame, HostFrame::FileChunk { .. } | HostFrame::FileClose)
            {
                return Err(Error::Protocol("host frame inside an open source file"));
            }
            match frame {
                HostFrame::Component { offset, bytes }
                    if files.is_empty()
                        && component.len() < component_bytes
                        && offset == component.len()
                        && !bytes.is_empty()
                        && bytes.len() <= component_bytes - component.len() =>
                {
                    component.extend(bytes);
                }
                HostFrame::FileOpen { path, len } if component.len() == component_bytes => {
                    let checked = WorkspacePath::parse(&path)
                        .map_err(|error| Error::Protocol(error.reason()))?;
                    let len = usize::try_from(len)
                        .map_err(|_| Error::Protocol("source file length overflow"))?;
                    shape
                        .add_file(&checked, len)
                        .map_err(|error| Error::Protocol(error.reason()))?;
                    open = Some(SeedFile {
                        file: workspace.create_seed(&path)?,
                        path: checked,
                        len,
                        received: 0,
                    });
                }
                HostFrame::FileChunk { bytes } => {
                    let Some(open) = open.as_mut() else {
                        return Err(Error::Protocol("source chunk outside a file"));
                    };
                    if bytes.is_empty()
                        || bytes.len() > MAX_CHUNK
                        || bytes.len() > open.len - open.received
                    {
                        return Err(Error::Protocol("source file chunk bounds"));
                    }
                    open.file.write_all(&bytes)?;
                    open.received += bytes.len();
                }
                HostFrame::FileClose => {
                    let Some(open) = open.take() else {
                        return Err(Error::Protocol("source end outside a file"));
                    };
                    if open.received != open.len {
                        return Err(Error::Protocol("incomplete source file"));
                    }
                    files.insert(open.path.as_str().to_owned(), open.len);
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

    /// Opens the one proposed file that the following chunks fill.
    pub(crate) fn open_write(&mut self, path: &str) -> Result<()> {
        if !self.request(&GuestFrame::WriteOpen { path })? {
            return Err(Error::Protocol("host refused proposal"));
        }
        Ok(())
    }

    /// One frame of the open file. Wait for its receipt without spending a
    /// logical request, so a file's size never spends the request budget.
    pub(crate) fn write_chunk(&mut self, bytes: &[u8]) -> Result<std::result::Result<(), String>> {
        if self.finished || bytes.len() > MAX_CHUNK {
            return Err(Error::Protocol("proposal frame bounds"));
        }
        self.send(&GuestFrame::WriteChunk { bytes })?;
        match self.read()? {
            HostFrame::Receipt { accepted: true } => Ok(Ok(())),
            HostFrame::Failure { code, detail } => Ok(Err(format!("{code}: {detail}"))),
            _ => Err(Error::Protocol("expected proposal chunk receipt")),
        }
    }

    pub(crate) fn close_write(&mut self) -> Result<()> {
        if !self.request(&GuestFrame::WriteClose)? {
            return Err(Error::Protocol("host refused proposal"));
        }
        Ok(())
    }

    pub(crate) fn delete(&mut self, path: &str) -> Result<()> {
        if !self.request(&GuestFrame::Delete { path })? {
            return Err(Error::Protocol("host refused deletion proposal"));
        }
        Ok(())
    }

    pub(crate) fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        if !self.request(&GuestFrame::Rename { from, to })? {
            return Err(Error::Protocol("host refused rename proposal"));
        }
        Ok(())
    }

    pub(crate) fn result(&mut self, result_json: &str) -> Result<()> {
        if self.finished || result_json.len() > MAX_FILE {
            return Err(Error::Protocol("step result bounds"));
        }
        self.send(&GuestFrame::StepResult { result_json })
    }

    pub(crate) fn finish(&mut self, status: i32) -> Result<()> {
        if self.finished {
            return Err(Error::Protocol("finish is consume-once"));
        }
        self.finished = true;
        self.send(&GuestFrame::Finish { status })
    }

    fn request(&mut self, frame: &GuestFrame<'_>) -> Result<bool> {
        // Reserve the terminal step-result and finish frames.
        if self.finished || self.requests >= MAX_REQUESTS - 2 {
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
