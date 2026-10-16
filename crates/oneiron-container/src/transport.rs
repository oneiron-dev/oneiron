//! A selected backend's private duplex transport and lifetime custody.
use crate::{GuestSession, SessionManifest};
use std::io::{Read, Write};

pub trait SessionLease: Send {
    fn is_running(&mut self) -> bool;
    fn abandoned(&self) -> bool { false }
}

pub struct SessionTransport {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    pub manifest: SessionManifest,
    pub lease: Box<dyn SessionLease>,
}
impl SessionLease for GuestSession {
    fn abandoned(&self) -> bool { self.abandoned() }
    fn is_running(&mut self) -> bool { self.is_running() }
}
impl GuestSession {
    pub fn into_transport(mut self) -> crate::Result<SessionTransport> {
        let (writer, reader) = self.take_stdio().ok_or_else(|| crate::Error::Fence(std::io::Error::other("guest stdio missing")))?;
        Ok(SessionTransport { reader: Box::new(reader), writer: Box::new(writer), manifest: self.manifest().clone(), lease: Box::new(self) })
    }
}
