//! The byte layout of TPM 2.0 commands and responses: big-endian fields and
//! sized buffers (`TPM2B`), written and read front to back.

use zeroize::Zeroizing;

/// The password authorization session.
const TPM_RS_PW: u32 = 0x4000_0009;
/// `TPMA_SESSION.continueSession`.
const SESSION_CONTINUE: u8 = 0x01;

/// Appends `value` with its 16-bit size before it (a `TPM2B`).
pub(super) fn push_sized(bytes: &mut Vec<u8>, value: &[u8]) {
    let size = u16::try_from(value.len()).unwrap_or(u16::MAX);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(value);
}

/// A TPM command's bytes: its header, then its fields in order. The header's
/// size is filled when it is sent. Held zeroized: a create carries the
/// secret, and a create or an unseal may carry an auth value.
pub(super) struct Command {
    bytes: Zeroizing<Vec<u8>>,
}

impl Command {
    pub(super) fn new(tag: u16, code: u32) -> Self {
        let mut bytes = Zeroizing::new(Vec::with_capacity(128));
        bytes.extend_from_slice(&tag.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        Self { bytes }
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// `value` with its 16-bit size before it (a `TPM2B`).
    pub(super) fn sized(&mut self, value: &[u8]) {
        push_sized(&mut self.bytes, value);
    }

    /// The authorization area of one password session whose password is
    /// `auth`: the handle's authorization for a command with one. Empty for
    /// the owner hierarchy, the storage key and a slot.
    pub(super) fn password_session(&mut self, auth: &[u8]) {
        // authorizationSize, then TPMS_AUTH_COMMAND: the session handle, an
        // empty nonce, its attributes and the password.
        self.u32(9u32.saturating_add(u32::try_from(auth.len()).unwrap_or(u32::MAX)));
        self.u32(TPM_RS_PW);
        self.u16(0);
        self.bytes.push(SESSION_CONTINUE);
        self.sized(auth);
    }

    /// The command's bytes with its size in the header.
    pub(super) fn finish(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = self.bytes.clone();
        let size = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        bytes[2..6].copy_from_slice(&size.to_be_bytes());
        bytes
    }
}

/// Reads big-endian fields from a response or a slot file, front to back.
pub(super) struct Reader<'b> {
    bytes: &'b [u8],
}

impl<'b> Reader<'b> {
    pub(super) fn new(bytes: &'b [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, len: usize) -> Option<&'b [u8]> {
        if self.bytes.len() < len {
            return None;
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Some(head)
    }

    pub(super) fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(drop)
    }

    pub(super) fn u16(&mut self) -> Option<u16> {
        self.take(2)?.try_into().ok().map(u16::from_be_bytes)
    }

    pub(super) fn u32(&mut self) -> Option<u32> {
        self.take(4)?.try_into().ok().map(u32::from_be_bytes)
    }

    /// A `TPM2B`'s body, its size read first.
    pub(super) fn sized(&mut self) -> Option<&'b [u8]> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    /// A `TPM2B` whole: its size and its body.
    pub(super) fn sized_raw(&mut self) -> Option<&'b [u8]> {
        let whole = self.bytes;
        let len = usize::from(self.u16()?);
        self.take(len)?;
        whole.get(..2 + len)
    }

    pub(super) fn rest(&self) -> &'b [u8] {
        self.bytes
    }
}
