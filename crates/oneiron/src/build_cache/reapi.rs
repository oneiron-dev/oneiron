//! REAPI v2 protobuf digest encoding. The engine key is the SHA-256 Action digest.
use super::*;
use sha2::{Digest, Sha256};

/// REAPI Digest: hash of serialized bytes and their exact byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapiDigest {
    pub hash: [u8; 32],
    pub size_bytes: u64,
}
impl ReapiDigest {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            hash: Sha256::digest(bytes).into(),
            size_bytes: bytes.len() as u64,
        }
    }
    fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        field(&mut out, 1, bytes_to_hex_lower(&self.hash).as_bytes());
        if self.size_bytes != 0 {
            varint(&mut out, 16);
            varint(&mut out, self.size_bytes);
        }
        out
    }
    /// Standard Action with default timeout and do_not_cache=false.
    pub fn action(command: Self, input_root: Self) -> Self {
        Self::of(&action_bytes(command, input_root))
    }
}
impl BuildAction {
    /// Deterministic REAPI Command. Platform and environment properties are sorted.
    pub fn reapi_command_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for arg in self.command.argv() {
            field(&mut out, 1, arg.as_bytes());
        }
        for (name, value) in self.command.env_allowlist() {
            let mut env = Vec::new();
            field(&mut env, 1, name.as_bytes());
            field(&mut env, 2, value.as_bytes());
            field(&mut out, 2, &env);
        }
        let mut platform = Vec::new();
        for (name, value) in self.platform.properties() {
            let mut property = Vec::new();
            field(&mut property, 1, name.as_bytes());
            field(&mut property, 2, value.as_bytes());
            field(&mut platform, 1, &property);
        }
        if !platform.is_empty() {
            field(&mut out, 5, &platform);
        }
        for path in self.declared_outputs() {
            field(&mut out, 7, path.as_str().as_bytes());
        }
        out
    }
    /// Use an actual REAPI Directory digest when a host already has a CAS tree.
    pub fn with_reapi_input_root(mut self, root: ReapiDigest) -> Self {
        self.reapi_input_root = Some(root);
        self
    }
    pub fn reapi_digest(&self) -> BuildCacheResult<ReapiDigest> {
        validate_repo_ref(&self.input_root.repo_ref)?;
        let root = match self.reapi_input_root {
            Some(root) => root,
            None => self.descriptor_directory_digest(),
        };
        Ok(ReapiDigest::action(
            ReapiDigest::of(&self.reapi_command_bytes()),
            root,
        ))
    }
    // Legacy engine snapshots have a blake3 manifest rather than a REAPI CAS
    // tree. Map their exact identity to a valid Directory containing one
    // descriptor FileNode; never pretend a blake3 digest is a SHA-256 Digest.
    fn descriptor_directory_digest(&self) -> ReapiDigest {
        let mut descriptor = Vec::new();
        field(
            &mut descriptor,
            1,
            self.input_root.repo_ref.canonical().as_bytes(),
        );
        field(&mut descriptor, 2, &self.input_root.fork_hash);
        for extra in &self.input_root.extra_inputs {
            field(&mut descriptor, 3, extra.as_bytes());
        }
        let mut file = Vec::new();
        field(&mut file, 1, b".oneiron-input-root");
        field(&mut file, 2, &ReapiDigest::of(&descriptor).encode());
        let mut directory = Vec::new();
        field(&mut directory, 1, &file);
        ReapiDigest::of(&directory)
    }
}
fn action_bytes(command: ReapiDigest, root: ReapiDigest) -> Vec<u8> {
    let mut out = Vec::new();
    field(&mut out, 1, &command.encode());
    field(&mut out, 2, &root.encode());
    out
}
fn field(out: &mut Vec<u8>, number: u64, bytes: &[u8]) {
    varint(out, (number << 3) | 2);
    varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reapi_action_digest_vector() {
        // protoc-compatible: Command { arguments: ["true"] }, empty Directory.
        let command = ReapiDigest::of(b"\x0a\x04true");
        let root = ReapiDigest::of(b"");
        let digest = ReapiDigest::action(command, root);
        assert_eq!(
            bytes_to_hex_lower(&digest.hash),
            "054435d0a7573cc13cb737477406ab0e34801a7563531631746e21edead1a3e8"
        );
        assert_eq!(digest.size_bytes, 138);
    }
}
