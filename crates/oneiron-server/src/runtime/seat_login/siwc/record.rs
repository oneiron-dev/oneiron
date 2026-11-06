//! Protected, runtime-local credentials for one issued registration.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::commands::credential_file;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct CredentialRecord {
    pub version: u8,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub client_id: String,
    pub ext_agent_host_id: String,
    /// The registered scheme, host and path; only its port may change.
    pub redirect_uri: String,
    pub nonce: String,
    pub session_active: bool,
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub scopes: Vec<String>,
    pub saved_at: u64,
    pub expires_at: u64,
    pub earliest_refresh_at: Option<serde_json::Value>,
}

impl Drop for CredentialRecord {
    fn drop(&mut self) {
        self.id_token.zeroize();
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

impl CredentialRecord {
    pub(super) fn read(path: &Path) -> anyhow::Result<Option<Self>> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => anyhow::bail!("cannot open the local SIWC credential record"),
        };
        credential_file::admit(path, &file)?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("cannot read the local SIWC credential record"))?;
        let record: Self = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid local SIWC credential record"))?;
        anyhow::ensure!(
            record.version == 1
                && record.issuer == super::ISSUER
                && !record.subject.is_empty()
                && !record.client_id.is_empty()
                && record.client_id != oneiron::dispatch_byoa::SIWC_DYNAMIC_AGENT_CLIENT,
            "invalid local SIWC registration identity"
        );
        Ok(Some(record))
    }

    pub(super) fn write(&self, path: &Path) -> anyhow::Result<()> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(self)
                .map_err(|_| anyhow::anyhow!("cannot encode the local SIWC credential record"))?,
        );
        credential_file::replace(path, &bytes)
    }

    pub(super) fn clear_tokens(&mut self) {
        self.session_active = false;
        self.id_token.zeroize();
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.refresh_token = None;
        self.scopes.clear();
        self.expires_at = 0;
        self.earliest_refresh_at = None;
    }

    pub(super) fn plan_usage_enabled(&self) -> bool {
        self.scopes.iter().any(|scope| scope == super::DIRECT_SCOPE)
    }
}

/// A per-record lock lives beside the atomic replacement, not on the inode
/// the replacement retires. It spans account selection through publication.
pub(super) fn lock(path: &Path) -> anyhow::Result<File> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("credential file needs a name"))?;
    let mut name = name.to_os_string();
    name.push(".lock");
    let path: PathBuf = path.with_file_name(name);
    let file = match credential_file::create(&path) {
        Ok(file) => file,
        Err(_) => File::options()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| anyhow::anyhow!("cannot open the SIWC credential lock"))?,
    };
    credential_file::admit(&path, &file)?;
    file.try_lock()
        .map_err(|_| anyhow::anyhow!("another SIWC operation is using this record"))?;
    Ok(file)
}

pub(super) fn random() -> String {
    let mut bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    bytes.zeroize();
    value
}

pub(super) fn host_id(path: &Path) -> anyhow::Result<String> {
    let _lock = lock(path)?;
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let host = random();
            credential_file::replace(path, serde_json::to_string(&host)?.as_bytes())?;
            return Ok(host);
        }
        Err(_) => anyhow::bail!("cannot open the SIWC host identity file"),
    };
    credential_file::admit(path, &file)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let host: String = serde_json::from_str(&text)
        .map_err(|_| anyhow::anyhow!("invalid SIWC host identity file"))?;
    anyhow::ensure!(
        !host.is_empty() && host.chars().all(|c| !c.is_control()),
        "invalid SIWC host identity file"
    );
    Ok(host)
}
