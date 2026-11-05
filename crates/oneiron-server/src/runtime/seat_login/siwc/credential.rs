//! One selected local registration, reopened before each physical send.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::header::HeaderValue;
use zeroize::Zeroizing;

use super::record::CredentialRecord;

/// The identity saved by the local sign-in verifier, not authority supplied
/// by a provider label or file name. Tokens stay in a per-send value.
pub(crate) struct CredentialSource {
    path: PathBuf,
    issuer: String,
    subject: String,
    client_id: String,
    host_id: String,
}

pub(crate) struct ActiveCredential {
    record: CredentialRecord,
    authorization: HeaderValue,
}

impl CredentialSource {
    pub(crate) fn select(path: &Path) -> anyhow::Result<Self> {
        let path = std::path::absolute(path)?;
        let record = read(&path)?;
        Ok(Self {
            path,
            issuer: record.issuer.clone(),
            subject: record.subject.clone(),
            client_id: record.client_id.clone(),
            host_id: record.ext_agent_host_id.clone(),
        })
    }

    fn matches(&self, record: &CredentialRecord) -> bool {
        record.issuer == self.issuer
            && record.subject == self.subject
            && record.client_id == self.client_id
            && record.ext_agent_host_id == self.host_id
    }

    pub(crate) fn open(&self) -> anyhow::Result<ActiveCredential> {
        let record = read(&self.path)?;
        anyhow::ensure!(
            self.matches(&record),
            "SIWC registration changed; rebuild the model runtime"
        );
        usable(&record)?;
        let bearer = Zeroizing::new(format!("Bearer {}", record.access_token));
        let mut authorization = HeaderValue::from_str(&bearer)
            .map_err(|_| anyhow::anyhow!("invalid local SIWC access token"))?;
        authorization.set_sensitive(true);
        Ok(ActiveCredential {
            record,
            authorization,
        })
    }

    /// An atomic refresh may replace the record while a request waits. Never
    /// resend a stale credential after that replacement or a local sign-out.
    pub(crate) fn release(&self, active: &ActiveCredential) -> anyhow::Result<()> {
        usable(&active.record)?;
        let current = read(&self.path)?;
        anyhow::ensure!(
            self.matches(&current) && current.access_token == active.record.access_token,
            "SIWC credentials changed before the physical send"
        );
        usable(&current)
    }
}

impl ActiveCredential {
    pub(crate) fn authorization(&self) -> HeaderValue {
        self.authorization.clone()
    }
}

fn read(path: &Path) -> anyhow::Result<CredentialRecord> {
    CredentialRecord::read(path)?
        .ok_or_else(|| anyhow::anyhow!("local SIWC credentials are missing; sign in first"))
}

fn usable(record: &CredentialRecord) -> anyhow::Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    anyhow::ensure!(
        record.expires_at > now,
        "local SIWC access token expired; sign in again"
    );
    anyhow::ensure!(
        record.plan_usage_enabled(),
        "local SIWC credentials lack the returned direct-plan scope"
    );
    anyhow::ensure!(
        !record.access_token.is_empty(),
        "local SIWC access token is empty"
    );
    Ok(())
}
