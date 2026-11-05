//! One selected local registration, reopened before each physical send.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    timeout: Duration,
    refresh: tokio::sync::Mutex<()>,
}

pub(crate) struct ActiveCredential {
    record: CredentialRecord,
    authorization: HeaderValue,
}

impl CredentialSource {
    pub(crate) fn select(path: &Path, timeout_secs: u64) -> anyhow::Result<Self> {
        let path = std::path::absolute(path)?;
        let record = read(&path)?;
        Ok(Self {
            path,
            issuer: record.issuer.clone(),
            subject: record.subject.clone(),
            client_id: record.client_id.clone(),
            host_id: record.ext_agent_host_id.clone(),
            timeout: Duration::from_secs(timeout_secs),
            refresh: tokio::sync::Mutex::new(()),
        })
    }

    fn matches(&self, record: &CredentialRecord) -> bool {
        record.issuer == self.issuer
            && record.subject == self.subject
            && record.client_id == self.client_id
            && record.ext_agent_host_id == self.host_id
    }

    async fn current(&self) -> anyhow::Result<CredentialRecord> {
        let path = self.path.clone();
        let record = tokio::task::spawn_blocking(move || read(&path))
            .await
            .map_err(|_| anyhow::anyhow!("SIWC credential read stopped"))??;
        self.check_registration(&record)?;
        Ok(record)
    }

    fn check_registration(&self, record: &CredentialRecord) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.matches(record),
            "SIWC registration changed; rebuild the model runtime"
        );
        active(record)
    }

    pub(crate) async fn open(&self) -> anyhow::Result<ActiveCredential> {
        let mut record = self.current().await?;
        if expired(&record)? {
            let _refresh = self.refresh.lock().await;
            record = self.current().await?;
            if expired(&record)? {
                // Lock the stable sibling, then reread: another process may
                // have refreshed or signed out since the first read.
                let path = self.path.clone();
                let (_record_lock, current) = tokio::task::spawn_blocking(move || {
                    let lock = super::record::lock(&path)?;
                    Ok::<_, anyhow::Error>((lock, read(&path)?))
                })
                .await
                .map_err(|_| anyhow::anyhow!("SIWC credential lock stopped"))??;
                self.check_registration(&current)?;
                record = current;
                if expired(&record)? {
                    let refreshed = super::refresh::rotate(record.clone(), self.timeout).await?;
                    // A removed or replaced record must not be resurrected
                    // after the network or verification await.
                    anyhow::ensure!(
                        self.current().await? == record,
                        "SIWC credentials changed during refresh"
                    );
                    // No detached task publishes. Dropping this opening
                    // future drops the exchange and the held record lock.
                    refreshed.write(&self.path)?;
                    record = refreshed;
                }
            }
        }
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

fn expired(record: &CredentialRecord) -> anyhow::Result<bool> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(record.expires_at <= now)
}

fn active(record: &CredentialRecord) -> anyhow::Result<()> {
    anyhow::ensure!(record.session_active, "local SIWC session is signed out");
    Ok(())
}

fn usable(record: &CredentialRecord) -> anyhow::Result<()> {
    active(record)?;
    anyhow::ensure!(
        !expired(record)?,
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
