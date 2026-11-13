//! Owner-selected ClawHub bytes. Provider descriptors are locators, not trust.
use super::{HttpEndpointSkillHubAdapter, MAX_HUB_PACKAGE_TOTAL_BYTES};
use crate::error::Result;
use crate::skill_hub::package_codec::invalid;
use crate::skill_hub::{GitEndpointSkillHubAdapter, HubPackage, HubPin, HubRef, SkillHubAdapter};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::{Duration, Instant};

// The existing HTTP archive fetch's parse deadline.
const CLAWHUB_ARCHIVE_TIMEOUT: Duration = Duration::from_secs(60);

#[doc(hidden)]
pub use oneiron_verb_wire::skill_hub::http_fetch::clawhub_download::ClawHubGitHubHandoff;

pub(crate) enum ClawHubDownload {
    Package {
        package: HubPackage,
        github_handoff: Option<ClawHubGitHubHandoff>,
    },
    ProviderError {
        status: u16,
        retry_after: Option<String>,
        body: String,
    },
}

impl HttpEndpointSkillHubAdapter {
    pub(crate) fn download_clawhub(
        &self,
        slug: &str,
        version: Option<&str>,
        tag: Option<&str>,
        response_limit_bytes: Option<usize>,
    ) -> Result<ClawHubDownload> {
        let deadline = Instant::now() + CLAWHUB_ARCHIVE_TIMEOUT;
        let mut url = self
            .endpoint
            .join("/api/v1/download")
            .map_err(|_| invalid("invalid ClawHub download URL"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("slug", slug);
            if let Some(version) = version {
                query.append_pair("version", version);
            }
            if let Some(tag) = tag {
                query.append_pair("tag", tag);
            }
        }
        let mut response = self
            .client
            .get(url)
            .send()
            .map_err(|_| invalid("ClawHub download transport failed"))?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        let json = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
            });
        let budget = response_limit_bytes.unwrap_or(MAX_HUB_PACKAGE_TOTAL_BYTES);
        if response.content_length().is_some_and(|n| n > budget as u64) {
            return Err(invalid("ClawHub download exceeds requested byte budget"));
        }
        let mut body = Vec::new();
        response
            .by_ref()
            .take((budget as u64).saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|_| invalid("ClawHub download response read failed"))?;
        if body.len() > budget {
            return Err(invalid("ClawHub download exceeds requested byte budget"));
        }
        if !status.is_success() {
            return Ok(ClawHubDownload::ProviderError {
                status: status.as_u16(),
                retry_after,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        if json {
            let handoff: ClawHubGitHubHandoff = serde_json::from_slice(&body)
                .map_err(|_| invalid("invalid ClawHub GitHub handoff"))?;
            if handoff.source_ref != "public-github" {
                return Err(invalid("unsupported ClawHub handoff source"));
            }
            // Local paths are host configuration, never provider input.
            if std::path::Path::new(&handoff.repo).is_absolute() {
                return Err(invalid("ClawHub handoff is not a public GitHub repository"));
            }
            let git = GitEndpointSkillHubAdapter::new(self.hub_id, &handoff.repo, &handoff.commit)?;
            let endpoint = reqwest::Url::parse(git.endpoint().unwrap_or_default())
                .map_err(|_| invalid("invalid ClawHub GitHub repository"))?;
            if endpoint.scheme() != "https"
                || endpoint.host_str() != Some("github.com")
                || endpoint.port_or_known_default() != Some(443)
            {
                return Err(invalid("ClawHub handoff is not a public GitHub repository"));
            }
            let source = HubRef::new(
                self.hub_id,
                &handoff.path,
                HubPin::Commit(git.resolved_commit().to_owned()),
            )?;
            let package = git.fetch_package(&source)?;
            return Ok(ClawHubDownload::Package {
                package,
                github_handoff: Some(handoff),
            });
        }
        let files = super::super::skill_archive::skill_archive(&body, deadline)?;
        let package = super::super::package_from_files(files)?;
        Ok(ClawHubDownload::Package {
            package,
            github_handoff: None,
        })
    }
}
