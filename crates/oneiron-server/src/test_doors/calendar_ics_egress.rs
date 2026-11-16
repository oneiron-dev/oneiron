//! Door to the ICS feed's network boundary (CAL-02): the feed URL's admission
//! and one GET on the feed client, with or without a managed node's hosted
//! egress guard. The installed-feed recheck `HttpIcsFeed` runs between the two
//! is left out: it needs an owner and an installed feed, and it decides
//! nothing about where the request may go.

use std::sync::Arc;

use oneiron::web_fetch::HostedEgressGuard;

/// Admits `url` and, when it passes, sends one GET to it on the feed client
/// `egress` builds: `Ok` with the provider's status, or the refusal or
/// transport error string the feed transport returns.
///
/// # Errors
///
/// The feed transport's error string.
pub fn get_ics_feed(egress: Option<Arc<HostedEgressGuard>>, url: &str) -> Result<u16, String> {
    let admitted = crate::calendar_host::admit_feed_url(url, egress.as_deref())?;
    let client = crate::calendar_host::feed_client(egress)
        .map_err(|_| "ICS HTTP client unavailable".to_owned())?;
    crate::calendar_host::get_admitted(&client, admitted, None).map(|response| response.status)
}
