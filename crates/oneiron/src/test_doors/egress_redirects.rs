//! Door for the egress redirect test (FIX 7945): a code sandbox's HTTP fetch
//! with every hop's host looked up as one address the test serves, because the
//! egress resolves only public addresses. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use std::io;
use std::net::SocketAddr;

use oneiron_container::{HttpRequest, HttpResponse};

use crate::code_sandbox::egress::OpenEgressProxy;

/// `proxy`'s HTTP fetch of `request`, as a guest's fetch takes it (policy,
/// receipts, redirects, the request deadline, the body floor), with each
/// hop's host resolved to `address` in place of the public-address lookup.
///
/// # Errors
///
/// What the fetch refuses or fails with.
pub fn fetch_resolved_to(
    proxy: &OpenEgressProxy,
    request: HttpRequest,
    address: SocketAddr,
) -> io::Result<HttpResponse> {
    crate::code_sandbox::egress::fetch_resolved(proxy, request, &|_, _| Ok(vec![address]))
}
