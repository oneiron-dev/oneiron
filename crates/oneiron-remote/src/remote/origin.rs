use super::*;

/// Normalizes the caller's origin exactly once (I13).
///
/// Everything a caller might append to an origin is refused rather than
/// silently dropped. A query string or fragment on a base URL means the caller
/// believes it carries meaning, and it does not: the facade path would replace
/// it. Userinfo is refused because a credential in a URL is a credential in
/// logs, shell history and error messages, and this SDK already has exactly
/// one place to put one.
pub(super) fn normalize_origin(url: &str) -> Result<Url, MemoryError> {
    let mut parsed = Url::parse(url).map_err(|error| {
        // The raw origin is NEVER echoed here. A malformed URL can still carry
        // `user:password@`, and a syntax failure such as a bad port fires
        // before the userinfo arm below could refuse it, so repeating the input
        // would put the credential in exactly the logs this function exists to
        // keep it out of. The parse error names the syntax fault, not the
        // credential.
        bad_request(
            format!("the Oneiron URL is not a valid URL: {error}"),
            &["Pass an absolute origin such as http://127.0.0.1:8080."],
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(bad_request(
            "the Oneiron URL has an unsupported scheme",
            &["Use HTTPS, or HTTP only for loopback development."],
        ));
    }
    if !parsed.has_host() {
        return Err(bad_request(
            "the Oneiron URL names no host",
            &["Pass an absolute origin such as http://127.0.0.1:8080."],
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(bad_request(
            "the Oneiron URL must not carry userinfo",
            &["Remove user:password@ from the URL; pass the credential as the key argument."],
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(bad_request(
            "the Oneiron URL must not carry a query string or fragment",
            &["Pass only the origin; the SDK appends the facade path itself."],
        ));
    }
    if parsed.scheme() == "http" && !is_loopback_origin(&parsed) {
        return Err(bad_request(
            "the Oneiron URL requires HTTPS outside loopback development",
            &["Use an https:// origin; cleartext HTTP is allowed only on loopback."],
        ));
    }
    // A trailing slash is what makes `Url::join` treat the path as a directory
    // to append to rather than a file to replace.
    if !parsed.path().ends_with('/') {
        let path = format!("{}/", parsed.path());
        parsed.set_path(&path);
    }
    Ok(parsed)
}

/// Allows only literal loopback addresses and the exact localhost name.
/// No DNS lookup can turn a caller-chosen remote hostname into an exemption.
fn is_loopback_origin(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

/// Builds the `Authorization` header and marks it sensitive (D3).
///
/// The slip crosses VERBATIM. This function measures it and refuses an empty
/// or non-ASCII value — both of which cannot be a minted `v2` token — and does
/// not otherwise look at it. In particular it does not check for the `v2.`
/// prefix: the wire form is the server's contract to enforce, and a client
/// that validated it would have to be re-released to accept the next one.
pub(super) fn bearer_header(key: &str) -> Result<HeaderValue, MemoryError> {
    if key.trim().is_empty() {
        return Err(forbidden(
            "connect() requires a paired credential",
            &[
                "Pair once with Oneiron.pair(link); the owner creates the link with: \
               oneiron-server token pair --scope core:read,core:write \
               --principal-ref <32hex> --actor-class human",
            ],
        ));
    }
    let mut header = HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| {
        forbidden(
            "the supplied key is not a valid HTTP header value",
            &["Pass the credential exactly as pair returned it."],
        )
    })?;
    // Marks the value redacted in this header map's own Debug output, so a
    // transport-level dump cannot print the credential.
    header.set_sensitive(true);
    Ok(header)
}
