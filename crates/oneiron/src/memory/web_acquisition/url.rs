use reqwest::Url;
use std::collections::BTreeSet;

/// What replaces the userinfo of any URL this module reports.
pub(crate) const REDACTED_USERINFO: &str = "REDACTED";

/// The single normalization step: drop the fragment and keep whatever the URL
/// parser already canonicalized (host lowercasing, default-port elision,
/// dot-segment resolution). No trailing-slash rewriting, query reordering, or
/// IDN transformation is added on top.
pub(crate) fn normalize_url(url: &Url) -> Url {
    let mut normalized = url.clone();
    normalized.set_fragment(None);
    normalized
}

/// Normalizes, filters to HTTP(S), sorts bytewise, and deduplicates one raw
/// link list.
///
/// Entries that do not join, or that are not credential-free absolute HTTP(S)
/// once normalized, are skipped. No count refuses a page: the response body
/// byte ceiling already bounds how many links one page can carry.
pub(crate) fn normalize_link_list<I, S>(links: I, base: &Url) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = BTreeSet::new();
    for raw in links {
        let Ok(joined) = base.join(raw.as_ref().trim()) else {
            continue;
        };
        let candidate = normalize_url(&joined);
        if !is_web_url(&candidate) {
            continue;
        }
        normalized.insert(candidate.to_string());
    }
    normalized.into_iter().collect()
}

/// Absolute HTTP(S), a non-empty host, and no embedded credentials: the only
/// transport this module speaks.
///
/// Userinfo is refused by the same predicate that decides "is this fetchable",
/// rather than stripped somewhere downstream. One predicate therefore keeps
/// `user:pass@host` out of every request this module sends, every provider
/// payload it builds, every URL it publishes, and every frontier it walks.
pub(crate) fn is_web_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|host| !host.is_empty())
        && !has_userinfo(url)
}

/// Whether a parsed URL carries a username or a password.
pub(crate) fn has_userinfo(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

/// Replaces the userinfo of a URL-shaped string with [`REDACTED_USERINFO`].
///
/// Every diagnostic this module emits is public: errors cross the crate
/// boundary, and a crawl failure reason is a stored string. Redaction is
/// therefore parse-first rather than textual, because a textual scan does not
/// recognize the spellings WHATWG parsing still accepts as credentialed:
/// `http:a:b@host` carries no `//` at all, `http:/a:b@host` carries one slash,
/// `http:\\a:b@host` carries backslashes, and ASCII tab or newline inside the
/// credential is stripped before the authority is read. Each of those parses to
/// an HTTP URL with a username and a password, so each is redacted on the
/// parsed [`Url`] and re-serialized in its canonical spelling — one sanitizer,
/// no spelling-dependent hole.
///
/// A credential-free URL is reported exactly as supplied. A string the parser
/// rejects has no [`Url`] to ask, so it falls back to a fail-closed textual
/// scan rather than being echoed raw.
pub(crate) fn redact_url_credentials(raw: &str) -> String {
    let Ok(parsed) = Url::parse(raw) else {
        return redact_userinfo_text(raw);
    };
    if !has_userinfo(&parsed) {
        return raw.to_string();
    }
    let mut sanitized = parsed;
    // Both setters refuse only a host-less URL, which cannot carry userinfo in
    // the first place; the textual scan stays the fail-closed answer anyway.
    if sanitized.set_password(None).is_err() || sanitized.set_username(REDACTED_USERINFO).is_err() {
        return redact_userinfo_text(raw);
    }
    sanitized.to_string()
}

/// The fail-closed textual half of [`redact_url_credentials`], reached only for
/// input the URL parser rejected outright.
///
/// It skips the same run of `/` and `\` between scheme and authority that the
/// parser skips, so an unparseable *and* credential-looking string — an empty
/// host behind a real credential, say — still loses its userinfo.
pub(crate) fn redact_userinfo_text(raw: &str) -> String {
    let Some(scheme_end) = raw.find(':') else {
        return raw.to_string();
    };
    let scheme = &raw[..scheme_end];
    let is_scheme_shaped = scheme.starts_with(|first: char| first.is_ascii_alphabetic())
        && scheme.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        });
    if !is_scheme_shaped {
        return raw.to_string();
    }
    let after_scheme = &raw[scheme_end + 1..];
    let authority_start = after_scheme
        .find(|character: char| character != '/' && character != '\\')
        .map_or(raw.len(), |offset| scheme_end + 1 + offset);
    let authority_end = raw[authority_start..]
        .find(['/', '\\', '?', '#'])
        .map_or(raw.len(), |offset| authority_start + offset);
    // The last `@` wins: a password may itself contain one.
    match raw[authority_start..authority_end].rfind('@') {
        Some(offset) => format!(
            "{}{REDACTED_USERINFO}{}",
            &raw[..authority_start],
            &raw[authority_start + offset..]
        ),
        None => raw.to_string(),
    }
}

/// The one parse-normalize-validate step behind every URL this module accepts,
/// whoever supplied it: a caller, a renderer, a provider envelope, or a link.
pub(crate) fn validated_web_url(raw: &str) -> Option<Url> {
    Url::parse(raw)
        .ok()
        .filter(is_web_url)
        .map(|url| normalize_url(&url))
}
