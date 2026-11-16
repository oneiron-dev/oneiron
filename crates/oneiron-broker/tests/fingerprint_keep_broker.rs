//! K-proof (oracle) for PLAN-UC-04 stage 4.2: the credential broker's request digests
//! keep their bytes.
//!
//! A model call's request digest (`purposes::broker::REQUEST`), a git exchange's
//! (`purposes::broker::GIT_REQUEST`) and an LFS exchange's (`purposes::broker::LFS_REQUEST`)
//! now start their BLAKE3 through the fingerprint crate's K door. None is stored, but each
//! crosses a process boundary: the daemon takes it and sends it in the call's header, and the
//! broker takes it again over the bytes it received and sends nothing whose digest differs.
//! A daemon and a broker on two builds must agree, so each must give main's bytes for every
//! request. The `base_*` modules hold main's lines at 65fca8fefceb, copied by range (each range is
//! named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only
//! in indentation. The few lines around the copies give them main's names: the imports, and
//! a trait that carries main's private `LfsTarget::kind` body (a trait fn cannot be `const`).
//!
//! Fleet: `cargo test --locked -p oneiron-broker --test fingerprint_keep_broker`

use oneiron_broker::{
    GitExchange, GitRepository, GitRequestDigest, GitService, GitTarget, LfsActionTarget,
    LfsBatchTarget, LfsOperation, LfsRequestDigest, LfsTarget, Refusal, git_request_digest,
    lfs_request_digest, request_digest,
};
use oneiron_fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_request {
    use oneiron_broker::{Refusal, is_auth_header};

    // main 65fca8fefceb: crates/oneiron-broker/src/digest.rs:8-10
    /// The blake3 key-derivation context: a digest of this form never equals a
    /// digest of another one.
    const CONTEXT: &str = "oneiron-broker 2026-10-11 request digest v1";

    // main 65fca8fefceb: crates/oneiron-broker/src/digest.rs:31-52
    /// The digest of one request, as lowercase hex. Each field is length-prefixed,
    /// so no two requests share an input. Header names are compared lowercase and
    /// the headers sorted, so their order on the wire does not change the digest.
    #[must_use]
    pub fn request_digest(
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> String {
        let sorted = sorted_headers(headers);
        let mut hasher = blake3::Hasher::new_derive_key(CONTEXT);
        field(&mut hasher, method.as_bytes());
        field(&mut hasher, path.as_bytes());
        hasher.update(&(sorted.len() as u64).to_le_bytes());
        for (name, value) in &sorted {
            field(&mut hasher, name.as_bytes());
            field(&mut hasher, value.as_bytes());
        }
        field(&mut hasher, body);
        hasher.finalize().to_hex().to_string()
    }

    // main 65fca8fefceb: crates/oneiron-broker/src/digest.rs:54-64
    /// `headers` as a digest takes them: auth headers left out, names
    /// lowercase, sorted.
    pub(crate) fn sorted_headers(headers: &[(String, String)]) -> Vec<(String, &str)> {
        let mut sorted: Vec<(String, &str)> = headers
            .iter()
            .filter(|(name, _)| !is_auth_header(name))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.as_str()))
            .collect();
        sorted.sort_unstable();
        sorted
    }

    // main 65fca8fefceb: crates/oneiron-broker/src/digest.rs:66-70
    /// One length-prefixed field of a digest.
    pub(crate) fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }

    // main 65fca8fefceb: crates/oneiron-broker/src/digest.rs:78-116
    /// The body half of a digest taken as its body passes (a git or an LFS
    /// exchange): the hasher its target and headers began, then the body's
    /// length and its bytes, checked against that length once the body ended.
    pub(crate) struct BodyDigest {
        hasher: blake3::Hasher,
        expected: u64,
        seen: u64,
    }

    impl BodyDigest {
        /// Begins a body of `body_len` bytes after what `hasher` holds.
        pub(crate) fn new(mut hasher: blake3::Hasher, body_len: u64) -> Self {
            hasher.update(&body_len.to_le_bytes());
            Self {
                hasher,
                expected: body_len,
                seen: 0,
            }
        }

        /// Takes the next `bytes` of the body.
        pub(crate) fn update(&mut self, bytes: &[u8]) {
            self.seen = self.seen.saturating_add(bytes.len() as u64);
            self.hasher.update(bytes);
        }

        /// The digest, as lowercase hex, once the whole body passed.
        ///
        /// # Errors
        ///
        /// [`Refusal::Body`] when the body's bytes are not the length the
        /// digest began with.
        pub(crate) fn finish(self) -> Result<String, Refusal> {
            if self.seen != self.expected {
                return Err(Refusal::Body);
            }
            Ok(self.hasher.finalize().to_hex().to_string())
        }
    }

    /// Main's context, for the tag test outside this module.
    pub(crate) const MAIN_CONTEXT: &str = CONTEXT;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
// `into_body`, the broker spool's door, is copied with its impl and has no caller here.
#[allow(dead_code)]
mod base_git {
    use oneiron_broker::{GitExchange, GitTarget, Refusal};

    use super::base_request::{BodyDigest, field, sorted_headers};

    // main 65fca8fefceb: crates/oneiron-broker/src/git_http.rs:61-62
    /// The blake3 key-derivation context of a git request digest.
    const DIGEST_CONTEXT: &str = "oneiron-broker 2026-11-06 git request digest v1";

    // main 65fca8fefceb: crates/oneiron-broker/src/git_http.rs:277-336
    /// The digest of one git request, taken as its body passes, in its own
    /// digest domain: the target (origin, repository, service, exchange), the
    /// method and path it derives, the sorted non-auth headers, the body's
    /// length and its bytes. Each field is length-prefixed. The daemon takes it
    /// as it spools the body; the broker takes it again as it receives the body
    /// and sends nothing whose digest differs.
    pub struct GitRequestDigest {
        body: BodyDigest,
    }

    impl GitRequestDigest {
        /// The digest of a request to `target` with `headers` and a body of
        /// `body_len` bytes, before its body.
        #[must_use]
        pub fn new(target: &GitTarget, headers: &[(String, String)], body_len: u64) -> Self {
            let mut hasher = blake3::Hasher::new_derive_key(DIGEST_CONTEXT);
            field(&mut hasher, target.repository.origin().as_bytes());
            field(&mut hasher, target.repository.path().as_bytes());
            field(&mut hasher, target.service.as_str().as_bytes());
            field(
                &mut hasher,
                match target.exchange {
                    GitExchange::Advertisement => b"advertisement",
                    GitExchange::Rpc => b"rpc",
                },
            );
            field(&mut hasher, target.method().as_bytes());
            field(&mut hasher, target.path().as_bytes());
            let sorted = sorted_headers(headers);
            hasher.update(&(sorted.len() as u64).to_le_bytes());
            for (name, value) in &sorted {
                field(&mut hasher, name.as_bytes());
                field(&mut hasher, value.as_bytes());
            }
            Self {
                body: BodyDigest::new(hasher, body_len),
            }
        }

        /// Takes the next `bytes` of the body.
        pub fn update(&mut self, bytes: &[u8]) {
            self.body.update(bytes);
        }

        /// The digest, as lowercase hex, once the whole body passed.
        ///
        /// # Errors
        ///
        /// [`Refusal::Body`] when the body's bytes are not the length the
        /// digest began with.
        pub fn finish(self) -> Result<String, Refusal> {
            self.body.finish()
        }

        /// Its body half, for the broker's spool to take the body into.
        #[cfg(unix)]
        pub(crate) fn into_body(self) -> BodyDigest {
            self.body
        }
    }

    // main 65fca8fefceb: crates/oneiron-broker/src/git_http.rs:420-433
    /// The digest of one whole git request.
    ///
    /// # Errors
    ///
    /// None in practice: the body's length is its own.
    pub fn git_request_digest(
        target: &GitTarget,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<String, Refusal> {
        let mut digest = GitRequestDigest::new(target, headers, body.len() as u64);
        digest.update(body);
        digest.finish()
    }

    /// Main's context, for the tag test outside this module.
    pub(crate) const MAIN_DIGEST_CONTEXT: &str = DIGEST_CONTEXT;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
// `into_body`, the broker spool's door, is copied with its impl and has no caller here.
#[allow(dead_code)]
mod base_lfs {
    use oneiron_broker::{LfsTarget, Refusal};

    use super::base_request::{BodyDigest, field};

    // main 65fca8fefceb: crates/oneiron-broker/src/lfs_http.rs:86-87
    /// The blake3 key-derivation context of an LFS request digest.
    const DIGEST_CONTEXT: &str = "oneiron-broker 2026-11-06 lfs request digest v1";

    /// Main's private `LfsTarget::kind`: its body is main's, and its signature drops the
    /// `const`, which a trait fn cannot carry. The copied digest's `target.kind()` reaches
    /// it, since the private inherent fn is not visible here.
    pub(crate) trait MainLfsKind {
        fn kind(&self) -> &'static str;
    }

    impl MainLfsKind for LfsTarget {
        fn kind(&self) -> &'static str {
            // main 65fca8fefceb: crates/oneiron-broker/src/lfs_http.rs:336-341
                    match self {
                        Self::Batch(_) => "batch",
                        Self::ObjectDownload(_) => "object_download",
                        Self::ObjectUpload(_) => "object_upload",
                        Self::Verify(_) => "verify",
                    }
        }
    }

    // main 65fca8fefceb: crates/oneiron-broker/src/lfs_http.rs:394-457
    /// The digest of one LFS request, taken as its body passes, in its own
    /// digest domain: the target's kind and repository; a batch's operation, or
    /// an action's batch digest, object id and size; the method and URL it
    /// derives; every header, in its order, as given; the body's length and
    /// its bytes. Each field is length-prefixed. The daemon takes it as it
    /// spools the body; the broker takes it again as it receives the body and
    /// sends nothing whose digest differs.
    pub struct LfsRequestDigest {
        body: BodyDigest,
    }

    impl LfsRequestDigest {
        /// The digest of a request to `target` with `headers` and a body of
        /// `body_len` bytes, before its body.
        #[must_use]
        pub fn new(target: &LfsTarget, headers: &[(String, String)], body_len: u64) -> Self {
            let mut hasher = blake3::Hasher::new_derive_key(DIGEST_CONTEXT);
            field(&mut hasher, target.kind().as_bytes());
            let repository = target.repository();
            field(&mut hasher, repository.origin().as_bytes());
            field(&mut hasher, repository.path().as_bytes());
            match target {
                LfsTarget::Batch(batch) => field(&mut hasher, batch.operation.as_str().as_bytes()),
                LfsTarget::ObjectDownload(action)
                | LfsTarget::ObjectUpload(action)
                | LfsTarget::Verify(action) => {
                    field(&mut hasher, action.batch.as_bytes());
                    field(&mut hasher, action.oid.as_bytes());
                    hasher.update(&action.size.to_le_bytes());
                }
            }
            field(&mut hasher, target.method().as_bytes());
            field(&mut hasher, target.endpoint().as_bytes());
            hasher.update(&(headers.len() as u64).to_le_bytes());
            for (name, value) in headers {
                field(&mut hasher, name.as_bytes());
                field(&mut hasher, value.as_bytes());
            }
            Self {
                body: BodyDigest::new(hasher, body_len),
            }
        }

        /// Takes the next `bytes` of the body.
        pub fn update(&mut self, bytes: &[u8]) {
            self.body.update(bytes);
        }

        /// The digest, as lowercase hex, once the whole body passed.
        ///
        /// # Errors
        ///
        /// [`Refusal::Body`] when the body's bytes are not the length the
        /// digest began with.
        pub fn finish(self) -> Result<String, Refusal> {
            self.body.finish()
        }

        /// Its body half, for the broker's spool to take the body into.
        #[cfg(unix)]
        pub(crate) fn into_body(self) -> BodyDigest {
            self.body
        }
    }

    // main 65fca8fefceb: crates/oneiron-broker/src/lfs_http.rs:459-472
    /// The digest of one whole LFS request.
    ///
    /// # Errors
    ///
    /// None in practice: the body's length is its own.
    pub fn lfs_request_digest(
        target: &LfsTarget,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<String, Refusal> {
        let mut digest = LfsRequestDigest::new(target, headers, body.len() as u64);
        digest.update(body);
        digest.finish()
    }

    /// Main's context, for the tag test outside this module.
    pub(crate) const MAIN_DIGEST_CONTEXT: &str = DIGEST_CONTEXT;
}

/// The bodies every table runs: empty, one byte, every byte value, and two that cross
/// BLAKE3's 1024-byte chunk and its 64-byte block bounds.
fn bodies() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"x".to_vec(),
        (0..=255_u8).collect(),
        (0..1025_u32).map(|n| (n % 251) as u8).collect(),
        (0..70_000_u32)
            .map(|n| (n.wrapping_mul(31) % 256) as u8)
            .collect(),
    ]
}

fn header(name: &str, value: &str) -> (String, String) {
    (name.to_owned(), value.to_owned())
}

/// The header lists every table runs: none; auth headers only, in mixed case (left out by
/// the model and git digests, kept by the LFS one); names that sort apart once lowercase;
/// one name twice; an empty name and value; non-ASCII and NUL bytes; one list in two orders.
fn header_sets() -> Vec<Vec<(String, String)>> {
    vec![
        Vec::new(),
        vec![
            header("Authorization", "Bearer sk-test"),
            header("X-API-KEY", "k"),
            header("xi-api-key", "v"),
        ],
        vec![
            header("Content-Type", "application/json"),
            header("accept", "*/*"),
            header("B-Header", "2"),
            header("a-header", "1"),
        ],
        vec![
            header("a-header", "1"),
            header("B-Header", "2"),
            header("accept", "*/*"),
            header("Content-Type", "application/json"),
        ],
        vec![
            header("x-dup", "second"),
            header("X-Dup", "first"),
            header("authorization", "Basic abc"),
            header("Proxy-Authorization", "p"),
        ],
        vec![header("", ""), header("x-empty", "")],
        vec![
            header("x-unicode", "h\u{e9}llo \u{2603}"),
            header("x-nul", "a\0b"),
            header("api-key", "q"),
            header("x-goog-api-key", "g"),
        ],
        vec![header("git-protocol", "version=2")],
    ]
}

fn assert_legacy(purpose: LegacyPurpose) {
    assert_eq!(purpose.hash(), LegacyHash::Blake3, "{}", purpose.tag());
    assert_eq!(
        purpose.tag_mode(),
        TagMode::DeriveKeyContext,
        "{}",
        purpose.tag()
    );
}

#[test]
fn the_broker_purposes_keep_main_s_contexts() {
    for (purpose, main) in [
        (purposes::broker::REQUEST, base_request::MAIN_CONTEXT),
        (purposes::broker::GIT_REQUEST, base_git::MAIN_DIGEST_CONTEXT),
        (purposes::broker::LFS_REQUEST, base_lfs::MAIN_DIGEST_CONTEXT),
    ] {
        assert_legacy(purpose);
        assert_eq!(purpose.tag(), main);
    }
}

#[test]
fn the_request_digest_keeps_its_bytes() {
    let methods = ["POST", "GET", "post", ""];
    let paths = [
        "/v1/chat/completions",
        "/",
        "",
        "/v1/models/gemini:generateContent?alt=sse&key=\u{e9}",
    ];
    let mut rows = 0;
    for method in methods {
        for path in paths {
            for headers in header_sets() {
                for body in bodies() {
                    assert_eq!(
                        request_digest(method, path, &headers, &body),
                        base_request::request_digest(method, path, &headers, &body),
                        "{method} {path} {headers:?} {} bytes",
                        body.len()
                    );
                    rows += 1;
                }
            }
        }
    }
    assert_eq!(rows, 640);
}

fn git_targets() -> Vec<GitTarget> {
    let repositories = [
        "https://github.com/oneiron-dev/oneiron.git",
        "https://git.example.com:8443/team/project",
        "https://example.org/a/b/c/",
    ];
    let mut targets = Vec::new();
    for url in repositories {
        let repository = GitRepository::parse(url).expect("a plain https repository");
        for service in [GitService::UploadPack, GitService::ReceivePack] {
            for exchange in [GitExchange::Advertisement, GitExchange::Rpc] {
                targets.push(GitTarget {
                    repository: repository.clone(),
                    service,
                    exchange,
                });
            }
        }
    }
    targets
}

#[test]
fn the_git_request_digest_keeps_its_bytes() {
    let mut rows = 0;
    for target in git_targets() {
        for headers in header_sets() {
            for body in bodies() {
                let main = base_git::git_request_digest(&target, &headers, &body);
                assert!(main.is_ok());
                assert_eq!(
                    git_request_digest(&target, &headers, &body),
                    main,
                    "{target:?} {headers:?} {} bytes",
                    body.len()
                );
                for chunk in [7, 64, 1024, 4096] {
                    let mut streamed = GitRequestDigest::new(&target, &headers, body.len() as u64);
                    for piece in body.chunks(chunk) {
                        streamed.update(piece);
                    }
                    assert_eq!(streamed.finish(), main, "{target:?} in {chunk}-byte pieces");
                }
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 480);
}

#[test]
fn the_git_request_digest_still_refuses_a_body_of_another_length() {
    let target = git_targets().remove(3);
    for (declared, body) in [
        (5_u64, &b"four"[..]),
        (3, &b"four"[..]),
        (0, &b"x"[..]),
        (1, &b""[..]),
    ] {
        let mut head = GitRequestDigest::new(&target, &[], declared);
        head.update(body);
        let mut main = base_git::GitRequestDigest::new(&target, &[], declared);
        main.update(body);
        assert_eq!(head.finish(), Err(Refusal::Body));
        assert_eq!(main.finish(), Err(Refusal::Body));
    }
}

fn lfs_targets() -> Vec<LfsTarget> {
    let repositories = [
        "https://github.com/oneiron-dev/oneiron.git",
        "https://git.example.com:8443/team/project",
    ];
    let request_digest_hex = "ab".repeat(32);
    let oid = "0123456789abcdef".repeat(4);
    let mut targets = Vec::new();
    for url in repositories {
        let repository = GitRepository::parse(url).expect("a plain https repository");
        for operation in [LfsOperation::Upload, LfsOperation::Download] {
            targets.push(LfsTarget::Batch(LfsBatchTarget {
                repository: repository.clone(),
                operation,
            }));
        }
        for (batch, oid, size, href) in [
            (
                request_digest_hex.as_str(),
                oid.as_str(),
                0_u64,
                "https://lfs.example.com/objects/1",
            ),
            (
                request_digest_hex.as_str(),
                oid.as_str(),
                1,
                "https://lfs.example.com/objects/1?sig=a%2Fb&exp=9",
            ),
            ("", "", 1_u64 << 32, "https://lfs.example.com/"),
            (
                request_digest_hex.as_str(),
                oid.as_str(),
                u64::MAX,
                "https://s3.example.com/bucket/\u{e9}",
            ),
        ] {
            let action = LfsActionTarget {
                repository: repository.clone(),
                batch: batch.to_owned(),
                oid: oid.to_owned(),
                size,
                href: href.to_owned(),
            };
            targets.push(LfsTarget::ObjectDownload(action.clone()));
            targets.push(LfsTarget::ObjectUpload(action.clone()));
            targets.push(LfsTarget::Verify(action));
        }
    }
    targets
}

#[test]
fn the_lfs_request_digest_keeps_its_bytes() {
    let mut rows = 0;
    for target in lfs_targets() {
        for headers in header_sets() {
            for body in bodies() {
                let main = base_lfs::lfs_request_digest(&target, &headers, &body);
                assert!(main.is_ok());
                assert_eq!(
                    lfs_request_digest(&target, &headers, &body),
                    main,
                    "{target:?} {headers:?} {} bytes",
                    body.len()
                );
                for chunk in [7, 1024] {
                    let mut streamed = LfsRequestDigest::new(&target, &headers, body.len() as u64);
                    for piece in body.chunks(chunk) {
                        streamed.update(piece);
                    }
                    assert_eq!(streamed.finish(), main, "{target:?} in {chunk}-byte pieces");
                }
                rows += 1;
            }
        }
    }
    // 2 repositories x (2 batches + 4 actions x 3 kinds) x 8 header lists x 5 bodies.
    assert_eq!(rows, 1120);
}

#[test]
fn the_lfs_request_digest_still_refuses_a_body_of_another_length() {
    let target = lfs_targets().remove(4);
    for (declared, body) in [
        (5_u64, &b"four"[..]),
        (3, &b"four"[..]),
        (0, &b"x"[..]),
        (1, &b""[..]),
    ] {
        let mut head = LfsRequestDigest::new(&target, &[], declared);
        head.update(body);
        let mut main = base_lfs::LfsRequestDigest::new(&target, &[], declared);
        main.update(body);
        assert_eq!(head.finish(), Err(Refusal::Body));
        assert_eq!(main.finish(), Err(Refusal::Body));
    }
}
