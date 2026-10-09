use super::*;

#[test]
fn endpoint_policy_refuses_remote_cleartext_and_local_dns() {
    assert!(CrossEncoder::local("http://localhost/rerank", "m", Duration::from_secs(1)).is_err());
    assert!(CrossEncoder::local("http://192.0.2.1/rerank", "m", Duration::from_secs(1)).is_err());
    assert!(
        CrossEncoder::remote(
            "http://example.invalid/rerank",
            "m",
            "t".into(),
            Duration::from_secs(1)
        )
        .is_err()
    );
}
