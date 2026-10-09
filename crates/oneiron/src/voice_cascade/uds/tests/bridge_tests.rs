use super::*;

#[test]
fn real_fired_skipped_promoted_preserves_order_and_private_projection() {
    let (_dir, vault) = vault();
    let a = put_text(&vault, 1, "Tokyo launch alpha");
    let b = put_text(&vault, 2, "Tokyo launch beta");
    let mut peer = Peer::new(
        Arc::clone(&vault),
        TestEnricher::stable(),
        BridgeLimits::default(),
    );
    let handle = peer.open();
    let fire = peer.observe("partial", &handle, 1, "Tokyo launch");
    assert_eq!(fire["decision"], "fired");
    let refs = fire["context"]["result_refs"].as_array().expect("refs");
    assert!(refs.contains(&json!(a)) && refs.contains(&json!(b)));
    let skip = peer.observe("partial", &handle, 2, "Tokyo launch plan");
    assert_eq!(skip["decision"], "skipped_unchanged");
    assert!(skip["context"].is_null());
    let runs = vault.retrieval_runs(200).expect("runs").len();
    let final_value = peer.observe("final", &handle, 3, "Tokyo launch plans");
    assert_eq!(final_value["context"]["promoted"], true);
    assert_eq!(
        final_value["context"]["result_refs"],
        fire["context"]["result_refs"]
    );
    assert_eq!(final_value["context"]["run_id"], fire["context"]["run_id"]);
    assert_eq!(vault.retrieval_runs(200).expect("runs").len(), runs);
    let context = final_value["context"].as_object().expect("context");
    assert_eq!(context.len(), 3);
    assert!(context.contains_key("result_refs"));
    assert!(context.contains_key("run_id"));
    assert!(context.contains_key("promoted"));
    for response in [&fire, &skip, &final_value] {
        let wire = response.to_string();
        assert!(!wire.contains("PRIVATE_BODY_SECRET"));
        assert!(!wire.contains("Tokyo"));
        assert!(!wire.contains("score"));
        assert!(!wire.contains("vector"));
    }
    assert_eq!(
        peer.finish(),
        ["Tokyo launch", "Tokyo launch plan", "Tokyo launch plans"]
    );
}

#[test]
fn provider_enrichment_is_rejected_and_host_failure_is_redacted_and_retryable() {
    let (_dir, vault) = vault();
    let enricher = TestEnricher {
        steps: VecDeque::from([]),
        texts: Vec::new(),
    };
    let mut peer = Peer::new(vault, enricher, BridgeLimits::default());
    let handle = peer.open();
    for op in ["partial", "final"] {
        for field in [
            "entity_labels",
            "salient_terms",
            "query_vector",
            "max_fires",
        ] {
            let mut request = json!({"op":op,"handle":handle,"revision":1,"text":"Tokyo"});
            request[field] = json!(["provider-controlled"]);
            let response = peer.send(request);
            assert_eq!(response["op"], "error");
            assert_eq!(response["code"], "invalid_request");
        }
    }
    // Eight malformed frames exhaust this connection without any enrichment.
    assert!(peer.finish().is_empty());
}

#[test]
fn host_errors_are_redacted_and_retryable_without_retrieval() {
    let (_dir, vault) = vault();
    let enricher = TestEnricher {
        steps: VecDeque::from([
            Err(Error::InvalidConfig(
                "HOST_SECRET /private/vault/provider-key".to_owned(),
            )),
            Ok(enrichment("host-result")),
        ]),
        texts: Vec::new(),
    };
    let mut peer = Peer::new(Arc::clone(&vault), enricher, BridgeLimits::default());
    let handle = peer.open();
    assert_eq!(
        peer.observe("final", &handle, 1, "Tokyo launch"),
        json!({"op":"error","code":"bridge_error"})
    );
    assert!(vault.retrieval_runs(200).expect("runs").is_empty());
    assert_eq!(
        peer.observe("final", &handle, 1, "Tokyo launch")["op"],
        "final"
    );
    assert_eq!(peer.finish(), ["Tokyo launch", "Tokyo launch"]);
}

#[test]
fn malformed_frames_are_isolated_and_revisions_do_not_advance_on_rejection() {
    let (_dir, vault) = vault();
    let mut peer = Peer::new(vault, TestEnricher::stable(), BridgeLimits::default());
    assert_eq!(peer.raw(b"{not-json")["code"], "invalid_request");
    assert_eq!(peer.raw(&[0xff])["code"], "invalid_request");
    let handle = peer.open();
    assert_eq!(
        peer.send(json!({"op":"open","utterance_id":"second"}))["code"],
        "already_open"
    );
    assert_eq!(
        peer.observe("partial", &handle, 1, "Tokyo")["decision"],
        "fired"
    );
    assert_eq!(
        peer.observe("partial", &handle, 1, "late")["code"],
        "bridge_error"
    );
    assert_eq!(peer.observe("final", &handle, 2, "Tokyo")["op"], "final");
    assert_eq!(peer.finish(), ["Tokyo", "Tokyo"]);
}

#[test]
fn foreign_stale_and_disconnected_handles_cannot_reach_enrichment() {
    let (_dir, vault) = vault();
    let mut first = Peer::new(
        Arc::clone(&vault),
        TestEnricher::stable(),
        BridgeLimits::default(),
    );
    let old = first.open();
    let mut second = Peer::new(
        Arc::clone(&vault),
        TestEnricher::stable(),
        BridgeLimits::default(),
    );
    let current = second.open();
    assert_ne!(old, current);
    assert_eq!(
        second.observe("partial", &old, 1, "foreign")["code"],
        "stale_handle"
    );
    assert_eq!(
        second.send(json!({"op":"close","handle":old}))["code"],
        "stale_handle"
    );
    assert_eq!(
        first.send(json!({"op":"close","handle":old}))["op"],
        "closed"
    );
    let reopened = first.open();
    assert_ne!(reopened, old);
    assert_eq!(
        first.observe("final", &old, 9, "stale")["code"],
        "stale_handle"
    );
    assert!(first.finish().is_empty());
    assert_eq!(
        second.observe("partial", &reopened, 1, "disconnected")["code"],
        "stale_handle"
    );
    assert_eq!(second.observe("final", &current, 1, "Tokyo")["op"], "final");
    assert_eq!(second.finish(), ["Tokyo"]);
    assert_eq!(
        Arc::strong_count(&vault),
        1,
        "all bridge and utterance vault refs dropped"
    );
}

#[test]
fn oversized_and_truncated_frames_close_without_enrichment() {
    let (_dir, vault) = vault();
    let mut peer = Peer::new(
        Arc::clone(&vault),
        TestEnricher::stable(),
        BridgeLimits::default(),
    );
    peer.writer
        .write_all(&vec![b'x'; MAX_FRAME_BYTES + 1])
        .expect("oversized frame");
    assert_eq!(peer.read()["code"], "frame_too_large");
    assert!(peer.finish().is_empty());
    let mut peer = Peer::new(vault, TestEnricher::stable(), BridgeLimits::default());
    peer.writer.write_all(b"{\"op\":").expect("fragment");
    peer.writer.shutdown(SocketShutdown::Write).expect("EOF");
    assert_eq!(peer.read()["code"], "truncated_frame");
    assert!(peer.finish().is_empty());
}

#[test]
fn exact_frame_bound_and_pipelined_frames_do_not_desynchronize() {
    let (_dir, vault) = vault();
    let mut peer = Peer::new(vault, TestEnricher::stable(), BridgeLimits::default());
    let mut frame = b"{\"op\":\"open\",\"utterance_id\":\"turn\"}".to_vec();
    frame.resize(MAX_FRAME_BYTES, b' ');
    let opened = peer.raw(&frame);
    let handle = opened["handle"].as_str().expect("opened");
    let final_request = json!({"op":"final","handle":handle,"revision":1,"text":"Tokyo"});
    peer.writer.write_all(b"{bad}\n").expect("malformed frame");
    let bytes = final_request.to_string();
    let split = bytes.len() / 2;
    peer.writer
        .write_all(&bytes.as_bytes()[..split])
        .expect("fragment one");
    peer.writer
        .write_all(&bytes.as_bytes()[split..])
        .expect("fragment two");
    peer.writer.write_all(b"\n").expect("newline");
    assert_eq!(peer.read()["code"], "invalid_request");
    assert_eq!(peer.read()["op"], "final");
    assert_eq!(peer.finish(), ["Tokyo"]);
}
