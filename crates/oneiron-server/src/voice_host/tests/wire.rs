use super::*;
use oneiron::voice_cascade::{
    Brain, BrainRequest, CascadeControl, ControlEvent, GenerationEpoch, TtsCommand, TtsSeamClient,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Default)]
struct TestBrain {
    starts: Vec<BrainRequest>,
    cancelled: Vec<GenerationEpoch>,
}

impl Brain for TestBrain {
    fn start(&mut self, request: &BrainRequest) -> oneiron::Result<()> {
        self.starts.push(request.clone());
        Ok(())
    }
    fn update_context(&mut self, _request: &BrainRequest) -> oneiron::Result<()> { Ok(()) }
    fn cancel(&mut self, generation: GenerationEpoch) -> oneiron::Result<()> {
        self.cancelled.push(generation);
        Ok(())
    }
}

#[derive(Default)]
struct TestTts(Vec<TtsCommand>);
impl TtsSeamClient for TestTts {
    fn submit(&mut self, command: TtsCommand) -> oneiron::Result<()> {
        self.0.push(command);
        Ok(())
    }
}

#[derive(Default)]
struct TestControl(Vec<ControlEvent>);
impl CascadeControl for TestControl {
    fn flush_queued_pcm(&mut self, _generation: GenerationEpoch) -> oneiron::Result<()> { Ok(()) }
    fn submit(&mut self, event: ControlEvent) -> oneiron::Result<()> {
        self.0.push(event);
        Ok(())
    }
}

async fn read_json(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> serde_json::Value {
    let mut line = String::new();
    assert!(reader.read_line(&mut line).await.unwrap() > 0);
    serde_json::from_str(&line).unwrap()
}

async fn send_json(writer: &mut tokio::net::unix::OwnedWriteHalf, value: serde_json::Value) {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    writer.write_all(&bytes).await.unwrap();
}

#[tokio::test]
async fn private_wire_validates_input_submits_existing_brain_and_dispatches_disconnect_stop() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let (client, server) = UnixStream::pair().unwrap();
    let (read, mut write) = client.into_split();
    let mut read = BufReader::new(read);
    let mut outputs = VoiceOutputs {
        brain: TestBrain::default(), tts: TestTts::default(), control: TestControl::default(),
    };
    let (served, ()) = tokio::join!(host.serve(server, &mut outputs), async {
        send_json(&mut write, json!({"op": "open", "utterance_id": "u"})).await;
        let opened = read_json(&mut read).await;
        let token = opened["handle"].as_str().unwrap();
        send_json(&mut write, json!({"op": "final", "handle": token, "revision": 1, "text": "text", "salient_terms": ["injected"]})).await;
        assert_eq!(read_json(&mut read).await["code"], json!("invalid_request"));
        assert!(calls.try_recv().is_err());
        send_json(&mut write, json!({"op": "final", "handle": token, "revision": 1, "text": "text"})).await;
        calls.recv().await.unwrap().reply.send(Ok(empty())).unwrap();
        let final_response = read_json(&mut read).await;
        assert_eq!(final_response["op"], json!("final"));
        assert_eq!(final_response["handle"], json!(token));
        assert_eq!(final_response["revision"], json!(1));
        write.shutdown().await.unwrap();
    });
    served.unwrap();
    assert_eq!(outputs.brain.starts.len(), 1);
    assert_eq!(outputs.brain.starts[0].transcript, "text");
    assert!(outputs.brain.starts[0].externally_tainted);
    assert!(!outputs.brain.starts[0].interlocutors.supervised());
    assert_eq!(outputs.brain.cancelled, [outputs.brain.starts[0].generation]);
    assert!(outputs.control.0.contains(&ControlEvent::SessionEnded));
    assert_eq!(vault.retrieval_runs(200).unwrap().len(), 1);
    assert_eq!(budget.read().reserved_units, 0);
    assert!(host.lock().unwrap().core.is_ended());
}

#[tokio::test]
async fn wire_close_interrupts_provider_wait_and_releases_budget() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let (client, server) = UnixStream::pair().unwrap();
    let (read, mut write) = client.into_split();
    let mut read = BufReader::new(read);
    let mut outputs = VoiceOutputs {
        brain: TestBrain::default(), tts: TestTts::default(), control: TestControl::default(),
    };
    let (served, ()) = tokio::join!(host.serve(server, &mut outputs), async {
        send_json(&mut write, json!({"op": "open", "utterance_id": "u"})).await;
        let opened = read_json(&mut read).await;
        let token = opened["handle"].as_str().unwrap();
        send_json(&mut write, json!({"op": "final", "handle": token, "revision": 1, "text": "pending"})).await;
        let call = calls.recv().await.unwrap();
        assert_eq!(budget.read().reserved_units, 8_000);
        send_json(&mut write, json!({"op": "close", "handle": token})).await;
        assert_eq!(read_json(&mut read).await["op"], json!("closed"));
        assert!(call.reply.send(Ok(empty())).is_err());
        assert_eq!(budget.read().reserved_units, 0);
        write.shutdown().await.unwrap();
    });
    served.unwrap();
    assert!(outputs.brain.starts.is_empty());
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn provider_timeout_preserves_revision_and_releases_lease() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let token = host.open("u".to_owned()).unwrap();
    let work = host.prepare(&token, 1, "pending".to_owned(), true).unwrap();
    let (result, call) = tokio::join!(work.run(), async {
        let call = calls.recv().await.unwrap();
        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        call
    });
    assert!(matches!(result, Err(HostError::Llm(LlmError::Retryable(RetryableLlmError::Timeout)))));
    assert!(call.reply.send(Ok(empty())).is_err());
    assert_eq!(budget.read().reserved_units, 0);
    assert!(host.prepare(&token, 1, "pending".to_owned(), true).is_ok());
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
}

#[tokio::test]
async fn wire_revision_replacement_cancels_old_work_and_correlates_partial_result() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let (client, server) = UnixStream::pair().unwrap();
    let (read, mut write) = client.into_split();
    let mut read = BufReader::new(read);
    let mut outputs = VoiceOutputs {
        brain: TestBrain::default(), tts: TestTts::default(), control: TestControl::default(),
    };
    let (served, ()) = tokio::join!(host.serve(server, &mut outputs), async {
        send_json(&mut write, json!({"op": "open", "utterance_id": "u"})).await;
        let opened = read_json(&mut read).await;
        let token = opened["handle"].as_str().unwrap();
        send_json(&mut write, json!({"op": "partial", "handle": token, "revision": 1, "text": "old"})).await;
        let old = calls.recv().await.unwrap();
        send_json(&mut write, json!({"op": "partial", "handle": token, "revision": 2, "text": "new"})).await;
        let current = calls.recv().await.unwrap();
        assert_ne!(old.lease_id, current.lease_id);
        assert_eq!(budget.read().reserved_units, 8_000, "only the replacement owns a lease");
        assert!(old.reply.send(Ok(empty())).is_err());
        let ContentPart::Text { text } = &current.request.messages[1].content[0] else {
            panic!("text input");
        };
        assert_eq!(serde_json::from_str::<serde_json::Value>(text).unwrap(), json!({"text": "new"}));
        // A stale close must not drop the replacement future or its reservation.
        send_json(&mut write, json!({"op": "close", "handle": "unknown"})).await;
        assert_eq!(read_json(&mut read).await["code"], json!("stale_request"));
        assert_eq!(budget.read().reserved_units, 8_000);
        current.reply.send(Ok(empty())).unwrap();
        let response = read_json(&mut read).await;
        assert_eq!(response["op"], json!("partial"));
        assert_eq!(response["handle"], json!(token));
        assert_eq!(response["revision"], json!(2));
        assert_eq!(response["decision"], json!("skipped_empty_signature"));
        assert_eq!(budget.read().reserved_units, 0);
        write.shutdown().await.unwrap();
    });
    served.unwrap();
    assert!(outputs.brain.starts.is_empty());
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
}

#[tokio::test]
async fn wire_eof_during_provider_wait_cancels_lease_and_ends_session() {
    let (_dir, vault, host, budget, mut calls) = fixture();
    let (client, server) = UnixStream::pair().unwrap();
    let (read, mut write) = client.into_split();
    let mut read = BufReader::new(read);
    let mut outputs = VoiceOutputs {
        brain: TestBrain::default(), tts: TestTts::default(), control: TestControl::default(),
    };
    let (served, call) = tokio::join!(host.serve(server, &mut outputs), async {
        send_json(&mut write, json!({"op": "open", "utterance_id": "u"})).await;
        let opened = read_json(&mut read).await;
        send_json(&mut write, json!({"op": "final", "handle": opened["handle"], "revision": 1, "text": "pending"})).await;
        let call = calls.recv().await.unwrap();
        assert_eq!(budget.read().reserved_units, 8_000);
        write.shutdown().await.unwrap();
        call
    });
    served.unwrap();
    assert!(call.reply.send(Ok(empty())).is_err());
    assert_eq!(budget.read().reserved_units, 0);
    assert!(host.lock().unwrap().core.is_ended());
    assert!(outputs.brain.starts.is_empty());
    assert!(outputs.control.0.contains(&ControlEvent::SessionEnded));
    assert!(vault.retrieval_runs(200).unwrap().is_empty());
}
