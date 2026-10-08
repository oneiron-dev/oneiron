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
    fn update_context(&mut self, _request: &BrainRequest) -> oneiron::Result<()> {
        Ok(())
    }
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
    fn flush_queued_pcm(&mut self, _generation: GenerationEpoch) -> oneiron::Result<()> {
        Ok(())
    }
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
        brain: TestBrain::default(),
        tts: TestTts::default(),
        control: TestControl::default(),
    };
    let (served, ()) = tokio::join!(host.serve(server, &mut outputs), async {
        send_json(&mut write, json!({"op": "open", "utterance_id": "u"})).await;
        let opened = read_json(&mut read).await;
        let token = opened["handle"].as_str().unwrap();
        send_json(&mut write, json!({"op": "final", "handle": token, "revision": 1, "text": "text", "salient_terms": ["injected"]})).await;
        assert_eq!(read_json(&mut read).await["code"], json!("invalid_request"));
        assert!(calls.try_recv().is_err());
        send_json(
            &mut write,
            json!({"op": "final", "handle": token, "revision": 1, "text": "text"}),
        )
        .await;
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
    assert_eq!(
        outputs.brain.cancelled,
        [outputs.brain.starts[0].generation]
    );
    assert!(outputs.control.0.contains(&ControlEvent::SessionEnded));
    assert_eq!(vault.retrieval_runs(200).unwrap().len(), 1);
    assert_eq!(budget.read().reserved_units, 0);
    assert!(host.lock().unwrap().core.is_ended());
}
