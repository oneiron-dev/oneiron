use serde_json::Value;

/// Keeps the parsed request in its caller until its transport has sent it.
pub(super) struct RequestId {
    message: Option<Value>,
    id: Option<Value>,
}

impl RequestId {
    pub(super) fn new(message: Value) -> Self {
        Self {
            message: Some(message),
            id: None,
        }
    }

    pub(super) fn release(&mut self) {
        if let Some(mut message) = self.message.take() {
            self.id = message.get_mut("id").map(Value::take);
        }
    }

    pub(super) fn into_id(mut self) -> Option<Value> {
        self.release();
        self.id
    }
}
