# Replying to an INBOX message

`self.inbox.reply` queues the bound actor's chosen words for one message.
It uses the existing connector reply worker and recorded outbound pipeline.
The host owns transport. Live grants, budgets, channel identity and thread
rules still apply when the worker sends.

1. Call `self.inbox.get` with the INBOX row's `item_id`.
2. Choose a message with a `reply_event_ref`. This is its exact frozen
   connector event, not a request to answer whichever message is newest.
3. Call `self.inbox.reply` with that anchor and a request reference:

```json
{
  "item_id": "<row handle>",
  "event_ref": "<message.reply_event_ref>",
  "request_ref": "<your stable request identity>",
  "text": "<the words to send>"
}
```

Keep `event_ref`, `request_ref` and `text` unchanged when retrying a request.
A new request reference allows an intentional follow-up or correction on
that same event, even if the words are identical. Changed text also names a
new logical reply. A row gaining another message does not retarget a retry.
The chosen words are persisted with the queue job. The worker does not ask
a model to rewrite them. Existing provider-specific limits still apply.

A message has no reply anchor until this actor's standing subscription has
frozen its connector event. Non-message cards and standing memberships with
no inbound message remain readable; they do not acquire a made-up recipient.

## Acceptance is not delivery

The response names `job.job_ref`, the queue's current `job.state`, and the
job's existing versioned `job.results`. It does not mark the inbound row
Done. Use `self.inbox.reply.status` with `{"job_ref":"<32 hex>"}` to read
that same actor's job later. No separate delivery status store is maintained.

A result's `stage: "dispatched"` does **not** necessarily mean delivery:
read its exact `outcome`. Suppressed, degraded, let-go and deferred work
also passes through dispatch. Held, failed, ambiguous, no-reply and fault
results stay distinct. An ambiguous send is not automatically resent.
Existing outbound receipts remain the authority on what reached a channel.

`self.inbox.done` still means that the actor answered or closed the inbound
item. It is an explicit separate act, not a delivery receipt. A newer inbound
message reopens the row under the existing read-state rules.
