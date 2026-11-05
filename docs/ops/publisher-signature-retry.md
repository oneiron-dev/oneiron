# Retry a publisher issue signature

The Coach sends content-free issue signatures through the ordinary outbound ledger.
An ordinary rerun keeps the same logical send. It does not retry a send that the ledger
already stopped, even after the publisher's endpoint recovers.

The vault owner can explicitly prepare a new logical send when the outbound ledger proves
that the previous one was not delivered. This never retries a delivered, uncertain,
deferred or still-running send. It does not send report text.

## Prepare the retry

1. Read `GET /v1/owner/feedback/delivery/status?issue_ref=<32 hex>`.
2. Copy `delivery.send.send_ref`. Check the publisher's binding in the same reply.
   If needed, change it with `PUT /v1/owner/feedback/delivery/binding` and
   `{"publisher_ref": "<publisher>", "bound": true}`. This binds the publisher to
   this server's configured feedback destination.
3. Call the owner retry route with the exact send reference you read:

   ```sh
   oneiron api raw POST /v1/owner/feedback/delivery/retry \
     --data '{"issue_ref":"<32 hex>","expected_send_ref":"<delivery.send.send_ref>"}'
   ```

The reply is the delivery record with a new `send.send_ref`, the current bound destination,
and no outcome or receipt for that new send yet. The frozen signature bytes and its custody
row do not change. The old send's intent, destination and receipt remain in the outbound
ledger. The retry route itself performs no network send.

The owner proof, selected current send and authoritative non-delivery are checked in one
writer. A different current send rejects a stale request. Repeating the same request returns
its immediate successor without creating a third send. To request another retry after that
successor also fails definitively, read its new reference and submit it explicitly.

## Run delivery and read the result

Call `POST /v1/owner/feedback/delivery/run` with `{}`, or let the next nightly Coach pass run.
Then read the issue's delivery status again. A queued run's completion is not proof that a
particular signature was delivered; the lane's receipt and outcome say what happened.

The normal current binding, destination, participation, publisher dial and outbound admission
checks still apply before the new send leaves. An unbound publisher must first be bound.
A disabled switch or unsupported destination is still a visible hold on the ordinary run.
No automatic retry of an ambiguous delivery is added.
