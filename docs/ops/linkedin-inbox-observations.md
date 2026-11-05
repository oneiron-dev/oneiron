# LinkedIn inbox observations and delivery receipts

The served LinkedIn loop admits every selected message using the original
message/event ID, cursor, seen marker, routing and durable handoff. Own messages
and messages with no known sender still get that admission. They do not become
foreign incoming text merely because a poll observed them.

For a structured transcript, its explicit sender must differ from the receiving
seat and its known profile names. For page text, the turn heading must also
match another member's profile link and not match the seat's profile names.
Unheaded text, unlinked names, and ambiguous own/other names do not supply reply
text. A non-profile link does not establish a member name.

Only those positively incoming messages are archived as provider-event text,
after the ordinary route selects the event and before its durable enqueue. The
exact returned blob/version ref goes into both the event and its final
provenance row. Other messages retain their original opaque provider ref; the
existing text reader returns no body for that ref. No message admission or
history is removed to avoid a reply loop.

## Sending

Before/after page counts are diagnostic observations, not proof that this
send delivered. A page can slide and reveal an older identical message.
Neither an increased count nor a generic successful tool return identifies
the message this send created.

The native structured path still requires the provider's send-result message
ID, the same ID in a matching own-sender transcript entry, and its absence from
the pre-send transcript. A page-only or ID-less result remains possible
delivery. A transport that proves the tool was never called keeps the existing
certain non-delivery path. No ID, sender, or successful delivery is fabricated.

This describes source behavior. It is not a live provider or runtime proof.
The provider's durable send-to-message identity remains required to complete
the ID-less/page-only delivery part of FIX12329.
