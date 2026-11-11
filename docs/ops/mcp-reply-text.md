# MCP malformed reply text

After a carrier completes, a JSON parse failure is reported as the same raw body
text in the existing JSON-RPC bridge error. The diagnostic consumes the owned
body bytes. Valid UTF-8 becomes a `String` with the same backing allocation;
invalid UTF-8 recovers those exact bytes and uses the existing lossy conversion.

JSON parse success, response ID validation, HTTP status handling, authentication
errors, body limits and deadlines are unchanged. This only removes a text copy
for already-valid UTF-8 malformed JSON. It does not make valid JSON parsing or
invalid UTF-8 conversion allocation-free, and does not establish streaming,
queue bounds or a runtime memory bound.
