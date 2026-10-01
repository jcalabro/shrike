# XRPC server parity

Source of truth: `bluesky-social/atproto` `packages/xrpc-server` at `52e51de0f`
(v0.13.3), with `packages/lexicon` for validation. Go references: indigo
`atproto/auth` (service JWTs, fixed vectors) and `atproto/lexicon/testdata`
(interop fixtures); atmos v0.4.0 `xrpcserver`/`serviceauth` for API shape.

## Dependency decisions (approved)

- axum `ws` feature; workspace tokio-tungstenite 0.26 → 0.28 so one
  tungstenite is compiled.
- flate2 (gzip/deflate) and brotli request-body decoding. We use
  `brotli-decompressor` (the decode half of `brotli`) at runtime and `brotli`
  only as a dev-dependency to produce test inputs.
- unicode-segmentation for `maxGraphemes`/`minGraphemes`.

## Scope

1. Lexicon: extended grapheme clusters, `minGraphemes`, `cid` and `uri`
   formats, XRPC params/input/output/message validation with defaults. Port
   indigo's record interop fixtures.
2. Service auth: `create_service_jwt` and `ServiceJwtVerifier` following TS
   `auth.ts` check order. Accept high-S signatures (TS `allowMalleableSig`),
   refresh the key once on a signature mismatch.
3. Server core: one `/xrpc/{nsid}` dispatcher, TS error names and statuses,
   `Incorrect HTTP method` errors, 501 for unknown methods, catchall hook,
   repeated and bracketed query params, strict param decoding, body presence
   rules, content-type checks, size limits on encoded and decoded bytes,
   gzip/deflate/br, raw streaming input and output, lexicon validation of
   params/input/output, auth hook with typed credentials, procedures that run
   to completion after the client disconnects.
4. Subscriptions: DAG-CBOR frames (`{t, op}` header), errors as frames after
   the upgrade, close 1008 with the error name, close 1000 at the end,
   backpressure per send.
5. Rate limiting: global, shared and route limiters, TS headers.
6. Client: send array params as repeated keys (currently fails in
   `serde_urlencoded`).

## Deliberate deviations from TS

Express artifacts are not reproduced: case-insensitive routes, HTML 404s,
`X-Powered-By`, ETags, mime-type extension shorthand (`json`), http-errors
names such as `PayloadTooLargeError`/`SyntaxError` on the wire (we use the
`ResponseType` names), legacy lenient coercion (`parseInt(x) || 0`, any
non-`true` string as false). We follow the newer `lex-schema` path there:
strict integers/booleans, empty values ignored. Brotli is accepted for JSON
bodies too. A malformed JWT header or payload is a 401 `BadJwt`, not a 500.

Further deviations, found while porting the tests:

- A `Content-Type` with no `Content-Length`/`Transfer-Encoding` is an empty
  body, not a missing one: reqwest (and so shrike's own client) omits
  `Content-Length: 0`.
- Bracketed array params (`a[]=x`, `a[0]=x`) are always folded, as the
  legacy `method()` path does; the TS `addLexicons` path needs
  `paramsParseLoose`.
- Validation messages use shrike's lexicon validator wording (they name the
  same field) rather than the TS sentences.
- Binary bodies are limited to 5 MiB by default (the reference PDS blob
  limit) rather than unlimited; `PayloadLimits { blob: None, .. }` opts out.
- A rate limit keyed by client IP (the default) rejects a request with a 500
  when there is no IP (no connect info), instead of not applying.
- Subscriptions are rate limited: global, shared and route limits are
  charged once per connection, after authentication, and exceeding one is a
  `RateLimitExceeded` error frame. TS applies no limits to subscriptions.
- A signature check that fails because the cached key's type does not match
  the token `alg` also refreshes the key, so a rotation to another curve is
  picked up.

Lexicon deviations (pinned in `tests/lexicon_reference.rs`): objects without
`properties` are accepted (indigo's fixtures rely on it), and
`validate_record` does not require `$type`.

## Status

Done. Tests: lexicon unit tests plus `tests/lexicon_interop.rs` (indigo
fixtures) and `tests/lexicon_reference.rs` (TS `general.test.ts`);
`service_auth` unit tests including indigo's fixed vectors; xrpc_server unit
tests (TS `parsing.test.ts` paths, frames, params, bodies and decoders, rate
limiting); `tests/xrpc_server.rs` ports every TS xrpc-server suite over real
HTTP/WebSocket (queries, procedures, responses, bodies, errors, parameters,
ipld, auth incl. a mock-PLC `Directory`, rate limiting, subscriptions) plus
shrike client end-to-end tests. Fuzz targets: `xrpc_frame`, `xrpc_params`,
`service_jwt_verify`.
