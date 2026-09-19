# shrike-wasm

Browser JavaScript/TypeScript bindings for Shrike.

Build from the repository root:

```sh
just wasm
```

To run the included demo, serve the repository root over HTTP and open
`/wasm/` (ES modules and WebAssembly do not load reliably from `file://`):

```sh
python3 -m http.server 8000
```

Then import the generated package:

```js
import init, {
  P256Key,
  TidClock,
  XrpcClient,
  cborEncode,
  connectJetstream,
  generatePkce,
  validateSyntax,
} from "./wasm/pkg/shrike_wasm.js";

await init();

const did = validateSyntax("did", "did:plc:z72i7hdynmk6r22z27h6tvur");
const key = new P256Key();
const signature = key.sign(new TextEncoder().encode(did));
const pkce = generatePkce();
const clock = new TidClock(0);
console.log(clock.next());

const encoded = cborEncode({ text: "hello from Shrike" });

const client = new XrpcClient("https://public.api.bsky.app");
const profile = await client.query("app.bsky.actor.getProfile", {
  actor: "bsky.app",
});

const stream = connectJetstream(
  "wss://your-relay.example/subscribe",
  { collections: ["app.bsky.feed.post"] },
  event => console.log(event),
  error => console.error(error),
);
// Later: stream.close();
```

## Jetstream v2 (sealed archive + live)

`connectJetstreamV2` is a separate binding backed by `shrike::jetstream`. It
merges sealed `.jss` archive segments with the live WebSocket tail into one
ordered, duplicate-free stream. A live-only tail needs no key; bounded replay
(`afterSeq`, `beforeSeq`, or `snapshotOnly`) reads the authenticated archive
and requires a `replayKey`.

```js
import init, { connectJetstreamV2 } from "./wasm/pkg/shrike_wasm.js";
await init();

const sub = connectJetstreamV2(
  {
    host: "jetstream.us-east.bsky.network", // wss + https by default
    collections: ["app.bsky.feed.post"],
    // Bounded replay is optional; omit for a live-only tail.
    // afterSeq: 123456, snapshotOnly: true, replayKey: "…",
  },
  event => console.log(event.kind, event.seq, event.collection),
  info => console.warn("info", info.name, info.message), // optional
  error => console.error("stream error", error),          // optional
);

console.log(sub.stats()); // { lastProcessedSeq, deliveredEvents, sealedTipSeq, … }
// Later: sub.close();  // idempotent; cancels the engine and drops listeners
```

Options: `host`, `insecure` (use `ws`/`http` instead of `wss`/`https`),
`archiveHost` (defaults to `host`), `collections`, `dids`, `kinds`, `afterSeq`,
`beforeSeq`, `snapshotOnly`, `noCompression`, and `replayKey`. Events, info
advisories, and `stats()` snapshots are delivered as plain JavaScript values.

Never embed a long-lived archive key in checked-in HTML, JavaScript, or WASM,
and never place it in a URL: browser bundles are readable by anyone who loads
them. Read the key from a session-only input, hand it to `connectJetstreamV2`
once, and do not persist it. The demo (`index.html`) clears its key field the
moment the stream starts.

## Browser constraints

HTTP APIs require CORS permission from the remote origin. Authenticated archive
replay additionally needs the server to allow the `Authorization`, `Range`, and
`If-Range` request headers and to expose `ETag`, `Content-Range`,
`Content-Length`, and `Retry-After`; a missing grant surfaces as a transport
error rather than corrupt data. Browser handle resolution uses
`https://<handle>/.well-known/atproto-did`; DNS TXT lookup is not available to
WebAssembly. Browser WebSockets also prohibit custom request headers, including
`User-Agent`.
