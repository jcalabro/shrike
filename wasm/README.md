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

HTTP APIs require CORS permission from the remote origin. Browser handle
resolution uses `https://<handle>/.well-known/atproto-did`; DNS TXT lookup is
not available to WebAssembly. Browser WebSockets also prohibit custom request
headers, including `User-Agent`.
