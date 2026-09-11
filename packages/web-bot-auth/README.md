# @agentwares/web-bot-auth

Sign your agent's outbound HTTP requests with Ed25519 so a verifier can tell who is calling,
and serve the signed key directory that publishes the key. This is the mechanism behind
Cloudflare's Verified Bots programme: a fetcher that signs is identified, and a fetcher that
does not is guessed at from its IP and user agent.

Web Crypto and the Fetch API only — no Node built-ins on the signing path — so it runs
unchanged on Vercel Functions, Cloudflare Workers, Deno and Node 20+.

```sh
npm install @agentwares/web-bot-auth
```

## Sign a request

```ts
import { importSigningKey, signRequest, attachSignature } from "@agentwares/web-bot-auth";

const key = await importSigningKey(JSON.parse(process.env.WEB_BOT_AUTH_PRIVATE_JWK!));

const request = new Request("https://example.com/page");
const headers = await signRequest(request, key, { directory: "https://bot.example" });

const response = await fetch(attachSignature(request, headers));
```

`headers` is the three fields a signed request carries:

```http
Signature-Agent: "https://bot.example"
Signature-Input: sig1=("@authority" "signature-agent");created=1757520000
 ;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519"
 ;expires=1757520060;nonce="…";tag="web-bot-auth"
Signature: sig1=:…:
```

The default window is 60 seconds, which is Cloudflare's recommended bound on replay. Cover
more than the authority when you can — `alsoCover: [{ name: "@method" }, { name: "@path" }]`
narrows a signature that would otherwise be reusable against any path on that origin until
it expires.

## Serve the key directory

The directory is a JWKS at a fixed path, and it signs itself: one signature per published
key, covering the `@authority` of the request that fetched it. That possession proof is what
stops someone re-serving your key set under their domain and registering as you.

```ts
import { directoryHandler } from "@agentwares/web-bot-auth";

export const GET = directoryHandler([key]); // mount at the well-known path
```

It answers with `Content-Type: application/http-message-signatures-directory+json`, a
`Content-Digest`, and `Signature` / `Signature-Input` tagged
`http-message-signatures-directory`. It must be generated per request, because `@authority`
comes from the request.

**The URL you register with Cloudflare** is the origin plus the well-known path, over HTTPS,
with no query and no redirect:

```
https://<your-host>/.well-known/http-message-signatures-directory
```

`directoryUrl("https://bot.example")` builds it. The `Signature-Agent` header carries the
_origin_ (`"https://bot.example"`); the verifier appends the well-known path itself.

## Verify

```ts
import { verifyRequest, verifyDirectoryResponse } from "@agentwares/web-bot-auth";

const result = await verifyRequest(request, { keys: publishedJwks });
if (result.ok) console.log(result.keyid, result.signatureAgent);
else console.log(result.code, result.cause, result.fix);
```

`verifyRequest` never throws on hostile input — a malformed field, an unusable key or a
replayed signature all come back as a `code` / `cause` / `fix` failure. It rebuilds the
signature base from the message it actually received, so a signature only passes if every
covered component survived the trip byte for byte.

`verifyDirectoryResponse(request, response)` checks a directory's possession proofs and
returns which published thumbprints proved possession.

## Generate a key

```sh
pnpm --filter @agentwares/web-bot-auth build
pnpm --filter @agentwares/web-bot-auth keygen
```

Writes the private JWK to `~/code/agentwares-secrets/web-bot-auth.key` at mode `0600`, the
public JWK and the thumbprint beside it, and prints only the thumbprint. It refuses to
overwrite an existing key, because a key registered with Cloudflare cannot be silently
replaced — rotation means publishing both and retiring the old one.

**The private key never goes in an environment variable, a commit, or a log.** Deployments
need the public JWK, which is served to the entire internet anyway.

## Which spec this implements

Built from, and tested against, the published test vectors in:

- **RFC 9421**, HTTP Message Signatures (February 2024) — signature base construction,
  `@signature-params`, structured-field serialization.
- **draft-ietf-webbotauth-httpsig-protocol-00** (1 September 2026) — the Web Bot Auth
  working-group draft: `Signature-Agent`, the `web-bot-auth` tag, the JWKS directory format,
  the well-known URI, and the Appendix B directory possession proof. It is a draft; it
  expires 5 March 2027 and the header syntax has already changed once (see below).
- **RFC 7638** / **RFC 8037 Appendix A.3** — the JWK thumbprint used as `keyid`.
- **Cloudflare's Web Bot Auth documentation**, which is what actually gates the Verified
  Bots programme today.

The Ed25519 vectors from Appendix E.2 of the draft and Appendix B.2.6 of RFC 9421 are
asserted byte for byte in the test suite: Ed25519 is deterministic, so a correct
implementation reproduces the published signature exactly, not merely one that verifies.
`signRequest` reproduces the example in Cloudflare's own documentation on the nose.

### Where Cloudflare and the current draft disagree

Cloudflare implements the older `draft-meunier-http-message-signatures-directory-03` /
`-web-bot-auth-architecture-02`. Two things have changed since, and the defaults here follow
Cloudflare, because Cloudflare is the verifier that decides whether your bot gets through.

|                            | Cloudflare today (the default)                                     | draft-ietf-webbotauth-httpsig-protocol-00                                           |
| -------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| `Signature-Agent`          | sf-string: `"https://bot.example"`, covered as `"signature-agent"` | Dictionary: `sig1="https://bot.example"`, covered as `"signature-agent";key="sig1"` |
| Directory signature covers | `("@authority";req)`                                               | `("@authority";req "content-digest")`                                               |

Cloudflare's docs are explicit that it **fails** verification for the dictionary form. Pass
`signatureAgentForm: "dictionary"` and `profile: "ietf-draft"` when you are talking to a
verifier that has moved on. Both forms are covered by the vectors and by round-trip tests.

Cloudflare also rejects the `sf`, `bs`, `key` and `req` component parameters on _request_
signatures, and the `@query-param` and `@status` components. This library refuses `sf` and
`bs` outright; the rest are available and simply should not be sent to Cloudflare.

Re-check all of this before you deploy. It moved between this package's first and second
paragraph of research, and it will move again.

## License

MIT
