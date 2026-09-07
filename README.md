# agentwares libs

The three shared libraries behind the [agentwares](https://agentwares.vercel.app) portfolio. Each is
published to npm on its own and has no dependency on the rest of the portfolio.

| Package                                   | What it does                                                                                                                                                                                                  |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@agentwares/mcp-kit`](packages/mcp-kit) | one `defineTool` definition served over stdio **and** Streamable HTTP, errors that always carry `code`/`cause`/`fix`/`retryable`, 402 gating, and generators for `server.json`, `llms.txt` and `pricing.json` |
| [`@agentwares/notify`](packages/notify)   | transactional email (Resend), Slack and Discord webhooks and HMAC-signed generic webhooks behind one fan-out call, with plain HTML templates                                                                  |
| [`@agentwares/x402`](packages/x402)       | `402 Payment Required` responses an agent can act on: x402 and Stripe MPP requirements plus a pluggable `PaymentVerifier`                                                                                     |

```sh
npm install @agentwares/mcp-kit    # or @agentwares/notify, @agentwares/x402
```

Everything here is Web-standard where it can be (`fetch`, `Request`, `Response`, `crypto.subtle`), so
the same code runs on Node 20+, Vercel Functions and Cloudflare Workers.

## Working on it

```sh
git clone https://github.com/agentwares/libs && cd libs
pnpm install && pnpm test && pnpm build
```

This repo is generated from the agentwares monorepo, which stays private because it also holds the
paid products. Issues and pull requests here are read and applied upstream.

MIT © agentwares contributors.
