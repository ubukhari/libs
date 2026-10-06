import { describe, expect, it } from "vitest";
import {
  StubVerifier,
  X402_HEADER,
  buildPaymentRequired,
  paymentRequiredResponse,
  type SelfServe,
} from "./index.js";

describe("x402 stub", () => {
  const SELF_SERVE: SelfServe = {
    keysUrl: "https://api.test/v1/keys",
    creditsUrl: "https://api.test/v1/credits",
    packsUsd: [10, 50, 200],
    idempotencyHeader: "Idempotency-Key",
  };

  it("builds a 402 with structured error fields", () => {
    const r = buildPaymentRequired({
      resource: "re_deal_memo",
      priceUsd: 0.75,
      payTo: "0xabc",
      selfServe: SELF_SERVE,
    });
    expect(r.status).toBe(402);
    expect(r.body.code).toBe("PAYMENT_REQUIRED");
    expect(r.body.retryable).toBe(true);
    expect(r.body.accepts.map((a) => a.rail)).toEqual(["x402", "prepaid_credits"]);
    expect(r.body.accepts[0]?.amountUsd).toBe("0.75");
    expect(r.headers["WWW-Authenticate"]).toContain("x402 prepaid_credits");
    expect(JSON.parse(r.headers[X402_HEADER] ?? "{}").x402Version).toBe(2);
  });

  it("never advertises a rail with nowhere to send the money", () => {
    // `accepts` is a promise the rail can be settled. The x402 entry was previously emitted
    // with payTo: undefined while no CDP account existed, so an agent that chose it had no
    // address to pay and spent a retry on a method that could not have been honoured.
    const noWallet = buildPaymentRequired({
      resource: "r",
      priceUsd: 0.75,
      selfServe: SELF_SERVE,
    });
    expect(noWallet.body.accepts.map((a) => a.rail)).toEqual(["prepaid_credits"]);
    expect(noWallet.body.accepts.every((a) => a.payTo)).toBe(true);

    const nothingConfigured = buildPaymentRequired({ resource: "r", priceUsd: 0.75 });
    expect(nothingConfigured.body.accepts).toEqual([]);
  });

  it("marks the rail that cannot be settled without a person", () => {
    const r = buildPaymentRequired({
      resource: "r",
      priceUsd: 0.75,
      payTo: "0xabc",
      selfServe: SELF_SERVE,
    });
    const x402 = r.body.accepts.find((a) => a.rail === "x402");
    const mpp = r.body.accepts.find((a) => a.rail === "prepaid_credits");
    // an unattended agent picks the rail with no humanRequired flag
    expect(x402?.humanRequired).toBeUndefined();
    expect(mpp?.humanRequired).toBe(true);
  });

  it("tells an unattended agent what it can do alone, and what it cannot", () => {
    const fix = buildPaymentRequired({
      resource: "r",
      priceUsd: 0.75,
      live: true,
      sampleMode: true,
      selfServe: SELF_SERVE,
    }).body.fix;
    expect(fix).toContain("sample=true");
    expect(fix).toMatch(/needs a person/);
    expect(fix).toMatch(/surface the URL to your operator/);
  });

  it("does not promise a free sample where there is none", () => {
    // This was unconditional, so every 402 in the portfolio advertised sample mode — including
    // products that have none, and including the credit top-up endpoint, where it read as an
    // offer of free credit. An agent that believes it spends a call finding out.
    const body = buildPaymentRequired({
      resource: "https://example/v1/credits/x402",
      priceUsd: 10,
      live: true,
      payTo: "0xabc",
    }).body;
    expect(body.fix).not.toMatch(/sample=true/);
    expect(body.alternatives).not.toContain("sample_mode");
    // and still says how to pay
    expect(body.fix).toMatch(/USDC/);
  });

  it("formats small amounts without float noise", () => {
    const amount = (priceUsd: number) =>
      buildPaymentRequired({ resource: "r", priceUsd, payTo: "0xabc" }).body.accepts[0]?.amountUsd;
    expect(amount(0.05)).toBe("0.05");
    expect(amount(5)).toBe("5.0");
    expect(() => buildPaymentRequired({ resource: "r", priceUsd: -1 })).toThrow();
  });

  it("returns a Web-standard Response", async () => {
    const res = paymentRequiredResponse({ resource: "r", priceUsd: 1 });
    expect(res.status).toBe(402);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = (await res.json()) as { priceUsd: number };
    expect(body.priceUsd).toBe(1);
  });

  it("stub verifier never accepts", async () => {
    const v = new StubVerifier();
    const req = new Request("https://x/y", { headers: { PAYMENT: "abc" } });
    const out = await v.verify(req, { rail: "x402", amountUsd: "1.0", resource: "r" });
    expect(out.ok).toBe(false);
    expect(out.reason).toMatch(/not live/);
  });
});

describe("the 402 a standard client can actually pay", () => {
  const built = buildPaymentRequired({
    resource: "https://example.test/v1/thing",
    priceUsd: 0.02,
    description: "one thing",
    payTo: "0x48e7DFa6958E8f71EF5fb417c88CbCA21DA482c5",
    live: true,
  });
  const x402 = built.body.accepts.find((a) => a.rail === "x402")!;

  it("carries every field a buyer needs to build the signature", () => {
    // Measured against a live catalogued resource in the PayAI Bazaar on 11 September 2026,
    // whose accepts entry carries exactly these: scheme, network, amount, asset, extra,
    // payTo, maxTimeoutSeconds. Ours carried amountUsd and the ticker "USDC", which is
    // readable by a person and unusable by a client.
    expect(x402.scheme).toBe("exact");
    expect(x402.network).toBe("eip155:8453");
    expect(x402.amount).toBe("20000");
    expect(x402.asset).toBe("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
    expect(x402.extra).toEqual({ name: "USD Coin", version: "2" });
    expect(x402.maxTimeoutSeconds).toBe(300);
  });

  it("still says the price in dollars for whoever reads it", () => {
    expect(x402.amountUsd).toBe("0.02");
  });

  it("never advertises the rail without an address to pay", () => {
    const noAddress = buildPaymentRequired({
      resource: "https://example.test/v1/thing",
      priceUsd: 0.02,
      live: true,
    });
    expect(noAddress.body.accepts.some((a) => a.rail === "x402")).toBe(false);
  });
});

describe("a token that is not USDC", () => {
  it("quotes the atomic amount in that token's decimals", () => {
    // The price is signed in atomic units, so wrong decimals do not fail loudly — the buyer
    // signs for an amount off by a factor of a thousand or a million.
    const built = buildPaymentRequired({
      resource: "https://example.test/v1/thing",
      priceUsd: 1.5,
      payTo: "0x48e7DFa6958E8f71EF5fb417c88CbCA21DA482c5",
      asset: "0x0000000000000000000000000000000000000001",
      assetDomain: { name: "Some Token", version: "1" },
      assetDecimals: 18,
      live: true,
    });
    const x402 = built.body.accepts.find((a) => a.rail === "x402")!;
    expect(x402.amount).toBe("1500000000000000000");
    expect(x402.asset).toBe("0x0000000000000000000000000000000000000001");
    expect(x402.extra).toEqual({ name: "Some Token", version: "1" });
  });

  it("still defaults to USDC's six", () => {
    const built = buildPaymentRequired({
      resource: "https://example.test/v1/thing",
      priceUsd: 1.5,
      payTo: "0x48e7DFa6958E8f71EF5fb417c88CbCA21DA482c5",
      live: true,
    });
    expect(built.body.accepts.find((a) => a.rail === "x402")!.amount).toBe("1500000");
  });
});
