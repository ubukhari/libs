import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { readErrorBody } from "./errors.js";
import { paymentRequiredHttpResponse, withPayment } from "./payment.js";
import { listToolManifest } from "./server.js";
import { createToolContext, defineTool } from "./tool.js";

const base = defineTool({
  name: "test_paid_lookup",
  description: "A paid lookup used to exercise withPayment in the tests.",
  input: z.object({ q: z.string() }),
  output: z.object({ q: z.string(), sample: z.boolean(), userId: z.string().optional() }),
  handler: ({ q }, ctx) => ({ q, sample: ctx.sample === true, userId: ctx.userId }),
});

function bodyText(result: CallToolResult): Record<string, unknown> {
  const first = result.content[0];
  if (!first || first.type !== "text") throw new Error("expected text");
  return JSON.parse(first.text) as Record<string, unknown>;
}

describe("withPayment", () => {
  it("without auth → PAYMENT_REQUIRED, advertising only rails that can be settled", async () => {
    // Nothing is configured here, so there is nowhere to send money and `accepts` is empty.
    // Listing a rail we cannot honour costs the caller a wasted retry.
    const paid = withPayment(base, { priceUsd: 0.05 });
    const result = await paid.invoke({ q: "x" }, createToolContext());
    expect(result.isError).toBe(true);
    expect(result._meta?.httpStatus).toBe(402);
    const body = readErrorBody(result);
    expect(body).toMatchObject({
      code: "PAYMENT_REQUIRED",
      retryable: true,
      priceUsd: 0.05,
      comingSoon: true,
    });
    expect(body?.accepts).toEqual([]);
    // `alternatives` follows the same rule as `accepts`: only what this deployment can
    // actually do. Nothing is configured here, so there is no credit path to advertise —
    // listing one is the same wasted retry as listing an unsettleable rail. Sample mode is
    // real, because withPayment adds the flag to every tool it wraps.
    expect(body?.alternatives).toEqual(["sample_mode"]);
    expect(body?.details).toEqual({ reason: "no payment header present" });
    expect(bodyText(result).code).toBe("PAYMENT_REQUIRED");
  });

  it("advertises a configured rail, and flags the one that needs a person", async () => {
    const paid = withPayment(base, {
      priceUsd: 0.05,
      live: true,
      payTo: "0xabc",
      selfServe: {
        keysUrl: "https://api.test/v1/keys",
        creditsUrl: "https://api.test/v1/credits",
        packsUsd: [10],
        idempotencyHeader: "Idempotency-Key",
      },
    });
    const body = readErrorBody(await paid.invoke({ q: "x" }, createToolContext()));
    const accepts = body?.accepts as { rail: string; payTo?: string; humanRequired?: boolean }[];
    expect(accepts.map((a) => a.rail)).toEqual(["x402", "prepaid_credits"]);
    expect(accepts.every((a) => a.payTo)).toBe(true);
    expect(accepts.find((a) => a.rail === "prepaid_credits")?.humanRequired).toBe(true);
    expect(accepts.find((a) => a.rail === "x402")?.humanRequired).toBeUndefined();
  });

  it("sample: true → handler result at no charge", async () => {
    const paid = withPayment(base, { priceUsd: 0.05 });
    const result = await paid.invoke({ q: "x", sample: true }, createToolContext());
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toEqual({ q: "x", sample: true });
  });

  it("authorize ok → handler result with userId; not ok → PAYMENT_REQUIRED with the reason", async () => {
    const paid = withPayment(base, {
      priceUsd: 1,
      authorize: (ctx) =>
        ctx.headers.get("authorization") === "Bearer ak_test_1"
          ? { ok: true, userId: "u1" }
          : { ok: false, reason: "unknown API key" },
    });
    const ok = await paid.invoke(
      { q: "x" },
      createToolContext({ headers: new Headers({ authorization: "Bearer ak_test_1" }) }),
    );
    expect(ok.structuredContent).toEqual({ q: "x", sample: false, userId: "u1" });

    const denied = await paid.invoke({ q: "x" }, createToolContext());
    const body = readErrorBody(denied);
    expect(body?.code).toBe("PAYMENT_REQUIRED");
    expect(body?.details).toEqual({ reason: "unknown API key" });
  });

  it("a custom verifier can accept a payment header", async () => {
    const paid = withPayment(base, {
      priceUsd: 0.5,
      live: true,
      verifier: { verify: async (req) => ({ ok: req.headers.get("payment") === "ok" }) },
    });
    const accepted = await paid.invoke(
      { q: "x" },
      createToolContext({ headers: new Headers({ payment: "ok" }) }),
    );
    expect(accepted.structuredContent).toEqual({ q: "x", sample: false });
    const rejected = readErrorBody(await paid.invoke({ q: "x" }, createToolContext()));
    expect(rejected?.comingSoon).toBe(false);
  });

  it("a configured verifier's refusal wins over the entitlement check's", async () => {
    // The wallet knows the caller is $0.70 short; "unknown API key" would send them nowhere.
    const paid = withPayment(base, {
      priceUsd: 0.75,
      live: true,
      authorize: () => ({ ok: false, reason: "unknown API key" }),
      verifier: { verify: async () => ({ ok: false, reason: "insufficient credit" }) },
    });
    const denied = readErrorBody(await paid.invoke({ q: "x" }, createToolContext()));
    expect(denied?.details).toEqual({ reason: "insufficient credit" });

    // With no verifier configured, the stub has nothing useful to say, so authorize's reason stands.
    const stubbed = withPayment(base, {
      priceUsd: 0.75,
      authorize: () => ({ ok: false, reason: "unknown API key" }),
    });
    const fallback = readErrorBody(await stubbed.invoke({ q: "x" }, createToolContext()));
    expect(fallback?.details).toEqual({ reason: "unknown API key" });
  });

  it("calls onPaidFailure with the receipt when a paid handler throws, then rethrows", async () => {
    const boom = defineTool({
      name: "test_paid_boom",
      description: "A paid tool whose handler always fails, to exercise the refund path.",
      input: z.object({ q: z.string() }),
      handler: () => {
        throw new Error("upstream is down");
      },
    });
    const refunded: unknown[] = [];
    const paid = withPayment(boom, {
      priceUsd: 0.05,
      live: true,
      verifier: {
        verify: async () => ({
          ok: true,
          rail: "prepaid_credits",
          receipt: { keyId: "ck_1", chargedUsd: 0.05 },
        }),
      },
      onPaidFailure: (_ctx, verified) => {
        refunded.push(verified.receipt);
      },
    });
    const result = await paid.invoke({ q: "x" }, createToolContext());
    expect(result.isError).toBe(true);
    expect(refunded).toEqual([{ keyId: "ck_1", chargedUsd: 0.05 }]);
  });

  it("adds an optional boolean sample field to the schema and the description", () => {
    const paid = withPayment(base, { priceUsd: 0.05 });
    const [entry] = listToolManifest([paid]);
    const properties = entry?.inputSchema.properties as Record<
      string,
      { type: string; default?: unknown }
    >;
    expect(properties.sample).toMatchObject({ type: "boolean", default: false });
    expect(entry?.inputSchema.required).toEqual(["q"]);
    expect(paid.description).toContain("$0.05");
    expect(paid.description).toContain("sample=true");
    expect(paid.name).toBe(base.name);
  });

  it("refuses to shadow an existing input field and negative prices", () => {
    const clash = defineTool({
      name: "test_has_sample",
      description: "Has its own sample field so withPayment must complain.",
      input: z.object({ sample: z.string() }),
      handler: () => ({}),
    });
    expect(() => withPayment(clash, { priceUsd: 1 })).toThrow(/already has a field named "sample"/);
    expect(() => withPayment(base, { priceUsd: -1 })).toThrow(/non-negative/);
  });

  it("re-exports the plain HTTP 402 response", async () => {
    const res = paymentRequiredHttpResponse({ resource: "r", priceUsd: 1 });
    expect(res.status).toBe(402);
    expect(res.headers.get("www-authenticate")).toContain("x402 prepaid_credits");
  });
});
