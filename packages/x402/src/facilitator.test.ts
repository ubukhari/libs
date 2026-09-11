import { describe, expect, it, vi } from "vitest";
import {
  createFacilitatorVerifier,
  toAtomicUnits,
  toShortNetwork,
  USDC_BASE,
  USDC_EIP712_DOMAIN,
  PAYAI_FACILITATOR_URL,
} from "./facilitator.js";
import type { PaymentRequirement } from "./index.js";

const PAY_TO = "0x48e7DFa6958E8f71EF5fb417c88CbCA21DA482c5";
const REQUIREMENT: PaymentRequirement = {
  rail: "x402",
  amountUsd: "0.02",
  resource: "https://api.test/v1/reserves/USDC",
  description: "One reserve lookup",
};

/** What a buyer sends: base64 JSON in X-PAYMENT. */
const PAYMENT = {
  x402Version: 2,
  scheme: "exact",
  network: "eip155:8453",
  payload: { signature: "0xsig", authorization: { from: "0xbuyer", value: "20000" } },
};

function paidRequest(payment: unknown = PAYMENT, header = "X-PAYMENT"): Request {
  return new Request("https://api.test/v1/reserves/USDC", {
    headers: { [header]: btoa(JSON.stringify(payment)) },
  });
}

/** A fake facilitator; `calls` records exactly what we sent it. */
function facilitator(responses: { verify?: unknown; settle?: unknown } = {}) {
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    calls.push({ path, body: JSON.parse(String(init?.body ?? "{}")) });
    const body =
      path === "/verify"
        ? (responses.verify ?? { isValid: true })
        : (responses.settle ?? { success: true, transaction: "0xtx" });
    return new Response(JSON.stringify(body), {
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

describe("toAtomicUnits", () => {
  it("converts USD to 6-decimal USDC without float error", () => {
    expect(toAtomicUnits("0.02")).toBe("20000");
    expect(toAtomicUnits("0.75")).toBe("750000");
    expect(toAtomicUnits("1")).toBe("1000000");
    expect(toAtomicUnits("0.000001")).toBe("1");
    // 0.07 * 1e6 is 70000.00000000001 in floating point; string math is not
    expect(toAtomicUnits("0.07")).toBe("70000");
    expect(toAtomicUnits("12.345678")).toBe("12345678");
  });

  it("refuses amounts it cannot represent exactly", () => {
    expect(() => toAtomicUnits("0.0000001")).toThrow(/decimal places/);
    expect(() => toAtomicUnits("abc")).toThrow(/decimal amount/);
    expect(() => toAtomicUnits("-1")).toThrow(/decimal amount/);
  });
});

describe("facilitator verifier", () => {
  it("sends the price, asset and our own address as the requirements", async () => {
    const f = facilitator();
    const v = createFacilitatorVerifier({
      payTo: PAY_TO,
      network: "eip155:8453",
      fetchImpl: f.fetchImpl,
    });
    const result = await v.verify(paidRequest(), REQUIREMENT);

    expect(result.ok).toBe(true);
    expect(result.rail).toBe("x402");
    expect(f.calls[0]?.path).toBe("/verify");
    expect(f.calls[0]?.body).toMatchObject({
      x402Version: 2,
      paymentRequirements: {
        scheme: "exact",
        network: "eip155:8453",
        amount: "20000",
        payTo: PAY_TO,
        asset: USDC_BASE,
        // not in the v2 schema, but a discovery catalog cannot list a settlement that
        // names no resource, and the facilitator accepts the field
        resource: REQUIREMENT.resource,
        // the facilitator cannot rebuild the buyer's signature without this
        extra: USDC_EIP712_DOMAIN,
      },
    });
  });

  it("verifying moves no money; settling is a separate call", async () => {
    const f = facilitator();
    const v = createFacilitatorVerifier({
      payTo: PAY_TO,
      network: "eip155:8453",
      fetchImpl: f.fetchImpl,
    });

    const verified = await v.verify(paidRequest(), REQUIREMENT);
    expect(f.calls.map((c) => c.path)).toEqual(["/verify"]);

    const settled = await v.settle(verified);
    expect(settled).toMatchObject({ ok: true, transaction: "0xtx" });
    expect(f.calls.map((c) => c.path)).toEqual(["/verify", "/settle"]);
    // settle must re-send the same requirements it verified against, not rebuild them
    expect(f.calls[1]?.body.paymentRequirements).toEqual(f.calls[0]?.body.paymentRequirements);
  });

  it("fails closed when the facilitator is unreachable", async () => {
    // The dangerous failure is the opposite: treating a network error as a paid call.
    const boom = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const log = vi.fn();
    const v = createFacilitatorVerifier({
      payTo: PAY_TO,
      network: "eip155:8453",
      fetchImpl: boom,
      log,
    });
    const result = await v.verify(paidRequest(), REQUIREMENT);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/unreachable/);
    expect(log).toHaveBeenCalled();
  });

  it("passes the facilitator's refusal through with its reason", async () => {
    const f = facilitator({
      verify: {
        isValid: false,
        invalidReason: "insufficient_funds",
        invalidMessage: "balance below value",
      },
    });
    const v = createFacilitatorVerifier({
      payTo: PAY_TO,
      network: "eip155:8453",
      fetchImpl: f.fetchImpl,
    });
    const result = await v.verify(paidRequest(), REQUIREMENT);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("insufficient_funds: balance below value");
  });

  it("refuses a request with no payment header, and never calls out", async () => {
    const f = facilitator();
    const v = createFacilitatorVerifier({
      payTo: PAY_TO,
      network: "eip155:8453",
      fetchImpl: f.fetchImpl,
    });
    const result = await v.verify(new Request("https://api.test/x"), REQUIREMENT);
    expect(result).toMatchObject({ ok: false, reason: "no payment header present" });
    expect(f.calls).toHaveLength(0);
  });

  it("accepts the PAYMENT header and a bare JSON payload too", async () => {
    const f = facilitator();
    const v = createFacilitatorVerifier({
      payTo: PAY_TO,
      network: "eip155:8453",
      fetchImpl: f.fetchImpl,
    });
    expect((await v.verify(paidRequest(PAYMENT, "PAYMENT"), REQUIREMENT)).ok).toBe(true);

    const bare = new Request("https://api.test/x", {
      headers: { "X-PAYMENT": JSON.stringify(PAYMENT) },
    });
    expect((await v.verify(bare, REQUIREMENT)).ok).toBe(true);
  });

  it("reports a settlement refused after the work was served, without throwing", async () => {
    const f = facilitator({ settle: { success: false, errorReason: "nonce_already_used" } });
    const log = vi.fn();
    const v = createFacilitatorVerifier({
      payTo: PAY_TO,
      network: "eip155:8453",
      fetchImpl: f.fetchImpl,
      log,
    });
    const verified = await v.verify(paidRequest(), REQUIREMENT);
    const settled = await v.settle(verified);
    // lost revenue, not a failed request: the buyer already has the result
    expect(settled).toMatchObject({ ok: false, reason: "nonce_already_used" });
    expect(log).toHaveBeenCalled();
  });

  it("nests `accepted` inside the payload, which is the whole of the v2 envelope", async () => {
    // Verified against the live PayAI facilitator on 9 September 2026. `accepted` at the top
    // level, or the payload without a sibling `paymentRequirements`, both come back as
    // `invalid_payment_requirements: ": Invalid input"` — an error that names no field, so
    // this shape is worth pinning in a test rather than rediscovering it.
    const f = facilitator();
    const v = createFacilitatorVerifier({
      payTo: PAY_TO,
      network: "eip155:8453",
      fetchImpl: f.fetchImpl,
    });
    const verified = await v.verify(paidRequest(), REQUIREMENT);
    await v.settle(verified);

    for (const call of f.calls) {
      expect(call.body.x402Version).toBe(2);
      const payload = call.body.paymentPayload as {
        x402Version: number;
        network: string;
        resource: unknown;
        accepted: unknown;
        payload: unknown;
      };
      expect(payload.x402Version).toBe(2);
      expect(payload.accepted).toEqual(call.body.paymentRequirements);
      // a payload-level `resource` must be an object; a string is rejected outright
      expect(payload.resource).toMatchObject({ url: REQUIREMENT.resource, type: "http" });
      expect(payload.network).toBe("eip155:8453");
      // the buyer's signed material must survive the restatement untouched
      expect(payload.payload).toEqual(PAYMENT.payload);
    }
  });

  it("still speaks v1 for a facilitator that refuses v2", async () => {
    // The rail worked over v1 for weeks; it settled money and never got catalogued. Keep the
    // path, because a facilitator that only speaks v1 should still be usable.
    const f = facilitator();
    const v = createFacilitatorVerifier({
      payTo: PAY_TO,
      network: "eip155:8453",
      protocolVersion: 1,
      fetchImpl: f.fetchImpl,
    });
    const verified = await v.verify(paidRequest(), REQUIREMENT);
    await v.settle(verified);

    for (const call of f.calls) {
      expect(call.body.x402Version).toBe(1);
      // v1 flattens scheme and network beside the payload and uses short network names
      expect((call.body.paymentPayload as { network: string }).network).toBe("base");
      expect((call.body.paymentPayload as { x402Version: number }).x402Version).toBe(1);
      expect(call.body.paymentRequirements).toMatchObject({ maxAmountRequired: "20000" });
      expect((call.body.paymentPayload as { payload: unknown }).payload).toEqual(PAYMENT.payload);
    }
  });

  it("maps CAIP-2 chains to the short names the API uses", () => {
    expect(toShortNetwork("eip155:8453")).toBe("base");
    expect(toShortNetwork("eip155:137")).toBe("polygon");
    // an unknown chain passes through rather than being silently dropped
    expect(toShortNetwork("eip155:999999")).toBe("eip155:999999");
    expect(toShortNetwork("base")).toBe("base");
  });

  it("defaults to a facilitator that needs no account", () => {
    expect(PAYAI_FACILITATOR_URL).toBe("https://facilitator.payai.network");
  });
});
