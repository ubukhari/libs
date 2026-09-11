/**
 * `withPayment` — gate a tool behind a price. Wave 0: nothing is charged; callers without an
 * entitlement get a 402-shaped `PAYMENT_REQUIRED` result advertising both rails (x402 on Base,
 * Stripe MPP) with `comingSoon: true`, and `sample: true` returns an example for free.
 */
import {
  StubVerifier,
  buildPaymentRequired,
  type PaymentRequirement,
  paymentRequiredResponse,
  type PaymentRequiredBody,
  type PaymentVerifier,
  type SelfServe,
  type VerifyResult,
} from "@agentwares/x402";
import { z } from "zod";
import { toolError, type McpToolError } from "./errors.js";
import { defineTool, type ToolContext, type ToolDef } from "./tool.js";

export interface AuthorizeResult {
  ok: boolean;
  userId?: string;
  /** why not, e.g. "API key revoked" — surfaced in `details.reason` */
  reason?: string;
}

export interface WithPaymentOptions {
  /** price per successful call, in USD (e.g. 0.05) */
  priceUsd: number;
  /** Entitlement check (API key + credits, subscription tier). `ok: true` skips payment. */
  authorize?: (ctx: ToolContext) => Promise<AuthorizeResult> | AuthorizeResult;
  /** Payment verifier for the request headers. Default: `StubVerifier` (never accepts). */
  verifier?: PaymentVerifier;
  /** set once pay-per-call is live (drops `comingSoon`) */
  live?: boolean;
  /** name of the boolean input field that requests a free sample (default `sample`) */
  sampleField?: string;
  /** shown in the payment requirement */
  description?: string;
  /**
   * Discovery metadata for the x402 `bazaar` extension. Advertised in the 402 so a client can
   * echo it back; without that echo the facilitator will not catalog the resource, however
   * many payments settle against it.
   */
  bazaar?: Record<string, unknown>;
  payTo?: string;
  /** prepaid_credits rail: the URL that takes a card and funds a balance */
  creditsPayTo?: string;
  signupUrl?: string;
  /** the no-human purchase path, advertised in the 402 body once the card rail is live */
  selfServe?: SelfServe;
  /**
   * Called when a call that was already paid for then fails. A verifier that charges up
   * front (the prepaid wallet does) uses this to give the money back, so a caller is never
   * billed for an error. `receipt` is whatever the verifier returned.
   */
  onPaidFailure?: (
    ctx: ToolContext,
    verified: VerifyResult,
    error: unknown,
  ) => Promise<void> | void;
  /**
   * The paid work succeeded but the money did not arrive — an on-chain settlement that was
   * refused or a facilitator that went away. Never throw from here: the buyer has a valid
   * result and this is our accounting problem, not their failed request.
   */
  onSettlementFailure?: (ctx: ToolContext, verified: VerifyResult, reason?: string) => void;
}

/** A `McpToolError` whose body is the x402 `PaymentRequiredBody` (code `PAYMENT_REQUIRED`). */
export function paymentRequiredError(body: PaymentRequiredBody, reason?: string): McpToolError {
  const { code, cause, fix, retryable, ...rest } = body;
  return toolError({
    code,
    cause,
    fix,
    retryable,
    httpStatus: 402,
    details: reason !== undefined ? { reason } : undefined,
    extra: rest,
  });
}

function formatUsd(priceUsd: number): string {
  return priceUsd
    .toFixed(6)
    .replace(/0+$/, "")
    .replace(/\.$/, ".00")
    .replace(/\.(\d)$/, ".$10");
}

/**
 * Wrap a tool so it requires an entitlement or payment. The returned tool has the same name,
 * schema and output, plus an optional boolean `sample` input (default false) documented as
 * "return an example response at no charge".
 *
 * Flow per call: `sample` → handler with `ctx.sample = true`; else `authorize` ok → handler
 * (with `ctx.userId`); else verifier accepts the request's payment headers → handler; else a
 * `PAYMENT_REQUIRED` error result (`_meta.httpStatus: 402`).
 */
export function withPayment(tool: ToolDef, opts: WithPaymentOptions): ToolDef {
  if (!Number.isFinite(opts.priceUsd) || opts.priceUsd < 0) {
    throw new Error(`withPayment(${tool.name}): priceUsd must be a non-negative number`);
  }
  const sampleField = opts.sampleField ?? "sample";
  if (sampleField in tool.input.shape) {
    throw new Error(
      `withPayment(${tool.name}): input already has a field named ${JSON.stringify(sampleField)}; pass sampleField to rename it`,
    );
  }
  const verifier: PaymentVerifier = opts.verifier ?? new StubVerifier();
  // A verifier that was configured is a rail that can actually be settled, so when it refuses
  // it knows why ("insufficient credit: $0.00 available, $0.75 needed") and its reason is the
  // one the caller can act on. Without one, `authorize`'s reason is all there is.
  const liveRail = opts.verifier !== undefined;
  const input = tool.input.extend({
    [sampleField]: z
      .boolean()
      .default(false)
      .describe(
        "Set true to return an example response at no charge (sample mode). Default false.",
      ),
  });
  const description = `${tool.description.trim()} Paid: $${formatUsd(opts.priceUsd)} per call; without credit you get a PAYMENT_REQUIRED result. Set ${sampleField}=true for a free example response.`;

  return defineTool({
    name: tool.name,
    title: tool.title,
    description,
    input,
    output: tool.output,
    annotations: tool.annotations,
    async handler(raw, ctx) {
      const record: Record<string, unknown> = { ...raw };
      const sample = record[sampleField] === true;
      delete record[sampleField];

      if (sample) return tool.handler(record, { ...ctx, sample: true });

      let reason: string | undefined;
      if (opts.authorize) {
        const auth = await opts.authorize(ctx);
        if (auth.ok) return tool.handler(record, { ...ctx, userId: auth.userId });
        reason = auth.reason;
      }

      // A tool name is not a resource. Over HTTP the front door knows the real URL and puts
      // it on the context; over stdio there is no URL and the name is the best there is.
      const resource = ctx.resourceUrl ?? tool.name;
      const required = buildPaymentRequired({
        resource,
        priceUsd: opts.priceUsd,
        live: opts.live,
        description: opts.description,
        payTo: opts.payTo,
        creditsPayTo: opts.creditsPayTo,
        signupUrl: opts.signupUrl,
        selfServe: opts.selfServe,
        // withPayment always adds a free `sample` flag to the tool's input schema
        sampleMode: true,
        ...(opts.bazaar ? { bazaar: opts.bazaar } : {}),
      });
      // What we advertise and what we accept are separate questions. `accepts` only lists
      // rails a caller could actually settle, and is empty when none is configured — but a
      // caller may still present credit or a payment header, so the verifier always runs.
      // The card rail is checked first because it is the one that can be settled today.
      const advertised =
        required.body.accepts.find((a) => a.rail === "prepaid_credits") ?? required.body.accepts[0];
      const requirement: PaymentRequirement = advertised ?? {
        rail: "prepaid_credits",
        amountUsd: String(required.body.priceUsd),
        resource,
        ...(opts.description ? { description: opts.description } : {}),
      };
      const verified = await verifier.verify(
        new Request(`https://mcp.local/${tool.name}`, { headers: ctx.headers }),
        requirement,
      );
      if (verified.ok) {
        let result: Awaited<ReturnType<typeof tool.handler>>;
        try {
          result = await tool.handler(record, ctx);
        } catch (error) {
          // Rails that already took the money refund here. Rails with a `settle` step have
          // not taken it yet, and the early return means they never will — the buyer is not
          // charged for a call that failed.
          await opts.onPaidFailure?.(ctx, verified, error);
          throw error;
        }
        // The work succeeded, so take the money. A settlement that fails now is lost
        // revenue, not a failed request: the buyer has already been served, and turning
        // this into an error would hand them the result *and* a 402.
        const settled = await verifier.settle?.(verified);
        if (settled && !settled.ok) {
          opts.onSettlementFailure?.(ctx, verified, settled.reason);
        }
        return result;
      }
      reason = liveRail ? (verified.reason ?? reason) : (reason ?? verified.reason);
      throw paymentRequiredError(required.body, reason);
    },
  });
}

/** Web-standard 402 `Response` for plain HTTP endpoints (re-export of `@agentwares/x402`). */
export const paymentRequiredHttpResponse = paymentRequiredResponse;

export { StubVerifier, buildPaymentRequired };
export type { PaymentRequiredBody, PaymentVerifier, SelfServe, VerifyResult };
